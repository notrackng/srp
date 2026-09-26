<?php

/**
 * SRP — Auto Installer (dashboard UI)
 *
 * First-run web wizard reachable at gen.<domain>/install.php. Refuses with 403
 * "Already installed" once <project-root>/install.lock exists.
 *
 * Before that, the wizard itself does not exist to a visitor who cannot read
 * <project-root>/install.token off the server's disk: a missing/too-short
 * token file yields 404 (not 403), so an unprepared deployment does not admit
 * an installer was ever there. The secret is POSTed, never placed in the URL,
 * and token attempts share the app's per-IP throttle (login_throttle.php; 8
 * failures/hour, scope "installer_token") — same model as the pre-audit
 * installer this file replaces. Without this gate any first visitor could
 * drive the whole wizard (DB, admin password, Cloudflare/cPanel tokens) ahead
 * of the real operator and lock them out via install.lock.
 *
 * Panels:
 *   1. System check
 *   2. Database (test connection + import schema.sql)
 *   3. Domain, server & services (cPanel subdomains)
 *   4. Admin & security (passwords + generated secrets)
 *   5. Cron jobs
 *   6. Finalize (writes .env, report_auth.php, .user.ini log paths, install.lock)
 *   7. Manual installation guide
 *
 * Reuses env.php (config loading, cPanel host detection, error-log path) and
 * public/cf-lib.php (Cloudflare API + cPanel UAPI helpers).
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';
require_once __DIR__ . '/cf-lib.php';
require_once dirname(__DIR__) . '/login_throttle.php';

const INST_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/**
 * Project root (one level above public/).
 */
function inst_root(): string
{
    return dirname(__DIR__);
}

function inst_lock_file(): string
{
    return inst_root() . '/install.lock';
}

function inst_env_file(): string
{
    return inst_root() . '/.env';
}

function inst_report_auth_file(): string
{
    return inst_root() . '/statistics/report_auth.php';
}

function inst_schema_file(): string
{
    return inst_root() . '/schema.sql';
}

function inst_token_file(): string
{
    return inst_root() . '/install.token';
}

/**
 * Pre-shared secret gating the whole installer. Returns null when the file is
 * absent/unreadable or shorter than 32 chars — the same minimum the setup
 * command (`php -r "echo bin2hex(random_bytes(32));" > install.token`)
 * produces — so a placeholder or truncated value cannot gate real secrets.
 */
function inst_read_install_token(): ?string
{
    $file = inst_token_file();
    if (!is_file($file) || !is_readable($file)) {
        return null;
    }

    $token = trim((string) @file_get_contents($file));

    return strlen($token) >= 32 ? $token : null;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function inst_json(int $code, array $payload): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

function inst_post(string $key, mixed $default = null): mixed
{
    return $_POST[$key] ?? $default;
}

function inst_post_string(string $key, string $default = ''): string
{
    $value = inst_post($key, $default);

    return is_string($value) ? trim($value) : $default;
}

/**
 * Set an environment variable in-process so shared helpers (cfCpanelUapi, cfApi,
 * app_env) see it even before .env exists.
 */
function inst_setenv(string $key, string $value): void
{
    putenv($key . '=' . $value);
    $_ENV[$key] = $value;
    $_SERVER[$key] = $value;
}

/**
 * Run a fixed shell command for server introspection (e.g. hostname -f / -I)
 * and return trimmed output, or null when shell execution is unavailable.
 */
function inst_shell_exec(string $command): ?string
{
    if (!function_exists('shell_exec')) {
        return null;
    }

    $disabled = ini_get('disable_functions');
    if (is_string($disabled) && str_contains($disabled, 'shell_exec')) {
        return null;
    }

    $output = @shell_exec($command);

    return is_string($output) ? trim($output) : null;
}

/**
 * Detect the cPanel server host. Prefers the FQDN from `hostname -f` (what
 * cPanel reports as the server name), then falls back to env.php's thorough
 * detector (reverse DNS + TLS probe).
 */
function inst_detect_cpanel_host(): string
{
    $fqdn = inst_shell_exec('hostname -f 2>/dev/null');
    if (is_string($fqdn) && $fqdn !== '') {
        $normalized = app_normalize_cpanel_host($fqdn);
        if ($normalized !== '') {
            return $normalized;
        }
    }

    return app_detect_cpanel_host();
}

/**
 * Auto-detect the server IP. Order: `hostname -I`, resolving the FQDN, then
 * SERVER_ADDR / REMOTE_ADDR. A public IP is preferred as the primary value.
 *
 * @return array{server_ip: string, ips: list<string>, server_addr: string, remote_addr: string, hostname: string}
 */
function inst_detect_server_ip(): array
{
    $ips = [];

    $collect = static function (string $raw) use (&$ips): void {
        foreach (preg_split('/[\s,]+/', trim($raw)) as $candidate) {
            if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                $ips[] = $candidate;
            }
        }
    };

    $hostnameI = inst_shell_exec('hostname -I 2>/dev/null');
    if (is_string($hostnameI) && $hostnameI !== '') {
        $collect($hostnameI);
    }

    $fqdn = inst_shell_exec('hostname -f 2>/dev/null');
    if (is_string($fqdn) && $fqdn !== '') {
        $resolved = gethostbynamel($fqdn);
        if (is_array($resolved)) {
            $collect(implode(' ', $resolved));
        }
    }

    $collect((string) ($_SERVER['SERVER_ADDR'] ?? ''));
    $collect((string) ($_SERVER['REMOTE_ADDR'] ?? ''));

    $ips = array_values(array_unique($ips));

    $primary = '';
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            $primary = $ip;
            break;
        }
    }
    if ($primary === '' && $ips !== []) {
        $primary = $ips[0];
    }

    return [
        'server_ip' => $primary,
        'ips' => $ips,
        'server_addr' => (string) ($_SERVER['SERVER_ADDR'] ?? ''),
        'remote_addr' => (string) ($_SERVER['REMOTE_ADDR'] ?? ''),
        'hostname' => gethostname() ?: '',
    ];
}

// ---------------------------------------------------------------------------
// Session + CSRF (state-changing actions only)
// ---------------------------------------------------------------------------

function inst_is_https(): bool
{
    // Delegates to the canonical detector in env.php (hard-required at the top of
    // this file). The previous body only inspected $_SERVER['HTTPS'], so behind a
    // TLS-terminating proxy or Cloudflare (HTTPS unset, X-Forwarded-Proto/CF-Visitor
    // set, or port 443) the installer session cookie was not flagged secure.
    return srp_request_is_https();
}

function inst_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    session_name('srp_installer');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => inst_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function inst_csrf_token(): string
{
    if (!isset($_SESSION['inst_csrf']) || !is_string($_SESSION['inst_csrf']) || $_SESSION['inst_csrf'] === '') {
        $_SESSION['inst_csrf'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['inst_csrf'];
}

function inst_verify_csrf(mixed $token): bool
{
    if (!is_string($token) || $token === '') {
        return false;
    }

    $expected = $_SESSION['inst_csrf'] ?? null;

    return is_string($expected) && $expected !== '' && hash_equals($expected, $token);
}

/**
 * Verify the POSTed install.token against the on-disk secret, throttled per
 * IP (8 fails/hour, matching every other credential surface in this app —
 * see login_throttle.php). On success marks the session so the rest of the
 * wizard becomes reachable.
 *
 * @return array{ok: bool, err?: string}
 */
function inst_act_verify_token(string $installToken): array
{
    $scope = 'installer_token';
    $state = srp_login_throttle_state($scope);
    if ($state['fails'] >= 8 && (time() - $state['last']) < 3600) {
        return ['ok' => false, 'err' => 'locked'];
    }

    $provided = inst_post_string('install_token');
    if ($provided === '' || !hash_equals($installToken, $provided)) {
        srp_login_throttle_register_fail($scope);

        return ['ok' => false, 'err' => 'invalid-token'];
    }

    srp_login_throttle_reset($scope);
    $_SESSION['inst_token_verified'] = true;

    return ['ok' => true];
}

/**
 * Minimal standalone page shown until the session passes inst_act_verify_token().
 * Deliberately does not include any of the wizard's system/environment detail.
 */
function inst_render_token_prompt(string $csrf): never
{
    $e = static function (mixed $value): string {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    };
    ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="<?= $e($csrf) ?>">
<title>SRP — Installer</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f172a;color:#e2e8f0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:28px;width:340px}
h1{font-size:16px;margin:0 0 14px}
input{width:100%;padding:9px 10px;border-radius:6px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;margin-bottom:10px;font:inherit;box-sizing:border-box}
button{width:100%;padding:9px;border:0;border-radius:6px;background:#3b82f6;color:#fff;font:inherit;cursor:pointer}
.status{margin-top:10px;font-size:12px;min-height:16px}
.status.bad{color:#ef4444}
</style>
</head>
<body>
<div class="card">
<h1>Installer token required</h1>
<form id="tokf" autocomplete="off">
<input type="password" id="tok" name="install_token" placeholder="install.token contents" autofocus>
<button type="submit">Continue</button>
<div class="status" id="st"></div>
</form>
</div>
<script>
(function(){
  var CSRF = document.querySelector('meta[name=csrf-token]').content;
  document.getElementById('tokf').addEventListener('submit', function(ev){
    ev.preventDefault();
    var st = document.getElementById('st');
    st.className = 'status'; st.textContent = 'Checking…';
    fetch(window.location.pathname, {
      method: 'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8','Accept':'application/json'},
      body: new URLSearchParams({action:'verify_token', install_token: document.getElementById('tok').value, csrf_token: CSRF}).toString()
    }).then(function(r){ return r.json().catch(function(){ return {ok:false}; }); })
      .then(function(r){
        if (r && r.ok) { window.location.reload(); return; }
        st.className = 'status bad';
        st.textContent = (r && r.err === 'locked') ? 'Too many attempts — try again later.' : 'Invalid token.';
      })
      .catch(function(){ st.className = 'status bad'; st.textContent = 'Request failed.'; });
  });
})();
</script>
</body>
</html>
    <?php
    exit;
}

// ---------------------------------------------------------------------------
// Secrets & passwords
// ---------------------------------------------------------------------------

/**
 * Keep a value only if it is already 64 hex chars; otherwise return a fresh
 * cryptographically-random 64-char hex secret.
 */
function inst_secret_or_generate(mixed $value): string
{
    if (is_string($value) && preg_match('/^[0-9a-fA-F]{64}$/', $value) === 1) {
        return strtolower($value);
    }

    return bin2hex(random_bytes(32));
}

function inst_random_password(int $length = 16): string
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $out = '';
    $max = strlen($alphabet) - 1;

    for ($i = 0; $i < $length; $i++) {
        $out .= $alphabet[random_int(0, $max)];
    }

    return $out;
}

/**
 * Hash a password. Returns [hash, plaintext] — when the input is blank a random
 * password is generated and returned so the operator sees it once.
 *
 * @return array{hash: string, plain: string}
 */
function inst_hash_password(mixed $value): array
{
    $plain = is_string($value) && trim($value) !== '' ? trim($value) : inst_random_password();
    $hash = password_hash($plain, PASSWORD_BCRYPT);

    return ['hash' => $hash, 'plain' => $plain];
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/**
 * @param array<string, mixed> $c
 */
function inst_pdo_connect(array $c): PDO
{
    $host = trim((string) ($c['host'] ?? ''));
    $port = (int) ($c['port'] ?? 3306);
    $user = trim((string) ($c['user'] ?? ''));
    $pass = (string) ($c['password'] ?? '');
    $name = trim((string) ($c['name'] ?? ''));
    $socket = trim((string) ($c['socket'] ?? ''));
    $charset = trim((string) ($c['charset'] ?? ''));

    if ($host === '' || $user === '' || $name === '') {
        throw new RuntimeException('Host, user and database name are required.');
    }

    if ($port < 1 || $port > 65535) {
        $port = 3306;
    }

    $charset = $charset !== '' ? $charset : 'utf8mb4';

    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $host, $port, $name, $charset);
    if ($socket !== '') {
        $dsn .= ';unix_socket=' . $socket;
    }

    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_TIMEOUT => 5,
    ];

    if (defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
        $options[PDO::MYSQL_ATTR_MULTI_STATEMENTS] = false;
    }

    return new PDO($dsn, $user, $pass, $options);
}

/**
 * Split schema.sql into runnable statements, stripping the mysql-CLI
 * DELIMITER procedure block (only needed to upgrade pre-existing databases)
 * and comment lines.
 *
 * @return list<string>
 */
function inst_split_schema(string $sql): array
{
    $sql = preg_replace('/DELIMITER \$\$.*?END \$\$.*?DELIMITER ;/s', '', $sql) ?? $sql;
    $sql = preg_replace('/^\s*(CALL|DROP PROCEDURE)[^;]*;/m', '', $sql) ?? $sql;
    $sql = preg_replace('/^\s*--.*$/m', '', $sql) ?? $sql;

    $statements = [];
    foreach (preg_split('/;\s*(?:\r\n|\r|\n|$)/', $sql) as $stmt) {
        $trimmed = trim((string) $stmt);
        if ($trimmed !== '') {
            $statements[] = $trimmed;
        }
    }

    return $statements;
}

/**
 * @return array{ok: bool, created: list<string>, error?: string}
 */
function inst_import_schema(PDO $pdo): array
{
    $path = inst_schema_file();
    if (!is_file($path) || !is_readable($path)) {
        return ['ok' => false, 'created' => [], 'error' => 'schema.sql missing or unreadable'];
    }

    $sql = file_get_contents($path);
    if (!is_string($sql)) {
        return ['ok' => false, 'created' => [], 'error' => 'schema.sql read failed'];
    }

    $created = [];
    foreach (inst_split_schema($sql) as $statement) {
        if (stripos($statement, 'CREATE TABLE') === 0) {
            $created[] = $statement;
        }
        $pdo->exec($statement);
    }

    // Verify the core tables exist. Uses information_schema (named placeholder)
    // instead of `SHOW TABLES LIKE ?` — MariaDB's native prepared statements
    // reject a parameter marker there (SQLSTATE 42000 near '?').
    $required = ['generate', 'addondomain', 'offering', 'clickrecord', 'leadreport', 'srp_short_links', 'shortlinks'];
    $missing = [];
    foreach ($required as $table) {
        $stmt = $pdo->prepare(
            'SELECT 1 FROM information_schema.tables '
            . 'WHERE table_schema = DATABASE() AND table_name = :table_name LIMIT 1',
        );
        $stmt->execute(['table_name' => $table]);
        if ($stmt->fetchColumn() === false) {
            $missing[] = $table;
        }
    }

    if ($missing !== []) {
        return ['ok' => false, 'created' => $created, 'error' => 'Tables missing after import: ' . implode(', ', $missing)];
    }

    return ['ok' => true, 'created' => $created];
}

// ---------------------------------------------------------------------------
// cPanel + cron provisioning (reuses cf-lib.php helpers)
// ---------------------------------------------------------------------------

/**
 * Apply cPanel credentials from a request payload in-process, then return the
 * normalized values for reporting.
 *
 * @return array<string, string>
 */
function inst_cpanel_credentials_from_post(): array
{
    $creds = [
        'CPANEL_USER' => inst_post_string('cpanel_user'),
        'CPANEL_API_TOKEN' => inst_post_string('cpanel_token'),
        'CPANEL_PASSWORD' => inst_post_string('cpanel_password'),
        'CPANEL_HOST' => inst_post_string('cpanel_host'),
        'CPANEL_PORT' => inst_post_string('cpanel_port', '2083'),
        'CPANEL_SSL_VERIFY' => inst_post_string('cpanel_ssl_verify', '1'),
    ];

    foreach ($creds as $key => $value) {
        inst_setenv($key, $value);
    }

    return $creds;
}

/**
 * @return array{ok: bool, results: list<array<string, mixed>>}
 */
function inst_provision_subdomains(): array
{
    $domain = inst_post_string('base_domain');
    $projectDir = trim(inst_post_string('project_dir'), '/');

    if ($domain === '' || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i', $domain) !== 1) {
        return ['ok' => false, 'results' => [['subdomain' => '', 'status' => 'error', 'message' => 'Invalid base domain.']]];
    }

    if ($projectDir === '' || str_contains($projectDir, '..')) {
        return ['ok' => false, 'results' => [['subdomain' => '', 'status' => 'error', 'message' => 'Invalid project directory.']]];
    }

    inst_cpanel_credentials_from_post();

    $plans = [
        ['gen', $projectDir . '/public'],
        ['s', $projectDir . '/statistics'],
        ['r', $projectDir . '/redirect'],
        ['*', $projectDir . '/redirect'],
    ];

    $results = [];
    $allOk = true;
    foreach ($plans as $plan) {
        [$sub, $dir] = $plan;
        $subdomain = $sub === '*' ? '*' : $sub . '.' . $domain;

        try {
            $resp = cfCpanelUapi('SubDomain', 'addsubdomain', [
                'domain' => $subdomain,
                'rootdomain' => $domain,
                'dir' => $dir,
            ]);

            $status = (int) ($resp['status'] ?? 0);
            if ($status === 1) {
                $results[] = ['subdomain' => $subdomain, 'status' => 'ok', 'message' => 'created'];
            } else {
                $allOk = false;
                $results[] = ['subdomain' => $subdomain, 'status' => 'error', 'message' => cfCpanelUapiError($resp)];
            }
        } catch (Throwable $e) {
            // "already exists" is reported as an error by cPanel; treat it as OK.
            $msg = $e->getMessage();
            $alreadyExists = str_contains($msg, 'already exists') || str_contains($msg, 'exists');
            $results[] = [
                'subdomain' => $subdomain,
                'status' => $alreadyExists ? 'ok' : 'error',
                'message' => $alreadyExists ? 'already exists' : $msg,
            ];
            if (!$alreadyExists) {
                $allOk = false;
            }
        }
    }

    return ['ok' => $allOk, 'results' => $results];
}

/**
 * @return array{ok: bool, added: list<string>, skipped: list<string>, warnings: list<string>}
 */
function inst_add_crons(): array
{
    $phpBin = trim(inst_post_string('php_bin'));
    $root = inst_root();

    if ($phpBin === '' || !str_starts_with($phpBin, '/')) {
        return ['ok' => false, 'added' => [], 'skipped' => [], 'warnings' => ['PHP binary path must be absolute (e.g. /usr/local/bin/php).']];
    }

    if (inst_post_string('cpanel_user') === '') {
        return ['ok' => false, 'added' => [], 'skipped' => [], 'warnings' => ['cPanel user is required — fill it in step 3 first.']];
    }

    inst_cpanel_credentials_from_post();

    $jobs = [
        ['0', '2', '*', '*', '*', $phpBin . ' ' . escapeshellarg($root . '/redirect/cleanup-cache.php')],
        ['0', '3', '*', '*', '3', $phpBin . ' ' . escapeshellarg($root . '/redirect/update-geoip.php')],
        ['30', '2', '*', '*', '*', $phpBin . ' ' . escapeshellarg($root . '/cleanup-storage.php')],
        // rotate-logs.sh is a shell script — must run via bash, never via the
        // PHP binary (PHP cannot execute it; a past manual crontab entry that
        // got this wrong silently never rotated a single log).
        ['0', '4', '*', '*', '*', '/bin/bash ' . escapeshellarg($root . '/rotate-logs.sh')],
    ];

    $existing = [];
    try {
        $list = cfCpanelUapi('Cron', 'list_lines', []);
        foreach (($list['data'] ?? []) as $item) {
            if (is_array($item) && isset($item['command']) && is_string($item['command'])) {
                $existing[] = $item['command'];
            }
        }
    } catch (Throwable $e) {
        $existing = [];
    }

    $added = [];
    $skipped = [];
    $warnings = [];

    foreach ($jobs as $job) {
        [$minute, $hour, $day, $month, $weekday, $command] = $job;
        $scriptPath = preg_replace('/^.*?(\/[^ ]+\.(?:php|sh)).*$/', '$1', $command) ?? $command;

        $already = false;
        foreach ($existing as $line) {
            if (str_contains($line, $scriptPath)) {
                $already = true;
                break;
            }
        }

        if ($already) {
            $skipped[] = $scriptPath;
            continue;
        }

        try {
            $resp = cfCpanelUapi('Cron', 'add_line', [
                'command' => $command,
                'minute' => $minute,
                'hour' => $hour,
                'day' => $day,
                'month' => $month,
                'weekday' => $weekday,
            ]);

            if ((int) ($resp['status'] ?? 0) === 1) {
                $added[] = $scriptPath;
            } else {
                $warnings[] = 'Could not add ' . $scriptPath . ': ' . cfCpanelUapiError($resp);
            }
        } catch (Throwable $e) {
            $warnings[] = 'Could not add ' . $scriptPath . ': ' . $e->getMessage();
        }
    }

    return ['ok' => true, 'added' => $added, 'skipped' => $skipped, 'warnings' => $warnings];
}

/**
 * Find or create the Cloudflare zone for the base domain, provision its DNS
 * records (apex + wildcard + www + null MX + SPF + DMARC) and optionally apply
 * the recommended settings.
 *
 * @return array{ok: bool, zone_id?: string, status?: string, name_servers?: list<string>, dns?: list<string>, applied?: bool, error?: string}
 */
function inst_provision_cloudflare_zone(): array
{
    $domain = inst_post_string('base_domain');
    $token = inst_post_string('cf_token');
    $accountId = inst_post_string('cf_account_id');
    $serverIp = inst_post_string('server_ip');
    $applyRecommended = inst_post_string('cf_apply_recommended', '1') !== '0';
    $sslMode = inst_post_string('cf_ssl_mode', 'flexible');

    if ($domain === '' || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i', $domain) !== 1) {
        return ['ok' => false, 'error' => 'Invalid base domain.'];
    }

    if ($token === '') {
        return ['ok' => false, 'error' => 'Cloudflare API token is required.'];
    }

    if ($serverIp === '') {
        return ['ok' => false, 'error' => 'Server IP is required — use "Detect server IP" first.'];
    }

    inst_setenv('CF_API_TOKEN', $token);
    inst_setenv('CF_ACCOUNT_ID', $accountId);
    inst_setenv('CF_SSL_MODE', $sslMode);

    // Find an existing zone, else create one.
    $zoneId = '';
    $status = '';
    $nameServers = [];

    $listResp = cfApi('GET', '/zones?name=' . urlencode($domain), null, $token);
    if (!empty($listResp['result']) && is_array($listResp['result'])) {
        $zone = $listResp['result'][0];
        $zoneId = (string) ($zone['id'] ?? '');
        $status = (string) ($zone['status'] ?? 'pending');
        $nameServers = $zone['name_servers'] ?? [];
    }

    if ($zoneId === '') {
        $createBody = ['name' => $domain, 'jump_start' => true];
        if ($accountId !== '') {
            $createBody['account'] = ['id' => $accountId];
        }

        $createResp = cfApi('POST', '/zones', $createBody, $token);
        if (empty($createResp['success'])) {
            $alreadyExists = false;
            foreach (($createResp['errors'] ?? []) as $cfErr) {
                if (($cfErr['code'] ?? 0) === 1061) {
                    $alreadyExists = true;
                    break;
                }
            }

            if ($alreadyExists) {
                $fallback = cfApi('GET', '/zones?name=' . urlencode($domain), null, $token);
                if (!empty($fallback['result'][0])) {
                    $zone = $fallback['result'][0];
                    $zoneId = (string) ($zone['id'] ?? '');
                    $status = (string) ($zone['status'] ?? 'pending');
                    $nameServers = $zone['name_servers'] ?? [];
                } else {
                    return ['ok' => false, 'error' => 'zone-exists'];
                }
            } else {
                $rawMsg = (string) ($createResp['errors'][0]['message'] ?? 'zone-create-failed');
                $msg = str_contains($rawMsg, 'zone.create')
                    ? 'cf-token-zone-create-denied'
                    : 'zone-create-failed';

                return ['ok' => false, 'error' => $msg];
            }
        } else {
            $zone = $createResp['result'];
            $zoneId = (string) ($zone['id'] ?? '');
            $status = (string) ($zone['status'] ?? 'pending');
            $nameServers = $zone['name_servers'] ?? [];
        }
    }

    if ($zoneId === '') {
        return ['ok' => false, 'error' => 'zone-id-missing'];
    }

    try {
        $dns = cfProvisionDns($zoneId, $domain, $serverIp, $token);
    } catch (Throwable $e) {
        $dns = ['error: ' . $e->getMessage()];
    }

    $applied = false;
    if ($applyRecommended) {
        try {
            cfApplyAllRecommended($zoneId, $token);
            $applied = true;
        } catch (Throwable $e) {
            $applied = false;
        }
    }

    $nsList = [];
    if (is_array($nameServers)) {
        foreach ($nameServers as $nsItem) {
            if (is_string($nsItem) && $nsItem !== '') {
                $nsList[] = $nsItem;
            }
        }
    }

    return [
        'ok' => true,
        'zone_id' => $zoneId,
        'status' => $status,
        'name_servers' => $nsList,
        'dns' => $dns,
        'applied' => $applied,
        'ssl_mode' => $sslMode,
    ];
}

/**
 * Install a Cloudflare Origin CA certificate on the origin (cPanel) for the
 * base domain's wildcard, then pin the zone to the selected SSL mode. This is
 * the fix for error 525 (origin had no certificate at all).
 *
 * @return array{ok: bool, ssl_mode?: string, install_domain?: string, cert_id?: string, expires_on?: string, error?: string}
 */
function inst_act_install_ssl(): array
{
    $domain = inst_post_string('base_domain');
    $token = inst_post_string('cf_token');
    $accountId = inst_post_string('cf_account_id');
    $sslMode = inst_post_string('cf_ssl_mode', 'flexible');

    if ($domain === '' || preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i', $domain) !== 1) {
        return ['ok' => false, 'error' => 'Invalid base domain.'];
    }

    if ($token === '') {
        return ['ok' => false, 'error' => 'Cloudflare API token is required.'];
    }

    inst_setenv('CF_API_TOKEN', $token);
    inst_setenv('CF_ACCOUNT_ID', $accountId);
    inst_setenv('CF_SSL_MODE', $sslMode);
    inst_cpanel_credentials_from_post();

    // Find an existing zone, else create one (the Origin CA install needs it).
    $zoneId = '';

    $listResp = cfApi('GET', '/zones?name=' . urlencode($domain), null, $token);
    if (!empty($listResp['result']) && is_array($listResp['result'])) {
        $zoneId = (string) ($listResp['result'][0]['id'] ?? '');
    }

    if ($zoneId === '') {
        $createBody = ['name' => $domain, 'jump_start' => true];
        if ($accountId !== '') {
            $createBody['account'] = ['id' => $accountId];
        }

        $createResp = cfApi('POST', '/zones', $createBody, $token);
        if (!empty($createResp['result']['id'])) {
            $zoneId = (string) $createResp['result']['id'];
        }
    }

    if ($zoneId === '') {
        return ['ok' => false, 'error' => 'zone-id-missing'];
    }

    try {
        $result = cfCreateAndInstallOriginCertificate($zoneId, $domain, $token);
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }

    // Pin the zone to the selected SSL mode now that the cert is installed.
    try {
        cfApi('PATCH', '/zones/' . $zoneId . '/settings/ssl', ['value' => $sslMode], $token);
    } catch (Throwable $e) {
        // Non-fatal: the cert is installed; the operator can re-pin later.
    }

    return [
        'ok' => true,
        'ssl_mode' => $sslMode,
        'install_domain' => (string) ($result['install_domain'] ?? ''),
        'cert_id' => (string) ($result['cert_id'] ?? ''),
        'expires_on' => (string) ($result['expires_on'] ?? ''),
    ];
}

/**
 * Detect an "already exists" cPanel API error and treat it as success — the
 * idempotency rule used by every provisioning step.
 */
function inst_is_already_exists(string $message): bool
{
    $lower = strtolower($message);

    return str_contains($lower, 'already exists') || str_contains($lower, 'already exist');
}

/**
 * Normalize a database/user identifier to cPanel's "<account>_" convention.
 * Returns null when the result would exceed the server's identifier limit.
 */
function inst_cpanel_db_identifier(string $value, string $account, int $maxLength): ?string
{
    $value = preg_replace('/[^A-Za-z0-9_]+/', '_', trim($value)) ?? '';
    if ($value === '') {
        return null;
    }

    $prefix = $account . '_';
    if (!str_starts_with(strtolower($value), strtolower($prefix))) {
        $value = $prefix . $value;
    }

    return strlen($value) <= $maxLength ? $value : null;
}

/**
 * Run one cPanel MySQL UAPI call, folding "already exists" into success.
 *
 * @param array<string, string> $params
 * @return array{ok: bool, message: string}
 */
function inst_cpanel_mysql_call(string $module, string $function, array $params): array
{
    try {
        $resp = cfCpanelUapi($module, $function, $params);
        if ((int) ($resp['status'] ?? 0) === 1) {
            return ['ok' => true, 'message' => $function . ' ok'];
        }

        $message = cfCpanelUapiError($resp);

        return ['ok' => inst_is_already_exists($message), 'message' => $message];
    } catch (Throwable $e) {
        $message = $e->getMessage();

        return ['ok' => inst_is_already_exists($message), 'message' => $message];
    }
}

/**
 * Auto-create a MySQL database + user via the cPanel UAPI and grant full
 * privileges. Names are auto-prefixed with the cPanel account when needed.
 *
 * @return array{ok: bool, db_name?: string, db_user?: string, db_host?: string, error?: string}
 */
function inst_act_create_database(): array
{
    $cpanelUser = inst_post_string('cpanel_user');
    $dbName = inst_post_string('db_name');
    $dbUser = inst_post_string('db_user');
    $dbPass = inst_post_string('db_password');

    if ($cpanelUser === '') {
        return ['ok' => false, 'error' => 'cPanel user is required — fill it in step 3 first.'];
    }

    if ($dbName === '' || $dbUser === '' || $dbPass === '') {
        return ['ok' => false, 'error' => 'Database name, user and password are required.'];
    }

    $dbName = inst_cpanel_db_identifier($dbName, $cpanelUser, 64);
    $dbUser = inst_cpanel_db_identifier($dbUser, $cpanelUser, 32);
    if ($dbName === null || $dbUser === null) {
        return ['ok' => false, 'error' => 'Database name/user too long after prefixing with the cPanel account.'];
    }

    inst_cpanel_credentials_from_post();

    $steps = [];
    $steps[] = inst_cpanel_mysql_call('Mysql', 'create_database', ['name' => $dbName]);
    $steps[] = inst_cpanel_mysql_call('Mysql', 'create_user', ['name' => $dbUser, 'password' => $dbPass]);
    $steps[] = inst_cpanel_mysql_call('Mysql', 'set_privileges_on_database', [
        'user' => $dbUser,
        'database' => $dbName,
        'privileges' => 'ALL PRIVILEGES',
    ]);

    $errors = [];
    foreach ($steps as $step) {
        if (!$step['ok']) {
            $errors[] = $step['message'];
        }
    }

    if ($errors !== []) {
        return ['ok' => false, 'db_name' => $dbName, 'db_user' => $dbUser, 'error' => implode('; ', $errors)];
    }

    return [
        'ok' => true,
        'db_name' => $dbName,
        'db_user' => $dbUser,
        'db_host' => 'localhost',
        'message' => 'Database created and privileges granted.',
    ];
}

/**
 * Apply production file permissions: directories 0755, files 0644, `.env` 0600,
 * and ensure the runtime-writable directories exist.
 *
 * @return array{ok: bool, dirs: int, files: int, error?: string}
 */
function inst_act_fix_permissions(): array
{
    $root = inst_root();
    $dirs = 0;
    $files = 0;

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($iterator as $item) {
            $path = $item->getPathname();
            $name = $item->getFilename();

            if ($item->isDir()) {
                if ($name === '.git') {
                    continue;
                }
                @chmod($path, 0755);
                $dirs++;
            } else {
                if ($name === '.env') {
                    continue; // handled below as 0600
                }
                @chmod($path, 0644);
                $files++;
            }
        }
    } catch (Throwable $e) {
        return ['ok' => false, 'dirs' => $dirs, 'files' => $files, 'error' => $e->getMessage()];
    }

    $envFile = inst_env_file();
    if (is_file($envFile)) {
        @chmod($envFile, 0600);
    }

    foreach (['statistics', 'redirect/databases', 'redirect/logs'] as $relative) {
        $dir = $root . '/' . $relative;
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        @chmod($dir, 0755);
    }

    return ['ok' => true, 'dirs' => $dirs, 'files' => $files];
}

// ---------------------------------------------------------------------------
// .env writer
// ---------------------------------------------------------------------------

function inst_env_value(string $value): string
{
    if ($value === '') {
        return '';
    }

    if (preg_match('/^[0-9]+$/', $value) === 1) {
        return $value;
    }

    // Strip control characters (incl. CR/LF) so a value can never inject an extra
    // .env line. Mirrors rdEnvValue() in redirect-decision.php: the installer is
    // the one writer that takes free-form operator input for every credential and
    // URL, so a newline here would split into a rogue KEY=VALUE line that all three
    // web roots then load as trusted config. Defense in depth; callers still validate.
    $value = preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '';

    return '"' . addcslashes($value, "\\\"") . '"';
}

/**
 * @param array<string, mixed> $c
 * @param array<string, string> $secrets
 * @param array<string, string> $hashes
 */
function inst_build_env(array $c, array $secrets, array $hashes): string
{
    $line = static function (string $key, string $value): string {
        return $key . '=' . inst_env_value($value);
    };

    $cpanelUser = (string) ($c['cpanel_user'] ?? '');
    $cpanelToken = (string) ($c['cpanel_token'] ?? '');
    $cpanelPassword = (string) ($c['cpanel_password'] ?? '');
    $cpanelHost = (string) ($c['cpanel_host'] ?? '');
    $cpanelPort = (string) ($c['cpanel_port'] ?? '2083');
    $cpanelSslVerify = (string) ($c['cpanel_ssl_verify'] ?? '1');
    $projectDir = trim((string) ($c['project_dir'] ?? ''), '/');

    $lines = [
        '# SRP — generated by install.php (v' . INST_VERSION . ')',
        'APP_ENV=production',
        'APP_DEBUG=0',
        $line('APP_URL', (string) ($c['app_url'] ?? '')),
        '',
        'DB_HOST=' . inst_env_value((string) ($c['db_host'] ?? '')),
        'DB_PORT=' . inst_env_value((string) ($c['db_port'] ?? '3306')),
        'DB_USER=' . inst_env_value((string) ($c['db_user'] ?? '')),
        'DB_PASSWORD=' . inst_env_value((string) ($c['db_password'] ?? '')),
        'DB_NAME=' . inst_env_value((string) ($c['db_name'] ?? '')),
        'DB_SOCKET=' . inst_env_value((string) ($c['db_socket'] ?? '')),
        'DB_CHARSET=' . inst_env_value((string) ($c['db_charset'] ?? 'utf8mb4')),
        'DB_PERSISTENT=0',
        '',
        'ADMIN_PASSWORD_HASH=' . inst_env_value($hashes['admin']),
        'A2ROOT_PASSWORD_HASH=' . inst_env_value($hashes['admin']),
        'ENV_EDITOR_PASSWORD_HASH=' . inst_env_value($hashes['env']),
        'RD_PASSWORD_HASH=' . inst_env_value($hashes['rd']),
        '',
        'CPANEL_USER=' . inst_env_value($cpanelUser),
        'CPANEL_PASSWORD=' . inst_env_value($cpanelPassword),
        'CPANEL_HOST=' . inst_env_value($cpanelHost),
        'CPANEL_PORT=' . inst_env_value($cpanelPort),
        'CPANEL_SUBDOMAIN_DIR=' . inst_env_value($projectDir),
        'CPANEL_API_TOKEN=' . inst_env_value($cpanelToken),
        'CPANEL_SSL_VERIFY=' . inst_env_value($cpanelSslVerify),
        '',
        'ADDON_DNS_PRECHECK=1',
        '',
        'CF_API_TOKEN=' . inst_env_value((string) ($c['cf_token'] ?? '')),
        'CF_SSL_MODE=' . inst_env_value((string) ($c['cf_ssl_mode'] ?? 'flexible')),
        'CF_ACCOUNT_ID=' . inst_env_value((string) ($c['cf_account_id'] ?? '')),
        'CF_SERVER_IP=' . inst_env_value((string) ($c['cf_server_ip'] ?? '')),
        'CF_APPLY_OPTIONAL_SETTINGS=' . inst_env_value((string) ($c['cf_apply_optional'] ?? '1')),
        'CF_APPLY_PAID_FEATURES=' . inst_env_value((string) ($c['cf_apply_paid'] ?? '1')),
        'CF_ENABLE_FACEBOOK_OG_WAF_SKIP=' . inst_env_value((string) ($c['cf_fb_og_skip'] ?? '1')),
        'CF_NS1=' . inst_env_value((string) ($c['cf_ns1'] ?? '')),
        'CF_NS2=' . inst_env_value((string) ($c['cf_ns2'] ?? '')),
        'CF_NS3=' . inst_env_value((string) ($c['cf_ns3'] ?? '')),
        'CF_NS4=' . inst_env_value((string) ($c['cf_ns4'] ?? '')),
        '',
        'AF_SECRET=' . inst_env_value($secrets['AF_SECRET']),
        'SRP_API_KEY=' . inst_env_value($secrets['SRP_API_KEY']),
        'SRP_RK_SECRET=' . inst_env_value($secrets['SRP_RK_SECRET']),
        'CF_TOKEN_ENC_KEY=' . inst_env_value($secrets['CF_TOKEN_ENC_KEY']),
        'SRP_SHORTEN_RATE_PER_MIN=300',
        'TRACKR_API_KEY=',
        'TRACKR_ENDPOINT=',
        'TINYURL_API_KEY=',
        '',
        'REPORT_HOST=' . inst_env_value((string) ($c['report_host'] ?? '')),
        '',
        'SRP_BLOCK_COUNTRIES=' . inst_env_value((string) ($c['block_countries'] ?? 'ID')),
        'SRP_BLOCK_URL=' . inst_env_value((string) ($c['block_url'] ?? '')),
        'SRP_BLOCK_VPN_ASN=1',
        '',
        'SRP_FILTER_URL=' . inst_env_value((string) ($c['filter_url'] ?? '')),
        'SRP_CYCLE_SECONDS=' . inst_env_value((string) ($c['cycle_seconds'] ?? '300')),
        'SRP_FILTER_SECONDS=' . inst_env_value((string) ($c['filter_seconds'] ?? '120')),
        '',
        'MAXMIND_LICENSE_KEY=' . inst_env_value((string) ($c['maxmind_key'] ?? '')),
        'MAXMIND_ACCOUNT_ID=' . inst_env_value((string) ($c['maxmind_account_id'] ?? '')),
        '',
        'POSTBACK_SECRET=' . inst_env_value($secrets['POSTBACK_SECRET']),
        'POSTBACK_TIMEZONE=' . inst_env_value((string) ($c['postback_timezone'] ?? 'UTC')),
        '',
        'SRP_CLOAK_DEBUG_KEY=' . inst_env_value((string) ($c['cloak_debug_key'] ?? '1')),
        'SRP_ALLOW_CLOUDFLARE_INSIGHTS=' . inst_env_value((string) ($c['allow_cf_insights'] ?? '0')),
    ];

    return implode("\n", $lines) . "\n";
}

// ---------------------------------------------------------------------------
// Finalize
// ---------------------------------------------------------------------------

/**
 * Rewrite the error_log path in every .user.ini (and any .htaccess php_value
 * block) to this account's real log path. Non-fatal: returns a summary.
 *
 * @return array<string, int>
 */
function inst_rewrite_error_log_paths(): array
{
    $logPath = srp_detect_error_log_path();
    if ($logPath === null) {
        return ['updated' => 0, 'unchanged' => 0, 'absent' => 0, 'failed' => 0, 'path' => null];
    }

    $files = [
        '.user.ini' => 'ini',
        'public/.user.ini' => 'ini',
        'redirect/.user.ini' => 'ini',
        'statistics/.user.ini' => 'ini',
        '.htaccess' => 'htaccess',
        'public/.htaccess' => 'htaccess',
        'redirect/.htaccess' => 'htaccess',
        'statistics/.htaccess' => 'htaccess',
    ];

    $summary = ['updated' => 0, 'unchanged' => 0, 'absent' => 0, 'failed' => 0, 'path' => $logPath];

    foreach ($files as $relative => $syntax) {
        $file = inst_root() . '/' . $relative;
        if (!is_file($file)) {
            $summary['absent']++;
            continue;
        }

        $current = @file_get_contents($file);
        if (!is_string($current)) {
            $summary['failed']++;
            continue;
        }

        if ($syntax === 'htaccess') {
            $updated = preg_replace(
                '/^([ \t]*)php_value[ \t]+error_log[ \t]+\S.*$/m',
                '${1}php_value error_log "' . $logPath . '"',
                $current,
                -1,
                $count,
            );
        } else {
            $updated = preg_replace(
                '/^[ \t]*error_log[ \t]*=.*$/m',
                'error_log = "' . $logPath . '"',
                $current,
                -1,
                $count,
            );

            if (is_string($updated) && $count === 0) {
                $updated = rtrim($current, "\r\n") . "\n" . 'error_log = "' . $logPath . '"' . "\n";
                $count = 1;
            }
        }

        if (!is_string($updated)) {
            $summary['failed']++;
            continue;
        }

        if ($count === 0) {
            $summary['absent']++;
            continue;
        }

        if ($updated === $current) {
            $summary['unchanged']++;
            continue;
        }

        if (@file_put_contents($file, $updated, LOCK_EX) === false) {
            $summary['failed']++;
        } else {
            $summary['updated']++;
        }
    }

    return $summary;
}

function inst_write_report_auth(string $hash): bool
{
    $file = inst_report_auth_file();
    $dir = dirname($file);

    if (!is_dir($dir)) {
        return false;
    }

    $php = "<?php\n\ndeclare(strict_types=1);\n\nreturn [\n    'password_hash' => " . var_export($hash, true) . ",\n];\n";

    $tmp = $file . '.tmp.' . bin2hex(random_bytes(8));
    if (@file_put_contents($tmp, $php, LOCK_EX) === false) {
        return false;
    }

    @chmod($tmp, 0640);

    if (!@rename($tmp, $file)) {
        @unlink($tmp);

        return false;
    }

    return true;
}

function inst_write_lock(): bool
{
    $content = json_encode([
        'installed_at' => gmdate('Y-m-d H:i:s'),
        'installer_version' => INST_VERSION,
    ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);

    return @file_put_contents(inst_lock_file(), $content . "\n", LOCK_EX) !== false;
}

/**
 * @return array{ok: bool, error?: string, secrets?: array<string, string>, passwords?: array<string, string>, log_paths?: array<string, int>}
 */
function inst_act_finalize(): array
{
    $root = inst_root();

    if (!is_writable($root)) {
        return ['ok' => false, 'error' => 'Project root is not writable: ' . $root];
    }

    $envFile = inst_env_file();
    if (is_file($envFile) && !is_writable($envFile)) {
        return ['ok' => false, 'error' => '.env exists but is not writable.'];
    }

    if (is_file(inst_lock_file()) && !is_writable(inst_lock_file())) {
        return ['ok' => false, 'error' => 'install.lock exists but is not writable.'];
    }

    $db = [
        'host' => inst_post_string('db_host'),
        'port' => inst_post_string('db_port', '3306'),
        'user' => inst_post_string('db_user'),
        'password' => inst_post_string('db_password'),
        'name' => inst_post_string('db_name'),
        'socket' => inst_post_string('db_socket'),
        'charset' => inst_post_string('db_charset', 'utf8mb4'),
    ];

    if ($db['host'] === '' || $db['user'] === '' || $db['name'] === '') {
        return ['ok' => false, 'error' => 'DB host, user and database name are required.'];
    }

    // Passwords (blank → generated once, returned below).
    $admin = inst_hash_password(inst_post('admin_password'));
    $stats = inst_hash_password(inst_post('stats_password'));
    $envPw = inst_hash_password(inst_post('env_password'));
    $rdPw = inst_hash_password(inst_post('rd_password'));

    $hashes = [
        'admin' => $admin['hash'],
        'env' => $envPw['hash'],
        'rd' => $rdPw['hash'],
    ];

    // Secrets.
    $secrets = [
        'AF_SECRET' => inst_secret_or_generate(inst_post('af_secret')),
        'SRP_API_KEY' => inst_secret_or_generate(inst_post('srp_api_key')),
        'POSTBACK_SECRET' => inst_secret_or_generate(inst_post('postback_secret')),
        'SRP_RK_SECRET' => inst_secret_or_generate(inst_post('srp_rk_secret')),
        'CF_TOKEN_ENC_KEY' => inst_secret_or_generate(inst_post('cf_token_enc_key')),
    ];

    // Config collected from the form.
    $c = [
        'app_url' => inst_post_string('app_url'),
        'db_host' => $db['host'],
        'db_port' => $db['port'],
        'db_user' => $db['user'],
        'db_password' => $db['password'],
        'db_name' => $db['name'],
        'db_socket' => $db['socket'],
        'db_charset' => $db['charset'],
        'cpanel_user' => inst_post_string('cpanel_user'),
        'cpanel_token' => inst_post_string('cpanel_token'),
        'cpanel_password' => inst_post_string('cpanel_password'),
        'cpanel_host' => inst_post_string('cpanel_host'),
        'cpanel_port' => inst_post_string('cpanel_port', '2083'),
        'cpanel_ssl_verify' => inst_post_string('cpanel_ssl_verify', '1'),
        'project_dir' => inst_post_string('project_dir'),
        'cf_token' => inst_post_string('cf_token'),
        'cf_ssl_mode' => inst_post_string('cf_ssl_mode', 'flexible'),
        'cf_account_id' => inst_post_string('cf_account_id'),
        'cf_server_ip' => inst_post_string('cf_server_ip'),
        'cf_apply_optional' => inst_post_string('cf_apply_optional', '1'),
        'cf_apply_paid' => inst_post_string('cf_apply_paid', '1'),
        'cf_fb_og_skip' => inst_post_string('cf_fb_og_skip', '1'),
        'cf_ns1' => inst_post_string('cf_ns1'),
        'cf_ns2' => inst_post_string('cf_ns2'),
        'cf_ns3' => inst_post_string('cf_ns3'),
        'cf_ns4' => inst_post_string('cf_ns4'),
        'report_host' => inst_post_string('report_host'),
        'block_countries' => inst_post_string('block_countries', 'ID'),
        'block_url' => inst_post_string('block_url'),
        'filter_url' => inst_post_string('filter_url'),
        'cycle_seconds' => inst_post_string('cycle_seconds', '300'),
        'filter_seconds' => inst_post_string('filter_seconds', '120'),
        'maxmind_key' => inst_post_string('maxmind_key'),
        'maxmind_account_id' => inst_post_string('maxmind_account_id'),
        'postback_timezone' => inst_post_string('postback_timezone', 'UTC'),
        'cloak_debug_key' => inst_post_string('cloak_debug_key', '1'),
        'allow_cf_insights' => inst_post_string('allow_cf_insights', '0'),
    ];

    // 1. Statistics report password → report_auth.php.
    if (!inst_write_report_auth($stats['hash'])) {
        return ['ok' => false, 'error' => 'Could not write statistics/report_auth.php — is statistics/ writable?'];
    }

    // 2. .env.
    $env = inst_build_env($c, $secrets, $hashes);
    if (@file_put_contents($envFile, $env, LOCK_EX) === false) {
        return ['ok' => false, 'error' => 'Could not write .env.'];
    }
    @chmod($envFile, 0600);

    // 3. error_log paths (non-fatal).
    $logPaths = inst_rewrite_error_log_paths();

    // 4. install.lock.
    if (!inst_write_lock()) {
        return ['ok' => false, 'error' => 'Could not write install.lock.'];
    }

    // Only return plaintext passwords that were auto-generated (blank inputs).
    $generatedPasswords = [];
    if (!is_string(inst_post('admin_password')) || trim((string) inst_post('admin_password')) === '') {
        $generatedPasswords['admin'] = $admin['plain'];
    }
    if (!is_string(inst_post('stats_password')) || trim((string) inst_post('stats_password')) === '') {
        $generatedPasswords['statistics_report'] = $stats['plain'];
    }
    if (!is_string(inst_post('env_password')) || trim((string) inst_post('env_password')) === '') {
        $generatedPasswords['env_editor'] = $envPw['plain'];
    }
    if (!is_string(inst_post('rd_password')) || trim((string) inst_post('rd_password')) === '') {
        $generatedPasswords['redirect_decision'] = $rdPw['plain'];
    }

    return [
        'ok' => true,
        'secrets' => $secrets,
        'passwords' => $generatedPasswords,
        'log_paths' => $logPaths,
    ];
}

// ---------------------------------------------------------------------------
// System check
// ---------------------------------------------------------------------------

/**
 * @return array{ok: bool, checks: list<array<string, mixed>>}
 */
function inst_act_detect(): array
{
    $root = inst_root();

    $checks = [];

    $phpOk = PHP_VERSION_ID >= 80300;
    $checks[] = [
        'name' => 'PHP ≥ 8.3',
        'required' => true,
        'ok' => $phpOk,
        'detail' => PHP_VERSION,
    ];

    foreach (['pdo_mysql' => true, 'curl' => true, 'json' => true, 'mbstring' => true, 'openssl' => true] as $ext => $required) {
        $checks[] = [
            'name' => 'Extension: ' . $ext,
            'required' => $required,
            'ok' => extension_loaded($ext),
            'detail' => extension_loaded($ext) ? 'loaded' : 'missing',
        ];
    }

    foreach (['gd' => false, 'zip' => false, 'maxminddb' => false] as $ext => $required) {
        $checks[] = [
            'name' => 'Extension: ' . $ext . ' (optional)',
            'required' => $required,
            'ok' => extension_loaded($ext),
            'detail' => extension_loaded($ext) ? 'loaded' : 'missing (optional)',
        ];
    }

    $checks[] = ['name' => 'Project root writable', 'required' => true, 'ok' => is_writable($root), 'detail' => $root];
    $checks[] = ['name' => 'schema.sql present', 'required' => true, 'ok' => is_file(inst_schema_file()), 'detail' => inst_schema_file()];
    $checks[] = ['name' => 'vendor/ present', 'required' => true, 'ok' => is_dir($root . '/vendor'), 'detail' => $root . '/vendor'];
    $checks[] = ['name' => 'statistics/ writable', 'required' => true, 'ok' => is_writable($root . '/statistics'), 'detail' => $root . '/statistics'];

    $mmdb = $root . '/redirect/databases/GeoLite2-Country.mmdb';
    $checks[] = ['name' => 'GeoIP database', 'required' => false, 'ok' => is_file($mmdb), 'detail' => $mmdb];

    $requiredFailures = 0;
    foreach ($checks as $check) {
        if ($check['required'] && !$check['ok']) {
            $requiredFailures++;
        }
    }

    return ['ok' => $requiredFailures === 0, 'checks' => $checks];
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

// Already installed?
if (is_file(inst_lock_file())) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Already installed.\n";
    exit;
}

// No prepared install.token → the installer does not exist to this visitor.
$installToken = inst_read_install_token();
if ($installToken === null) {
    http_response_code(404);
    exit;
}

inst_session_start();
$csrf = inst_csrf_token();
$tokenVerified = ($_SESSION['inst_token_verified'] ?? false) === true;

$action = '';
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $action = inst_post_string('action');
} else {
    $action = isset($_GET['action']) && is_string($_GET['action']) ? $_GET['action'] : '';
}

$readOnly = ['detect', 'detect_ip', 'detect_cpanel_host'];

if ($action !== '') {
    if ($action === 'verify_token') {
        if (!inst_verify_csrf(inst_post('csrf_token') ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null))) {
            inst_json(419, ['ok' => false, 'err' => 'invalid-csrf']);
        }
        inst_json(200, inst_act_verify_token($installToken));
    }

    if (!$tokenVerified) {
        inst_json(401, ['ok' => false, 'err' => 'token-required']);
    }

    if (!in_array($action, $readOnly, true)) {
        if (!inst_verify_csrf(inst_post('csrf_token') ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null))) {
            inst_json(419, ['ok' => false, 'err' => 'invalid-csrf']);
        }
    }

    switch ($action) {
        case 'detect':
            inst_json(200, inst_act_detect());
            break;

        case 'detect_ip':
            inst_json(200, inst_detect_server_ip());
            break;

        case 'detect_cpanel_host':
            inst_json(200, ['host' => inst_detect_cpanel_host()]);
            break;

        case 'test_db':
            try {
                $pdo = inst_pdo_connect([
                    'host' => inst_post_string('db_host'),
                    'port' => inst_post_string('db_port', '3306'),
                    'user' => inst_post_string('db_user'),
                    'password' => inst_post_string('db_password'),
                    'name' => inst_post_string('db_name'),
                    'socket' => inst_post_string('db_socket'),
                    'charset' => inst_post_string('db_charset', 'utf8mb4'),
                ]);
                $_SESSION['inst_db'] = [
                    'host' => inst_post_string('db_host'),
                    'port' => inst_post_string('db_port', '3306'),
                    'user' => inst_post_string('db_user'),
                    'password' => inst_post_string('db_password'),
                    'name' => inst_post_string('db_name'),
                    'socket' => inst_post_string('db_socket'),
                    'charset' => inst_post_string('db_charset', 'utf8mb4'),
                ];
                unset($pdo);
                inst_json(200, ['ok' => true, 'message' => 'Connection OK']);
            } catch (Throwable $e) {
                inst_json(200, ['ok' => false, 'err' => $e->getMessage()]);
            }
            break;

        case 'import_schema':
            try {
                $cfg = $_SESSION['inst_db'] ?? [
                    'host' => inst_post_string('db_host'),
                    'port' => inst_post_string('db_port', '3306'),
                    'user' => inst_post_string('db_user'),
                    'password' => inst_post_string('db_password'),
                    'name' => inst_post_string('db_name'),
                    'socket' => inst_post_string('db_socket'),
                    'charset' => inst_post_string('db_charset', 'utf8mb4'),
                ];
                $pdo = inst_pdo_connect($cfg);
                $result = inst_import_schema($pdo);
                unset($pdo);
                inst_json(200, $result);
            } catch (Throwable $e) {
                inst_json(200, ['ok' => false, 'created' => [], 'error' => $e->getMessage()]);
            }
            break;

        case 'provision_wildcard':
            inst_json(200, inst_provision_subdomains());
            break;

        case 'add_crons':
            inst_json(200, inst_add_crons());
            break;

        case 'create_database':
            inst_json(200, inst_act_create_database());
            break;

        case 'fix_permissions':
            inst_json(200, inst_act_fix_permissions());
            break;

        case 'provision_cf_zone':
            inst_json(200, inst_provision_cloudflare_zone());
            break;

        case 'install_ssl':
            inst_json(200, inst_act_install_ssl());
            break;

        case 'finalize':
            inst_json(200, inst_act_finalize());
            break;

        default:
            inst_json(400, ['ok' => false, 'err' => 'unknown-action']);
    }
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

if (!$tokenVerified) {
    inst_render_token_prompt($csrf);
}

$checksJson = json_encode(inst_act_detect(), JSON_THROW_ON_ERROR);
$e = static function (mixed $value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
};
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="<?= $e($csrf) ?>">
<title>SRP — Installer</title>
<style>
:root{--bg:#0f172a;--panel:#1e293b;--panel-2:#273449;--line:#334155;--txt:#e2e8f0;--muted:#94a3b8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--brand:#3b82f6;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{background:linear-gradient(90deg,#1d4ed8,#0ea5e9);padding:20px 24px}
header h1{margin:0;font-size:20px;font-weight:700}
header p{margin:4px 0 0;opacity:.85;font-size:13px}
.wrap{max-width:960px;margin:0 auto;padding:24px}
.tabs{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}
.tab{border:1px solid var(--line);background:var(--panel);color:var(--muted);padding:8px 14px;border-radius:8px;cursor:pointer;font-size:13px}
.tab.active{background:var(--brand);color:#fff;border-color:var(--brand)}
.pane{display:none;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}
.pane.active{display:block}
.pane h2{margin:0 0 12px;font-size:16px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:4px}
.field input,.field select{width:100%;background:var(--panel-2);border:1px solid var(--line);color:var(--txt);border-radius:8px;padding:9px 10px;font-size:13px}
.field input:focus{outline:none;border-color:var(--brand)}
.btn{display:inline-flex;align-items:center;gap:6px;background:var(--brand);color:#fff;border:0;border-radius:8px;padding:9px 16px;cursor:pointer;font-size:13px}
.btn.ghost{background:var(--panel-2);border:1px solid var(--line);color:var(--txt)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.checks{display:flex;flex-direction:column;gap:8px;margin-bottom:14px}
.check{display:flex;align-items:center;gap:10px;background:var(--panel-2);border:1px solid var(--line);border-radius:8px;padding:9px 12px}
.dot{width:10px;height:10px;border-radius:50%;flex:none}
.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}.dot.bad{background:var(--bad)}
.check .name{flex:1;font-size:13px}
.check .detail{font-family:var(--mono);font-size:11px;color:var(--muted);word-break:break-all}
.badge{font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--line)}
.badge.req{color:var(--bad)}.badge.opt{color:var(--muted)}
.status{font-family:var(--mono);font-size:12px;color:var(--muted);margin-top:10px;white-space:pre-wrap}
.status.ok{color:var(--ok)}.status.bad{color:var(--bad)}
.secrets{margin-top:12px;border:1px dashed var(--line);border-radius:8px;padding:14px;background:var(--panel-2)}
.secrets b{font-family:var(--mono);color:#fbbf24}
.actions{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
.note{font-size:12px;color:var(--muted);margin-top:10px}
pre.manual{background:var(--panel-2);border:1px solid var(--line);border-radius:8px;padding:14px;font-family:var(--mono);font-size:12px;overflow:auto;color:var(--muted)}
</style>
</head>
<body>
<header>
  <h1>SRP — Auto Installer</h1>
  <p>Smart Redirect Proxy · wizard instalasi (first-run) · v<?= $e(INST_VERSION) ?></p>
</header>
<div class="wrap">
  <div class="tabs" id="tabs">
    <button class="tab active" data-pane="p1">1 · System</button>
    <button class="tab" data-pane="p2">2 · Database</button>
    <button class="tab" data-pane="p3">3 · Domain &amp; Server</button>
    <button class="tab" data-pane="p4">4 · Admin &amp; Security</button>
    <button class="tab" data-pane="p5">5 · Cron</button>
    <button class="tab" data-pane="p6">6 · Finalize</button>
    <button class="tab" data-pane="p7">7 · Manual</button>
  </div>

  <!-- 1 · System -->
  <section class="pane active" id="p1">
    <h2>1 · System Check</h2>
    <div class="checks" id="checks"></div>
    <div class="actions">
      <button class="btn" id="recheck">Re-check</button>
      <button class="btn ghost" id="fix_perms">Fix permissions (chmod 755/644)</button>
    </div>
    <div class="status" id="p1_status"></div>
  </section>

  <!-- 2 · Database -->
  <section class="pane" id="p2">
    <h2>2 · Database</h2>
    <div class="grid">
      <div class="field"><label>Host</label><input id="db_host" value="localhost"></div>
      <div class="field"><label>Port</label><input id="db_port" value="3306"></div>
      <div class="field"><label>User</label><input id="db_user"></div>
      <div class="field"><label>Password</label><input id="db_password" type="password"></div>
      <div class="field"><label>Database name</label><input id="db_name"></div>
      <div class="field"><label>Socket (optional)</label><input id="db_socket"></div>
    </div>
    <div class="actions">
      <button class="btn" id="db_test">Test connection</button>
      <button class="btn ghost" id="db_import" disabled>Import schema.sql</button>
      <button class="btn ghost" id="db_create">Create database &amp; user (cPanel)</button>
    </div>
    <p class="note">Auto-create needs cPanel credentials (fill them in step 3 first). Names are auto-prefixed with your cPanel username.</p>
    <div class="status" id="db_status"></div>
  </section>

  <!-- 3 · Domain & Server -->
  <section class="pane" id="p3">
    <h2>3 · Domain, Server &amp; Services</h2>
    <div class="grid">
      <div class="field"><label>Base domain</label><input id="base_domain" placeholder="example.com"></div>
      <div class="field"><label>Project dir (rel. to account home)</label><input id="project_dir" placeholder="yourdomain.com"></div>
      <div class="field"><label>Server IP</label><input id="server_ip" placeholder="auto-detect"></div>
      <div class="field"><label>Report host</label><input id="report_host" placeholder="s.example.com"></div>
      <div class="field"><label>cPanel user</label><input id="cpanel_user"></div>
      <div class="field"><label>cPanel host</label><input id="cpanel_host"><button class="btn ghost" id="detect_host" type="button" style="margin-top:6px">Detect</button></div>
      <div class="field"><label>cPanel port</label><input id="cpanel_port" value="2083"></div>
      <div class="field"><label>cPanel API token (or password)</label><input id="cpanel_token" type="password"></div>
      <div class="field"><label>cPanel password (if no token)</label><input id="cpanel_password" type="password"></div>
      <div class="field"><label>cPanel SSL verify (0/1)</label><input id="cpanel_ssl_verify" value="1"></div>
      <div class="field"><label>Cloudflare API token</label><input id="cf_token" type="password"></div>
      <div class="field"><label>Cloudflare account ID</label><input id="cf_account_id"></div>
      <div class="field"><label>Cloudflare SSL mode</label>
        <select id="cf_ssl_mode">
          <option value="flexible" selected>Flexible (tanpa SSL origin)</option>
          <option value="full">Full (butuh sertifikat origin)</option>
          <option value="strict">Full strict (validasi hostname)</option>
        </select>
      </div>
    </div>
    <div class="actions">
      <button class="btn" id="detect_ip">Detect server IP</button>
      <button class="btn" id="provision">Create subdomains (cPanel)</button>
      <button class="btn ghost" id="provision_cf">Provision Cloudflare zone</button>
      <button class="btn ghost" id="install_ssl">Install SSL (Origin CA)</button>
    </div>
    <div class="status" id="p3_status"></div>
    <div class="status" id="p3_cf_status"></div>
  </section>

  <!-- 4 · Admin & Security -->
  <section class="pane" id="p4">
    <h2>4 · Admin &amp; Security</h2>
    <div class="grid">
      <div class="field"><label>Admin portal password</label><input id="admin_password" type="password"></div>
      <div class="field"><label>Statistics report password</label><input id="stats_password" type="password"></div>
      <div class="field"><label>Env editor / status password</label><input id="env_password" type="password"></div>
      <div class="field"><label>Redirect Decision password</label><input id="rd_password" type="password"></div>
    </div>
    <p class="note">Blank passwords are generated at finalize and shown once. Secrets below are generated server-side during finalize — no need to paste them.</p>
  </section>

  <!-- 5 · Cron -->
  <section class="pane" id="p5">
    <h2>5 · Cron Jobs</h2>
    <div class="field"><label>Absolute PHP binary path</label><input id="php_bin" placeholder="/usr/local/bin/php"></div>
    <div class="actions"><button class="btn" id="add_crons">Add cron jobs (cPanel)</button></div>
    <div class="status" id="p5_status"></div>
  </section>

  <!-- 6 · Finalize -->
  <section class="pane" id="p6">
    <h2>6 · Finalize</h2>
    <p class="note">Writes <code>.env</code>, <code>statistics/report_auth.php</code>, the <code>.user.ini</code> log paths, and <code>install.lock</code>. This is the only destructive step — back up any existing <code>.env</code> first.</p>
    <div class="field" style="max-width:340px"><label>App URL</label><input id="app_url" placeholder="https://example.com"></div>
    <div class="actions"><button class="btn" id="finalize">Finalize install</button></div>
    <div class="status" id="p6_status"></div>
    <div class="secrets" id="p6_secrets" style="display:none"></div>
  </section>

  <!-- 7 · Manual -->
  <section class="pane" id="p7">
    <h2>7 · Manual Installation Guide</h2>
    <pre class="manual">1. Create a MySQL database + user in cPanel (MySQL Databases).
2. Import schema.sql:   mysql -u USER -p DBNAME &lt; schema.sql
3. Copy .env.example to .env and fill every value.
   Secrets:  php -r "foreach(['AF_SECRET','SRP_API_KEY','POSTBACK_SECRET','SRP_RK_SECRET','CF_TOKEN_ENC_KEY'] as \$k) echo \$k.'='.bin2hex(random_bytes(32)).PHP_EOL;"
   Passwords (hash):  php -r "echo password_hash('YOUR_PASSWORD', PASSWORD_BCRYPT).PHP_EOL;"
4. Create subdomains in cPanel → Subdomains:
     gen.&lt;domain&gt; → &lt;root&gt;/public
     s.&lt;domain&gt;  → &lt;root&gt;/statistics
     r.&lt;domain&gt;  → &lt;root&gt;/redirect
     *.&lt;domain&gt;  → &lt;root&gt;/redirect   (wildcard, create last)
5. Set the statistics report password at s.&lt;domain&gt;/report-password.php.
6. Cron:
     0 2 * * *   /usr/local/bin/php &lt;root&gt;/redirect/cleanup-cache.php
     0 3 * * 3   /usr/local/bin/php &lt;root&gt;/redirect/update-geoip.php
     30 2 * * *  /usr/local/bin/php &lt;root&gt;/cleanup-storage.php
     0 4 * * *   /bin/bash &lt;root&gt;/rotate-logs.sh
   Or just run: bash &lt;root&gt;/setup-cron.sh --php /usr/local/bin/php
7. Verify:  curl https://&lt;domain&gt;/health.php</pre>
  </section>
</div>
<script>
(function(){
  var CSRF = document.querySelector('meta[name=csrf-token]').content;
  function q(id){ return document.getElementById(id); }
  function req(action, data, method){
    method = method || 'POST';
    var body = null;
    var url = window.location.pathname;
    if (method === 'GET') { url += '?action=' + encodeURIComponent(action); }
    else {
      data = data || {};
      data.action = action;
      data.csrf_token = CSRF;
      body = new URLSearchParams(data).toString();
    }
    return fetch(url, {
      method: method, body: body,
      headers: method === 'GET' ? {} : {'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8','Accept':'application/json'}
    }).then(function(r){ return r.json().catch(function(){ return {ok:false, err:'non-json'}; }); });
  }
  function setStatus(id, ok, text){
    var el = q(id); el.className = 'status ' + (ok ? 'ok' : 'bad'); el.textContent = text;
  }
  function setBtn(id, on){ q(id).disabled = !on; }

  // Tabs
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tab'));
  tabs.forEach(function(t){ t.addEventListener('click', function(){
    tabs.forEach(function(x){ x.classList.remove('active'); });
    document.querySelectorAll('.pane').forEach(function(p){ p.classList.remove('active'); });
    t.classList.add('active');
    document.getElementById(t.getAttribute('data-pane')).classList.add('active');
  }); });

  // 1 · System
  function renderChecks(checks){
    var box = q('checks'); box.textContent = '';
    checks.forEach(function(c){
      var d = document.createElement('div'); d.className = 'check';
      var dot = document.createElement('span'); dot.className = 'dot ' + (c.ok ? 'ok' : (c.required ? 'bad' : 'warn'));
      var name = document.createElement('span'); name.className = 'name'; name.textContent = c.name;
      var badge = document.createElement('span'); badge.className = 'badge ' + (c.required ? 'req' : 'opt'); badge.textContent = c.required ? 'required' : 'optional';
      var detail = document.createElement('span'); detail.className = 'detail'; detail.textContent = c.detail;
      d.appendChild(dot); d.appendChild(name); d.appendChild(badge); d.appendChild(detail);
      box.appendChild(d);
    });
  }
  function detect(){ req('detect', null, 'GET').then(function(r){ if (r.checks) renderChecks(r.checks); }); }
  q('recheck').addEventListener('click', detect);
  q('fix_perms').addEventListener('click', function(){
    setStatus('p1_status', null, 'Fixing permissions…');
    req('fix_permissions', {}).then(function(r){
      if (r.ok) { setStatus('p1_status', true, 'Permissions fixed: ' + r.dirs + ' dirs, ' + r.files + ' files.'); detect(); }
      else { setStatus('p1_status', false, r.error || 'failed'); }
    });
  });
  detect();

  // 2 · Database
  q('db_test').addEventListener('click', function(){
    setStatus('db_status', null, 'Testing…');
    req('test_db', {
      db_host: q('db_host').value, db_port: q('db_port').value, db_user: q('db_user').value,
      db_password: q('db_password').value, db_name: q('db_name').value, db_socket: q('db_socket').value
    }).then(function(r){
      if (r.ok) { setStatus('db_status', true, 'Connection OK'); setBtn('db_import', true); }
      else { setStatus('db_status', false, r.err || 'failed'); setBtn('db_import', false); }
    });
  });
  q('db_import').addEventListener('click', function(){
    setStatus('db_status', null, 'Importing…');
    req('import_schema', {}).then(function(r){
      if (r.ok) setStatus('db_status', true, 'Schema imported. Tables: ' + (r.created || []).length);
      else setStatus('db_status', false, r.error || r.err || 'import failed');
    });
  });
  q('db_create').addEventListener('click', function(){
    setStatus('db_status', null, 'Creating database & user…');
    req('create_database', {
      db_name: q('db_name').value, db_user: q('db_user').value, db_password: q('db_password').value,
      cpanel_user: q('cpanel_user').value, cpanel_token: q('cpanel_token').value,
      cpanel_password: q('cpanel_password').value, cpanel_host: q('cpanel_host').value,
      cpanel_port: q('cpanel_port').value, cpanel_ssl_verify: q('cpanel_ssl_verify').value
    }).then(function(r){
      if (!r.ok) { setStatus('db_status', false, r.error || 'failed'); return; }
      if (r.db_name) q('db_name').value = r.db_name;
      if (r.db_user) q('db_user').value = r.db_user;
      if (r.db_host) q('db_host').value = r.db_host;
      setStatus('db_status', true, 'Database ' + r.db_name + ' ready. Testing connection…');
      q('db_test').click();
    });
  });

  // 3 · Domain & Server
  q('detect_ip').addEventListener('click', function(){
    req('detect_ip', null, 'GET').then(function(r){ q('server_ip').value = r.server_ip || r.server_addr || r.remote_addr || ''; });
  });
  q('detect_host').addEventListener('click', function(){
    req('detect_cpanel_host', null, 'GET').then(function(r){ if (r.host) q('cpanel_host').value = r.host; });
  });
  q('provision').addEventListener('click', function(){
    setStatus('p3_status', null, 'Provisioning subdomains…');
    req('provision_wildcard', {
      base_domain: q('base_domain').value, project_dir: q('project_dir').value,
      cpanel_user: q('cpanel_user').value, cpanel_token: q('cpanel_token').value,
      cpanel_password: q('cpanel_password').value, cpanel_host: q('cpanel_host').value,
      cpanel_port: q('cpanel_port').value, cpanel_ssl_verify: q('cpanel_ssl_verify').value
    }).then(function(r){
      var lines = (r.results || []).map(function(x){ return x.subdomain + ' → ' + x.status + (x.message ? ' (' + x.message + ')' : ''); });
      setStatus('p3_status', r.ok, lines.join('\n') || 'no result');
    });
  });
  q('provision_cf').addEventListener('click', function(){
    setStatus('p3_cf_status', null, 'Provisioning Cloudflare zone…');
    req('provision_cf_zone', {
      base_domain: q('base_domain').value,
      server_ip: q('server_ip').value,
      cf_token: q('cf_token').value,
      cf_account_id: q('cf_account_id').value,
      cf_apply_recommended: '1',
      cf_ssl_mode: q('cf_ssl_mode').value
    }).then(function(r){
      if (!r.ok) { setStatus('p3_cf_status', false, r.error || 'failed'); return; }
      var lines = ['Zone: ' + r.zone_id + ' (' + r.status + ')'];
      if (r.name_servers && r.name_servers.length) lines.push('Nameservers:\n  ' + r.name_servers.join('\n  '));
      if (r.dns && r.dns.length) lines.push('DNS:\n  ' + r.dns.join('\n  '));
      if (r.applied) lines.push('Recommended settings applied.');
      setStatus('p3_cf_status', true, lines.join('\n'));
    });
  });
  q('install_ssl').addEventListener('click', function(){
    setStatus('p3_cf_status', null, 'Installing SSL certificate…');
    req('install_ssl', {
      base_domain: q('base_domain').value,
      cf_token: q('cf_token').value,
      cf_account_id: q('cf_account_id').value,
      cf_ssl_mode: q('cf_ssl_mode').value,
      cpanel_user: q('cpanel_user').value, cpanel_token: q('cpanel_token').value,
      cpanel_password: q('cpanel_password').value, cpanel_host: q('cpanel_host').value,
      cpanel_port: q('cpanel_port').value, cpanel_ssl_verify: q('cpanel_ssl_verify').value
    }).then(function(r){
      if (!r.ok) { setStatus('p3_cf_status', false, r.error || 'failed'); return; }
      setStatus('p3_cf_status', true, 'SSL installed for ' + r.install_domain + ' (mode ' + r.ssl_mode + ').');
    });
  });

  // 5 · Cron
  q('add_crons').addEventListener('click', function(){
    setStatus('p5_status', null, 'Adding cron jobs…');
    req('add_crons', {
      php_bin: q('php_bin').value,
      cpanel_user: q('cpanel_user').value, cpanel_token: q('cpanel_token').value,
      cpanel_password: q('cpanel_password').value, cpanel_host: q('cpanel_host').value,
      cpanel_port: q('cpanel_port').value, cpanel_ssl_verify: q('cpanel_ssl_verify').value
    }).then(function(r){
      var lines = [];
      if (r.added && r.added.length) lines.push('Added: ' + r.added.join(', '));
      if (r.skipped && r.skipped.length) lines.push('Skipped (existing): ' + r.skipped.join(', '));
      if (r.warnings && r.warnings.length) lines = lines.concat(r.warnings);
      setStatus('p5_status', !r.warnings || !r.warnings.length, lines.join('\n') || 'done');
    });
  });

  // 6 · Finalize
  q('finalize').addEventListener('click', function(){
    setStatus('p6_status', null, 'Finalizing…');
    req('finalize', {
      app_url: q('app_url').value,
      db_host: q('db_host').value, db_port: q('db_port').value, db_user: q('db_user').value,
      db_password: q('db_password').value, db_name: q('db_name').value, db_socket: q('db_socket').value,
      admin_password: q('admin_password').value, stats_password: q('stats_password').value,
      env_password: q('env_password').value, rd_password: q('rd_password').value,
      cpanel_user: q('cpanel_user').value, cpanel_token: q('cpanel_token').value,
      cpanel_password: q('cpanel_password').value, cpanel_host: q('cpanel_host').value,
      cpanel_port: q('cpanel_port').value, cpanel_ssl_verify: q('cpanel_ssl_verify').value,
      project_dir: q('project_dir').value,
      report_host: q('report_host').value,
      cf_token: q('cf_token').value,
      cf_account_id: q('cf_account_id').value,
      cf_server_ip: q('server_ip').value,
      cf_ssl_mode: q('cf_ssl_mode').value
    }).then(function(r){
      if (!r.ok) { setStatus('p6_status', false, r.error || r.err || 'failed'); return; }
      setStatus('p6_status', true, 'Installed. Copy the values below — they are shown only once.');
      var box = q('p6_secrets'); box.style.display = 'block'; box.textContent = '';
      function kvRow(k, v) {
        var row = document.createElement('div');
        var b = document.createElement('b'); b.textContent = k;
        row.appendChild(b);
        row.appendChild(document.createTextNode(' = ' + v));
        return row;
      }
      if (r.secrets) {
        Object.keys(r.secrets).forEach(function(k){
          box.appendChild(kvRow(k, r.secrets[k]));
        });
      }
      if (r.passwords && Object.keys(r.passwords).length) {
        var h = document.createElement('div');
        h.appendChild(document.createElement('br'));
        h.appendChild(document.createTextNode('Generated passwords:'));
        box.appendChild(h);
        Object.keys(r.passwords).forEach(function(k){
          box.appendChild(kvRow(k, r.passwords[k]));
        });
      }
    });
  });
})();
</script>
</body>
</html>
