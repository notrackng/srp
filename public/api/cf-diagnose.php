<?php

/**
 * CLI Cloudflare sync diagnostic.
 *
 * Runs the key provisioning operations against a real zone and prints the ACTUAL
 * Cloudflare response (success + error code/message) for each — unlike the live
 * sync, which swallows every failure as "best-effort". Use this to find out WHY
 * "Sync CF" appears to change nothing (almost always a missing token permission
 * or a plan limit).
 *
 *   php public/api/cf-diagnose.php <domain>
 *   php public/api/cf-diagnose.php            # uses the first zone the token sees
 *
 * CLI-only: refuses to run over HTTP.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("CLI only.\n");
}

require_once __DIR__ . '/../../env.php';
load_env_file(__DIR__ . '/../../.env');
require_once __DIR__ . '/../cf-lib.php';

$token  = (string) app_env('CF_API_TOKEN', '');
$domain = isset($argv[1]) ? strtolower(trim((string) $argv[1])) : '';

if ($token === '') {
    fwrite(STDERR, "CF_API_TOKEN missing in .env\n");
    exit(1);
}

/** Pretty-print a CF API result row. */
function report(string $label, array $resp): void
{
    $ok = (bool) ($resp['success'] ?? false);
    $mark = $ok ? 'OK  ' : 'FAIL';
    $detail = '';
    if (!$ok) {
        $errs = $resp['errors'] ?? [];
        $parts = [];
        foreach (is_array($errs) ? $errs : [] as $e) {
            $parts[] = '[' . ($e['code'] ?? '?') . '] ' . ($e['message'] ?? 'unknown');
        }
        $detail = $parts ? '  → ' . implode('; ', $parts) : '  → (no error detail)';
    }
    printf("  [%s] %-42s%s\n", $mark, $label, $detail);
}

function call(string $method, string $path, ?array $body, string $token): array
{
    try {
        return cfApi($method, $path, $body, $token);
    } catch (Throwable $e) {
        return ['success' => false, 'errors' => [['code' => 'transport', 'message' => $e->getMessage()]]];
    }
}

echo "== Cloudflare sync diagnostic ==\n\n";

// 1) Token validity + what it can see.
$verify = call('GET', '/user/tokens/verify', null, $token);
report('token verify', $verify);

// 2) Resolve the zone.
$zonePath = $domain !== ''
    ? '/zones?name=' . rawurlencode($domain)
    : '/zones?per_page=1';
$zones = call('GET', $zonePath, null, $token);
report('list zones', $zones);

$zone = $zones['result'][0] ?? null;
if (!is_array($zone) || empty($zone['id'])) {
    fwrite(STDERR, "\nNo zone found" . ($domain !== '' ? " for '$domain'" : '') . " — token may lack Zone:Read, or the zone is in another account.\n");
    exit(1);
}

$zoneId = (string) $zone['id'];
printf(
    "\nZone: %s  id=%s  status=%s  plan=%s\n\n",
    $zone['name'] ?? '?',
    $zoneId,
    $zone['status'] ?? '?',
    $zone['plan']['name'] ?? '?',
);

// 2b) SSL/TLS posture. Read-only, and the first thing to check on a 526:
// Cloudflare answers "Invalid SSL certificate" only in Full (strict), where it
// validates the origin certificate. A zone enrolled in Automatic SSL/TLS can be
// moved to strict by Cloudflare itself, and while the enrolment is `auto` the
// manual `ssl` value the sync writes is ignored — so the sync looks healthy
// while the redirect path is down. cfPinSslMode() opts out and re-pins; this
// shows whether that took.
$sslMode = call('GET', '/zones/' . $zoneId . '/settings/ssl', null, $token);
$autoMode = call('GET', '/zones/' . $zoneId . '/settings/ssl_automatic_mode', null, $token);

$sslValue = (string) ($sslMode['result']['value'] ?? '?');
$autoValue = (string) ($autoMode['result']['value'] ?? 'unavailable');

printf("SSL/TLS: mode=%s  automatic_enrolment=%s\n", $sslValue, $autoValue);

if ($sslValue === 'strict') {
    echo "  WARNING: Full (strict) validates the origin certificate. Any hostname whose\n"
       . "           Origin CA cert is missing, expired, or absent from the SAN list will\n"
       . "           return error 526. Run cfPinSslMode(), or PATCH settings/ssl to 'full'.\n";
}

if ($autoValue === 'auto') {
    echo "  WARNING: Automatic SSL/TLS is enrolled — Cloudflare may move this zone to\n"
       . "           strict on its own, and it overrides the mode the sync writes.\n";
}

echo "\n";

// 3) Representative write ops — each maps to a required token permission.
echo "Write operations (each line = one required permission):\n";

report(
    'settings/ssl  (Zone Settings:Edit)',
    call('PATCH', '/zones/' . $zoneId . '/settings/ssl', ['value' => 'full'], $token),
);

report(
    'settings/speed_brain  (Zone Settings:Edit)',
    call('PATCH', '/zones/' . $zoneId . '/settings/speed_brain', ['value' => 'on'], $token),
);

report(
    'managed_headers  (Transform Rules:Edit)',
    call(
        'PATCH',
        '/zones/' . $zoneId . '/managed_headers',
        [
            'managed_response_headers' => [
                ['id' => 'remove_x-powered-by_header', 'enabled' => true],
                ['id' => 'add_security_headers',       'enabled' => true],
            ],
        ],
        $token,
    ),
);

report(
    'custom firewall rule  (Firewall Services:Edit)',
    call(
        'PUT',
        '/zones/' . $zoneId . '/rulesets/phases/http_request_firewall_custom/entrypoints',
        [
            'rules' => [[
                'action'      => 'skip',
                'action_parameters' => ['phases' => ['http_request_firewall_managed']],
                'expression'  => '(ip.src.asnum in {32934 63293})',
                'description' => 'cf-diagnose test — skip Meta ASN',
                'enabled'     => true,
            ]],
        ],
        $token,
    ),
);

report(
    'header transform rule  (Transform Rules:Edit)',
    call(
        'PUT',
        '/zones/' . $zoneId . '/rulesets/phases/http_response_headers_transform/entrypoints',
        [
            'rules' => [[
                'action' => 'rewrite',
                'action_parameters' => ['headers' => ['X-Powered-By' => ['operation' => 'remove']]],
                'expression' => 'true',
                'description' => 'cf-diagnose test — remove X-Powered-By',
                'enabled' => true,
            ]],
        ],
        $token,
    ),
);

echo "\nInterpretation:\n";
echo "  • FAIL [9109]/[10000]/'Authentication error' → token lacks that permission.\n";
echo "  • FAIL mentioning plan/upgrade            → feature needs a higher CF plan.\n";
echo "  • All OK but dashboard unchanged          → sync isn't being triggered for this zone.\n";
echo "\nThe firewall/header-transform rules written above are real test rules — re-run a normal Sync to overwrite them with the production set.\n";
