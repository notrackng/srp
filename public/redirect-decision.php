<?php

/**
 * Admin "Redirect Decision" control.
 *
 * Sets the timed-filter cycle used by redirect/index.php:
 *   filter window (default 2 min) → normal window (default 3 min) → repeat.
 * Writes a unified runtime override file (filter_config.json) into the shared
 * {tmp}/srp_bb/ cache dir that the redirect engine reads as one atomic snapshot;
 * legacy filter_timing.json + filter_url.txt are still honored as a fallback and
 * are removed on save. No deploy needed.
 */

declare(strict_types=1);

use Srp\Redirect\FilterEngine;

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

const RD_CSRF_NS  = 'rd_panel';
const RD_CACHE    = 'srp_bb';
const RD_DEF_FILTER = 120;
const RD_DEF_CYCLE  = 300;
const RD_SESSION  = 'srp_rd_panel';
const RD_MAX_FAILS = 8;
const RD_LIVE_STATS_CACHE_TTL = 15;
const RD_TABLE_STATS_CACHE_TTL = 60;
const RD_ENV_BACKUP_KEEP = 20;

require_once dirname(__DIR__) . '/env.php';
// Single source for the filter_config.json format, its cycle bounds and the
// timing / filter-URL / VPN-ASN precedence. The panel must resolve these the
// same way redirect/index.php does, or it shows settings the engine will not
// actually honor.
require_once dirname(__DIR__) . '/redirect/FilterEngine.php';
load_env_file(dirname(__DIR__) . '/.env');
require_once dirname(__DIR__) . '/login_throttle.php';

/** Redirect Decision password hash must be configured explicitly in .env. */
$rdPasswordHash = app_env('RD_PASSWORD_HASH', '') ?? '';

/** Lazy PDO — stats panels degrade gracefully if the DB is unreachable. */
function rdPdo(): ?PDO
{
    static $pdo = false;
    if ($pdo === false) {
        try {
            $candidate = require dirname(__DIR__) . '/connection_pdo.php';
            $pdo = $candidate instanceof PDO ? $candidate : null;
        } catch (Throwable $e) {
            $pdo = null;
        }
    }

    return $pdo;
}

function rdCacheDir(): string
{
    return rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . RD_CACHE;
}

function rdStatsCacheFile(string $name): string
{
    return rdCacheDir() . DIRECTORY_SEPARATOR . $name . '_' . gmdate('Ymd') . '.json';
}

/**
 * @return array<int|string,mixed>|null
 */
function rdReadStatsCache(string $file, int $ttlSeconds): ?array
{
    if (!is_file($file)) {
        return null;
    }

    $mtime = filemtime($file);
    if ($mtime === false || (time() - $mtime) > $ttlSeconds) {
        return null;
    }

    $raw = file_get_contents($file, false, null, 0, 65536);
    if (!is_string($raw) || $raw === '') {
        return null;
    }

    try {
        $decoded = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        return null;
    }

    if (!is_array($decoded) || ($decoded['_date'] ?? '') !== gmdate('Y-m-d')) {
        return null;
    }

    $payload = $decoded['payload'] ?? null;

    return is_array($payload) ? $payload : null;
}

/**
 * @param array<int|string,mixed> $payload
 */
function rdWriteStatsCache(string $file, array $payload): void
{
    $dir = dirname($file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }

    $json = json_encode(
        ['_date' => gmdate('Y-m-d'), 'payload' => $payload],
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
    );
    if (@file_put_contents($file, $json, LOCK_EX) !== false) {
        @chmod($file, 0600);
    }
}

function rdWriteAtomicFile(string $path, string $content): bool
{
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return false;
    }

    // Name the scratch file after its target so whatever protects the target
    // protects the scratch too. This matters: the .env write happens in the
    // DOCROOT, and a generic prefix like "rd_" matches no deny rule — a crash
    // between tempnam() and rename() would leave a world-fetchable file holding
    // every production secret. ".env" yields ".env.XXXXXX", already covered by
    // the "\.env\..*" rule in .htaccess.
    $tempPath = tempnam($dir, basename($path) . '.');
    if (!is_string($tempPath)) {
        return false;
    }

    $written = @file_put_contents($tempPath, $content, LOCK_EX);
    if ($written === false) {
        @unlink($tempPath);

        return false;
    }

    @chmod($tempPath, 0600);

    if (@rename($tempPath, $path)) {
        return true;
    }

    @unlink($tempPath);

    return false;
}

function rdPruneEnvBackups(string $backupDir, int $keep = RD_ENV_BACKUP_KEEP): void
{
    if ($keep < 1 || !is_dir($backupDir)) {
        return;
    }

    $files = glob($backupDir . DIRECTORY_SEPARATOR . '.env.*.bak');
    if (!is_array($files) || $files === []) {
        return;
    }

    usort(
        $files,
        static function (string $a, string $b): int {
            return (filemtime($b) ?: 0) <=> (filemtime($a) ?: 0);
        },
    );

    foreach (array_slice($files, $keep) as $oldFile) {
        if (is_string($oldFile) && is_file($oldFile)) {
            @unlink($oldFile);
        }
    }
}

/**
 * @param array<int|string,mixed> $row
 * @return array{clicks_today:int,leads_today:int,postbacks_today:int,payout_today:float,ts:string}
 */
function rdNormalizeLiveStats(array $row): array
{
    return [
        'clicks_today' => rdNumberToInt($row['clicks_today'] ?? null),
        'leads_today' => rdNumberToInt($row['leads_today'] ?? null),
        'postbacks_today' => rdNumberToInt($row['postbacks_today'] ?? null),
        'payout_today' => rdNumberToFloat($row['payout_today'] ?? null),
        'ts' => is_string($row['ts'] ?? null) ? $row['ts'] : gmdate('H:i:s') . ' UTC',
    ];
}

function rdNumberToInt(mixed $value): int
{
    if (is_int($value)) {
        return $value;
    }
    if (is_float($value)) {
        return (int) $value;
    }
    if (is_string($value) && is_numeric($value)) {
        return (int) $value;
    }

    return 0;
}

function rdNumberToFloat(mixed $value): float
{
    if (is_float($value) || is_int($value)) {
        return (float) $value;
    }
    if (is_string($value) && is_numeric($value)) {
        return (float) $value;
    }

    return 0.0;
}

/**
 * @return list<array<string,mixed>>|null
 */
function rdReadRowsCache(string $file, int $ttlSeconds): ?array
{
    $payload = rdReadStatsCache($file, $ttlSeconds);
    if ($payload === null) {
        return null;
    }

    $rows = [];
    foreach ($payload as $row) {
        if (is_array($row)) {
            /** @var array<string,mixed> $row */
            $rows[] = $row;
        }
    }

    return $rows;
}

/**
 * Live counters for today (clicks + leads from clickrecord, postbacks from
 * leadreport). Used by both the initial render and the ?stats=1 poll.
 *
 * @return array{clicks_today:int,leads_today:int,postbacks_today:int,payout_today:float,ts:string}
 */
function rdLiveStats(): array
{
    $cacheFile = rdStatsCacheFile('redirect_decision_live');
    $cached = rdReadStatsCache($cacheFile, RD_LIVE_STATS_CACHE_TTL);
    if ($cached !== null) {
        return rdNormalizeLiveStats($cached);
    }

    $pdo = rdPdo();
    $out = ['clicks_today' => 0, 'leads_today' => 0, 'postbacks_today' => 0, 'payout_today' => 0.0, 'ts' => gmdate('H:i:s') . ' UTC'];
    if (!$pdo instanceof PDO) {
        return $out;
    }

    try {
        $stmt = $pdo->query('SELECT COALESCE(SUM(clicks),0) c, COALESCE(SUM(CAST(leads AS UNSIGNED)),0) l FROM clickrecord WHERE click_date = CURDATE()');
        $r = $stmt !== false ? $stmt->fetch(PDO::FETCH_ASSOC) : false;
        $out['clicks_today'] = (int) (is_array($r) ? ($r['c'] ?? 0) : 0);
        $out['leads_today']  = (int) (is_array($r) ? ($r['l'] ?? 0) : 0);

        $stmt2 = $pdo->query('SELECT COUNT(*) n, COALESCE(SUM(CAST(payout AS DECIMAL(18,2))),0) p FROM leadreport WHERE conversion_date = CURDATE()');
        $p = $stmt2 !== false ? $stmt2->fetch(PDO::FETCH_ASSOC) : false;
        $out['postbacks_today'] = (int) (is_array($p) ? ($p['n'] ?? 0) : 0);
        $out['payout_today']    = (float) (is_array($p) ? ($p['p'] ?? 0) : 0);
    } catch (Throwable $e) {
        // leave zeros
    }

    rdWriteStatsCache($cacheFile, $out);

    return $out;
}

/**
 * Raw hits and unique IPs per click_id, from the daily click log.
 *
 * clickrecord cannot answer this: it stores one deduplicated counter per
 * click_id+date and keeps no per-visit rows, so there is nothing to count
 * distinct IPs over. statistics/temp/YYYY-MM-DD.json does keep one record per
 * click event, including ip_address — that is the only source for hits/uniques.
 *
 * Scope is TODAY ONLY: _meetups/clicks.php unlinks yesterday's file each day, so
 * no earlier log survives to aggregate.
 *
 * Keeps the IP SET per tracker, not just a count: the table footer needs the
 * union across trackers, and unique IPs are not additive — one visitor hitting
 * two trackers must count once in the total, not twice. Memoized per request so
 * the log is parsed once even though rows and footer both need it.
 *
 * @return array<string, array{hits:int, ips:array<string,true>}> keyed by UPPERCASE click_id
 */
function rdClickLogToday(): array
{
    static $memo = null;

    if ($memo !== null) {
        return $memo;
    }

    return $memo = rdParseClickLogToday();
}

/**
 * @return array<string, array{hits:int, ips:array<string,true>}>
 */
function rdParseClickLogToday(): array
{
    $dir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'statistics' . DIRECTORY_SEPARATOR . 'temp';
    $file = $dir . DIRECTORY_SEPARATOR . gmdate('Y-m-d') . '.json';

    if (!is_file($file) || !is_readable($file)) {
        return [];
    }

    $decoded = json_decode((string) @file_get_contents($file), true);
    if (!is_array($decoded)) {
        return [];
    }

    /** @var array<string, array{hits:int, ips:array<string,true>}> $acc */
    $acc = [];
    foreach ($decoded as $row) {
        if (!is_array($row) || !isset($row['click_id']) || !is_scalar($row['click_id'])) {
            continue;
        }

        // clickrecord stores click_id uppercased; the log keeps it as received.
        $key = strtoupper(trim((string) $row['click_id']));
        if ($key === '') {
            continue;
        }

        $acc[$key] ??= ['hits' => 0, 'ips' => []];
        $acc[$key]['hits']++;

        $ip = isset($row['ip_address']) && is_scalar($row['ip_address']) ? trim((string) $row['ip_address']) : '';
        if ($ip !== '') {
            $acc[$key]['ips'][$ip] = true;
        }
    }

    return $acc;
}

/**
 * Per-tracker totals (clickrecord grouped by click_id), highest clicks first.
 *
 * @return list<array<string,mixed>>
 */
function rdTrackers(int $limit = 20): array
{
    $limit = max(1, min($limit, 100));
    // v3: the v2 query selected hits/uniques, columns clickrecord never had, so
    // it raised "Unknown column" on every call and the swallowing catch below
    // turned that into an empty table. Cache key bumped so the stale empty
    // result from the broken version is not served after the fix.
    $cacheFile = rdStatsCacheFile('redirect_decision_trackers_v3_' . $limit);
    $cached = rdReadRowsCache($cacheFile, RD_TABLE_STATS_CACHE_TTL);
    if ($cached !== null) {
        return $cached;
    }

    $pdo = rdPdo();
    if (!$pdo instanceof PDO) {
        return [];
    }

    try {
        // leads and payout are TEXT columns holding numeric strings, so they are
        // cast the same way rdLiveStats() casts them.
        $sql = 'SELECT click_id,
                       COALESCE(SUM(clicks), 0)                          AS clicks,
                       COALESCE(SUM(CAST(leads AS UNSIGNED)), 0)         AS leads,
                       COALESCE(SUM(CAST(payout AS DECIMAL(18,2))), 0)   AS payout,
                       MAX(click_date)                                   AS last_date
                FROM clickrecord
                GROUP BY click_id
                ORDER BY clicks DESC, last_date DESC
                LIMIT ' . $limit;
        $stmt = $pdo->query($sql);

        $rows = $stmt !== false ? ($stmt->fetchAll(PDO::FETCH_ASSOC) ?: []) : [];

        // Attach today's raw hits / unique IPs from the click log. Trackers with
        // no activity today report 0 rather than being dropped from the table.
        $today = rdClickLogToday();
        foreach ($rows as $i => $row) {
            $key = strtoupper(trim((string) ($row['click_id'] ?? '')));
            $rows[$i]['hits'] = $today[$key]['hits'] ?? 0;
            $rows[$i]['uniques'] = isset($today[$key]['ips']) ? count($today[$key]['ips']) : 0;
        }

        rdWriteStatsCache($cacheFile, $rows);

        return $rows;
    } catch (Throwable $e) {
        // Do not fail silently: a schema drift like the hits/uniques one above
        // is otherwise indistinguishable from "no data yet".
        error_log('[rd] tracker query failed: ' . $e->getMessage());

        return [];
    }
}

/**
 * Incoming postbacks per day from leadreport (most recent first).
 *
 * @return list<array<string,mixed>>
 */
function rdDailyPostbacks(int $days = 14): array
{
    $days = max(1, min($days, 90));
    $cacheFile = rdStatsCacheFile('redirect_decision_postbacks_' . $days);
    $cached = rdReadRowsCache($cacheFile, RD_TABLE_STATS_CACHE_TTL);
    if ($cached !== null) {
        return $cached;
    }

    $pdo = rdPdo();
    if (!$pdo instanceof PDO) {
        return [];
    }

    try {
        $sql = 'SELECT conversion_date,
                       COUNT(*)                           AS postbacks,
                       SUM(CAST(payout AS DECIMAL(18,2))) AS payout
                FROM leadreport
                GROUP BY conversion_date
                ORDER BY conversion_date DESC
                LIMIT ' . $days;
        $stmt = $pdo->query($sql);

        $rows = $stmt !== false ? ($stmt->fetchAll(PDO::FETCH_ASSOC) ?: []) : [];
        rdWriteStatsCache($cacheFile, $rows);

        return $rows;
    } catch (Throwable $e) {
        return [];
    }
}

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function rdHttps(): bool
{
    return srp_request_is_https();
}

function rdStartSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name(RD_SESSION);
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => rdHttps(),
        'httponly' => true, 'samesite' => 'Strict',
    ]);
    if (!session_start()) {
        throw new RuntimeException('Unable to start admin session.');
    }
}

function rdIsAuthed(): bool
{
    return !empty($_SESSION['rd_authed']);
}

function rdPasswordHashUsable(string $hash): bool
{
    if ($hash === '') {
        return false;
    }

    $info = password_get_info($hash);

    return isset($info['algo']) && $info['algo'] !== 0;
}

function rdPasswordNotConfigured(): never
{
    error_log('[redirect-decision] RD_PASSWORD_HASH missing or invalid');
    http_response_code(503);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo 'Service unavailable';
    exit;
}

/** Render the standalone login screen (themed like the panel) and exit. */
function rdRenderLogin(string $error = ''): never
{
    $csrf  = rdCsrfToken();
    $nonce = base64_encode(random_bytes(16));
    header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; object-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'");
    header('Content-Type: text/html; charset=utf-8');
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Redirect Decision — Login</title>
<style nonce="<?= rdEsc($nonce) ?>">:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168,100,66,0.16);--panel:rgba(252,251,248,0.82);--border:rgba(37,42,46,0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--bg:var(--porcelain);--surface:var(--porcelain);--line:var(--soft-steel);--fg:var(--graphite);--dark:var(--ink);--muted:var(--steel-gray);--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--red:#a33f43;--green:#2f7048;--top-offset:clamp(18px,4vh,40px);--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7} *{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent} html,body{width:100%;height:100dvh;margin:0} html{color-scheme:light;-webkit-text-size-adjust:100%}::selection{background:var(--border);color:var(--fg)} body{padding:clamp(46px,10vh,120px) 14px 28px;color:var(--fg);font:13px/1.5 var(--font);background:radial-gradient(circle at 50% 0,rgba(37,42,46,.055),transparent 34rem),linear-gradient(180deg,var(--paper) 0,var(--paper) 44%,var(--porcelain) 100%);overflow-x:hidden;position:relative;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale} body::before{content:"";position:fixed;inset:-24vmax;background:radial-gradient(ellipse at 16% 42%,rgba(217,222,226,.34) 0,rgba(217,222,226,.22) 18%,rgba(217,222,226,0) 44%),radial-gradient(ellipse at 72% 32%,rgba(252,251,248,.72) 0,rgba(217,222,226,.26) 20%,rgba(217,222,226,0) 48%),radial-gradient(ellipse at 48% 74%,rgba(217,222,226,.24) 0,rgba(252,251,248,.18) 24%,rgba(252,251,248,0) 54%),conic-gradient(from 90deg at 50% 50%,rgba(217,222,226,0),rgba(217,222,226,.15),rgba(252,251,248,.36),rgba(217,222,226,.12),rgba(217,222,226,0));background-size:86vmax 58vmax,78vmax 52vmax,92vmax 62vmax,128vmax 128vmax;background-position:-18vmax 18%,62vw 20%,34vw 76%,center;opacity:.86;filter:blur(34px) saturate(1.04);transform:translate3d(0,0,0);pointer-events:none;z-index:0} body::after{content:"";position:fixed;inset:-18vmax;background:linear-gradient(90deg,rgba(252,251,248,.72),rgba(252,251,248,.34),rgba(252,251,248,.72)),radial-gradient(ellipse at 22% 24%,rgba(252,251,248,.54) 0,rgba(217,222,226,.20) 28%,rgba(217,222,226,0) 58%),radial-gradient(ellipse at 80% 78%,rgba(217,222,226,.28) 0,rgba(252,251,248,.22) 30%,rgba(252,251,248,0) 62%),radial-gradient(circle at center,rgba(217,222,226,.05) 0,rgba(252,251,248,.22) 35%,rgba(252,251,248,.82) 100%);background-size:100% 100%,76vmax 48vmax,82vmax 54vmax,100% 100%;background-position:center,left 10% top 12%,right 4% bottom 0,center;opacity:.94;filter:blur(18px);transform:translate3d(0,0,0);pointer-events:none;z-index:0}  button{appearance:none} .rd-watermark{position:fixed;inset:0;z-index:1;display:flex;align-items:center;justify-content:center;gap:clamp(22px,4.4vw,58px);pointer-events:none;transform:none;white-space:nowrap;user-select:none} .rd-watermark::before{content:"";position:fixed;inset:clamp(22px,3vw,42px);background:linear-gradient(var(--dark),var(--dark)) left top/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) left top/4px 28px no-repeat,linear-gradient(var(--dark),var(--dark)) right top/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) right bottom/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) right bottom/4px 28px no-repeat,linear-gradient(var(--dark),var(--dark)) left bottom/28px 4px no-repeat;opacity:.82} .rd-watermark span,.rd-watermark strong{display:inline-block;font:500 clamp(42px,7.8vw,92px)/1 var(--mono);letter-spacing:.42em;text-transform:uppercase;text-shadow:0 1px 0 rgba(252,251,248,.72),0 16px 40px rgba(37,42,46,.15)} .rd-watermark span{color:var(--ink);opacity:.18} .rd-watermark b{display:inline-flex;align-items:center;justify-content:center;margin:0 clamp(4px,1vw,12px);color:var(--dark);font:900 clamp(34px,6.2vw,74px)/1 var(--mono);letter-spacing:0;opacity:.30} .rd-watermark strong{color:var(--dark);opacity:.26} .rd-card{position:relative;z-index:1;width:min(94vw,440px);margin:0 auto;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);box-shadow:var(--shadow);overflow:hidden;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)} .rd-card-heading{min-height:50px;display:flex;align-items:center;padding:10px 11px;border-bottom:1px solid var(--line);background:rgba(252,251,248,.92);color:var(--fg);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.04em;text-transform:uppercase} .rd-card-body{padding:14px} label{display:block;margin:0 0 6px;color:var(--muted);font-size:var(--fs-xs);font-weight:var(--fw-bold);letter-spacing:.12em;text-transform:uppercase} .rd-control{width:100%;min-height:34px;border:1px solid rgba(217,222,226,.98);border-radius:var(--radius);background:rgba(252,251,248,.86);color:var(--fg);font:12px/1.2 var(--font);font-weight:var(--fw-bold);outline:0;padding:8px 9px} .rd-control:focus{border-color:rgba(37,42,46,1);background:var(--paper)} .rd-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;width:100%;min-height:34px;margin-top:12px;border:1px solid var(--fg);border-radius:var(--radius);background:var(--fg);color:var(--bg);padding:8px 11px;font:11px/1 var(--font);font-weight:var(--fw-bold);text-transform:uppercase;letter-spacing:.04em;cursor:pointer;text-decoration:none;user-select:none} .rd-btn:hover{filter:contrast(1.05)} .rd-btn:focus-visible{outline:2px solid rgba(37,42,46,1);outline-offset:2px} .rd-error{margin:0 0 10px;padding:9px 10px;border:1px solid rgba(168,100,66,.42);border-radius:var(--radius);background:rgba(252,251,248,.84);color:var(--red);font-size:var(--fs-sm);overflow-wrap:anywhere} @media(max-width:560px){body{padding:54px 9px 24px} .rd-card-body{padding:12px} .rd-card-heading{min-height:46px}} body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none}body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)} .noise{position:fixed;z-index:90;inset:0;pointer-events:none;opacity:0.035;mix-blend-mode:soft-light;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.7'/%3E%3C/svg%3E")} .scanline{position:fixed;z-index:-2;inset:0;pointer-events:none;background-image:linear-gradient(rgba(102,113,122,0.07) 1px,transparent 1px),linear-gradient(90deg,rgba(102,113,122,0.07) 1px,transparent 1px);background-size:44px 44px;mask-image:linear-gradient(to bottom,black,transparent 92%)} .vignette{position:fixed;inset:0;pointer-events:none} .vignette{z-index:4;box-shadow:inset 0 0 9rem 2rem rgba(37,42,46,0.11)}</style>
</head>
<body>
    <style nonce="<?= rdEsc($nonce) ?>">@media(max-width:640px){.rd-card-body.rd-pad0{padding:8px;overflow:visible}.rd-table{display:block;min-width:0;border-collapse:separate}.rd-table colgroup,.rd-table thead{display:none}.rd-table tbody,.rd-table tfoot{display:block}.rd-table tbody tr,.rd-table tfoot tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0;margin-bottom:8px;border:1px solid var(--line);border-radius:var(--radius);background:rgba(252,251,248,.78);overflow:hidden}.rd-table tbody tr:last-child{margin-bottom:0}.rd-table td,.rd-table td.rd-r{display:flex;align-items:center;justify-content:space-between;gap:12px;width:auto;height:auto;min-height:38px;padding:8px 10px;border:0;border-bottom:1px solid rgba(217,222,226,.72);text-align:right;white-space:normal;overflow-wrap:anywhere;text-overflow:clip}.rd-table td::before{content:attr(data-label);flex:0 0 auto;color:var(--muted);font:700 var(--fs-xs)/1.2 var(--font);letter-spacing:.05em;text-align:left;text-transform:uppercase}.rd-table td:first-child,.rd-table td:last-child{grid-column:1/-1}.rd-table td:nth-last-child(-n+2){border-bottom:0}.rd-table tbody tr:hover td{background:transparent}.rd-table .rd-empty{display:block;grid-column:1/-1;text-align:center}.rd-table .rd-empty::before,.rd-table td[aria-hidden=true]{display:none}.rd-table tfoot{margin-top:8px}.rd-table tfoot tr{margin:0;background:rgba(252,251,248,.96)}.rd-table tfoot td{position:static;border-top:0;background:transparent}.rd-table tfoot td:first-child{font-size:var(--fs-sm);text-transform:uppercase}.rd-table tfoot td:nth-child(4){border-bottom:0}}</style>
    <div class="noise" aria-hidden="true"></div>
<div class="scanline" aria-hidden="true"></div>
<div class="vignette" aria-hidden="true"></div>
  <div class="rd-watermark" aria-hidden="true"><span>NGIX</span><b>•</b><strong>XCTD</strong></div>
  <form class="rd-card" method="post" autocomplete="off">
    <div class="rd-card-heading">Redirect Decision</div>
    <div class="rd-card-body">
      <?php if ($error !== '') : ?>
        <p class="rd-error"><?= rdEsc($error) ?></p>
      <?php endif; ?>
      <label for="pw">Password</label>
      <input class="rd-control" id="pw" name="password" type="password" maxlength="4096" autocomplete="current-password" autofocus required>
      <input type="hidden" name="action" value="login">
      <input type="hidden" name="csrf_token" value="<?= rdEsc($csrf) ?>">
      <button class="rd-btn" type="submit">Sign In</button>
    </div>
  </form>
<style nonce="<?= rdEsc($nonce) ?>">:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168,100,66,.16);--panel:rgba(252,251,248,.82);--border:rgba(37,42,46,.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--bg:var(--porcelain);--surface:var(--porcelain);--line:var(--soft-steel);--fg:var(--graphite);--dark:var(--ink);--muted:var(--steel-gray);--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--red:#a33f43;--green:#2f7048;--top-offset:clamp(18px,4vh,40px);--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7} *,::before,::after{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent} html,body{width:100%;height:100dvh;margin:0} html{color-scheme:light;-webkit-text-size-adjust:100%}::selection{background:var(--border);color:var(--fg)} body{padding:clamp(46px,10vh,120px) 14px 28px;color:var(--fg);font:13px/1.5 var(--font);background:radial-gradient(circle at 50% 0,rgba(37,42,46,.055),transparent 34rem),linear-gradient(180deg,var(--paper) 0,var(--paper) 44%,var(--porcelain) 100%);overflow-x:hidden;position:relative;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale} body::before{content:"";position:fixed;inset:-24vmax;background:radial-gradient(ellipse at 16% 42%,rgba(217,222,226,.34) 0,rgba(217,222,226,.22) 18%,rgba(217,222,226,0) 44%),radial-gradient(ellipse at 72% 32%,rgba(252,251,248,.72) 0,rgba(217,222,226,.26) 20%,rgba(217,222,226,0) 48%),radial-gradient(ellipse at 48% 74%,rgba(217,222,226,.24) 0,rgba(252,251,248,.18) 24%,rgba(252,251,248,0) 54%),conic-gradient(from 90deg at 50% 50%,rgba(217,222,226,0),rgba(217,222,226,.15),rgba(252,251,248,.36),rgba(217,222,226,.12),rgba(217,222,226,0));background-size:86vmax 58vmax,78vmax 52vmax,92vmax 62vmax,128vmax 128vmax;background-position:-18vmax 18%,62vw 20%,34vw 76%,center;opacity:.86;filter:blur(34px) saturate(1.04);transform:translate3d(0,0,0);pointer-events:none;z-index:0} body::after{content:"";position:fixed;inset:-18vmax;background:linear-gradient(90deg,rgba(252,251,248,.72),rgba(252,251,248,.34),rgba(252,251,248,.72)),radial-gradient(ellipse at 22% 24%,rgba(252,251,248,.54) 0,rgba(217,222,226,.2) 28%,rgba(217,222,226,0) 58%),radial-gradient(ellipse at 80% 78%,rgba(217,222,226,.28) 0,rgba(252,251,248,.22) 30%,rgba(252,251,248,0) 62%),radial-gradient(circle at center,rgba(217,222,226,.05) 0,rgba(252,251,248,.22) 35%,rgba(252,251,248,.82) 100%);background-size:100% 100%,76vmax 48vmax,82vmax 54vmax,100% 100%;background-position:center,left 10% top 12%,right 4% bottom 0,center;opacity:.94;filter:blur(18px);transform:translate3d(0,0,0);pointer-events:none;z-index:0}  button{appearance:none} .rd-watermark{position:fixed;inset:0;z-index:1;display:flex;align-items:center;justify-content:center;gap:clamp(22px,4.4vw,58px);pointer-events:none;white-space:nowrap;user-select:none} .rd-watermark::before{content:"";position:fixed;inset:clamp(22px,3vw,42px);background:linear-gradient(var(--dark),var(--dark)) left top/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) left top/4px 28px no-repeat,linear-gradient(var(--dark),var(--dark)) right top/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) right bottom/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) right bottom/4px 28px no-repeat,linear-gradient(var(--dark),var(--dark)) left bottom/28px 4px no-repeat;opacity:.82} .rd-watermark span,.rd-watermark strong{display:inline-block;font:500 clamp(42px,7.8vw,92px)/1 var(--mono);letter-spacing:.42em;text-transform:uppercase;text-shadow:0 1px 0 rgba(252,251,248,.72),0 16px 40px rgba(37,42,46,.15)} .rd-watermark span{color:var(--ink);opacity:.18} .rd-watermark b{display:inline-flex;align-items:center;justify-content:center;margin:0 clamp(4px,1vw,12px);color:var(--dark);font:900 clamp(34px,6.2vw,74px)/1 var(--mono);letter-spacing:0;opacity:.3} .rd-watermark strong{color:var(--dark);opacity:.26} .rd-card{position:relative;z-index:2;width:min(94vw,440px);margin:0 auto;border:1px solid var(--line);border-radius:var(--radius);background:rgba(252,251,248,.82);box-shadow:var(--shadow);overflow:hidden;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)} .rd-card-heading{min-height:50px;display:flex;align-items:center;padding:10px 11px;border-bottom:1px solid var(--line);background:rgba(252,251,248,.92);color:var(--fg);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.04em;text-transform:uppercase} .rd-card-body{padding:14px} label{display:block;margin:0 0 6px;color:var(--muted);font-size:var(--fs-xs);font-weight:var(--fw-bold);letter-spacing:.12em;text-transform:uppercase} .rd-control{width:100%;min-height:34px;border:1px solid rgba(217,222,226,.98);border-radius:var(--radius);background:rgba(252,251,248,.86);color:var(--fg);font:700 12px/1.2 var(--font);outline:0;padding:8px 9px} .rd-control:focus{border-color:var(--graphite);background:var(--paper)} .rd-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;width:100%;min-height:34px;margin-top:12px;border:1px solid var(--fg);border-radius:var(--radius);background:var(--fg);color:var(--paper);padding:8px 11px;font:700 11px/1 var(--font);text-transform:uppercase;letter-spacing:.04em;cursor:pointer;text-decoration:none;user-select:none} .rd-btn:hover{filter:contrast(1.05)} .rd-btn:focus-visible{outline:2px solid var(--graphite);outline-offset:2px} .rd-error{margin:0 0 10px;padding:9px 10px;border:1px solid rgba(168,100,66,.42);border-radius:var(--radius);background:rgba(252,251,248,.84);color:var(--red);font-size:var(--fs-sm);overflow-wrap:anywhere} @media(max-width:560px){body{padding:54px 9px 24px}.rd-card-body{padding:12px}.rd-card-heading{min-height:46px}} .noise{position:fixed;z-index:90;inset:0;pointer-events:none;opacity:0.035;mix-blend-mode:soft-light;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.7'/%3E%3C/svg%3E")} .scanline{position:fixed;z-index:-2;inset:0;pointer-events:none;background-image:linear-gradient(rgba(102,113,122,0.07) 1px,transparent 1px),linear-gradient(90deg,rgba(102,113,122,0.07) 1px,transparent 1px);background-size:44px 44px;mask-image:linear-gradient(to bottom,black,transparent 92%)} .vignette{position:fixed;inset:0;pointer-events:none} .vignette{z-index:4;box-shadow:inset 0 0 9rem 2rem rgba(37,42,46,0.11)}</style>
<style nonce="<?= rdEsc($nonce) ?>">img,picture,svg,canvas,.ngix-image-backdrop,.image-protect,.app-banner,.brand-logo,.logo{-webkit-user-drag:none!important;-webkit-touch-callout:none!important;-webkit-user-select:none!important;user-select:none!important}</style>
<script nonce="<?= rdEsc($nonce) ?>">(function(){'use strict';var protectedSelector='img,picture,svg,canvas,.ngix-image-backdrop,.image-protect,.app-banner,.brand-logo,.logo';var editableSelector='input,textarea,select,[contenteditable="true"],[contenteditable=""]';function closest(node,selector){return node&&typeof node.closest==='function'?node.closest(selector):null;}function hasProtectedBackground(node){var current=node&&node.nodeType===1?node:null;while(current&&current!==document.documentElement){if(current.classList&&(current.classList.contains('ngix-image-backdrop')||current.classList.contains('image-protect')||current.classList.contains('app-banner')||current.classList.contains('brand-logo'))){return true;}var backgroundImage=window.getComputedStyle(current).backgroundImage;if(backgroundImage&&backgroundImage!=='none'&&backgroundImage.indexOf('url(')!==-1){return true;}if(current===document.body){break;}current=current.parentElement;}return false;}function isProtectedTarget(node){if(!node||closest(node,editableSelector)){return false;}return!!closest(node,protectedSelector)||hasProtectedBackground(node);}function blockImageAction(event){if(!isProtectedTarget(event.target)){return;}event.preventDefault();event.stopPropagation();}function hardenImages(){document.querySelectorAll('img,picture,svg,canvas').forEach(function(node){node.setAttribute('draggable','false');});}document.addEventListener('contextmenu',blockImageAction,true);document.addEventListener('dragstart',blockImageAction,true);if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',hardenImages,{once:true});return;}hardenImages();}());</script>
</body>
</html>
    <?php
    exit;
}

/**
 * Own path, safe to put in a Location header or a form action.
 *
 * REQUEST_URI is request-controlled. Taken raw it can start with "//", which a
 * browser reads as a protocol-relative URL — i.e. a redirect off-site — so the
 * value is accepted only when it is a single-slash path of harmless characters.
 * Anything else falls back to the literal panel path.
 */
function rdSelfPath(): string
{
    $fallback = '/redirect-decision.php';
    $uri = strtok((string) ($_SERVER['REQUEST_URI'] ?? ''), '?');

    if (!is_string($uri) || $uri === '' || str_starts_with($uri, '//')) {
        return $fallback;
    }

    return preg_match('#^/[A-Za-z0-9._~/-]*$#D', $uri) === 1 ? $uri : $fallback;
}

function rdEsc(string $v): string
{
    return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}

function rdCsrfToken(): string
{
    if (!isset($_SESSION['csrf'][RD_CSRF_NS]) || !is_string($_SESSION['csrf'][RD_CSRF_NS])) {
        $_SESSION['csrf'][RD_CSRF_NS] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf'][RD_CSRF_NS];
}

function rdValidCsrf(mixed $t): bool
{
    $s = $_SESSION['csrf'][RD_CSRF_NS] ?? null;

    return is_string($t) && is_string($s) && hash_equals($s, $t);
}

function rdValidateIntInput(mixed $value, int $min, int $max): ?int
{
    if (is_int($value)) {
        return $value >= $min && $value <= $max ? $value : null;
    }

    if (!is_string($value) || preg_match('/^(?:0|[1-9][0-9]{0,3})$/D', $value) !== 1) {
        return null;
    }

    $validated = filter_var(
        $value,
        FILTER_VALIDATE_INT,
        ['options' => ['min_range' => $min, 'max_range' => $max]],
    );

    return $validated === false ? null : (int) $validated;
}

/**
 * Shared FilterEngine for this request.
 *
 * Constructed with the panel's own cache dir and defaults, which are the same
 * values redirect/index.php passes the engine (srp_bb / 120 / 300), so the panel
 * resolves timing and the VPN/ASN flag through exactly the parser, bounds and
 * precedence the redirect engine applies at request time. Previously this file
 * carried its own copy of all three, kept aligned only by a "keep in sync"
 * comment.
 *
 * One instance per request on purpose: the engine memoizes its parse of
 * filter_config.json, so the readers below share a single consistent snapshot
 * and a single read, instead of three that a concurrent save could interleave.
 */
function rdFilterEngine(): FilterEngine
{
    static $engine = null;

    return $engine ??= new FilterEngine(RD_CACHE, RD_DEF_FILTER, RD_DEF_CYCLE);
}

/** Current timing: [filterSeconds, cycleSeconds]. */
function rdCurrentTiming(): array
{
    return rdFilterEngine()->getTiming();
}

/**
 * Current filter URL, resolved exactly the way the redirect engine resolves it.
 *
 * The engine ignores a non-https URL — getFilterUrl() returns null and filtering
 * stays inert — so the panel now renders an empty field in that case instead of
 * a value that looks active but is not. '' therefore means "no filter URL in
 * effect", which is also what the save handler writes to clear the override.
 */
function rdCurrentFilterUrl(): string
{
    return rdFilterEngine()->getFilterUrl() ?? '';
}

/**
 * Current VPN/proxy + blocked-ASN block toggle: unified config → env → default
 * true (fail-closed).
 */
function rdCurrentBlockVpnAsn(): bool
{
    return rdFilterEngine()->getBlockVpnAsn();
}

/** Serialize a value for .env: integers plain, everything else double-quoted. */
function rdEnvValue(string $v): string
{
    if ($v === '') {
        return '""';
    }
    if (preg_match('/^-?\d+$/', $v) === 1) {
        return $v;
    }

    // Strip control characters (incl. CR/LF) so a value can never inject an extra
    // .env line. Callers already validate inputs; this is defense in depth.
    $v = preg_replace('/[\x00-\x1F\x7F]/', '', $v) ?? '';

    return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"';
}

/**
 * Atomically update keys in the project .env — flock + timestamped backup.
 * Existing keys are replaced in place; new keys appended.
 *
 * @param array<string,string> $kv
 */
function rdWriteEnv(array $kv): bool
{
    $envFile  = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.env';
    $lockFile = $envFile . '.lock';

    $fp = @fopen($lockFile, 'c');
    if ($fp === false || !flock($fp, LOCK_EX)) {
        if ($fp !== false) {
            fclose($fp);
        }

        return false;
    }

    $content = '';
    if (is_file($envFile)) {
        $loaded = @file_get_contents($envFile);
        if (!is_string($loaded)) {
            flock($fp, LOCK_UN);
            fclose($fp);

            return false;
        }
        $content = $loaded;
    }

    $backupDir = dirname($envFile) . DIRECTORY_SEPARATOR . '.env-backups';
    if (is_dir($backupDir) || @mkdir($backupDir, 0700, true) || is_dir($backupDir)) {
        $backupFile = $backupDir . DIRECTORY_SEPARATOR . '.env.' . gmdate('Ymd_His_u') . '.' . bin2hex(random_bytes(3)) . '.bak';
        if (@file_put_contents($backupFile, $content, LOCK_EX) !== false) {
            @chmod($backupFile, 0600);
        }
        rdPruneEnvBackups($backupDir);
    }

    $lines = $content === '' ? [] : (preg_split('/\r\n|\r|\n/', $content) ?: []);
    $seen  = [];
    foreach ($lines as $i => $line) {
        if (preg_match('/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=/', $line, $m) && array_key_exists($m[1], $kv)) {
            $lines[$i] = $m[1] . '=' . rdEnvValue($kv[$m[1]]);
            $seen[$m[1]] = true;
        }
    }
    foreach ($kv as $k => $v) {
        if (empty($seen[$k])) {
            $lines[] = $k . '=' . rdEnvValue($v);
        }
    }

    $ok = rdWriteAtomicFile($envFile, rtrim(implode("\n", $lines), "\n") . "\n");

    flock($fp, LOCK_UN);
    fclose($fp);

    return $ok;
}

function rdJson(int $code, array $payload): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo json_encode($payload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
    exit;
}

function rdClearSession(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            (string) session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => (string) ($params['path'] ?? '/'),
                'domain' => (string) ($params['domain'] ?? ''),
                'secure' => (bool) ($params['secure'] ?? rdHttps()),
                'httponly' => true,
                'samesite' => 'Strict',
            ],
        );
    }

    session_destroy();
}

function rdUnauthorized(): never
{
    rdClearSession();
    rdJson(401, ['ok' => false, 'err' => 'unauthorized', 'logout' => true]);
}

function rdLogout(): never
{
    rdClearSession();
    header('Location: ' . rdSelfPath());
    exit;
}

rdStartSession();

if (!rdPasswordHashUsable((string) $rdPasswordHash)) {
    rdPasswordNotConfigured();
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Permissions-Policy: accelerometer=(), autoplay=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet');
header('Cross-Origin-Opener-Policy: same-origin');
if (rdHttps()) {
    header('Strict-Transport-Security: max-age=31536000');
}

// ── Logout ──────────────────────────────────────────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    if (!rdIsAuthed()) {
        rdUnauthorized();
    }

    if (!rdValidCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Invalid CSRF token.';
        exit;
    }

    rdLogout();
}

// ── Login (standalone password gate) ────────────────────────────────────────
if (!rdIsAuthed() && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'login') {
    // Throttle on the strongest of two signals: per-session counter AND a per-IP
    // file counter (login_throttle.php). The IP counter survives a dropped session
    // cookie, so clearing cookies can no longer reset the lockout.
    $sessionFails = isset($_SESSION['rd_fails']) && is_int($_SESSION['rd_fails']) ? $_SESSION['rd_fails'] : 0;
    $fails = max($sessionFails, srp_login_throttle_state('rd_login')['fails']);
    if ($fails >= RD_MAX_FAILS) {
        rdRenderLogin('Too many attempts. Close the browser or wait for a new session.');
    }
    if (!rdValidCsrf($_POST['csrf_token'] ?? null)) {
        rdRenderLogin('Session expired. Please try again.');
    }
    $password = $_POST['password'] ?? null;
    $passwordValid = is_string($password)
        && strlen($password) <= 4096
        && password_verify($password, $rdPasswordHash);

    if ($passwordValid) {
        session_regenerate_id(true);
        $_SESSION['rd_authed'] = true;
        unset($_SESSION['rd_fails']);
        srp_login_throttle_reset('rd_login');
        header('Location: ' . rdSelfPath());
        exit;
    }
    $_SESSION['rd_fails'] = $sessionFails + 1;
    srp_login_throttle_register_fail('rd_login');
    rdRenderLogin('Incorrect password.');
}

// ── Gate everything below behind the panel session ──────────────────────────
if (!rdIsAuthed()) {
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        rdUnauthorized();
    }
    rdRenderLogin();
}

// ── Save ────────────────────────────────────────────────────────────────────
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!rdValidCsrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? null))) {
        rdJson(419, ['ok' => false, 'err' => 'invalid-csrf']);
    }

    $filterMin = rdValidateIntInput($_POST['filter_min'] ?? null, 0, 1440);
    $normalMin = rdValidateIntInput($_POST['normal_min'] ?? null, 0, 1440);
    $filterUrlRaw = $_POST['filter_url'] ?? '';
    $blockVpnAsnRaw = $_POST['block_vpn_asn'] ?? null;
    $blockVpnAsn = !(is_string($blockVpnAsnRaw)
        && in_array(strtolower(trim($blockVpnAsnRaw)), ['0', 'false', 'off', 'no'], true));

    // filter 0–1440 min, normal 0–1440 min, cycle must be ≥ 1 min.
    if (
        $filterMin === null
        || $normalMin === null
        || ($filterMin + $normalMin) < 1
        || ($filterMin + $normalMin) > 1440
    ) {
        rdJson(422, ['ok' => false, 'err' => 'invalid-timing']);
    }

    if (!is_string($filterUrlRaw)) {
        rdJson(422, ['ok' => false, 'err' => 'invalid-filter-url (must be https, <=2048 chars)']);
    }

    $filterUrl = trim($filterUrlRaw);
    if ($filterUrl !== '') {
        // Validated with the engine's own rule, so anything accepted here is by
        // construction a URL FilterEngine::getFilterUrl() will honor — the panel
        // can no longer save a value the engine would silently ignore. The
        // length cap bounds the filter_config.json envelope to the engine's
        // read window.
        $okUrl = strlen($filterUrl) <= FilterEngine::MAX_FILTER_URL_LENGTH
            && FilterEngine::isValidHttpsUrl($filterUrl);
        if (!$okUrl) {
            rdJson(422, ['ok' => false, 'err' => 'invalid-filter-url (must be https, <=2048 chars)']);
        }
    }

    $dir = rdCacheDir();
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        rdJson(500, ['ok' => false, 'err' => 'cache-dir-unwritable']);
    }

    $config = [
        'filter_seconds' => $filterMin * 60,
        'cycle_seconds'  => ($filterMin + $normalMin) * 60,
        'filter_url'     => $filterUrl, // '' when the override is cleared
        'block_vpn_asn'  => $blockVpnAsn,
    ];

    // Single atomic write: timing and URL live in one file so the redirect
    // engine can never read a new timing paired with a stale URL (or vice versa).
    $wrote = rdWriteAtomicFile(
        $dir . DIRECTORY_SEPARATOR . 'filter_config.json',
        // Unescaped slashes so a long https URL stays ~1 byte/char and the whole
        // envelope fits the engine's 2560-byte read window.
        json_encode($config, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
    );
    if ($wrote === false) {
        rdJson(500, ['ok' => false, 'err' => 'write-failed']);
    }

    // Remove the legacy split files so the unified config is the only on-disk
    // source (harmless if already absent). Best-effort: a failed unlink does not
    // break the save — the engine ignores legacy files when the unified file is
    // present.
    foreach (['filter_timing.json', 'filter_url.txt'] as $legacyName) {
        $legacyPath = $dir . DIRECTORY_SEPARATOR . $legacyName;
        if (is_file($legacyPath)) {
            @unlink($legacyPath);
        }
    }

    // Persist to .env as the durable source of truth so the setting survives the
    // 30-day cache cleanup (engine precedence: file → env → const).
    $envSynced = rdWriteEnv([
        'SRP_FILTER_URL'     => $filterUrl,
        'SRP_FILTER_SECONDS' => (string) $config['filter_seconds'],
        'SRP_CYCLE_SECONDS'  => (string) $config['cycle_seconds'],
        'SRP_BLOCK_VPN_ASN'  => $blockVpnAsn ? '1' : '0',
    ]);

    rdJson(200, [
        'ok' => true,
        'filter_seconds' => $config['filter_seconds'],
        'cycle_seconds'  => $config['cycle_seconds'],
        'filter_url'     => $filterUrl,
        'block_vpn_asn'  => $blockVpnAsn,
        'env_synced'     => $envSynced,
    ]);
}

// ── Render ──────────────────────────────────────────────────────────────────
[$curFilter, $curCycle] = rdCurrentTiming();
$curFilterMin = (int) round($curFilter / 60);
$curNormalMin = (int) round(($curCycle - $curFilter) / 60);
$curUrl       = rdCurrentFilterUrl();
$curBlockVpnAsn = rdCurrentBlockVpnAsn();
$trackers     = rdTrackers(20);
$csrf         = rdCsrfToken();
$nonce        = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; object-src 'none'; style-src 'nonce-$nonce'; style-src-elem 'nonce-$nonce'; style-src-attr 'unsafe-inline'; script-src 'nonce-$nonce'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'");
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="<?= rdEsc($csrf) ?>">
<title>Redirect Decision</title>
<style nonce="<?= rdEsc($nonce) ?>">:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168,100,66,0.16);--panel:rgba(252,251,248,0.82);--border:rgba(37,42,46,0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--bg:var(--porcelain);--surface:var(--porcelain);--line:var(--soft-steel);--fg:var(--graphite);--dark:var(--ink);--muted:var(--steel-gray);--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--red:#a33f43;--green:#2f7048;--top-offset:clamp(18px,4vh,40px);--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7} *{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent} html,body{width:100%;height:100dvh;margin:0} html{color-scheme:light;scroll-behavior:smooth;-webkit-text-size-adjust:100%}::selection{background:var(--border);color:var(--fg)}::-moz-selection{background:var(--border);color:var(--fg)} body{padding:var(--top-offset) 12px 34px;background:radial-gradient(circle at 50% 0,rgba(37,42,46,.055),transparent 34rem),linear-gradient(180deg,var(--paper) 0,var(--paper) 44%,var(--porcelain) 100%);color:var(--fg);font:13px/1.5 var(--font);overflow-x:hidden;position:relative;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale} body::before{content:"";position:fixed;inset:-24vmax;background:radial-gradient(ellipse at 16% 42%,rgba(217,222,226,.34) 0,rgba(217,222,226,.22) 18%,rgba(217,222,226,0) 44%),radial-gradient(ellipse at 72% 32%,rgba(252,251,248,.72) 0,rgba(217,222,226,.26) 20%,rgba(217,222,226,0) 48%),radial-gradient(ellipse at 48% 74%,rgba(217,222,226,.24) 0,rgba(252,251,248,.18) 24%,rgba(252,251,248,0) 54%),conic-gradient(from 90deg at 50% 50%,rgba(217,222,226,0),rgba(217,222,226,.15),rgba(252,251,248,.36),rgba(217,222,226,.12),rgba(217,222,226,0));background-size:86vmax 58vmax,78vmax 52vmax,92vmax 62vmax,128vmax 128vmax;background-position:-18vmax 18%,62vw 20%,34vw 76%,center;opacity:.86;filter:blur(34px) saturate(1.04);transform:translate3d(0,0,0);pointer-events:none;z-index:0} body::after{content:"";position:fixed;inset:-18vmax;background:linear-gradient(90deg,rgba(252,251,248,.72),rgba(252,251,248,.34),rgba(252,251,248,.72)),radial-gradient(ellipse at 22% 24%,rgba(252,251,248,.54) 0,rgba(217,222,226,.20) 28%,rgba(217,222,226,0) 58%),radial-gradient(ellipse at 80% 78%,rgba(217,222,226,.28) 0,rgba(252,251,248,.22) 30%,rgba(252,251,248,0) 62%),radial-gradient(circle at center,rgba(217,222,226,.05) 0,rgba(252,251,248,.22) 35%,rgba(252,251,248,.82) 100%);background-size:100% 100%,76vmax 48vmax,82vmax 54vmax,100% 100%;background-position:center,left 10% top 12%,right 4% bottom 0,center;opacity:.94;filter:blur(18px);transform:translate3d(0,0,0);pointer-events:none;z-index:0}  a{color:inherit} button{appearance:none} .rd-watermark{position:fixed;inset:0;z-index:1;display:flex;align-items:center;justify-content:center;gap:clamp(22px,4.4vw,58px);pointer-events:none;transform:none;white-space:nowrap;user-select:none} .rd-watermark::before{content:"";position:fixed;inset:clamp(22px,3vw,42px);background:linear-gradient(var(--dark),var(--dark)) left top/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) left top/4px 28px no-repeat,linear-gradient(var(--dark),var(--dark)) right top/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) right bottom/28px 4px no-repeat,linear-gradient(var(--dark),var(--dark)) right bottom/4px 28px no-repeat,linear-gradient(var(--dark),var(--dark)) left bottom/28px 4px no-repeat;opacity:.82} .rd-watermark span,.rd-watermark strong{display:inline-block;font:500 clamp(42px,7.8vw,92px)/1 var(--mono);letter-spacing:.42em;text-transform:uppercase;text-shadow:0 1px 0 rgba(252,251,248,.72),0 16px 40px rgba(37,42,46,.15)} .rd-watermark span{color:var(--ink);opacity:.18} .rd-watermark b{display:inline-flex;align-items:center;justify-content:center;margin:0 clamp(4px,1vw,12px);color:var(--dark);font:900 clamp(34px,6.2vw,74px)/1 var(--mono);letter-spacing:0;opacity:.30} .rd-watermark strong{color:var(--dark);opacity:.26} .rd-shell{position:relative;z-index:2;width:min(100%,980px);margin:0 auto} .rd-tabs{position:sticky;top:10px;z-index:14;display:flex;align-items:center;gap:6px;width:100%;min-height:48px;margin:0 0 12px;padding:7px;border:1px solid var(--line);border-radius:var(--radius);background:rgba(252,251,248,.94);box-shadow:var(--shadow);overflow-x:auto;overscroll-behavior-x:contain;scrollbar-width:thin;backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)} .rd-tab{appearance:none;-webkit-appearance:none;flex:0 0 auto;min-height:32px;padding:8px 11px;border:1px solid transparent;border-radius:var(--radius);background:transparent;color:var(--muted);font:11px/1 var(--font);font-weight:var(--fw-bold);text-transform:uppercase;letter-spacing:.04em;white-space:nowrap;cursor:pointer;outline:0;transition:border-color .15s ease,background .15s ease,color .15s ease,transform .15s ease} .rd-tab:hover{border-color:rgba(217,222,226,.98);background:rgba(252,251,248,.78);color:var(--fg);transform:translateY(-1px)} .rd-tab:focus-visible{outline:2px solid rgba(37,42,46,1);outline-offset:2px} .rd-tab.is-active{border-color:rgba(37,42,46,.45);background:rgba(252,251,248,.94);color:var(--fg)} .rd-logout{appearance:none;-webkit-appearance:none;flex:0 0 auto;margin-left:auto;min-height:32px;padding:9px 8px;border:0;background:transparent;color:var(--muted);font-size:var(--fs-xs);font-weight:var(--fw-bold);letter-spacing:.06em;line-height:1;text-decoration:none;text-transform:uppercase;white-space:nowrap;cursor:pointer} .rd-logout:hover{color:var(--red)} .rd-logout-form{flex:0 0 auto;margin-left:auto} .rd-logout-form .rd-logout{margin-left:0} .rd-pane{display:none} .rd-pane.is-active{display:block} .rd-card{width:100%;margin-bottom:12px;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);box-shadow:var(--shadow);overflow:hidden;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)} .rd-card-heading{display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:50px;padding:10px 11px;border-bottom:1px solid var(--line);background:rgba(252,251,248,.92);color:var(--fg);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.04em;text-transform:uppercase} .rd-card-body{padding:12px 13px} .rd-card-body.rd-pad0{padding:0;overflow-x:auto} .rd-sub{margin:0 0 12px;border:1px solid var(--line);border-radius:var(--radius);background:rgba(252,251,248,.72);padding:9px 10px;color:var(--muted);font-size:var(--fs-sm);line-height:var(--lh-normal);overflow-wrap:anywhere} code{font-family:var(--mono);font-size:var(--fs-xs);color:var(--fg);background:rgba(252,251,248,.72);border:1px solid rgba(217,222,226,.88);border-radius:var(--radius);padding:1px 4px} label{display:block;margin:0 0 6px;color:var(--muted);font-size:var(--fs-xs);font-weight:var(--fw-bold);letter-spacing:.12em;text-transform:uppercase} .rd-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-bottom:12px} .rd-col{min-width:0} .rd-control{width:100%;min-height:34px;border:1px solid rgba(217,222,226,.98);border-radius:var(--radius);background:rgba(252,251,248,.86);color:var(--fg);font:12px/1.2 var(--font);font-weight:var(--fw-bold);font-variant-numeric:tabular-nums;outline:0;padding:8px 9px} .rd-control:focus{border-color:rgba(37,42,46,1);background:var(--paper)} input[type=url].rd-control{font-size:var(--fs-sm);overflow-wrap:anywhere} .rd-bar{display:flex;height:34px;margin:7px 0 7px;border:1px solid var(--line);border-radius:var(--radius);background:rgba(252,251,248,.72);overflow:hidden} .rd-bar>div{display:flex;align-items:center;justify-content:center;min-width:0;padding:0 8px;overflow:hidden;font-size:var(--fs-xs);font-weight:var(--fw-bold);text-overflow:ellipsis;text-transform:uppercase;white-space:nowrap} .seg-f{background:var(--fg);color:var(--bg)} .seg-n{background:rgba(252,251,248,.72);color:var(--fg)} .rd-legend{display:flex;flex-wrap:wrap;gap:8px 16px;margin:0 0 12px;color:var(--muted);font-size:var(--fs-xs)} .rd-live-mode{display:flex;align-items:center;gap:9px;margin-bottom:12px;flex-wrap:wrap} .rd-badge{display:inline-flex;align-items:center;min-height:24px;padding:5px 8px;border:1px solid rgba(217,222,226,.88);border-radius:var(--radius);background:rgba(252,251,248,.72);color:rgba(37,42,46,.72);font-size:var(--fs-xs);font-weight:var(--fw-bold);letter-spacing:.06em;text-transform:uppercase;white-space:nowrap} .rd-badge--filter{background:var(--fg);border-color:var(--fg);color:var(--bg)} .rd-badge--normal{background:rgba(252,251,248,.86);border-color:rgba(37,42,46,.42);color:var(--fg)} .rd-badge--off{background:rgba(252,251,248,.72);color:var(--muted)} .rd-count{font:700 12px var(--mono);color:var(--muted)} .rd-dot{display:inline-block;width:9px;height:9px;margin-right:5px;border-radius:2px;vertical-align:middle} .rd-dot--f{background:var(--fg)} .rd-dot--n{background:rgba(252,251,248,.72);border:1px solid var(--line)} .rd-hint{margin:7px 0 0;color:var(--muted);font-size:var(--fs-sm);line-height:var(--lh-normal);overflow-wrap:anywhere} .rd-actions{display:flex;justify-content:flex-end;margin-top:14px} .rd-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-width:96px;min-height:34px;border:1px solid rgba(217,222,226,.98);border-radius:var(--radius);background:rgba(252,251,248,.78);color:var(--fg);padding:8px 11px;font:11px/1 var(--font);font-weight:var(--fw-bold);text-transform:uppercase;letter-spacing:.04em;cursor:pointer;text-decoration:none;user-select:none;white-space:nowrap} .rd-btn:hover{filter:contrast(1.05)} .rd-btn:focus-visible{outline:2px solid rgba(37,42,46,1);outline-offset:2px} .rd-btn-primary{background:var(--fg);border-color:var(--fg);color:var(--bg)} .rd-btn-primary:hover{filter:contrast(1.12)} .rd-btn:disabled{opacity:.65;cursor:not-allowed} .rd-status{min-height:18px;margin-top:10px;font-size:var(--fs-sm);overflow-wrap:anywhere} .rd-status.ok{color:var(--green)} .rd-status.bad{color:var(--red)} .rd-pad0{padding:0;overflow-x:auto;overscroll-behavior-x:contain;-webkit-overflow-scrolling:touch} .rd-pad0:focus-visible{outline:2px solid var(--graphite);outline-offset:-2px} .rd-table{width:100%;min-width:760px;border-collapse:collapse;table-layout:fixed;font-size:var(--fs-sm);font-variant-numeric:tabular-nums} .rd-table col:nth-child(1){width:34%} .rd-table col:nth-child(2){width:14%} .rd-table col:nth-child(3){width:14%} .rd-table col:nth-child(4){width:14%} .rd-table col:nth-child(5){width:24%} .rd-table th{position:sticky;top:0;z-index:1;padding:8px 10px;background:rgba(252,251,248,.96);border-bottom:1px solid var(--line);color:var(--muted);font-size:var(--fs-xs);font-weight:var(--fw-bold);letter-spacing:.08em;text-align:left;text-transform:uppercase;white-space:nowrap} .rd-table td{height:38px;padding:8px 10px;border-top:1px solid rgba(217,222,226,.72);color:var(--fg);line-height:1.25;vertical-align:middle;white-space:nowrap;overflow:hidden;text-overflow:ellipsis} .rd-table tbody tr:hover td{background:rgba(252,251,248,.70)} .rd-table th.rd-r,.rd-table td.rd-r{text-align:right} .rd-mono{font-family:var(--mono);font-size:var(--fs-sm)} .rd-empty{padding:16px 10px;color:var(--muted);text-align:center} .rd-table tfoot td{position:sticky;bottom:0;z-index:1;height:38px;padding:8px 10px;border-top:2px solid var(--line);background:rgba(252,251,248,.96);color:var(--fg);font-weight:var(--fw-bold)} @media(max-width:780px){.rd-shell{width:100%}.rd-tabs{top:8px}} @media(max-width:560px){:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168,100,66,0.16);--panel:rgba(252,251,248,0.82);--border:rgba(37,42,46,0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--red:#a33f43;--green:#2f7048;--top-offset:clamp(18px,4vh,40px);--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}body{padding:9px 8px 24px}.rd-tabs{position:relative;top:auto;margin-bottom:9px}.rd-tab{padding:8px 10px}.rd-card-heading{align-items:flex-start;flex-direction:column;gap:2px;min-height:48px}.rd-card-body{padding:11px}.rd-row{grid-template-columns:1fr}.rd-actions{display:block}.rd-btn{width:100%}.rd-watermark{gap:clamp(10px,2vw,20px);align-items:center}.rd-watermark::before{inset:18px;background-size:22px 3px,3px 22px,22px 3px,22px 3px,3px 22px,22px 3px}.rd-watermark span,.rd-watermark strong{font-size:clamp(28px,9vw,50px);letter-spacing:.28em}.rd-watermark b{font-size:clamp(26px,8vw,46px)}} body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none} body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)} .btn,.btn-sm,.btn-xs,.page-link,.page-link--primary,input[type=submit],input[type=button],.swal2-confirm,.swal2-cancel{border-color:var(--btn-border)!important;color:var(--btn-fg)!important;background:var(--btn-bg)!important} .btn:hover,.btn-sm:hover,.btn-xs:hover,.page-link:hover,input[type=submit]:hover,input[type=button]:hover{border-color:var(--btn-border)!important;color:var(--btn-fg)!important;background:var(--btn-bg)!important;filter:brightness(1.18)} .btn:disabled,.btn-sm:disabled,.btn-xs:disabled,input[type=submit]:disabled,input[type=button]:disabled{opacity:.55;filter:none} .noise{position:fixed;z-index:90;inset:0;pointer-events:none;opacity:0.035;mix-blend-mode:soft-light;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.7'/%3E%3C/svg%3E")} .scanline{position:fixed;z-index:-2;inset:0;pointer-events:none;background-image:linear-gradient(rgba(102,113,122,0.07) 1px,transparent 1px),linear-gradient(90deg,rgba(102,113,122,0.07) 1px,transparent 1px);background-size:44px 44px;mask-image:linear-gradient(to bottom,black,transparent 92%)} .vignette{position:fixed;inset:0;pointer-events:none} .vignette{z-index:4;box-shadow:inset 0 0 9rem 2rem rgba(37,42,46,0.11)}</style>
</head>
<body>
    <div class="noise" aria-hidden="true"></div>
    <div class="scanline" aria-hidden="true"></div>
<style nonce="<?= rdEsc($nonce) ?>">@media(max-width:640px){.rd-card-body.rd-pad0{padding:8px;overflow:visible}.rd-table{display:block;min-width:0;border-collapse:separate}.rd-table colgroup,.rd-table thead{display:none}.rd-table tbody,.rd-table tfoot{display:block}.rd-table tbody tr,.rd-table tfoot tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));margin-bottom:8px;border:1px solid var(--line);border-radius:var(--radius);background:rgba(252,251,248,.78);overflow:hidden}.rd-table tbody tr:last-child{margin-bottom:0}.rd-table td,.rd-table td.rd-r{display:flex;align-items:center;justify-content:space-between;gap:12px;width:auto;height:auto;min-height:38px;padding:8px 10px;border:0;border-bottom:1px solid rgba(217,222,226,.72);text-align:right;white-space:normal;overflow-wrap:anywhere;text-overflow:clip}.rd-table td::before{content:attr(data-label);flex:0 0 auto;color:var(--muted);font:700 var(--fs-xs)/1.2 var(--font);letter-spacing:.05em;text-align:left;text-transform:uppercase}.rd-table td:first-child,.rd-table td:last-child{grid-column:1/-1}.rd-table td:nth-last-child(-n+2){border-bottom:0}.rd-table tbody tr:hover td{background:transparent}.rd-table .rd-empty{display:block;grid-column:1/-1;text-align:center}.rd-table .rd-empty::before,.rd-table td[aria-hidden=true]{display:none}.rd-table tfoot{margin-top:8px}.rd-table tfoot tr{margin:0;background:rgba(252,251,248,.96)}.rd-table tfoot td{position:static;border-top:0;background:transparent}.rd-table tfoot td:first-child{font-size:var(--fs-sm);text-transform:uppercase}.rd-table tfoot td:nth-child(4){border-bottom:0}}</style>
<style nonce="<?= rdEsc($nonce) ?>">@media(max-width:640px){.rd-table tbody tr,.rd-table tfoot tr{grid-template-columns:repeat(3,minmax(0,1fr))}.rd-table td:first-child,.rd-table td:last-child{grid-column:1/-1}.rd-table td:nth-child(n+2):nth-child(-n+4){flex-direction:column;justify-content:center;gap:4px;min-width:0;text-align:center}.rd-table td:nth-child(n+2):nth-child(-n+4)::before{width:100%;font-size:10px;text-align:center;white-space:normal}.rd-table td:nth-child(2),.rd-table td:nth-child(3){border-right:1px solid rgba(217,222,226,.72)}.rd-table td:nth-child(4){border-bottom:1px solid rgba(217,222,226,.72)}.rd-table td:last-child{border-bottom:0}.rd-table tfoot td:nth-child(4){border-bottom:0}}</style>
<div class="rd-watermark" aria-hidden="true"><span>NGIX</span><b>•</b><strong>XCTD</strong></div>
<div class="rd-shell">
    <div class="vignette" aria-hidden="true"></div>
  <div class="rd-tabs" role="tablist" aria-label="Redirect Decision" aria-orientation="horizontal">
    <button class="rd-tab is-active" id="tab-config" type="button" role="tab" aria-controls="pane-config" aria-selected="true" data-pane="pane-config">Redirect Decision</button>
    <button class="rd-tab" id="tab-tracker" type="button" role="tab" aria-controls="pane-tracker" aria-selected="false" data-pane="pane-tracker">Tracker</button>
    <form class="rd-logout-form" method="post" action="<?= rdEsc(rdSelfPath()) ?>">
      <input type="hidden" name="action" value="logout">
      <input type="hidden" name="csrf_token" value="<?= rdEsc($csrf) ?>">
      <button class="rd-logout" type="submit">Logout</button>
    </form>
  </div>

  <section class="rd-pane is-active" id="pane-config" role="tabpanel" aria-labelledby="tab-config">
  <div class="rd-card">
    <div class="rd-card-heading">Redirect Decision</div>
    <div class="rd-card-body">
      <div class="rd-row">
        <div class="rd-col">
          <label for="filter_min">Filter (minutes)</label>
          <input class="rd-control" id="filter_min" type="number" min="0" max="1440" step="1" value="<?= $curFilterMin ?>">
        </div>
        <div class="rd-col">
          <label for="normal_min">Normal (minutes)</label>
          <input class="rd-control" id="normal_min" type="number" min="0" max="1440" step="1" value="<?= $curNormalMin ?>">
        </div>
      </div>

      <label>Cycle preview</label>
      <div class="rd-bar" id="bar"></div>
      <div class="rd-legend">
        <span><span class="rd-dot rd-dot--f"></span>Filter → SRP_FILTER_URL</span>
        <span><span class="rd-dot rd-dot--n"></span>Normal → original flow</span>
      </div>

      <label>Current status · live (traffic synchronized)</label>
      <div class="rd-live-mode">
        <span class="rd-badge" id="cycle-badge">—</span>
        <span class="rd-count" id="cycle-count"></span>
      </div>

      <label for="filter_url">Filter URL (https) — leave blank to disable</label>
      <input class="rd-control" id="filter_url" type="url" placeholder="https://example.com/safe" value="<?= rdEsc($curUrl) ?>">

      <label for="block_vpn_asn" style="display:flex;align-items:center;gap:8px;margin:14px 0 4px;cursor:pointer;">
        <input id="block_vpn_asn" type="checkbox" <?= $curBlockVpnAsn ? 'checked' : '' ?>>
        <span>Block VPN / proxy / datacenter (blocked-ASN) traffic</span>
      </label>
      <div class="rd-hint">ON → VPN/proxy/blocked-ASN visitors get the OG cloak page (no click recorded). OFF → they follow the normal redirect to the final URL.</div>

      <div class="rd-actions">
        <button class="rd-btn rd-btn-primary" id="save" type="button">Save</button>
      </div>
      <div class="rd-status" id="status" role="status" aria-live="polite"></div>
    </div>
  </div>
  </section>

  <section class="rd-pane" id="pane-tracker" role="tabpanel" aria-labelledby="tab-tracker" hidden>
  <div class="rd-card">
    <div class="rd-card-heading">Tracker · clickrecord (top 20)</div>
    <div class="rd-card-body rd-pad0" tabindex="0" role="region" aria-label="Responsive tracker table">
      <table class="rd-table">
        <colgroup><col><col><col><col><col></colgroup>
        <thead><tr><th>Click ID</th><th class="rd-r">Clicks</th><th class="rd-r">Hits</th><th class="rd-r">Uniques</th><th>Last Date</th></tr></thead>
        <tbody>
        <?php if ($trackers === []) : ?>
          <tr><td colspan="5" class="rd-empty">No click data yet.</td></tr>
        <?php else :
            foreach ($trackers as $t) :
                $c = rdNumberToInt($t['clicks'] ?? null);
                $h = rdNumberToInt($t['hits'] ?? null);
                $u = rdNumberToInt($t['uniques'] ?? null); ?>
          <tr>
            <td class="rd-mono" data-label="Click ID"><?= rdEsc(strtoupper((string) $t['click_id'])) ?></td>
            <td class="rd-r" data-label="Clicks"><?= $c ?></td>
            <td class="rd-r" data-label="Hits"><?= $h ?></td>
            <td class="rd-r" data-label="Uniques"><?= $u ?></td>
            <td class="rd-mono" data-label="Last Date"><?= rdEsc((string) $t['last_date']) ?></td>
          </tr>
            <?php endforeach;
        endif; ?>
        </tbody>
        <?php if ($trackers !== []) :
            $sumClicks = 0;
            $sumHits   = 0;
            // Unique IPs are NOT additive: one visitor may appear under several
            // trackers, and summing the per-row counts would count them twice.
            // The real total is the union of the IP sets of the shown rows.
            $ipUnion   = [];
            $logToday  = rdClickLogToday();

            foreach ($trackers as $t) {
                $sumClicks += rdNumberToInt($t['clicks'] ?? null);
                $sumHits   += rdNumberToInt($t['hits'] ?? null);

                $key = strtoupper(trim((string) ($t['click_id'] ?? '')));
                foreach (array_keys($logToday[$key]['ips'] ?? []) as $ip) {
                    $ipUnion[$ip] = true;
                }
            }
            $sumUniques = count($ipUnion); ?>
        <tfoot>
          <tr class="rd-total">
            <td data-label="Summary">Total</td>
            <td class="rd-r" data-label="Clicks"><?= $sumClicks ?></td>
            <td class="rd-r" data-label="Hits"><?= $sumHits ?></td>
            <td class="rd-r" data-label="Uniques"><?= $sumUniques ?></td>
            <td aria-hidden="true"></td>
          </tr>
        </tfoot>
        <?php endif; ?>
      </table>
    </div>
  </div>
  </section>

</div>

<script nonce="<?= rdEsc($nonce) ?>">(function(){var csrf=document.querySelector('meta[name=csrf-token]').content;var fEl=document.getElementById('filter_min'),nEl=document.getElementById('normal_min'),uEl=document.getElementById('filter_url'),bEl=document.getElementById('block_vpn_asn'),bar=document.getElementById('bar'),st=document.getElementById('status'),btn=document.getElementById('save');var RD_CYCLE={filter:<?= (int) $curFilter ?>,cycle:<?= (int) $curCycle ?>,hasUrl:<?= $curUrl !== '' ? 'true' : 'false' ?>};var RD_OFFSET=<?= time() ?>-Math.floor(Date.now()/1000);function rdServerNow(){return Math.floor(Date.now()/1000)+RD_OFFSET;}function rdDur(s){s=Math.max(0,Math.floor(s));var m=Math.floor(s/60),x=s%60;return m+':'+(x<10?'0':'')+x;}function tickCycle(){var b=document.getElementById('cycle-badge'),c=document.getElementById('cycle-count');if(!b||!c){return;}if(RD_CYCLE.filter<=0||RD_CYCLE.cycle<=0){b.textContent='Filter disabled';b.className='rd-badge rd-badge--off';c.textContent='all traffic → normal flow';return;}var pos=rdServerNow()%RD_CYCLE.cycle;if(pos<0){pos+=RD_CYCLE.cycle;}if(pos<RD_CYCLE.filter){b.textContent=RD_CYCLE.hasUrl?'FILTER active':'FILTER active · no URL';b.className='rd-badge rd-badge--filter';c.textContent='→ NORMAL in '+rdDur(RD_CYCLE.filter-pos);}else{b.textContent='NORMAL';b.className='rd-badge rd-badge--normal';c.textContent='→ FILTER in '+rdDur(RD_CYCLE.cycle-pos);}}setInterval(tickCycle,1000);tickCycle();function clampInt(v,lo,hi){v=parseInt(v,10);if(isNaN(v))v=0;return Math.max(lo,Math.min(hi,v));}function forceLogoutIfUnauthorized(res){if(res&&res.j&&res.j.logout===true&&res.j.err==='unauthorized'){window.location.replace(window.location.pathname);return true;}return false;}function request(url,options,timeout){var controller=typeof AbortController==='function'?new AbortController():null;var timer=controller?setTimeout(function(){controller.abort();},timeout||10000):null;var opts=options||{};if(controller){opts.signal=controller.signal;}return fetch(url,opts).then(function(response){var contentType=response.headers.get('content-type')||'';if(contentType.indexOf('application/json')===-1){throw new Error('invalid-response');}return response.json().then(function(json){return{ok:response.ok,j:json};});}).then(function(result){if(timer){clearTimeout(timer);}return result;},function(error){if(timer){clearTimeout(timer);}throw error;});}function draw(){var f=clampInt(fEl.value,0,1440),n=clampInt(nEl.value,0,1440),t=f+n;bar.innerHTML='';if(t<=0){var e=document.createElement('div');e.className='seg-n';e.style.flex='1';e.textContent='—';bar.appendChild(e);return;}if(f>0){var d=document.createElement('div');d.className='seg-f';d.style.flex=f;d.textContent='Filter '+f+'m';bar.appendChild(d);}if(n>0){var d2=document.createElement('div');d2.className='seg-n';d2.style.flex=n;d2.textContent='Normal '+n+'m';bar.appendChild(d2);}}fEl.addEventListener('input',draw);nEl.addEventListener('input',draw);draw();btn.addEventListener('click',function(){var f=clampInt(fEl.value,0,1440),n=clampInt(nEl.value,0,1440);if(f+n<1||f+n>1440){st.className='rd-status bad';st.textContent='Total filter+normal must be 1–1440 minutes.';return;}btn.disabled=true;st.className='rd-status';st.textContent='Saving…';var body=new URLSearchParams({filter_min:f,normal_min:n,filter_url:uEl.value.trim(),block_vpn_asn:(bEl.checked?'1':'0'),csrf_token:csrf});request(window.location.pathname,{method:'POST',headers:{'X-CSRF-Token':csrf,'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},credentials:'same-origin',cache:'no-store',body:body.toString()},12000).then(function(res){if(forceLogoutIfUnauthorized(res)){return;}if(res.ok&&res.j.ok){st.className='rd-status ok';st.textContent='Saved. Filter '+(res.j.filter_seconds/60)+'m / cycle '+(res.j.cycle_seconds/60)+'m.'+(res.j.env_synced?' (.env synced)':' (.env WRITE FAILED — cache active)');RD_CYCLE.filter=res.j.filter_seconds;RD_CYCLE.cycle=res.j.cycle_seconds;RD_CYCLE.hasUrl=!!(res.j.filter_url&&res.j.filter_url.length);tickCycle();}else{st.className='rd-status bad';st.textContent='Failed: '+((res.j&&res.j.err)||'unknown');}}).catch(function(){st.className='rd-status bad';st.textContent='Request failed.';}).then(function(){btn.disabled=false;});});var tabs=Array.prototype.slice.call(document.querySelectorAll('.rd-tab'));function activate(paneId){tabs.forEach(function(t){var on=t.getAttribute('data-pane')===paneId;t.classList.toggle('is-active',on);t.setAttribute('aria-selected',on?'true':'false');});Array.prototype.forEach.call(document.querySelectorAll('.rd-pane'),function(p){var on=p.id===paneId;p.classList.toggle('is-active',on);p.hidden=!on;});try{history.replaceState(null,'','#'+paneId);}catch(e){}}tabs.forEach(function(t){t.addEventListener('click',function(){activate(t.getAttribute('data-pane'));});});document.querySelector('.rd-tabs').addEventListener('keydown',function(event){if(event.key!=='ArrowLeft'&&event.key!=='ArrowRight'&&event.key!=='Home'&&event.key!=='End'){return;}var current=tabs.indexOf(document.activeElement);if(current<0){return;}event.preventDefault();var next=event.key==='Home'?0:event.key==='End'?tabs.length-1:(current+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tabs[next].focus();activate(tabs[next].getAttribute('data-pane'));});if(location.hash&&/^#pane-/.test(location.hash)&&document.getElementById(location.hash.slice(1))){activate(location.hash.slice(1));}})();</script>
</body>
</html>
