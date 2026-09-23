<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/env.php';

load_env_file(dirname(__DIR__, 2) . '/.env');

require_once dirname(__DIR__, 2) . '/Base64URL.php';
require_once dirname(__DIR__, 2) . '/login_throttle.php';
require_once __DIR__ . '/../public_link.php';

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

if (srp_api_is_https()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ── Shared: resolve API key ───────────────────────────────────────────────────
$apiKey = app_env('SRP_API_KEY', '') ?? '';

if ($apiKey === '') {
    error_log('SRP_API_KEY is not configured');
    srp_api_fail(500, 'Internal Server Error');
}

// ── Mode A: Authorization: Bearer <key> + JSON body ──────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    srp_api_fail(405, 'Method Not Allowed');
}

// Per-IP throttle on failed auth (separate from the post-auth rate limiter
// below, which only ever sees successful requests). 20 fails -> 15 min
// lockout: SRP_API_KEY is a 256-bit secret so brute force is not realistically
// feasible either way, but every other credential surface in this app is
// throttled and an unthrottled auth endpoint is an easy thing to miss.
$shortenAuthScope = 'shorten_api';
$shortenAuthState = srp_login_throttle_state($shortenAuthScope);
if ($shortenAuthState['fails'] >= 20 && (time() - $shortenAuthState['last']) < 900) {
    header('Retry-After: 900');
    srp_api_fail(429, 'Too Many Requests');
}

$authHeader = isset($_SERVER['HTTP_AUTHORIZATION']) && is_string($_SERVER['HTTP_AUTHORIZATION'])
    ? $_SERVER['HTTP_AUTHORIZATION']
    : '';

if (substr_compare($authHeader, 'Bearer ', 0, 7, false) !== 0) {
    srp_login_throttle_register_fail($shortenAuthScope);
    header('WWW-Authenticate: Bearer realm="srp-api"');
    srp_api_fail(401, 'Unauthorized');
}

$providedKey = substr($authHeader, 7);

if (!hash_equals($apiKey, $providedKey)) {
    srp_login_throttle_register_fail($shortenAuthScope);
    header('WWW-Authenticate: Bearer realm="srp-api"');
    srp_api_fail(401, 'Unauthorized');
}

srp_login_throttle_reset($shortenAuthScope);

// ── Per-IP rate limit (fail-open, env-tunable) ───────────────────────────────
// Generous default so bulk/server-to-server shortening is unaffected; only true
// flooding is capped. Set SRP_SHORTEN_RATE_PER_MIN=0 to disable.
$rateMax = (int) (app_env('SRP_SHORTEN_RATE_PER_MIN', '300') ?? '300');
if ($rateMax > 0 && srp_shorten_rate_exceeded($rateMax)) {
    header('Retry-After: 60');
    srp_api_fail(429, 'Too Many Requests');
}

// ── Parse JSON body ───────────────────────────────────────────────────────────
$rawBody = (string) file_get_contents('php://input');

if ($rawBody === '') {
    srp_api_fail(400, 'Empty request body');
}

if (strlen($rawBody) > 8192) {
    srp_api_fail(413, 'Request body too large');
}

try {
    $body = json_decode($rawBody, true, 8, JSON_THROW_ON_ERROR);
} catch (JsonException $e) {
    srp_api_fail(400, 'Invalid JSON');
}

if (!is_array($body)) {
    srp_api_fail(400, 'Expected a JSON object');
}

// ── Resolve payload ───────────────────────────────────────────────────────────
$payload = null;

if (isset($body['sub_id']) && is_string($body['sub_id'])) {
    $payload = srp_public_link_decode_legacy_token(trim($body['sub_id']));

    if ($payload === null) {
        srp_api_fail(422, 'Invalid sub_id token');
    }
} else {
    $clickId = srp_public_link_sanitize_token_part($body['click_id'] ?? null, 64);
    $userLp  = srp_public_link_sanitize_token_part($body['user_lp'] ?? null, 64);

    if ($clickId === null || $userLp === null) {
        srp_api_fail(422, 'Provide either sub_id or both click_id and user_lp');
    }

    $payload = [
        'click_id'     => $clickId,
        'user_lp'      => $userLp,
        'canonical_url' => srp_public_link_normalize_https_url($body['canonical_url'] ?? '') ?? '',
        'image_url'    => srp_public_link_normalize_https_url($body['image_url'] ?? '') ?? '',
        'title'        => srp_public_link_normalize_title($body['title'] ?? ''),
        'lg'           => srp_public_link_normalize_lg($body['lg'] ?? ''),
    ];
}

// ── Optional custom short code ────────────────────────────────────────────────
$requestedCode = null;

if (isset($body['code']) && is_string($body['code']) && $body['code'] !== '') {
    $requestedCode = srp_short_link_sanitize_code($body['code']);

    if ($requestedCode === null) {
        srp_api_fail(422, 'Invalid code — use 4–32 chars [A-Za-z0-9_-]');
    }
}

// ── Optional base_url override ────────────────────────────────────────────────
$baseUrl = null;

if (isset($body['base_url']) && is_string($body['base_url']) && $body['base_url'] !== '') {
    $baseUrl = srp_public_link_normalize_https_url(trim($body['base_url']));

    if ($baseUrl === null) {
        srp_api_fail(422, 'Invalid base_url — must be an absolute https:// URL');
    }

    $baseUrl = rtrim((string) $baseUrl, '/');
}

if ($baseUrl === null) {
    $configuredBaseUrl = srp_public_link_normalize_https_url((string) app_env('APP_URL', ''));

    if (is_string($configuredBaseUrl) && $configuredBaseUrl !== '') {
        $baseUrl = rtrim($configuredBaseUrl, '/');
    } else {
        $scheme  = srp_api_is_https() ? 'https' : 'http';
        $rawHost = isset($_SERVER['HTTP_HOST']) && is_string($_SERVER['HTTP_HOST'])
            ? $_SERVER['HTTP_HOST']
            : 'localhost';
        $host = preg_replace('/[^a-zA-Z0-9.\-:\[\]]/', '', $rawHost);
        $baseUrl = $scheme . '://' . $host;
    }
}

// ── Persist ───────────────────────────────────────────────────────────────────
try {
    /** @var PDO $pdo */
    $pdo = require __DIR__ . '/../connection.config.php';

    srp_short_link_ensure_table($pdo);

    if ($requestedCode !== null) {
        if (srp_short_link_exists($pdo, $requestedCode)) {
            srp_api_fail(409, 'Short code already taken');
        }

        $code = $requestedCode;
    } else {
        $code = srp_short_link_generate_unique_code($pdo);
    }

    srp_short_link_create($pdo, $code, $payload);
} catch (Throwable $e) {
    error_log('api/shorten failed: ' . $e->getMessage());
    srp_api_fail(500, 'Internal Server Error');
}

$shortToken = srp_short_link_build_token($code);

// Display-only: the returned URL string always shows http://, regardless of
// how $baseUrl resolved above (explicit base_url, APP_URL, or request-scheme
// detection — all validated/resolved as https:// so far). This does not
// change TLS/redirect behavior for the link itself: Cloudflare's
// always_use_https zone setting still upgrades any real http:// request to
// https before it reaches the origin. Only the text shown to the caller
// differs.
$displayBaseUrl = preg_replace('/^https:\/\//i', 'http://', $baseUrl, 1) ?? $baseUrl;
$shortUrl = $displayBaseUrl . '/' . $shortToken;

http_response_code(201);
echo json_encode(
    ['ok' => true, 'code' => $code, 'token' => $shortToken, 'url' => $shortUrl],
    JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
);

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * @return never
 */
function srp_api_fail(int $status, string $message): never
{
    http_response_code($status);
    echo json_encode(
        ['ok' => false, 'error' => $message],
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE,
    );
    exit;
}

/**
 * Fixed-window per-IP rate check for the shorten API. Fail-open: any inability to
 * identify the client or write the counter returns false (request allowed), so
 * the limiter can never lock out or crash the endpoint. Counter files live in the
 * shared srp_bb temp area and are swept by the existing cache cleanup.
 */
function srp_shorten_rate_exceeded(int $maxPerMinute): bool
{
    require_once dirname(__DIR__, 2) . '/ip_address.php';

    $ip = getUserIP();
    if ($ip === '') {
        return false;
    }

    $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
        . (defined('SRP_CACHE_DIR_NAME') ? SRP_CACHE_DIR_NAME : 'srp_bb');
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return false;
    }

    $window = (int) (time() / 60);
    $file   = $dir . DIRECTORY_SEPARATOR . 'rl_shorten_' . md5($ip . '|' . $window) . '.json';

    $count = 0;
    if (is_file($file)) {
        $data = json_decode((string) @file_get_contents($file), true);
        if (is_array($data) && isset($data['c']) && is_int($data['c'])) {
            $count = $data['c'];
        }
    }

    $count++;
    @file_put_contents($file, json_encode(['c' => $count]), LOCK_EX);

    return $count > $maxPerMinute;
}

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function srp_api_is_https(): bool
{
    return srp_request_is_https();
}
