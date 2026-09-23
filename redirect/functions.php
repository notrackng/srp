<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';

/**
 * SRP Redirect — Pure Functions
 * =============================
 * Stateless validation, sanitization, and transformation functions.
 * No database, file I/O, HTTP calls, or side effects.
 *
 * Extracted from redirect/index.php for:
 *   - Unit testability
 *   - Reuse across modules
 *   - First step toward OOP migration
 */

// ── Token & String Sanitization ──────────────────────────────────────────────

function srp_sanitize_token(string $value, int $max): ?string
{
    $value = trim($value);

    if ($value === '' || strlen($value) > $max) {
        return null;
    }

    return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1 ? $value : null;
}

function srp_sanitize_title(string $value): string
{
    $value = preg_replace('/[\r\n\t]+/', ' ', trim($value)) ?? '';

    return mb_substr($value, 0, 200, 'UTF-8');
}

// ── URL Validation ───────────────────────────────────────────────────────────

function srp_sanitize_https_url(string $value): ?string
{
    if ($value === '' || strlen($value) > 2048) {
        return null;
    }

    if (filter_var($value, FILTER_VALIDATE_URL) === false) {
        return null;
    }

    $scheme = parse_url($value, PHP_URL_SCHEME);

    return is_string($scheme) && strtolower($scheme) === 'https' ? $value : null;
}

// ── LG (Landing/Direct) Normalization ────────────────────────────────────────

function srp_normalize_lg(mixed $value): string
{
    if (!is_scalar($value)) {
        return 'direct';
    }

    $normalized = strtolower(trim((string) $value));

    if ($normalized === 'landing' || $normalized === '1') {
        return 'landing';
    }

    if ($normalized === 'landing2' || $normalized === '2') {
        return 'landing2';
    }

    return 'direct';
}

/**
 * Whether an lg value denotes landing mode (either template). Both templates
 * share the landing exemptions in srp_traffic_decision() and the landing
 * rendering path in redirect/index.php, so they must be treated as one mode
 * wherever the country block / filter diversion is bypassed.
 */
function srp_is_landing_lg(string $lg): bool
{
    return $lg === 'landing' || $lg === 'landing2';
}

// ── Device Type Detection ────────────────────────────────────────────────────

/**
 * Build a Mobile Detect instance (mobiledetect.net library) for a given UA.
 */
function srp_mobile_detect(string $userAgent): \Detection\MobileDetect
{
    $detect = new \Detection\MobileDetect();
    $detect->setUserAgent($userAgent);

    return $detect;
}

function srp_device_type(\Detection\MobileDetect $detect): string
{
    // isTablet() first: in this library isMobile() is also true for tablets.
    if ($detect->isTablet()) {
        return 'TABLET';
    }

    if ($detect->isMobile()) {
        return 'WAP';
    }

    return 'WEB';
}

/**
 * Decide whether a visitor should be diverted to the filter URL during an active
 * filter window. Pure (no I/O, no globals) so the policy is unit testable in
 * isolation from the network reputation lookup.
 *
 * When the VPN/ASN block is ON ($blockVpnAsn === true), fail-closed: divert ONLY
 * real mobile (WAP) visitors whose IP is CONFIRMED clean ($proxyOrVpn === false).
 * Unknown (null: reputation lookup timeout / no usable IP) or a confirmed
 * proxy/VPN (true) both stay on the normal offer path, so a lookup outage never
 * over-diverts genuine mobile traffic.
 *
 * When the VPN/ASN block is OFF, VPN/proxy/blocked-ASN visitors are treated as
 * normal traffic and are subject to the filter window exactly like clean mobile
 * visitors, so any mobile visitor is diverted during the window.
 *
 * @param string    $deviceType  Result of srp_device_type(): 'WAP'|'TABLET'|'WEB'.
 * @param bool|null $proxyOrVpn  Tri-state from srp_is_proxy_or_vpn().
 * @param bool      $blockVpnAsn VPN/ASN block toggle (true = block).
 */
function srp_should_divert_to_filter(string $deviceType, ?bool $proxyOrVpn, bool $blockVpnAsn = true): bool
{
    if ($deviceType !== 'WAP') {
        return false;
    }

    if (!$blockVpnAsn) {
        return true;
    }

    return $proxyOrVpn === false;
}

/**
 * Route a visitor: cloak page, country block, filter diversion, or the real
 * redirect. Pure (no I/O, no globals) so the whole policy is unit testable in
 * isolation from the signal lookups that feed it.
 *
 * Ordering matters and is load-bearing:
 *
 *   1. The cloak runs FIRST so the outcome does not depend on the visitor's
 *      country or on the filter window — a bot is a bot everywhere. The offer
 *      URL is never emitted and no click is recorded, because the _meetups hop
 *      is never reached.
 *   2. The country block outranks the filter diversion, matching the original
 *      flow where step 3 ran before step 5.
 *   3. A 'landing' link is exempt from BOTH diversions — a landing-mode link
 *      must reach its landing page on wap and web alike — but is NOT exempt
 *      from the cloak.
 *
 * $isCloakedAsn is tested before $isPreviewProbe when choosing the cloak reason.
 * That looks inverted, and is deliberate: index.php only assigns $isCloakedAsn
 * inside `if (!$isPreviewProbe)`, so "preview probe AND blocked ASN" cannot
 * occur. Preserving the original expression order means behaviour does not
 * silently shift if that guard is ever removed.
 *
 * The three cloak reasons are observable output — they reach $cloakDebugInfo
 * and are rendered by srp_render_og() when debug mode is on. Do not rename them.
 *
 * The $blockVpnAsn toggle governs all three non-preview cloak signals together:
 * blocked-ASN ($isCloakedAsn), hosting/datacenter ($isHosting — the curated ASN
 * list plus the organisation-name heuristic) and VPN/proxy ($proxyVpnStatus).
 * When the toggle is OFF, none of them cloak and that traffic follows the normal
 * redirect; when ON, any of them serves the OG cloak page. Preview probes cloak
 * regardless of the toggle (a bot is a bot everywhere).
 *
 * $isHosting === null means the ASN lookup produced nothing — a missing or
 * stale MaxMind database, typically. That fails OPEN: not cloaked (=== true is
 * required). A lookup outage must not cloak legitimate visitors, matching the
 * "degrades to not blocked rather than cloaking everyone" stance in index.php.
 *
 * @param  ?bool $isHosting true = hosting infrastructure, false = not, null = unknown.
 * @param  string      $lg              'landing' or 'direct'.
 * @param  ?string     $filterDivertUrl Pre-resolved: null when no diversion applies.
 * @return array{action:string, reason:string} action is one of
 *         CLOAK | BLOCK_COUNTRY | DIVERT_FILTER | REDIRECT.
 */
function srp_traffic_decision(
    bool $isPreviewProbe,
    bool $blockVpnAsn,
    bool $isCloakedAsn,
    ?bool $proxyVpnStatus,
    ?bool $isHosting,
    string $lg,
    bool $countryBlocked,
    ?string $filterDivertUrl,
): array {
    if (
        $isPreviewProbe
        || ($blockVpnAsn && ($isCloakedAsn || $isHosting === true || $proxyVpnStatus === true))
    ) {
        return [
            'action' => 'CLOAK',
            'reason' => $isCloakedAsn
                ? 'blocked-asn'
                : ($isHosting === true
                    ? 'hosting'
                    : ($proxyVpnStatus === true ? 'vpn-proxy' : 'user-agent')),
        ];
    }

    if (!srp_is_landing_lg($lg)) {
        if ($countryBlocked) {
            return ['action' => 'BLOCK_COUNTRY', 'reason' => 'country'];
        }

        if ($filterDivertUrl !== null) {
            return ['action' => 'DIVERT_FILTER', 'reason' => 'filter-window'];
        }
    }

    return ['action' => 'REDIRECT', 'reason' => 'normal'];
}

// ── Social Bot Detection ─────────────────────────────────────────────────────

function srp_is_social_bot(string $ua): bool
{
    if ($ua === '') {
        return false;
    }

    // Exclude FB in-app browser (not a crawler)
    if (preg_match('/\b(FBAN|FBAV)\b/', $ua) === 1) {
        return false;
    }

    // Googlebot alone already covers Googlebot-Image/News/Video, so those
    // variants are deliberately not repeated here.
    return preg_match(
        '/facebookexternalhit|facebookcatalog|Facebot|FacebookBot|facebookplatform'
        . '|Facebookscraper|meta-externalagent|meta-externalfetcher|ThreadsExternalAgent'
        . '|Twitterbot|WhatsApp|TelegramBot|LinkedInBot|Slackbot|Discordbot|Applebot'
        . '|Googlebot|APIs-Google|Mediapartners-Google|AdsBot-Google|FeedFetcher-Google'
        . '|Google-Read-Aloud|DuplexWeb-Google|Google-InspectionTool|Storebot-Google'
        . '|google-extended|googleweblight|Google Favicon|google keyword|google page speed'
        . '|bingbot|Amazonbot|vkShare|CheckMarkNetwork|W3C-checklink'
        . '|Go-http-client|HttpClient|ScaleBot/i',
        $ua,
    ) === 1;
}

/**
 * Detect a redirect checker / tracker / preview / validator that spoofs a MOBILE
 * device — i.e. a request that claims to be a phone/tablet but carries an
 * automation, HTTP-client, or link-checker/monitor signature. Such requests are
 * served OG meta tags (HTTP 200) like preview bots instead of the real offer
 * redirect, so they only ever see a benign page during the "check redirect" step.
 *
 * Intentionally conservative: BOTH a mobile token AND a probe signature are
 * required. Genuine mobile browsers (Mobile Safari / Chrome Mobile / in-app
 * WebViews) never contain these probe markers, so real mobile visitors are NOT
 * affected. Fully-spoofed UAs that mimic a real browser exactly cannot be caught
 * by UA inspection alone and are out of scope here.
 */
function srp_is_suspicious_mobile_probe(string $ua): bool
{
    if ($ua === '') {
        return false;
    }

    $looksMobile = preg_match(
        '/android|iphone|ipad|ipod|iemobile|windows phone|blackberry|bb10|opera mini|opera mobi|\bmobile\b/i',
        $ua,
    ) === 1;

    if (!$looksMobile) {
        return false;
    }

    return preg_match(
        '/headless|phantomjs|puppeteer|playwright|selenium|webdriver'
        . '|python-requests|python-urllib|aiohttp|httpx|libwww|lwp::|java\/|jakarta'
        . '|okhttp|go-http-client|guzzle|axios|node-fetch|got\/|curl\/|wget|scrapy'
        . '|apache-httpclient|restsharp|postmanruntime|insomnia|httpclient'
        . '|bot|crawler|spider|preview|validator|verif|scanner|monitor|checker|probe|fetcher'
        . '|linkcheck|uptime|pingdom|statuscake|site24x7|datadog|newrelic|ahrefs|semrush/i',
        $ua,
    ) === 1;
}

/**
 * Detect an automation / HTTP-client / headless-browser signature regardless of
 * whether the UA claims to be a mobile or a desktop device. Complements
 * srp_is_suspicious_mobile_probe(), which only catches automation that ALSO
 * spoofs a mobile device: a link checker, redirect validator, or scraper that
 * sends a plain desktop `curl/`, `wget`, `python-requests`, or headless-Chrome
 * UA is caught here so it is served the OG cloak page instead of the real offer
 * redirect.
 *
 * Scope is intentionally limited to signatures that can never appear in a
 * genuine desktop or mobile browser UA, so this cannot cloak a real visitor.
 */
function srp_is_automation_client(string $ua): bool
{
    if ($ua === '') {
        return false;
    }

    return preg_match(
        '/headlesschrome|phantomjs|puppeteer|playwright|selenium|webdriver'
        . '|python-requests|python-urllib|aiohttp|httpx|libwww|lwp::|java\/|jakarta'
        . '|okhttp|go-http-client|guzzle|axios|node-fetch|got\/|scrapy'
        . '|apache-httpclient|restsharp|postmanruntime|insomnia|\bhttpclient\b'
        . '|curl\/|wget\/|uptimerobot|pingdom|statuscake|site24x7|datadog|newrelic'
        . '|ahrefs|semrush/i',
        $ua,
    ) === 1;
}

// ── Country Code Resolution ──────────────────────────────────────────────────

function srp_header_country_code(string $key): ?string
{
    $value = trim(srp_server_string($key));

    if ($value === '' || strlen($value) !== 2 || preg_match('/^[A-Za-z]{2}$/', $value) !== 1) {
        return null;
    }

    $countryCode = strtoupper($value);

    return in_array($countryCode, ['T1', 'XX'], true) ? null : $countryCode;
}

/**
 * @param array<string, mixed> $geo
 */
function srp_geo_country_code(array $geo): string
{
    if (!isset($geo['countryCode']) || !is_string($geo['countryCode']) || $geo['countryCode'] === '') {
        return 'XX';
    }

    return strtoupper($geo['countryCode']);
}

// ── IP Utilities ─────────────────────────────────────────────────────────────

function srp_normalize_ip(string $value): string
{
    $value = trim($value);

    if ($value === '' || strlen($value) > 45) {
        return '';
    }

    return $value;
}

function srp_is_valid_ip(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

// ── HTTPS Detection ──────────────────────────────────────────────────────────

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function srp_is_https(): bool
{
    return srp_request_is_https();
}

// ── Server Helpers ───────────────────────────────────────────────────────────

function srp_server_string(string $key): string
{
    if (!isset($_SERVER[$key]) || !is_string($_SERVER[$key])) {
        return '';
    }

    return $_SERVER[$key];
}

function srp_validate_host(string $host): bool
{
    return $host !== '' && preg_match('/^[a-zA-Z0-9.\-]+(:\d{1,5})?$/', $host) === 1;
}

function srp_ensure_private_dir(string $dir): bool
{
    $dir = rtrim($dir, DIRECTORY_SEPARATOR);

    if ($dir === '') {
        return false;
    }

    if (is_dir($dir)) {
        @chmod($dir, 0700);

        if (DIRECTORY_SEPARATOR === '/') {
            return (fileperms($dir) & 0777) === 0700;
        }

        return true;
    }

    if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return false;
    }

    @chmod($dir, 0700);

    if (DIRECTORY_SEPARATOR === '/') {
        return (fileperms($dir) & 0777) === 0700;
    }

    return true;
}

function srp_write_private_file(string $path, string $content): bool
{
    $dir = dirname($path);
    if (!srp_ensure_private_dir($dir)) {
        return false;
    }

    $tmpPath = @tempnam($dir, '.srp_');
    if ($tmpPath === false) {
        return false;
    }

    $written = @file_put_contents($tmpPath, $content, LOCK_EX);
    if ($written === false) {
        @unlink($tmpPath);

        return false;
    }

    @chmod($tmpPath, 0600);

    if (file_exists($path)) {
        @unlink($path);
    }

    if (!@rename($tmpPath, $path)) {
        @unlink($tmpPath);

        return false;
    }

    @chmod($path, 0600);

    if (DIRECTORY_SEPARATOR === '/') {
        return is_file($path) && ((fileperms($path) & 0777) === 0600);
    }

    return is_file($path);
}

// ── Output Escaping ──────────────────────────────────────────────────────────

function srp_e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}
