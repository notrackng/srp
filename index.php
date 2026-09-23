<?php

declare(strict_types=1);

require_once __DIR__ . '/asset_url.php';


function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function ngixExtractSubId(string $requestUri): ?string
{
    $path = (string) parse_url($requestUri, PHP_URL_PATH);

    if ($path === '' || $path === '/') {
        return null;
    }

    $segments = explode('/', trim($path, '/'));

    if (count($segments) !== 1 || $segments[0] === '') {
        return null;
    }

    $subId = rawurldecode($segments[0]);

    if (preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/', $subId) !== 1) {
        return null;
    }

    return $subId;
}

function ngixNormalizeRedirectHost(string $host): ?string
{
    $host = strtolower(trim($host));

    if ($host === '' || str_contains($host, '@')) {
        return null;
    }

    $host = preg_replace('/:\\d+$/', '', $host);

    if (!is_string($host) || $host === '') {
        return null;
    }

    if (str_starts_with($host, 'www.')) {
        $host = substr($host, 4);
    }

    if (str_starts_with($host, 'gen.')) {
        return null;
    }

    if (preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$/', $host) !== 1) {
        return null;
    }

    return $host;
}

function request_path(): string
{
    $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
    $path = parse_url($uri, PHP_URL_PATH);

    if (!is_string($path) || $path === '') {
        return '/';
    }

    return $path;
}

function is_https_request(): bool
{
    // Kept in sync with srp_request_is_https() in env.php (the canonical rule).
    // This top-level page deliberately does not bootstrap env.php, so the logic
    // is mirrored here rather than delegated. The previous copy only accepted
    // HTTPS 'on'/'1' and had no SERVER_PORT===443 fallback, so it under-detected
    // TLS on some setups; this matches the canonical detector exactly.
    $https = $_SERVER['HTTPS'] ?? null;
    if (is_string($https) && $https !== '' && strtolower($https) !== 'off') {
        return true;
    }

    $forwardedProto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null;
    if (is_string($forwardedProto) && strtolower($forwardedProto) === 'https') {
        return true;
    }

    $cfVisitor = $_SERVER['HTTP_CF_VISITOR'] ?? null;
    if (is_string($cfVisitor) && str_contains(strtolower($cfVisitor), '"scheme":"https"')) {
        return true;
    }

    $serverPort = $_SERVER['SERVER_PORT'] ?? null;

    return (is_numeric($serverPort) ? (int) $serverPort : 0) === 443;
}

function safe_host(): string
{
    $host = strtolower((string) ($_SERVER['HTTP_HOST'] ?? 'localhost'));
    $host = preg_replace('/:\\d+\\z/', '', $host) ?? 'localhost';
    $host = trim($host, '.');

    if ($host === '' || !preg_match('/\\A[a-z0-9.-]{1,253}\\z/', $host)) {
        return 'localhost';
    }

    return $host;
}

function login_url(): string
{
    $scheme = is_https_request() ? 'https' : 'http';
    $host = safe_host();

    $host = preg_replace('/\\Awww\\./i', '', $host) ?? $host;
    $host = preg_replace('/\\Agen\\./i', '', $host) ?? $host;

    return $scheme . '://gen.' . $host . '/';
}

function canonical_url(): string
{
    $scheme = is_https_request() ? 'https' : 'http';

    return $scheme . '://' . safe_host() . '/';
}

try {
    $nonce = bin2hex(random_bytes(16));
} catch (Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo 'Internal Server Error';
    exit;
}

$subId = ngixExtractSubId((string) ($_SERVER['REQUEST_URI'] ?? ''));
$redirectHost = ngixNormalizeRedirectHost((string) ($_SERVER['HTTP_HOST'] ?? ''));

if ($subId !== null && $redirectHost !== null) {
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Location: https://gen.' . $redirectHost . '/' . rawurlencode($subId), true, 302);
    exit;
}

$isHttps = is_https_request();

$path = request_path();
$isWrongPath = !in_array($path, ['/', '/index.php'], true);
$statusCode = $isWrongPath ? 404 : 200;
$brandName = 'NGIX|XCTD';
$pageTitle = $isWrongPath ? '404 - Wrong URL' : 'NGIX';
$canonical = canonical_url();
$year = date('Y');

http_response_code($statusCode);
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Permissions-Policy: accelerometer=(), autoplay=(), camera=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Robots-Tag: ' . ($isWrongPath ? 'noindex, nofollow, noarchive' : 'index, follow'));
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Vary: Accept');

if ($isHttps) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}

$csp = [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'self'",
    "object-src 'none'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "style-src 'self' 'nonce-{$nonce}'",
    "script-src 'self' 'nonce-{$nonce}'",
    "connect-src 'self'",
    'upgrade-insecure-requests',
];
header('Content-Security-Policy: ' . implode('; ', $csp));

header('Link: </.well-known/api-catalog>; rel="api-catalog"', false);
header('Link: </auth.md>; rel="service-doc"', false);
header('Link: </health.php>; rel="status"', false);
header('Link: </privacy.html>; rel="privacy-policy"', false);
header('Link: </terms.html>; rel="terms-of-service"', false);
header('Link: </abuse.html>; rel="abuse-report"', false);
header('Link: </sitemap.xml>; rel="sitemap"', false);
header('Link: </robots.txt>; rel="robots"', false);
header('Link: </.well-known/agent-skills/index.json>; rel="https://agentskills.io/schema/v0.2.0/index.json"', false);
header('Link: </.well-known/mcp/server-card.json>; rel="https://modelcontextprotocol.io/server-card"', false);

$acceptHeader = $_SERVER['HTTP_ACCEPT'] ?? '';
$accept = is_string($acceptHeader) ? $acceptHeader : '';

if (str_contains($accept, 'text/markdown')) {
    header('Content-Type: text/markdown; charset=UTF-8');
    echo "# NGIX|XCTD\n\n";
    echo "Static Gateway / Faded Inverse\n\n";
    echo "## Discovery\n\n";
    echo "- [Home](/)\n";
    echo "- [Privacy Policy](/privacy.html)\n";
    echo "- [Terms of Service](/terms.html)\n";
    echo "- [Abuse Reporting](/abuse.html)\n";
    echo "- [Sitemap](/sitemap.xml)\n";
    echo "- [Robots](/robots.txt)\n";
    echo "- [API Catalog](/.well-known/api-catalog)\n";
    echo "- [API Authentication](/auth.md)\n";
    echo "- [Health Check](/health.php)\n";
    echo "- [Agent Skills](/.well-known/agent-skills/index.json)\n";
    echo "- [MCP Server Card](/.well-known/mcp/server-card.json)\n";
    exit;
}

header('Content-Type: text/html; charset=UTF-8');

$schema = [
    '@context' => 'https://schema.org',
    '@type' => 'WebPage',
    'name' => $brandName,
    'url' => $canonical,
    'description' => 'Secure static gateway welcome page for authenticated workspace access.',
    'inLanguage' => 'en',
];
$schemaJson = json_encode(
    $schema,
    JSON_UNESCAPED_SLASHES
    | JSON_UNESCAPED_UNICODE
    | JSON_HEX_TAG
    | JSON_HEX_AMP
    | JSON_HEX_APOS
    | JSON_HEX_QUOT
    | JSON_THROW_ON_ERROR,
);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="color-scheme" content="light">
    <meta name="theme-color" content="#F4F1EC">
    <title><?= e($pageTitle); ?></title>
    <meta name="description" content="Secure static gateway welcome page for authenticated workspace access.">
    <meta name="robots" content="<?= $isWrongPath ? 'noindex,nofollow,noarchive' : 'index,follow'; ?>">
    <link rel="canonical" href="<?= e($canonical); ?>">
    <link rel="icon" href="/favicon.ico" sizes="any">
    <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
    <link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/public-link.css') ?>">
    <style nonce="<?= e($nonce); ?>">
        .meta-toolbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .meta-toolbar .meta {
            flex: 1 1 0;
            min-width: 0;
            margin: 0;
        }
    </style>
    <script type="application/ld+json" nonce="<?= e($nonce); ?>"><?= $schemaJson; ?></script>
</head>
<body>
    <div class="scanline" aria-hidden="true"></div>
    <div class="noise" aria-hidden="true"></div>

    <main class="stage">
        <section class="panel" id="panel" aria-labelledby="title">
            <p class="eyebrow"><span class="status-dot" aria-hidden="true"></span> standalone / zero dependency</p>

            <div class="hero">
                <div class="hero-emoji" aria-hidden="true">🦊</div>
                <div>
                    <h1 id="title">XC<span>TD</span></h1>
                    <p class="subtitle hint">Stay in bed &bull; Feel relaxed</p>
                </div>
            </div>

            <div class="meta-toolbar controls">
                <div class="meta" aria-label="Technical characteristics">
                    <a class="chip" href="/privacy.html">Privacy</a>
                    <a class="chip" href="/terms.html">Terms</a>
                    <a class="chip" href="/abuse.html">Abuse</a>
                    <a class="chip" href="/sitemap.xml">Sitemap</a>
                    <a class="chip" href="/robots.txt">Robots</a>
                </div>
            </div>

        </section>
    </main>

    <div class="vignette" aria-hidden="true"></div>

    <footer class="page-footer">&copy; <?= e($year); ?> NGIX|XCTD</footer>
</body>
</html>
