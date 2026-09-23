<?php

declare(strict_types=1);

if (!function_exists('e')) {
    function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
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

$path = request_path();
$brandName = 'Wrong URL';
$pageTitle = '404 - Wrong URL';

try {
    $nonce = bin2hex(random_bytes(16));
} catch (Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo 'Internal Server Error';
    exit;
}

http_response_code(404);
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Permissions-Policy: accelerometer=(), autoplay=(), camera=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if (is_https_request()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}

$csp = [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'none'",
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

$schema = [
    '@context' => 'https://schema.org',
    '@type' => 'WebPage',
    'name' => $brandName,
    'description' => 'Standalone wrong URL landing page for invalid, incomplete, or removed links.',
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
    | JSON_THROW_ON_ERROR
);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="color-scheme" content="light">
    <meta name="theme-color" content="#F4F1EC">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <meta name="description" content="A clean fallback page for invalid, incomplete, or removed links.">
    <title><?= e($pageTitle); ?></title>
    <link rel="icon" href="/favicon.ico" sizes="any">
    <link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
    <script type="application/ld+json" nonce="<?= e($nonce); ?>"><?= $schemaJson; ?></script>
    <style nonce="<?= e($nonce); ?>">
        :root {
            --porcelain: #f4f1ec;
            --paper: #fcfbf8;
            --soft-steel: #d9dee2;
            --graphite: #252a2e;
            --steel-gray: #66717a;
            --ink: #16191c;
            --burnt-copper: #a86442;
            --burnt-copper-soft: rgba(168, 100, 66, 0.16);
            --panel: rgba(252, 251, 248, 0.82);
            --border: rgba(37, 42, 46, 0.14);
            --shadow: rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;
            --radius: 0.3rem;
            --pointer-x: 50vw;
            --pointer-y: 50vh;
        }

        *,
        *::before,
        *::after {
            box-sizing: border-box;
        }

        html {
            min-height: 100%;
            background: var(--porcelain);
        }

        body {
            min-height: 100svh;
            margin: 0;
            overflow: hidden;
            color: var(--ink);
            background:
                radial-gradient(circle at var(--pointer-x) var(--pointer-y), var(--burnt-copper-soft), transparent 24rem),
                radial-gradient(circle at 50% 120%, rgba(102, 113, 122, 0.14), transparent 42rem),
                var(--porcelain);
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            text-rendering: optimizeLegibility;
        }

        body::after {
            content: "";
            position: fixed;
            inset: 0;
            z-index: -1;
            pointer-events: none;
            background-image: url('/assets/img/bg-intro.png');
            background-repeat: no-repeat;
            background-position: center center;
            background-size: cover;
            background-attachment: fixed;
            opacity: .28;
            filter: saturate(.68) contrast(.84) brightness(1.03) blur(.32px);
        }

        .noise,
        .scanline,
        .vignette {
            position: fixed;
            inset: 0;
            pointer-events: none;
        }

        .noise {
            z-index: 1;
            opacity: 0.024;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.8' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.7'/%3E%3C/svg%3E");
        }

        .scanline {
            z-index: 0;
            background-image:
                linear-gradient(rgba(102, 113, 122, 0.07) 1px, transparent 1px),
                linear-gradient(90deg, rgba(102, 113, 122, 0.07) 1px, transparent 1px);
            background-size: 44px 44px;
            -webkit-mask-image: linear-gradient(to bottom, black, transparent 92%);
            mask-image: linear-gradient(to bottom, black, transparent 92%);
        }

        .vignette {
            z-index: 4;
            box-shadow: inset 0 0 9rem 2rem rgba(37, 42, 46, 0.11);
        }

        .stage {
            position: relative;
            z-index: 2;
            display: grid;
            min-height: 100svh;
            place-items: center;
            padding:
                max(1rem, env(safe-area-inset-top))
                max(1rem, env(safe-area-inset-right))
                max(1rem, env(safe-area-inset-bottom))
                max(1rem, env(safe-area-inset-left));
            isolation: isolate;
        }

        .panel {
            position: relative;
            width: min(44rem, calc(100vw - 2rem));
            padding: clamp(1.4rem, 4vw, 2.6rem);
            overflow: hidden;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: linear-gradient(145deg, rgba(255, 255, 255, 0.88), rgba(244, 241, 236, 0.76));
            box-shadow: var(--shadow);
            backdrop-filter: blur(1.25rem) saturate(110%);
        }

        .panel::before {
            position: absolute;
            z-index: -1;
            inset: -1px;
            padding: 1px;
            border-radius: inherit;
            background: linear-gradient(120deg, rgba(168, 100, 66, 0.48), transparent 35%, rgba(37, 42, 46, 0.12));
            content: "";
            opacity: 0.42;
            mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
            mask-composite: exclude;
        }

        .eyebrow {
            display: flex;
            align-items: center;
            gap: 0.65rem;
            margin: 0 0 1.5rem;
            color: var(--steel-gray);
            font-size: 0.72rem;
            letter-spacing: 0.18em;
            text-transform: uppercase;
        }

        .status-dot {
            width: 0.46rem;
            height: 0.46rem;
            border-radius: 50%;
            background: var(--burnt-copper);
            box-shadow: 0 0 0 0.28rem rgba(168, 100, 66, 0.12), 0 0 1.1rem rgba(168, 100, 66, 0.42);
            animation: status-pulse 2.4s ease-in-out infinite;
        }

        .hero {
            display: grid;
            grid-template-columns: auto 1fr;
            align-items: center;
            gap: clamp(1rem, 4vw, 2rem);
        }

        .code-wrap {
            position: relative;
            display: grid;
            width: clamp(7rem, 22vw, 10rem);
            aspect-ratio: 1;
            place-items: center;
            border: 1px solid rgba(168, 100, 66, 0.34);
            border-radius: 50%;
            background:
                radial-gradient(circle at 35% 30%, rgba(255, 255, 255, 0.92), transparent 36%),
                rgba(252, 251, 248, 0.92);
            box-shadow: inset 0 0 2rem rgba(168, 100, 66, 0.08), 0 0 2.4rem rgba(37, 42, 46, 0.08);
            animation: breathe 4.5s ease-in-out infinite;
        }

        .code-wrap::before,
        .code-wrap::after {
            position: absolute;
            inset: -0.65rem;
            border: 1px solid rgba(168, 100, 66, 0.18);
            border-radius: 50%;
            content: "";
            animation: radar 4s ease-out infinite;
        }

        .code-wrap::after {
            animation-delay: 2s;
        }

        .code {
            color: var(--graphite);
            font-size: clamp(2.4rem, 8vw, 4.4rem);
            font-weight: 700;
            letter-spacing: -0.12em;
            transform: translateX(-0.06em);
        }

        .code span {
            color: var(--burnt-copper);
        }

        h1 {
            margin: 0;
            color: var(--ink);
            font-size: clamp(2rem, 3vw, 4.6rem);
            line-height: 0.94;
            letter-spacing: -0.07em;
        }

        h1 span {
            color: var(--burnt-copper);
        }

        .subtitle {
            max-width: 31rem;
            margin: 0.9rem 0 0;
            color: var(--graphite);
            font-size: clamp(0.78rem, 2vw, 0.96rem);
            line-height: 1.7;
        }

        .path {
            display: inline-block;
            max-width: 100%;
            margin-top: 1rem;
            padding: 0.48rem 0.65rem;
            overflow: hidden;
            border: 1px solid rgba(37, 42, 46, 0.1);
            border-radius: var(--radius);
            color: var(--steel-gray);
            background: rgba(255, 255, 255, 0.58);
            font-size: 0.7rem;
            text-overflow: ellipsis;
            vertical-align: top;
            white-space: nowrap;
        }


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

        .meta-toolbar .controls {
            flex: 0 0 auto;
            width: auto;
            margin: 0 0 0 auto;
            padding: 0;
            border: 0;
        }

        .meta-toolbar .actions {
            display: flex;
            gap: 0.5rem;
        }

        .controls {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            margin-top: 1.8rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(37, 42, 46, 0.1);
        }

        .hint {
            color: var(--steel-gray);
            font-size: 0.7rem;
            line-height: 1.5;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 0.55rem;
        }

        .action {
            display: inline-flex;
            min-height: 2.45rem;
            align-items: center;
            justify-content: center;
            gap: 0.45rem;
            padding: 0.62rem 0.85rem;
            border: 1px solid rgba(37, 42, 46, 0.14);
            border-radius: var(--radius);
            color: var(--graphite);
            background: rgba(255, 255, 255, 0.76);
            text-decoration: none;
            cursor: pointer;
            transition: border-color 160ms ease, color 160ms ease, transform 160ms ease, background 160ms ease;
        }

        .action-primary {
            border-color: rgba(168, 100, 66, 0.52);
            color: var(--paper);
            background: var(--burnt-copper);
        }

        .action:hover {
            border-color: rgba(168, 100, 66, 0.7);
            color: var(--ink);
            background: rgba(168, 100, 66, 0.12);
            transform: translateY(-1px);
        }

        .action-primary:hover {
            color: var(--paper);
            background: #915638;
        }

        .action:focus-visible {
            outline: 2px solid var(--burnt-copper);
            outline-offset: 0.2rem;
        }

        .footer-mark {
            position: absolute;
            right: 1rem;
            bottom: 0.75rem;
            color: rgba(37, 42, 46, 0.2);
            font-size: clamp(3rem, 10vw, 7rem);
            font-weight: 700;
            letter-spacing: -0.12em;
            pointer-events: none;
            user-select: none;
        }

        @keyframes breathe {
            0%,
            100% {
                transform: translateY(0) scale(1);
            }

            50% {
                transform: translateY(-0.3rem) scale(1.025);
            }
        }

        @keyframes radar {
            0% {
                opacity: 0.5;
                transform: scale(0.78);
            }

            100% {
                opacity: 0;
                transform: scale(1.38);
            }
        }

        @keyframes status-pulse {
            0%,
            100% {
                opacity: 0.66;
            }

            50% {
                opacity: 1;
            }
        }

        @media (max-width: 38rem) {
            .hero {
                grid-template-columns: 1fr;
                text-align: center;
            }

            .code-wrap {
                margin-inline: auto;
            }

            .path {
                max-width: calc(100vw - 5rem);
            }

            .controls {
                flex-direction: column;
                justify-content: center;
            }

            .hint {
                text-align: center;
            }

            .actions {
                justify-content: center;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                scroll-behavior: auto !important;
                animation-duration: 1ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 1ms !important;
            }
        }
    </style>
</head>
<body>
    <div class="scanline" aria-hidden="true"></div>
    <div class="noise" aria-hidden="true"></div>

    <main class="stage">
        <section class="panel" aria-labelledby="page-title">
            <p class="eyebrow">
                <span class="status-dot" aria-hidden="true"></span>
                HTTP status / resource unavailable
            </p>

            <div class="hero">
                <div class="code-wrap" aria-hidden="true">
                    <div class="code">4<span>0</span>4</div>
                </div>

                <div>
                    <h1 id="page-title">Page <span>not found</span>.</h1>
                    <p class="subtitle hint">
                        The requested resource does not exist, was moved, or is temporarily unavailable. Check the address or return to a valid route.
                    </p>
                </div>
            </div>

            <div class="meta-toolbar controls">
                <span class="path meta" id="requestedPath"><?= e($path); ?></span>
                <div class="controls">
                    <div class="actions">
                        <button class="action" id="backButton" type="button">← Go back</button>
                        <a class="action action-primary" href="/">Return home →</a>
                    </div>
                </div>
            </div>

            <div class="footer-mark" aria-hidden="true">X/</div>
        </section>
    </main>

    <div class="vignette" aria-hidden="true"></div>

    <script nonce="<?= e($nonce); ?>">
        (() => {
            'use strict';

            const backButton = document.getElementById('backButton');
            const requestedPath = document.getElementById('requestedPath');

            if (!backButton || !requestedPath) {
                return;
            }

            const updatePointer = (event) => {
                document.documentElement.style.setProperty('--pointer-x', `${event.clientX}px`);
                document.documentElement.style.setProperty('--pointer-y', `${event.clientY}px`);
            };

            requestedPath.textContent = `${window.location.pathname}${window.location.search}` || '/';

            backButton.addEventListener('click', () => {
                if (window.history.length > 1) {
                    window.history.back();
                    return;
                }

                window.location.assign('/');
            });

            window.addEventListener('pointermove', updatePointer, { passive: true });
        })();
    </script>
</body>
</html>
