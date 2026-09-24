<?php

/**
 * CLI reachability harness:  php internal/verify.php <route> [host]
 * =================================================================
 * Resolves the route exactly like the live controller, then performs the same
 * server-side fetch and reports status. Pass [host] (the public masked host,
 * e.g. r.example.com) so the self-loop guard can run — without it the guard is
 * skipped in CLI and a destination that points back at itself is not detected.
 *
 * Exit codes: 0 = reachable (2xx/3xx), 1 = fetch failed or bad status,
 *             2 = usage / validation / self-loop.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit;
}

error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once __DIR__ . '/engine.php';

$route = $argv[1] ?? '';
if (!is_string($route) || $route === '') {
    fwrite(STDERR, "Usage: php internal/verify.php <route> [host]\n");
    exit(2);
}
$route = trim($route);

// Public masked host — needed so the self-loop guard can run in CLI.
$maskHost = $argv[2] ?? app_env('INTERNAL_MASK_HOST');
if (!is_string($maskHost)) {
    $maskHost = (string) ($_SERVER['HTTP_HOST'] ?? '');
}
$maskHost = trim($maskHost);
if ($maskHost !== '') {
    $_SERVER['HTTP_HOST'] = $maskHost;
}

// Reuse the exact token gate the live controller uses.
$_GET['route'] = $route;
$token = internal_route_token();
if ($token === null) {
    fwrite(STDERR, "ERROR: invalid route token: {$route}\n");
    exit(2);
}

$destination = internal_resolve_destination($token, internal_fallback_map());
if ($destination === null) {
    fwrite(
        STDERR,
        "ERROR: no destination resolved for route '{$token}'.\n"
        . '       Set INTERNAL_MAP_' . strtoupper($token)
        . " to a URL or 'random:offering' (check the offering table has rows).\n",
    );
    exit(2);
}

// Self-loop guard — the destination must be the hidden REAL origin, never the
// masked host/path itself.
$destHost = strtolower((string) parse_url($destination, PHP_URL_HOST));
if (
    $maskHost !== ''
    && $destHost !== ''
    && ($destHost === strtolower($maskHost) || str_ends_with($destHost, '.' . strtolower($maskHost)))
) {
    fwrite(
        STDERR,
        "ERROR: destination points back at the masked host ({$destination}).\n"
        . '       This is a self-loop. Set INTERNAL_MAP_' . strtoupper($token)
        . " to the REAL target URL (the hidden origin), not the cloaked path.\n",
    );
    exit(2);
}

if (!internal_url_allowed($destination)) {
    fwrite(STDERR, "ERROR: destination failed validation (must be well-formed https, not self): {$destination}\n");
    exit(2);
}

echo "Route      : /internal/v1/{$token}\n";
echo "Destination: {$destination}\n";
if ($maskHost !== '') {
    echo "Mask host  : {$maskHost}\n";
}

try {
    $upstream = internal_fetch($destination, 'GET', '', internal_forward_headers(internal_user_agent(), 'browser'));
} catch (RuntimeException $exception) {
    fwrite(STDERR, 'ERROR: ' . $exception->getMessage() . "\n");
    exit(1);
}

echo 'Status     : ' . $upstream['status'] . "\n";
echo 'Bytes      : ' . strlen($upstream['body']) . "\n";
echo 'Headers    : ' . count($upstream['headers']) . " lines\n";

if ($upstream['status'] >= 200 && $upstream['status'] < 400) {
    echo "\nOK — destination reachable (HTTP {$upstream['status']}); the masked path is ready to serve.\n";
    exit(0);
}

fwrite(
    STDERR,
    "\nWARNING: destination returned HTTP {$upstream['status']} — the target exists but responded with an error.\n"
    . "         Check that the REAL target URL is correct.\n",
);
exit(1);
