<?php

/**
 * /internal/v1/{route} — silent cloaking controller.
 * ==================================================
 * The address bar NEVER changes. The visitor always sees an internal-looking
 * path like `/internal/v1/auth`; the real destination is resolved and fetched
 * server-side only, from an allowlist route map. User input can only select a
 * route KEY, never a fetch target (SSRF-safe).
 *
 * Decision order (fixed priority):
 *   1. Bot / User-Agent   → serve raw upstream (crawler fidelity)
 *   2. Request-header     → ajax/json: relay raw payload untouched
 *   3. URL / path         → browser: rewrite origin references onto the mask
 */

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require_once __DIR__ . '/engine.php';

$route = internal_route_token();
if ($route === null) {
    http_response_code(404);
    exit;
}

$destination = internal_resolve_destination($route, internal_fallback_map());
if ($destination === null) {
    // Route not mapped — indistinguishable from a missing page.
    http_response_code(404);
    exit;
}

if (!internal_url_allowed($destination)) {
    error_log('[srp] internal cloak blocked destination for route: ' . $route);
    http_response_code(404);
    exit;
}

$userAgent = internal_user_agent();
$isBot = internal_is_bot($userAgent);
$headerFlag = $isBot ? 'bot' : (internal_header_flag() ?? 'browser');

$method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
$method = in_array($method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], true)
    ? $method
    : 'GET';

$requestBody = '';
if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
    $requestBody = (string) file_get_contents('php://input');
    if (strlen($requestBody) > INTERNAL_MAX_BODY) {
        http_response_code(413);
        exit;
    }
}

$forwardUrl = internal_forward_url($destination, $_GET);
$maskedPath = '/internal/v1/' . $route;

try {
    $upstream = internal_fetch($forwardUrl, $method, $requestBody, internal_forward_headers($userAgent, $headerFlag));
} catch (RuntimeException $exception) {
    // Log the real reason; the client gets a generic 502 — never the URL.
    error_log('[srp] internal cloak fetch failed for ' . $route . ': ' . $exception->getMessage());
    http_response_code(502);
    exit;
}

http_response_code((int) $upstream['status']);

// Only human browsers (layer 3) get body rewriting; bots (1) and ajax/json (2)
// receive the raw payload so crawlers and API clients stay byte-faithful.
$responseBody = $headerFlag === 'browser'
    ? internal_rewrite_body($upstream['body'], $destination, $maskedPath)
    : $upstream['body'];

internal_relay_headers($upstream['headers'], $maskedPath);

if ($method !== 'HEAD') {
    header('Content-Length: ' . strlen($responseBody));
    echo $responseBody;
}
