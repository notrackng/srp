<?php

declare(strict_types=1);

include_once __DIR__ . '/../login.php';

// Auth is settled; drop the session lock immediately. PHP holds an EXCLUSIVE
// lock on the session file for the whole request, and the realtime page runs
// several pollers at once — without this they serialise behind each other and
// a slow one can stall the rest into an origin timeout. This endpoint never
// touches $_SESSION again.
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

function sendJson(array $payload, int $statusCode = 200): never
{
    http_response_code($statusCode);

    try {
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        http_response_code(500);
        echo '{"error":"json-encode-failed"}';
    }

    exit;
}

function fetchIpinfoApp(string $ip): array
{
    if (!extension_loaded('curl') || !function_exists('curl_init')) {
        throw new RuntimeException('curl-unavailable');
    }

    $url = 'https://atlas.ipinfo.app/api/v2/ip/' . rawurlencode($ip);

    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('curl-init-failed');
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => false,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 4,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
        ],
        CURLOPT_USERAGENT => 'SRP-IP-Lookup/1.0',
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
    ]);

    $responseBody = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErrorNo = curl_errno($ch);

    curl_close($ch);

    if ($curlErrorNo !== 0 || !is_string($responseBody) || $responseBody === '') {
        throw new RuntimeException('upstream-request-failed');
    }

    if ($httpCode < 200 || $httpCode >= 300) {
        throw new RuntimeException('upstream-bad-status');
    }

    try {
        $decoded = json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        throw new RuntimeException('upstream-json-invalid');
    }

    if (!is_array($decoded)) {
        throw new RuntimeException('upstream-json-not-object');
    }

    if (
        array_key_exists('error', $decoded)
        && $decoded['error'] !== null
        && trim((string) $decoded['error']) !== ''
    ) {
        throw new RuntimeException('upstream-returned-error');
    }

    return $decoded;
}

if (!isset($_GET['IP2Location'])) {
    sendJson(['error' => 'missing-param']);
}

$rawIp = trim((string) $_GET['IP2Location']);

if ($rawIp === '' || strlen($rawIp) > 45) {
    sendJson(['error' => 'invalid-ip'], 400);
}

$ip = filter_var($rawIp, FILTER_VALIDATE_IP);
if ($ip === false) {
    sendJson(['error' => 'invalid-ip'], 400);
}

try {
    $records = fetchIpinfoApp($ip);

    $resolvedIp = (string) ($records['ip'] ?? $ip);
    if (filter_var($resolvedIp, FILTER_VALIDATE_IP) === false) {
        $resolvedIp = $ip;
    }

    sendJson([
        'ip_address' => $resolvedIp,
        'code' => strtoupper((string) ($records['country_code'] ?? '')),
        'name' => (string) ($records['country'] ?? ''),
        'region' => '',
        'city' => '',
    ]);
} catch (Throwable $e) {
    sendJson(['error' => 'lookup-failed'], 502);
}
