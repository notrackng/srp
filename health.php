<?php

/**
 * Health check endpoint — returns JSON status of all critical dependencies.
 *
 * GET /health.php
 *
 * Response 200:
 *   { "ok": true, "checks": { "db": true, "geoip2": true, "tmp_writable": true, ... } }
 *
 * Response 503:
 *   { "ok": false, "checks": { "db": false, ... }, "errors": ["DB: connection refused"] }
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/env.php';

$checks = [];
$errors = [];

// ── Database (MySQL via PDO — redirect module connection) ──────────────────

try {
    load_env_file(__DIR__ . '/.env');

    $dbHost = app_env('DB_HOST', 'localhost') ?? 'localhost';
    $dbPort = (int) (app_env('DB_PORT', '3306') ?? '3306');
    $dbUser = app_required_env('DB_USER');
    $dbPass = (string) app_env('DB_PASSWORD', '');
    $dbName = app_required_env('DB_NAME');
    $dbSocket = app_env('DB_SOCKET', '');
    $dbCharset = app_env('DB_CHARSET', 'utf8mb4') ?? 'utf8mb4';

    if ($dbPort < 1 || $dbPort > 65535) {
        $dbPort = 3306;
    }

    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $dbHost, $dbPort, $dbName, $dbCharset);
    if ($dbSocket !== null && $dbSocket !== '') {
        $dsn .= ';unix_socket=' . $dbSocket;
    }

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];

    if (defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
        $options[PDO::MYSQL_ATTR_MULTI_STATEMENTS] = false;
    }

    $pdo = new PDO($dsn, $dbUser, $dbPass, $options);
    $pdo->query('SELECT 1');
    $checks['db'] = true;
} catch (Throwable $e) {
    $checks['db'] = false;
    error_log('[health] DB check failed: ' . get_class($e));
    $errors[] = 'DB: connection failed';
}

// ── GeoIP2 database ────────────────────────────────────────────────────────

try {
    $geoipPath = __DIR__ . '/redirect/databases/GeoLite2-Country.mmdb';
    $checks['geoip2'] = is_file($geoipPath) && is_readable($geoipPath);
    if (!$checks['geoip2']) {
        $errors[] = 'GeoIP2: database not available';
    }
} catch (Throwable $e) {
    $checks['geoip2'] = false;
    error_log('[health] GeoIP2 check failed: ' . get_class($e));
    $errors[] = 'GeoIP2: check failed';
}

// ── Temp directory (writable) ──────────────────────────────────────────────

try {
    $tmpDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
    $testFile = $tmpDir . DIRECTORY_SEPARATOR . 'srp_health_check_test';
    $written = @file_put_contents($testFile, '1', LOCK_EX);
    $checks['tmp_writable'] = $written !== false;
    if ($written !== false) {
        @unlink($testFile);
    }
    if (!$checks['tmp_writable']) {
        $errors[] = 'Tmp: directory not writable';
    }
} catch (Throwable $e) {
    $checks['tmp_writable'] = false;
    error_log('[health] Tmp check failed: ' . get_class($e));
    $errors[] = 'Tmp: check failed';
}

// ── PHP extensions ─────────────────────────────────────────────────────────

$requiredExtensions = ['pdo', 'pdo_mysql', 'curl', 'openssl', 'mbstring', 'json'];
foreach ($requiredExtensions as $ext) {
    $checks['ext_' . $ext] = extension_loaded($ext);
    if (!$checks['ext_' . $ext]) {
        $errors[] = 'Extension missing: ' . $ext;
    }
}

// ── PHP version ────────────────────────────────────────────────────────────

$checks['php_version'] = PHP_VERSION_ID >= 80300;
if (!$checks['php_version']) {
    $errors[] = 'PHP version: ' . PHP_VERSION . ' (need >= 8.3)';
}

// ── Response ───────────────────────────────────────────────────────────────

$allOk = !in_array(false, $checks, true);
$statusCode = $allOk ? 200 : 503;

http_response_code($statusCode);

echo json_encode(
    [
        'ok'       => $allOk,
        'checks'   => $checks,
        'errors'   => $errors,
        'time'     => date('c'),
    ],
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
) . "\n";
