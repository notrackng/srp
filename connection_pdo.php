<?php

/**
 * Unified PDO connection bootstrap for all three modules.
 *
 * Replaces the old per-module connection files:
 *   public/connection.config.php   (mysqli)
 *   public/connection.php          (dbObj/mysqli)
 *   redirect/connection.config.php (PDO — kept for Composer autoload)
 *   statistics/connection.config.php (mysqli)
 *
 * Usage:
 *   // In any module:
 *   /** @var PDO $pdo *\/
 *   $pdo = require __DIR__ . '/connection_pdo.php';
 *
 *   $stmt = $pdo->prepare('SELECT ... WHERE col = :val');
 *   $stmt->execute(['val' => $value]);
 *   $row = $stmt->fetch(PDO::FETCH_ASSOC);
 *
 * Environment variables (from .env):
 *   DB_HOST, DB_PORT (default 3306), DB_USER, DB_PASSWORD, DB_NAME,
 *   DB_SOCKET (optional, for Unix socket), DB_CHARSET (default utf8mb4),
 *   DB_PERSISTENT (default 0)
 */

declare(strict_types=1);

require_once __DIR__ . '/env.php';
load_env_file(__DIR__ . '/.env');

// Resolve configuration
$dbHost   = app_env('DB_HOST', 'localhost') ?? 'localhost';
$dbPort   = (int) (app_env('DB_PORT', '3306') ?? '3306');
$dbUser   = app_required_env('DB_USER');
$dbPass   = (string) app_env('DB_PASSWORD', '');
$dbName   = app_required_env('DB_NAME');
$dbSocket = app_env('DB_SOCKET', '');
$dbCharset = app_env('DB_CHARSET', 'utf8mb4') ?? 'utf8mb4';
$dbPersistent = filter_var(app_env('DB_PERSISTENT', '0') ?? '0', FILTER_VALIDATE_BOOL);

if ($dbPort < 1 || $dbPort > 65535) {
    $dbPort = 3306;
}

// Build DSN
$dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=%s', $dbHost, $dbPort, $dbName, $dbCharset);

if ($dbSocket !== null && $dbSocket !== '') {
    $dsn .= ';unix_socket=' . $dbSocket;
}

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
    PDO::ATTR_PERSISTENT         => $dbPersistent,
    PDO::ATTR_TIMEOUT            => 5, // connect timeout (seconds), PHP 8.2+
];

if (defined('PDO::MYSQL_ATTR_MULTI_STATEMENTS')) {
    $options[PDO::MYSQL_ATTR_MULTI_STATEMENTS] = false;
}

try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, $options);
} catch (Throwable $e) {
    error_log('[db] Connection failed: ' . $e->getMessage());
    if (defined('SRP_DB_THROW_ON_CONNECT_FAILURE') && SRP_DB_THROW_ON_CONNECT_FAILURE === true) {
        throw new RuntimeException('Database connection failed.', 0, $e);
    }

    // CLI callers (migrations/*.php, cron scripts) must see a FAILING exit code.
    // Falling through to the web branch below exits 0, so a deploy script doing
    // `php migrations/006_....php && echo ok` printed "ok" on a dead database.
    // No detail is echoed — the reason is already in the error log.
    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, 'Database connection failed. Check DB_* settings in .env.' . PHP_EOL);
        exit(1);
    }

    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    exit('Internal Server Error');
}

return $pdo;
