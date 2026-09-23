<?php

declare(strict_types=1);

$options = getopt('', ['sub-id:', 'code::', 'base-url::', 'help']);

if ($options === false) {
    srp_short_link_cli_usage(STDERR);
    exit(1);
}

if (array_key_exists('help', $options)) {
    srp_short_link_cli_usage(STDOUT);
    exit(0);
}

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('Not Found');
}

require_once dirname(__DIR__) . '/env.php';

load_env_file(dirname(__DIR__) . '/.env');

require_once dirname(__DIR__) . '/Base64URL.php';
require_once __DIR__ . '/public_link.php';

/** @var PDO $pdo */
$pdo = require __DIR__ . '/connection.config.php';

$legacySubId = is_string($options['sub-id'] ?? null)
    ? trim($options['sub-id'])
    : '';

if ($legacySubId === '') {
    fwrite(STDERR, "Missing required option --sub-id.\n\n");
    srp_short_link_cli_usage(STDERR);
    exit(1);
}

$payload = srp_public_link_decode_legacy_token($legacySubId);

if ($payload === null) {
    fwrite(STDERR, "Invalid legacy sub_id payload.\n");
    exit(1);
}

$baseUrl = is_string($options['base-url'] ?? null)
    ? trim($options['base-url'])
    : '';

if (
    $baseUrl !== ''
    && (
        filter_var($baseUrl, FILTER_VALIDATE_URL) === false
        || !preg_match('/^https?:\/\//i', $baseUrl)
    )
) {
    fwrite(STDERR, "Invalid --base-url. Use an absolute http/https URL.\n");
    exit(1);
}

try {
    srp_short_link_ensure_table($pdo);

    $rawRequestedCode = is_string($options['code'] ?? null)
        ? $options['code']
        : null;
    $requestedCode = srp_short_link_sanitize_code($rawRequestedCode);

    if (array_key_exists('code', $options) && $requestedCode === null) {
        throw new RuntimeException('Invalid --code. Use 4-32 chars [A-Za-z0-9_-].');
    }

    if ($requestedCode !== null) {
        if (srp_short_link_exists($pdo, $requestedCode)) {
            throw new RuntimeException('Short code already exists.');
        }

        $code = $requestedCode;
    } else {
        $code = srp_short_link_generate_unique_code($pdo);
    }

    srp_short_link_create($pdo, $code, $payload);

    $token = srp_short_link_build_token($code);

    fwrite(STDOUT, 'Short code: ' . $code . PHP_EOL);
    fwrite(STDOUT, 'Public token: ' . $token . PHP_EOL);

    if ($baseUrl !== '') {
        fwrite(STDOUT, 'Public URL: ' . rtrim($baseUrl, '/') . '/' . $token . PHP_EOL);
    }
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . PHP_EOL);
    exit(1);
}

/** @param resource $stream */
function srp_short_link_cli_usage($stream): void
{
    fwrite($stream, "Usage:\n");
    fwrite(
        $stream,
        "  php generate-short-link.php --sub-id=LEGACY_TOKEN [--code=custom123] [--base-url=https://domain.tld]\n\n",
    );
    fwrite($stream, "Example:\n");
    fwrite(
        $stream,
        "  php generate-short-link.php --sub-id=REtk... --base-url=https://domainkamu.com\n",
    );
}
