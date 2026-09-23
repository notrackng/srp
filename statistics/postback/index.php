<?php

declare(strict_types=1);

const PB_MAX_RETRIES = 3;
const PB_RETRY_BASE_MS = 100;
const PB_MAX_ENCODED_CLICK_ID_LENGTH = 512;
const PB_MAX_CLICK_ID_LENGTH = 128;
const PB_MAX_LABEL_LENGTH = 64;

function pbSendSecurityHeaders(): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header(
        "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; "
        . "base-uri 'none'; form-action 'none'"
    );
    header(
        'Permissions-Policy: accelerometer=(), camera=(), geolocation=(), '
        . 'gyroscope=(), microphone=(), payment=(), usb=()'
    );
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

function pbRespond(int $statusCode, array $payload): never
{
    http_response_code($statusCode);

    $json = json_encode(
        $payload,
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
        | JSON_INVALID_UTF8_SUBSTITUTE
    );

    if ($json === false) {
        echo '{"success":false,"error":"Internal server error"}';
        exit;
    }

    echo $json;
    exit;
}

function pbLog(string $event, array $context = []): void
{
    $entry = ['event' => $event] + $context;
    $json = json_encode(
        $entry,
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
        | JSON_INVALID_UTF8_SUBSTITUTE
    );

    if ($json === false) {
        error_log('[postback] logging_failure');
        return;
    }

    error_log('[postback] ' . $json);
}

function pbReadQueryString(string $name): string
{
    if (!isset($_GET[$name]) || !is_string($_GET[$name])) {
        return '';
    }

    return $_GET[$name];
}

function pbLoadProjectRuntime(string $projectRoot): void
{
    $envLoader = $projectRoot . '/env.php';
    $envFile = $projectRoot . '/.env';

    if (!is_file($envLoader) || !is_readable($envLoader)) {
        throw new RuntimeException('Environment loader is unavailable.');
    }

    require_once $envLoader;

    if (!function_exists('load_env_file')) {
        throw new RuntimeException('Environment loader is invalid.');
    }

    load_env_file($envFile);
}

function pbEnv(string $key, string $default = ''): string
{
    // Resolve through the canonical app_env() so this endpoint reads env vars in
    // the SAME precedence ($_ENV, then $_SERVER, then getenv()) as the rest of
    // the codebase. This copy previously checked getenv() first — the reverse
    // order — which resolves a key differently when the same name is set to
    // different values across sources. pbLoadProjectRuntime() require's env.php
    // before any pbEnv() call, so app_env() is available; the guard keeps this
    // safe if that call order ever changes.
    if (function_exists('app_env')) {
        return app_env($key, $default) ?? $default;
    }

    // Fallback (env.php not yet loaded): mirror app_env()'s precedence exactly.
    $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);

    if ($value === false || $value === null || $value === '') {
        return $default;
    }

    return is_string($value) ? $value : (string) $value;
}

function pbDecodePayload(string $encodedPayload): array
{
    $encodedPayload = trim($encodedPayload);
    $length = strlen($encodedPayload);

    if (
        $length === 0
        || $length > PB_MAX_ENCODED_CLICK_ID_LENGTH
        || preg_match('/^[A-Za-z0-9_-]+$/D', $encodedPayload) !== 1
    ) {
        throw new InvalidArgumentException('Invalid encoded payload.');
    }

    $remainder = $length % 4;

    if ($remainder === 1) {
        throw new InvalidArgumentException('Invalid Base64URL length.');
    }

    $base64 = strtr($encodedPayload, '-_', '+/');

    if ($remainder > 0) {
        $base64 .= str_repeat('=', 4 - $remainder);
    }

    $decoded = base64_decode($base64, true);

    if ($decoded === false || $decoded === '') {
        throw new InvalidArgumentException('Unable to decode payload.');
    }

    $payload = explode(',', $decoded);

    if (count($payload) !== 5) {
        throw new InvalidArgumentException('Invalid payload field count.');
    }

    return array_values($payload);
}

function pbNormalizeClickId(string $clickId): string
{
    $clickId = trim($clickId);

    if (
        $clickId === ''
        || strlen($clickId) > PB_MAX_CLICK_ID_LENGTH
        || preg_match('/^[A-Za-z0-9_-]+$/D', $clickId) !== 1
    ) {
        throw new InvalidArgumentException('Invalid click ID.');
    }

    return $clickId;
}

function pbNormalizeCountry(string $country): string
{
    $country = strtoupper(trim($country));

    if (preg_match('/^[A-Z]{2}$/D', $country) !== 1) {
        throw new InvalidArgumentException('Invalid country.');
    }

    return $country;
}

function pbNormalizeIp(string $ipAddress): string
{
    $ipAddress = trim($ipAddress);
    $validated = filter_var($ipAddress, FILTER_VALIDATE_IP);

    if (!is_string($validated)) {
        throw new InvalidArgumentException('Invalid IP address.');
    }

    return $validated;
}

function pbNormalizeLabel(string $value, string $field): string
{
    $value = trim($value);

    if (
        $value === ''
        || strlen($value) > PB_MAX_LABEL_LENGTH
        || preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/D', $value) !== 1
    ) {
        throw new InvalidArgumentException('Invalid ' . $field . '.');
    }

    return $value;
}

function pbNormalizeTraffic(string $traffic): string
{
    return pbNormalizeLabel($traffic, 'traffic');
}

function pbNormalizeNetwork(string $network): string
{
    return pbNormalizeLabel($network, 'network');
}

function pbNormalizePayout(string $payout): string
{
    $payout = trim($payout);

    if (
        $payout === ''
        || strlen($payout) > 19
        || preg_match('/^\d{1,10}(?:\.\d{1,8})?$/D', $payout) !== 1
    ) {
        throw new InvalidArgumentException('Invalid payout.');
    }

    return $payout;
}

function pbComputeIdempotencyKey(
    string $clickId,
    string $payout,
    string $network,
    string $traffic,
    int $timestamp
): string {
    $minute = intdiv($timestamp, 60);

    return hash(
        'sha256',
        $clickId . '|' . $payout . '|' . $network . '|' . $traffic . '|' . $minute
    );
}

function pbConnect(string $connectionFile): PDO
{
    if (!is_file($connectionFile) || !is_readable($connectionFile)) {
        throw new RuntimeException('Database connection file is unavailable.');
    }

    $pdo = require $connectionFile;

    if (!$pdo instanceof PDO) {
        throw new RuntimeException('Database connection is invalid.');
    }

    return $pdo;
}

function pbInsertLeadReport(
    PDO $pdo,
    string $clickId,
    string $ipAddress,
    string $country,
    string $payout,
    string $conversionDate,
    string $currencySymbol,
    string $network,
    string $traffic,
    string $idempotencyKey
): bool {
    $statement = $pdo->prepare(
        'INSERT INTO leadreport
            (click_id, ip_address, country, payout, conversion_date,
             currency_symbol, network, traffic, idempotency_key)
         VALUES
            (:click_id, :ip_address, :country, :payout, :conversion_date,
             :currency_symbol, :network, :traffic, :idempotency_key)
         ON DUPLICATE KEY UPDATE idempotency_key = idempotency_key'
    );

    $statement->execute([
        'click_id' => $clickId,
        'ip_address' => $ipAddress,
        'country' => $country,
        'payout' => $payout,
        'conversion_date' => $conversionDate,
        'currency_symbol' => $currencySymbol,
        'network' => $network,
        'traffic' => $traffic,
        'idempotency_key' => $idempotencyKey,
    ]);

    return $statement->rowCount() === 1;
}

function pbUpsertClickRecord(
    PDO $pdo,
    string $clickId,
    string $payout,
    string $conversionDate
): void {
    $statement = $pdo->prepare(
        'INSERT INTO clickrecord
            (click_id, clicks, leads, payout, click_date)
         VALUES
            (:click_id, 0, 1, CAST(:payout_insert AS DECIMAL(18,2)), :click_date)
         ON DUPLICATE KEY UPDATE
            leads = leads + 1,
            payout = payout + CAST(:payout_update AS DECIMAL(18,2))'
    );

    $statement->execute([
        'click_id' => $clickId,
        'payout_insert' => $payout,
        'click_date' => $conversionDate,
        'payout_update' => $payout,
    ]);
}

function pbPersistConversion(
    PDO $pdo,
    string $clickId,
    string $ipAddress,
    string $country,
    string $payout,
    string $conversionDate,
    string $currencySymbol,
    string $network,
    string $traffic,
    string $idempotencyKey
): void {
    if (!$pdo->beginTransaction()) {
        throw new RuntimeException('Unable to start database transaction.');
    }

    $isNewConversion = pbInsertLeadReport(
        $pdo,
        $clickId,
        $ipAddress,
        $country,
        $payout,
        $conversionDate,
        $currencySymbol,
        $network,
        $traffic,
        $idempotencyKey
    );

    if ($isNewConversion) {
        pbUpsertClickRecord($pdo, $clickId, $payout, $conversionDate);
    }

    if (!$pdo->commit()) {
        throw new RuntimeException('Unable to commit database transaction.');
    }
}

function pbRollback(PDO $pdo): void
{
    if (!$pdo->inTransaction()) {
        return;
    }

    try {
        $pdo->rollBack();
    } catch (Throwable $e) {
        pbLog('rollback_failed', ['error_type' => $e::class]);
    }
}

function pbRetryDelay(int $attempt): void
{
    $delayUs = (PB_RETRY_BASE_MS * (2 ** $attempt)) * 1000;
    $jitterUs = 0;

    try {
        $jitterUs = random_int(0, (int) ($delayUs * 0.3));
    } catch (Throwable $e) {
        pbLog('retry_jitter_unavailable', ['error_type' => $e::class]);
    }

    usleep($delayUs + $jitterUs);
}

function pbMain(): never
{
    pbSendSecurityHeaders();

    $requestMethod = $_SERVER['REQUEST_METHOD'] ?? '';

    if (!is_string($requestMethod) || $requestMethod !== 'GET') {
        header('Allow: GET');

        pbRespond(405, [
            'success' => false,
            'error' => 'Method not allowed',
        ]);
    }

    $projectRoot = dirname(__DIR__, 2);

    // The runtime is loaded before the token check, not after it: POSTBACK_SECRET
    // in .env is the single source of this credential now (postback-config.php is
    // gone), so .env has to be in memory before there is anything to compare
    // against. An unreadable .env therefore fails closed as a configuration
    // error — never as "unauthorized", which would misreport a broken deployment
    // as an attacker to whoever is reading the network's postback logs.
    try {
        pbLoadProjectRuntime($projectRoot);
    } catch (Throwable $e) {
        pbLog('runtime_load_failed', ['error_type' => $e::class]);

        pbRespond(500, [
            'success' => false,
            'error' => 'Server configuration error',
        ]);
    }

    // Empty is the shipped state (no .env in a release package), and it means
    // "not configured" — the endpoint accepts nothing until an operator sets it.
    $expectedToken = pbEnv('POSTBACK_SECRET');

    if ($expectedToken === '' || strlen($expectedToken) > 512) {
        pbLog('configuration_token_invalid');

        pbRespond(500, [
            'success' => false,
            'error' => 'Server configuration error',
        ]);
    }

    $token = pbReadQueryString('token');

    if (
        $token === ''
        || strlen($token) > 512
        || !hash_equals($expectedToken, $token)
    ) {
        pbRespond(403, [
            'success' => false,
            'error' => 'Unauthorized',
        ]);
    }

    $encodedClickId = trim(pbReadQueryString('click_id'));
    $rawPayout = trim(pbReadQueryString('payout'));

    try {
        $payload = pbDecodePayload($encodedClickId);
        $clickId = pbNormalizeClickId((string) $payload[0]);
        $country = pbNormalizeCountry((string) $payload[1]);
        $ipAddress = pbNormalizeIp((string) $payload[2]);
        $traffic = pbNormalizeTraffic((string) $payload[3]);
        $network = pbNormalizeNetwork((string) $payload[4]);
        $payout = pbNormalizePayout($rawPayout);
    } catch (Throwable $e) {
        pbRespond(400, [
            'success' => false,
            'error' => 'Invalid postback payload',
        ]);
    }

    $timezoneName = pbEnv('POSTBACK_TIMEZONE', 'UTC');

    try {
        $dateTimeZone = new DateTimeZone($timezoneName);
    } catch (Throwable $e) {
        pbLog('timezone_invalid', ['error_type' => $e::class]);
        $dateTimeZone = new DateTimeZone('UTC');
    }

    $timestamp = time();
    $conversionDate = (new DateTimeImmutable('@' . $timestamp))
        ->setTimezone($dateTimeZone)
        ->format('Y-m-d');
    $idempotencyKey = pbComputeIdempotencyKey(
        $clickId,
        $payout,
        $network,
        $traffic,
        $timestamp
    );
    $connectionFile = $projectRoot . '/connection_pdo.php';

    for ($attempt = 0; $attempt < PB_MAX_RETRIES; $attempt++) {
        $pdo = null;

        try {
            $pdo = pbConnect($connectionFile);
            pbPersistConversion(
                $pdo,
                $clickId,
                $ipAddress,
                $country,
                $payout,
                $conversionDate,
                '$',
                $network,
                $traffic,
                $idempotencyKey
            );

            pbRespond(200, [
                'success' => true,
                'click_id' => $encodedClickId,
                'payout' => $rawPayout,
            ]);
        } catch (Throwable $e) {
            if ($pdo instanceof PDO) {
                pbRollback($pdo);
            }

            pbLog('database_attempt_failed', [
                'attempt' => $attempt + 1,
                'error_type' => $e::class,
            ]);

            $pdo = null;

            if ($attempt < PB_MAX_RETRIES - 1) {
                pbRetryDelay($attempt);
            }
        }
    }

    pbLog('database_retries_exhausted', [
        'attempts' => PB_MAX_RETRIES,
        'click_id_hash' => hash('sha256', $encodedClickId),
    ]);

    pbRespond(503, [
        'success' => false,
        'error' => 'Service unavailable',
    ]);
}

if (!defined('PB_TEST_MODE') || PB_TEST_MODE !== true) {
    pbMain();
}
