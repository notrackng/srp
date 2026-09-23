<?php

declare(strict_types=1);

/**
 * @return array{
 *     click_id: string,
 *     user_lp: string,
 *     canonical_url: string,
 *     image_url: string,
 *     title: string,
 *     lg: string,
 *     block_vpn_asn: ?bool
 * }|null
 */
function srp_public_link_decode_legacy_token(string $token): ?array
{
    $token = trim($token);

    if ($token === '' || strlen($token) > 2048 || preg_match('/^[A-Za-z0-9_-]+$/', $token) !== 1) {
        return null;
    }

    $decoded = base64url_decode($token);

    if (!is_string($decoded) || $decoded === '') {
        return null;
    }

    $parts = str_getcsv($decoded);

    if (count($parts) < 7) {
        return null;
    }

    $clickId = srp_public_link_sanitize_token_part(
        $parts[1] ?? null,
        64,
    );
    $userLp = srp_public_link_sanitize_token_part(
        $parts[4] ?? null,
        64,
    );

    if ($clickId === null || $userLp === null) {
        return null;
    }

    return [
        'click_id' => $clickId,
        'user_lp' => $userLp,
        'canonical_url' => srp_public_link_normalize_https_url($parts[3] ?? '') ?? '',
        'image_url' => srp_public_link_normalize_https_url($parts[6] ?? '') ?? '',
        'title' => srp_public_link_normalize_title($parts[5] ?? ''),
        'lg' => srp_public_link_normalize_lg($parts[7] ?? ''),
        'block_vpn_asn' => srp_public_link_decode_block_vpn_asn($parts[8] ?? null),
    ];
}

/**
 * Parse the per-link VPN/ASN block flag. Absent/invalid → null (fall back to
 * the global toggle); an explicit off value → false; anything else → true.
 */
function srp_public_link_decode_block_vpn_asn(mixed $value): ?bool
{
    if (!is_scalar($value)) {
        return null;
    }

    $normalized = strtolower(trim((string) $value));
    if ($normalized === '') {
        return null;
    }

    return !in_array($normalized, ['0', 'false', 'off', 'no'], true);
}

function srp_public_link_extract_short_code(string $token): ?string
{
    $token = trim($token);

    if ($token === '' || strlen($token) > 34 || substr_compare($token, 's-', 0, 2, true) !== 0) {
        return null;
    }

    return srp_short_link_sanitize_code(substr($token, 2));
}

function srp_short_link_build_token(string $code): string
{
    return 's-' . $code;
}

function srp_short_link_sanitize_code(mixed $value): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);
    if ($value === '' || strlen($value) < 4 || strlen($value) > 32) {
        return null;
    }

    return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1 ? $value : null;
}

function srp_short_link_ensure_table(PDO $pdo): void
{
    $statement = $pdo->prepare(
        'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = :table_name LIMIT 1',
    );
    $statement->execute(['table_name' => 'srp_short_links']);

    if ($statement->fetchColumn() !== false) {
        return;
    }

    throw new RuntimeException('Required table srp_short_links is not installed.');
}

/**
 * @return array{
 *     click_id: string,
 *     user_lp: string,
 *     canonical_url: string,
 *     image_url: string,
 *     title: string,
 *     lg: string
 * }|null
 */
function srp_short_link_find(PDO $pdo, string $code): ?array
{
    // Same file-cache treatment as the legacy srp_shortlinks_find() below —
    // this is the PRIMARY lookup for every s-<code> request, so an uncached
    // DB round trip here is paid on every click even though short-link rows
    // rarely change once created. Own prefix (slp_ = "short link primary")
    // so it can never collide with the legacy table's sl_ cache for the same
    // code string. Registered in redirect/cleanup-cache.php's $rules.
    $cacheSubdir = defined('SRP_CACHE_DIR_NAME') ? SRP_CACHE_DIR_NAME : 'srp_bb';
    $cacheDir    = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $cacheSubdir;
    $cacheFile   = $cacheDir . DIRECTORY_SEPARATOR . 'slp_' . md5($code) . '.json';
    $cacheTtl    = 300; // 5 minutes

    if (is_file($cacheFile)) {
        $mtime = filemtime($cacheFile);
        if ($mtime !== false && (time() - $mtime) < $cacheTtl) {
            $cached = json_decode((string) file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                return isset($cached['__miss']) ? null : $cached;
            }
        }
    }

    try {
        $statement = $pdo->prepare(
            'SELECT click_id, user_lp, lg, canonical_url, title, image_url '
            . 'FROM srp_short_links '
            . 'WHERE short_code = :short_code AND is_active = 1 LIMIT 1',
        );
        $statement->execute(['short_code' => $code]);
        $row = $statement->fetch();
    } catch (Throwable $e) {
        error_log('Public short-link lookup failed for srp_short_links: ' . $e->getMessage());
        return null;
    }

    $result = null;

    if (is_array($row)) {
        $clickId = srp_public_link_sanitize_token_part($row['click_id'] ?? null, 64);
        $userLp = srp_public_link_sanitize_token_part($row['user_lp'] ?? null, 64);

        if ($clickId !== null && $userLp !== null) {
            $result = [
                'click_id' => $clickId,
                'user_lp' => $userLp,
                'canonical_url' => srp_public_link_normalize_https_url($row['canonical_url'] ?? '') ?? '',
                'image_url' => srp_public_link_normalize_https_url($row['image_url'] ?? '') ?? '',
                'title' => srp_public_link_normalize_title($row['title'] ?? ''),
                'lg' => srp_public_link_normalize_lg($row['lg'] ?? ''),
            ];
        }
    }

    // Cache both hits and misses to prevent DB hammering for non-existent codes.
    if (!srp_ensure_private_dir($cacheDir)) {
        return $result;
    }

    srp_write_private_file(
        $cacheFile,
        json_encode($result ?? ['__miss' => true]),
    );

    return $result;
}

/**
 * @param array{
 *     click_id: string,
 *     user_lp: string,
 *     canonical_url: string,
 *     image_url: string,
 *     title: string,
 *     lg: string
 * } $payload
 */
function srp_short_link_create(PDO $pdo, string $code, array $payload): void
{
    $statement = $pdo->prepare(
        'INSERT INTO srp_short_links '
        . '(short_code, click_id, user_lp, lg, canonical_url, title, image_url) '
        . 'VALUES (:short_code, :click_id, :user_lp, :lg, :canonical_url, :title, :image_url)',
    );
    $statement->execute([
        'short_code' => $code,
        'click_id' => $payload['click_id'],
        'user_lp' => $payload['user_lp'],
        'lg' => $payload['lg'],
        'canonical_url' => $payload['canonical_url'],
        'title' => $payload['title'],
        'image_url' => $payload['image_url'],
    ]);
}

function srp_short_link_exists(PDO $pdo, string $code): bool
{
    $statement = $pdo->prepare(
        'SELECT 1 FROM srp_short_links WHERE short_code = :short_code LIMIT 1',
    );
    $statement->execute(['short_code' => $code]);

    return $statement->fetchColumn() !== false;
}

function srp_short_link_generate_unique_code(PDO $pdo, int $length = 8): string
{
    for ($attempt = 0; $attempt < 20; $attempt++) {
        $code = srp_short_link_generate_candidate($length);

        if (!srp_short_link_exists($pdo, $code)) {
            return $code;
        }
    }

    throw new RuntimeException('Unable to generate a unique short code.');
}

function srp_public_link_normalize_lg(mixed $value): string
{
    if (!is_scalar($value)) {
        return 'direct';
    }

    $normalized = strtolower(trim((string) $value));

    if ($normalized === 'landing' || $normalized === '1') {
        return 'landing';
    }
    if ($normalized === 'landing2' || $normalized === '2') {
        return 'landing2';
    }
    return 'direct';
}

function srp_public_link_normalize_title(mixed $value): string
{
    if (!is_scalar($value)) {
        return '';
    }

    $value = preg_replace('/[\r\n\t]+/', ' ', trim((string) $value)) ?? '';

    return mb_substr($value, 0, 200, 'UTF-8');
}

function srp_public_link_normalize_https_url(mixed $value): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);

    if ($value === '' || strlen($value) > 2048 || filter_var($value, FILTER_VALIDATE_URL) === false) {
        return null;
    }

    $scheme = parse_url($value, PHP_URL_SCHEME);

    return is_string($scheme) && strtolower($scheme) === 'https' ? $value : null;
}

function srp_public_link_sanitize_token_part(mixed $value, int $maxLength): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);
    if ($value === '' || strlen($value) > $maxLength) {
        return null;
    }

    return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1 ? $value : null;
}

/**
 * Look up a code in the `shortlinks` table (created by generate_api.php).
 * Result is cached in tmp for 5 minutes — viral links skip repeated DB hits.
 * Returns {long_url, og_title, og_image} or null if not found.
 *
 * @return array{long_url: string, og_title: string, og_image: string}|null
 */
function srp_shortlinks_find(PDO $pdo, string $code): ?array
{
    $cacheSubdir = defined('SRP_CACHE_DIR_NAME') ? SRP_CACHE_DIR_NAME : 'srp_bb';
    $cacheDir    = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $cacheSubdir;
    $cacheFile   = $cacheDir . DIRECTORY_SEPARATOR . 'sl_' . md5($code) . '.json';
    $cacheTtl    = 300; // 5 minutes

    if (is_file($cacheFile)) {
        $mtime = filemtime($cacheFile);
        if ($mtime !== false && (time() - $mtime) < $cacheTtl) {
            $cached = json_decode((string) file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                return isset($cached['__miss']) ? null : $cached;
            }
        }
    }

    try {
        $stmt = $pdo->prepare(
            'SELECT long_url, '
            . "COALESCE(og_title, '') AS og_title, "
            . "COALESCE(og_image, '') AS og_image "
            . 'FROM shortlinks WHERE code = :code LIMIT 1',
        );
        $stmt->execute(['code' => $code]);
        $row = $stmt->fetch();
    } catch (Throwable) {
        return null;
    }

    $result = null;

    if (is_array($row) && !empty($row['long_url'])) {
        $longUrl = trim((string) $row['long_url']);
        if (
            filter_var($longUrl, FILTER_VALIDATE_URL) !== false
            && strtolower((string) parse_url($longUrl, PHP_URL_SCHEME)) === 'https'
        ) {
            $result = [
                'long_url' => $longUrl,
                'og_title' => trim((string) ($row['og_title'] ?? '')),
                'og_image' => trim((string) ($row['og_image'] ?? '')),
            ];
        }
    }

    // Cache both hits and misses to prevent DB hammering for non-existent codes.
    if (!is_dir($cacheDir)) {
        @mkdir($cacheDir, 0700, true);
    }
    @file_put_contents(
        $cacheFile,
        json_encode($result ?? ['__miss' => true, 'long_url' => '']),
        LOCK_EX,
    );

    return $result;
}

function srp_short_link_generate_candidate(int $length): string
{
    $alphabet = 'abcdefghijkmnopqrstuvwxyz23456789';
    $alphabetLength = strlen($alphabet) - 1;
    $buffer = '';

    for ($index = 0; $index < $length; $index++) {
        $buffer .= $alphabet[random_int(0, $alphabetLength)];
    }

    return $buffer;
}
