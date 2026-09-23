<?php

/**
 * CLI-only updater for GeoLite2-Country.mmdb.
 *
 * Usage:
 *   php redirect/update-geoip.php
 *
 * Requires MAXMIND_LICENSE_KEY in the project root .env file.
 * Get a free key at: https://www.maxmind.com/en/geolite2/signup
 *
 * MaxMind has two download methods. The legacy one (license_key only, as a
 * query parameter against download.maxmind.com) still works for older
 * accounts, but newer accounts get a plain HTTP 401 from it even with a
 * correct, active license key — MaxMind only grants those accounts the
 * newer method: HTTP Basic Auth (account_id as username, license_key as
 * password) against updates.maxmind.com. Set MAXMIND_ACCOUNT_ID (visible on
 * the same "My License Keys" page as the license key) to use that method;
 * leave it unset to keep using the legacy one.
 *
 * Crontab (setiap Rabu 03:00 — MaxMind rilis Selasa pertama tiap bulan):
 *   0 3 * * 3 /usr/local/bin/php /home/<user>/redirect/update-geoip.php >> /home/<user>/redirect/logs/geoip-update.log 2>&1
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit(1);
}

require_once __DIR__ . '/../env.php';
load_env_file(dirname(__DIR__) . '/.env');

const GEOIP_EDITION             = 'GeoLite2-Country';
const GEOIP_MMDB_FILENAME       = 'GeoLite2-Country.mmdb';
const GEOIP_DOWNLOAD_BASE_LEGACY = 'https://download.maxmind.com/app/geoip_download';
const GEOIP_DOWNLOAD_BASE_V2    = 'https://updates.maxmind.com/geoip/databases';
const GEOIP_CONNECT_TIMEOUT     = 10;
const GEOIP_READ_TIMEOUT        = 90;

function geoip_log(string $level, string $message): void
{
    $line = date('[Y-m-d H:i:s]') . " [{$level}] {$message}" . PHP_EOL;
    fwrite($level === 'ERROR' ? STDERR : STDOUT, $line);
}

/**
 * @return array{url: string, userpwd: ?string}
 */
function geoip_build_request(string $edition, string $suffix, string $licenseKey, ?string $accountId): array
{
    if ($accountId !== null && $accountId !== '') {
        return [
            'url'     => GEOIP_DOWNLOAD_BASE_V2 . '/' . rawurlencode($edition) . '/download?'
                . http_build_query(['suffix' => $suffix]),
            'userpwd' => $accountId . ':' . $licenseKey,
        ];
    }

    return [
        'url' => GEOIP_DOWNLOAD_BASE_LEGACY . '?' . http_build_query([
            'edition_id'  => $edition,
            'license_key' => $licenseKey,
            'suffix'      => $suffix,
        ]),
        'userpwd' => null,
    ];
}

function geoip_curl_to_file(string $url, string $destPath, ?string $userpwd = null): void
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('curl_init failed.');
    }

    $fp = fopen($destPath, 'wb');
    if ($fp === false) {
        curl_close($ch);

        throw new RuntimeException('Cannot open temp file: ' . $destPath);
    }

    curl_setopt_array($ch, [
        CURLOPT_FILE            => $fp,
        CURLOPT_CONNECTTIMEOUT  => GEOIP_CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT         => GEOIP_READ_TIMEOUT,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 3,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_USERAGENT       => 'GeoIP-Updater/1.0',
        CURLOPT_FAILONERROR     => true,
    ]);

    if ($userpwd !== null && $userpwd !== '') {
        curl_setopt_array($ch, [
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERPWD  => $userpwd,
        ]);
    }

    $ok      = curl_exec($ch);
    $code    = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno   = curl_errno($ch);
    $errstr  = curl_error($ch);
    curl_close($ch);
    fclose($fp);

    if ($ok === false || $errno !== 0) {
        throw new RuntimeException("cURL error ({$errno}): {$errstr}");
    }

    if ($code !== 200) {
        throw new RuntimeException("HTTP {$code} downloading archive.");
    }
}

function geoip_curl_string(string $url, ?string $userpwd = null): string
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('curl_init failed.');
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_CONNECTTIMEOUT  => GEOIP_CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT         => 15,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 3,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_USERAGENT       => 'GeoIP-Updater/1.0',
        CURLOPT_FAILONERROR     => true,
    ]);

    if ($userpwd !== null && $userpwd !== '') {
        curl_setopt_array($ch, [
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERPWD  => $userpwd,
        ]);
    }

    $body   = curl_exec($ch);
    $code   = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno  = curl_errno($ch);
    $errstr = curl_error($ch);
    curl_close($ch);

    if ($body === false || $errno !== 0) {
        throw new RuntimeException("cURL error ({$errno}): {$errstr}");
    }

    if ($code !== 200 || !is_string($body)) {
        throw new RuntimeException("HTTP {$code} fetching checksum.");
    }

    return $body;
}

function geoip_find_mmdb(string $dir, string $filename): ?string
{
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($it as $file) {
        if ($file instanceof SplFileInfo && $file->getFilename() === $filename) {
            return $file->getPathname();
        }
    }

    return null;
}

function geoip_rmdir_recursive(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }

    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($it as $item) {
        if (!($item instanceof SplFileInfo)) {
            continue;
        }

        if ($item->isDir()) {
            @rmdir($item->getPathname());
        } else {
            @unlink($item->getPathname());
        }
    }

    @rmdir($dir);
}

// ── Guard ─────────────────────────────────────────────────────────────────────

if (!function_exists('curl_init')) {
    geoip_log('ERROR', 'cURL extension tidak tersedia. Install php-curl lalu coba lagi.');
    exit(1);
}

$licenseKey = app_env('MAXMIND_LICENSE_KEY');
if ($licenseKey === null || $licenseKey === '') {
    geoip_log('ERROR', 'MAXMIND_LICENSE_KEY is not configured in the project root .env file.');
    exit(1);
}

$accountId = app_env('MAXMIND_ACCOUNT_ID');
if ($accountId !== null && $accountId !== '') {
    geoip_log('INFO', 'MAXMIND_ACCOUNT_ID diisi — pakai Basic Auth ke updates.maxmind.com.');
}

// ── Paths ─────────────────────────────────────────────────────────────────────

$dbPath    = __DIR__ . '/databases/' . GEOIP_MMDB_FILENAME;
$dbDir     = dirname($dbPath);
// tempnam() CREATES the file it names; appending .tar.gz then works on a
// different path and orphans the original zero-byte file. Keep the stub path so
// the finally block below can remove it too — otherwise every run leaks one.
$tmpStub   = tempnam(sys_get_temp_dir(), 'geoip_dl_');
$tmpTarGz  = $tmpStub . '.tar.gz';
$tmpExtDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'geoip_ext_' . bin2hex(random_bytes(8));

// ── Main ──────────────────────────────────────────────────────────────────────

// Exit code is recorded, not acted on, until after the finally block below:
// PHP skips finally entirely when exit()/die() is called, so exiting inside the
// try or catch would silently strand the scratch files this script downloads.
// Defaults to failure so an unexpected fall-through is never reported as success.
$exitCode = 1;

try {
    // Step 1 — Checksum dulu (kecil, cepat; jika gagal tidak buang bandwidth)
    geoip_log('INFO', 'Mengunduh checksum SHA-256…');
    $checksumReq  = geoip_build_request(GEOIP_EDITION, 'tar.gz.sha256', $licenseKey, $accountId);
    $checksumRaw  = geoip_curl_string($checksumReq['url'], $checksumReq['userpwd']);
    $expectedHash = strtolower(trim(explode(' ', trim($checksumRaw))[0]));

    if ($expectedHash === '' || strlen($expectedHash) !== 64 || preg_match('/^[0-9a-f]{64}$/', $expectedHash) !== 1) {
        throw new RuntimeException('Format checksum tidak terduga: ' . substr($checksumRaw, 0, 80));
    }

    // Step 2 — Download archive
    geoip_log('INFO', 'Mengunduh ' . GEOIP_EDITION . '.tar.gz…');
    $downloadReq = geoip_build_request(GEOIP_EDITION, 'tar.gz', $licenseKey, $accountId);
    geoip_curl_to_file($downloadReq['url'], $tmpTarGz, $downloadReq['userpwd']);

    $downloadedBytes = filesize($tmpTarGz);
    geoip_log('INFO', sprintf('Unduhan selesai (%.1f MB).', ($downloadedBytes !== false ? $downloadedBytes : 0) / 1048576));

    // Step 3 — Verifikasi SHA-256
    $actualHash = strtolower((string) hash_file('sha256', $tmpTarGz));
    if (!hash_equals($expectedHash, $actualHash)) {
        throw new RuntimeException("SHA-256 mismatch. expected={$expectedHash} actual={$actualHash}");
    }
    geoip_log('INFO', 'Checksum OK.');

    // Step 4 — Ekstrak
    mkdir($tmpExtDir, 0700, true);
    $phar = new PharData($tmpTarGz);
    $phar->extractTo($tmpExtDir);
    unset($phar); // tutup handle sebelum cleanup

    $mmdbSrc = geoip_find_mmdb($tmpExtDir, GEOIP_MMDB_FILENAME);
    if ($mmdbSrc === null) {
        throw new RuntimeException(GEOIP_MMDB_FILENAME . ' tidak ditemukan di dalam archive.');
    }

    // Step 5 — Atomic replace (copy → chmod → rename)
    if (!is_dir($dbDir)) {
        mkdir($dbDir, 0700, true);
    }

    $tmpDest = $dbPath . '.tmp.' . bin2hex(random_bytes(4));

    if (!copy($mmdbSrc, $tmpDest)) {
        throw new RuntimeException("copy() gagal: {$mmdbSrc} → {$tmpDest}");
    }

    chmod($tmpDest, 0600);

    if (!rename($tmpDest, $dbPath)) {
        @unlink($tmpDest);

        throw new RuntimeException("rename() gagal saat mengganti {$dbPath}");
    }

    geoip_log('INFO', 'GeoLite2-Country.mmdb berhasil diperbarui → ' . $dbPath);

    // ── ASN database ────────────────────────────────────────────────────

    $asnEdition       = 'GeoLite2-ASN';
    $asnFilename      = 'GeoLite2-ASN.mmdb';
    $asnDbPath        = __DIR__ . '/databases/' . $asnFilename;
    // Same tempnam() stub caveat as the country DB above.
    $asnTmpStub       = tempnam(sys_get_temp_dir(), 'geoip_asn_dl_');
    $asnTmpTarGz      = $asnTmpStub . '.tar.gz';
    $asnTmpExtDir     = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'geoip_asn_ext_' . bin2hex(random_bytes(8));

    try {
        geoip_log('INFO', 'Mengunduh checksum ' . $asnEdition . '…');
        $asnChecksumReq  = geoip_build_request($asnEdition, 'tar.gz.sha256', $licenseKey, $accountId);
        $asnChecksumRaw  = geoip_curl_string($asnChecksumReq['url'], $asnChecksumReq['userpwd']);
        $asnExpectedHash = strtolower(trim(explode(' ', trim($asnChecksumRaw))[0]));

        if ($asnExpectedHash === '' || strlen($asnExpectedHash) !== 64 || preg_match('/^[0-9a-f]{64}$/', $asnExpectedHash) !== 1) {
            throw new RuntimeException('Format checksum ASN tidak terduga: ' . substr($asnChecksumRaw, 0, 80));
        }

        geoip_log('INFO', 'Mengunduh ' . $asnEdition . '.tar.gz…');
        $asnDownloadReq = geoip_build_request($asnEdition, 'tar.gz', $licenseKey, $accountId);
        geoip_curl_to_file($asnDownloadReq['url'], $asnTmpTarGz, $asnDownloadReq['userpwd']);

        $asnDownloadedBytes = filesize($asnTmpTarGz);
        geoip_log('INFO', sprintf('Unduhan ASN selesai (%.1f MB).', ($asnDownloadedBytes !== false ? $asnDownloadedBytes : 0) / 1048576));

        $asnActualHash = strtolower((string) hash_file('sha256', $asnTmpTarGz));
        if (!hash_equals($asnExpectedHash, $asnActualHash)) {
            throw new RuntimeException("ASN SHA-256 mismatch. expected={$asnExpectedHash} actual={$asnActualHash}");
        }
        geoip_log('INFO', 'ASN Checksum OK.');

        mkdir($asnTmpExtDir, 0700, true);
        $asnPhar = new PharData($asnTmpTarGz);
        $asnPhar->extractTo($asnTmpExtDir);
        unset($asnPhar);

        $asnMmdbSrc = geoip_find_mmdb($asnTmpExtDir, $asnFilename);
        if ($asnMmdbSrc === null) {
            throw new RuntimeException($asnFilename . ' tidak ditemukan di dalam archive.');
        }

        $asnTmpDest = $asnDbPath . '.tmp.' . bin2hex(random_bytes(4));
        if (!copy($asnMmdbSrc, $asnTmpDest)) {
            throw new RuntimeException("copy() ASN gagal: {$asnMmdbSrc} → {$asnTmpDest}");
        }
        chmod($asnTmpDest, 0600);
        if (!rename($asnTmpDest, $asnDbPath)) {
            @unlink($asnTmpDest);
            throw new RuntimeException("rename() ASN gagal saat mengganti {$asnDbPath}");
        }

        geoip_log('INFO', 'GeoLite2-ASN.mmdb berhasil diperbarui → ' . $asnDbPath);
    } catch (Throwable $e) {
        // ASN is optional enhancement — don't fail the whole update if it errors.
        geoip_log('ERROR', 'ASN update: ' . $e->getMessage());
    } finally {
        if (is_file($asnTmpTarGz)) {
            @unlink($asnTmpTarGz);
        }
        if (is_file($asnTmpStub)) {
            @unlink($asnTmpStub);
        }
        geoip_rmdir_recursive($asnTmpExtDir);
    }

    $exitCode = 0;
} catch (Throwable $e) {
    geoip_log('ERROR', $e->getMessage());
    $exitCode = 1;
} finally {
    if (is_file($tmpTarGz)) {
        @unlink($tmpTarGz);
    }
    if (is_file($tmpStub)) {
        @unlink($tmpStub);
    }
    geoip_rmdir_recursive($tmpExtDir);
}

exit($exitCode);
