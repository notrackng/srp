<?php

declare(strict_types=1);

require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../redirect_payload.php';
require_once __DIR__ . '/../sanitize.php';

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection.config.php';

$redirectPayload = srp_redirect_payload_decode($_GET['rk'] ?? null);

if ($redirectPayload === null) {
    meetup_fail(400);
}

$clickId = meetup_sanitize_token($redirectPayload['click_id'], 128);
$countryCode = meetup_sanitize_country_code($redirectPayload['country_code']);
$deviceType = meetup_sanitize_token($redirectPayload['device_type'], 32);
$ipAddress = meetup_sanitize_ip($redirectPayload['ip_address']);
$userLp = meetup_sanitize_token($redirectPayload['user_lp'], 64);

if ($clickId === null || $countryCode === null || $deviceType === null || $userLp === null) {
    meetup_fail(400);
}

// Country block for the click-through.
//
// ../index.php deliberately exempts landing-mode links from the country block so
// the landing page renders everywhere. This is the second gate: a blocked country
// may see the landing page, but pressing YES sends it to SRP_BLOCK_URL instead of
// the offer. Direct-mode links from a blocked country never reach this file at
// all — they are already stopped upstream.
//
// Placed before the dedup/click write on purpose: blocked traffic must not
// inflate clickrecord or the daily click log, since it never sees an offer.
if (in_array(strtoupper($countryCode), meetup_blocked_countries(), true)) {
    header('Location: ' . meetup_block_url(), true, 302);
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Referrer-Policy: no-referrer');
    exit;
}

$recordUrl = strtoupper($clickId);
$clickDate = gmdate('Y-m-d'); // UTC: canonical clock for clickrecord.click_date (matches statistics/postback conversion_date and every reader)
$redirectToken = srp_redirect_payload_encode(
    $recordUrl,
    strtolower($countryCode),
    strtolower($deviceType),
    $ipAddress,
    strtolower($userLp),
);

// Dedup & cache directory
$dedupTtl  = 300; // 5 minutes
$dedupDir  = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
    . DIRECTORY_SEPARATOR . (defined('SRP_CACHE_DIR_NAME') ? SRP_CACHE_DIR_NAME : 'srp_bb');

// Lazy cache cleanup — sweep stale files ~1% of requests.
// Avoids unbounded disk growth even without cron.
if (random_int(0, 99) === 0) {
    meetup_sweep_cache($dedupDir);
}

try {
    // Verified once, before either the replay check or the marker write below:
    // a predictable path under sys_get_temp_dir() can be pre-created (as a
    // world-writable directory, or a symlink) by another local user/process on
    // a shared host. When it can't be verified private, dedup is skipped for
    // this request rather than trusted — worst case is an extra click counted,
    // never a poisoned marker trusted or written through.
    $dedupDirSafe = srp_ensure_private_dir($dedupDir);

    // Dedup: skip click increment if same click_id+date+ip seen within 5 min.
    // Prevents accidental replay (bot re-crawl, refresh) and deliberate spam.
    $dedupKey  = 'click_' . md5($recordUrl . $clickDate . $ipAddress);
    $dedupFile = $dedupDir . DIRECTORY_SEPARATOR . $dedupKey . '.json';
    $isReplay  = $dedupDirSafe && !is_link($dedupFile)
        && is_file($dedupFile) && filemtime($dedupFile) > (time() - $dedupTtl);

    if (!$isReplay) {
        // clickrecord is provisioned by the installer (schema.sql); the previous
        // per-click information_schema existence probe was removed from this hot
        // path. A missing table now surfaces as a PDOException below → caught →
        // meetup_fail(500), the same client-visible outcome as before.
        $generateStatement = $pdo->prepare('SELECT 1 FROM generate WHERE sub_id = :sub_id LIMIT 1');
        $generateStatement->execute(['sub_id' => $recordUrl]);

        if ($generateStatement->fetchColumn() === false) {
            error_log('[srp] click_id not found in generate: ' . $recordUrl);
            meetup_fail(404);
        }

        // Wrap UPDATE + INSERT in a transaction to prevent concurrent requests from
        // both seeing rowCount=0 and racing to INSERT, which would cause a duplicate key error.
        $pdo->beginTransaction();

        $updateStatement = $pdo->prepare(
            'UPDATE clickrecord SET clicks = clicks + 1 WHERE click_id = :click_id AND click_date = :click_date',
        );
        $updateStatement->execute([
            'click_id' => $recordUrl,
            'click_date' => $clickDate,
        ]);

        if ($updateStatement->rowCount() === 0) {
            $insertStatement = $pdo->prepare(
                'INSERT INTO clickrecord (click_id, clicks, leads, payout, click_date) '
                . 'VALUES (:click_id, 1, :leads, :payout, :click_date)',
            );
            $insertStatement->execute([
                'click_id' => $recordUrl,
                'leads' => '0',
                'payout' => '0',
                'click_date' => $clickDate,
            ]);
        }

        $pdo->commit();

        // Persist dedup marker
        if ($dedupDirSafe && !is_link($dedupFile)) {
            @touch($dedupFile);
        }
    }
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        try {
            $pdo->rollBack();
        } catch (Throwable) {
            // rollback failed — connection may be dead
        }
    }
    error_log('Meetup click pipeline failed: ' . $e->getMessage());
    meetup_fail(500);
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Location: /_meetups/r.php?rk=' . rawurlencode($redirectToken), true, 302);
exit;

/**
 * Remove cache files older than $ttlSeconds from the SRP cache directory.
 * Called probabilistically (~1% of requests) for self-healing without cron.
 */
function meetup_sweep_cache(string $cacheDir, int $ttlSeconds = 86400): void
{
    if (!is_dir($cacheDir)) {
        return;
    }

    $files = @scandir($cacheDir);
    if (!is_array($files)) {
        return;
    }

    $cutoff = time() - $ttlSeconds;
    $scanned = 0;
    $maxScan = 200; // cap per-sweep to bound I/O on shared hosting

    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }

        $path = $cacheDir . DIRECTORY_SEPARATOR . $file;

        if (!is_file($path)) {
            continue;
        }

        $scanned++;
        if ($scanned > $maxScan) {
            break;
        }

        $mtime = @filemtime($path);
        if ($mtime === false || $mtime >= $cutoff) {
            continue;
        }

        @unlink($path);
    }
}

function meetup_fail(int $statusCode): never
{
    http_response_code($statusCode);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    exit;
}
