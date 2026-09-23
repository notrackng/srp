<?php

/**
 * CLI-only: re-sync Cloudflare zone settings for every addon domain that
 * already has a linked zone. Applies cfApplyAllRecommended() — HSTS, Auto
 * Minify, Brotli, Early Hints, and (when CF_APPLY_PAID_FEATURES=1) Mirage /
 * Polish / Image Resizing / Speed Brain — the same call the admin panel's
 * "Sync All CF" button makes per row, just for the whole table in one run.
 *
 * security_level is set to cfApplySettings()'s baseline ('medium') on every
 * call, same as the admin panel's per-row sync. cfProvisionAddonDomainZone()
 * no longer force-overrides it to Under Attack Mode — that used to challenge
 * every visitor on every synced domain and silently revert any manual
 * downgrade on the next sync. Use the admin panel's SSL mode action (or
 * cfSetSecurityLevel() directly) for a deliberate, one-off incident response.
 *
 * Usage:
 *   php public/addondomain/sync-all-cf.php --dry-run   # list domains, no API calls
 *   php public/addondomain/sync-all-cf.php             # actually sync
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("CLI only.\n");
}

$dryRun = in_array('--dry-run', $argv, true);

// Include cf.php for its functions/$pdo without running its HTTP router —
// the same reuse hook cf.php already exposes for this purpose.
define('ADDON_CF_NO_ROUTER', true);
require __DIR__ . '/cf.php';

/** @var PDO $pdo */
cfRequireAddonDomainSchema($pdo);

$stmt = $pdo->query(
    "SELECT id, domain FROM addondomain WHERE cf_zone_id IS NOT NULL AND cf_zone_id <> '' ORDER BY id ASC",
);
$rows = $stmt !== false ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];

$total = count($rows);
printf('%s: %d domain(s) with an existing Cloudflare zone found.%s', $dryRun ? 'DRY RUN' : 'SYNC', $total, PHP_EOL);

if ($total === 0) {
    exit(0);
}

if ($dryRun) {
    foreach ($rows as $row) {
        printf('  - #%d %s%s', (int) $row['id'], (string) $row['domain'], PHP_EOL);
    }

    exit(0);
}

$okCount     = 0;
$failedCount = 0;

foreach ($rows as $row) {
    $id     = (int) $row['id'];
    $domain = (string) $row['domain'];

    $result = cfProvisionAddonDomainZone($pdo, $id);

    if (!empty($result['ok'])) {
        $okCount++;
        $warnings = (int) ($result['cf_warnings'] ?? 0);
        printf('OK   #%d %s%s%s', $id, $domain, $warnings > 0 ? " ({$warnings} warning(s) — see error_log)" : '', PHP_EOL);
    } else {
        $failedCount++;
        printf('FAIL #%d %s -- %s%s', $id, $domain, (string) ($result['err'] ?? 'unknown'), PHP_EOL);
    }

    // Be polite to the Cloudflare API across many zones in one run.
    usleep(300000);
}

printf('DONE: %d ok, %d failed, %d total.%s', $okCount, $failedCount, $total, PHP_EOL);

exit($failedCount > 0 ? 1 : 0);
