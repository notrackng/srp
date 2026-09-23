<?php

declare(strict_types=1);

/**
 * Migration 006 — add `leadreport.notified_at`.
 *
 * Cross-device claim marker for the realtime lead notification poller
 * (statistics/realtime/lead.php). When two or more devices/browsers are
 * logged into the same realtime dashboard at once, each one used to fire
 * its own audio/push alert for the same lead independently. This column
 * lets the first poller to see a lead atomically claim it (single UPDATE
 * ... WHERE notified_at IS NULL); every other device still receives the
 * row (so table/data state stays identical everywhere) but is told to
 * stay silent instead of re-alerting.
 *
 * Idempotent: checks information_schema first and skips if the column
 * already exists. The request path detects the column at runtime — see
 * statistics/realtime/lead.php — so deploying the app code before running
 * this migration is safe; the claim just always "succeeds" (every device
 * alerts, today's pre-migration behavior) until the column is present.
 *
 * Usage:  php migrations/006_add_leadreport_notified_at.php [--dry-run]
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("CLI only.\n");
}

$dryRun = in_array('--dry-run', $argv, true);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection_pdo.php';

$check = $pdo->prepare(
    'SELECT 1 FROM information_schema.columns
     WHERE table_schema = DATABASE()
       AND table_name = :table_name
       AND column_name = :column_name
     LIMIT 1'
);
$check->execute(['table_name' => 'leadreport', 'column_name' => 'notified_at']);
$exists = $check->fetchColumn() !== false;

if ($exists) {
    printf('%s: leadreport.notified_at already present — nothing to do.%s', $dryRun ? 'DRY RUN' : 'DONE', PHP_EOL);

    return;
}

$ddl = 'ALTER TABLE `leadreport`
        ADD COLUMN `notified_at` DATETIME NULL DEFAULT NULL AFTER `created_at`';

if ($dryRun) {
    printf('DRY RUN: would run:%s%s%s', PHP_EOL, $ddl, PHP_EOL);

    return;
}

$pdo->exec($ddl);

printf('DONE: added leadreport.notified_at (default NULL).%s', PHP_EOL);
