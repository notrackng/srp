<?php

declare(strict_types=1);

/**
 * Migration 004 — enforce one `clickrecord` row per (click_id, click_date).
 *
 * WHY
 * ----
 * redirect/_meetups/index.php relies on the UPDATE→(rowCount 0)→INSERT pattern
 * inside a transaction, and its comment assumes a concurrent INSERT "would cause
 * a duplicate key error". statistics/postback/index.php's pbUpdateClickRecord
 * also assumes a single row per (click_id, click_date) — it UPDATEs without a
 * LIMIT. But the schema only had a NON-UNIQUE `idx_click_id_date`, so under
 * concurrency two clicks could both INSERT, producing duplicate rows and
 * double-counted leads/payout.
 *
 * WHAT
 * ----
 * 1. Collapse any existing duplicate (click_id, click_date) groups into the
 *    lowest-id row (clicks summed; leads/payout summed numerically).
 * 2. Replace the non-unique `idx_click_id_date` with a UNIQUE key on the same
 *    columns + prefix, so the app's race-safety assumption is actually enforced.
 *
 * LOGIC CHANGE / RISK
 * -------------------
 * - The UNIQUE key uses the same `click_id`(64) prefix as the existing index.
 *   Two click_ids that share the first 64 chars on the same date would now
 *   collide. click_id is an uppercase token [A-Z0-9._:-] (<=128). The DRY RUN
 *   reports any such prefix-collision groups so you can verify none exist before
 *   applying. If the report shows >0 prefix-only collisions, STOP and review.
 * - Duplicate collapse rewrites leads/payout of the keeper row. Take a DB backup
 *   first. The pre-merge state is reported by DRY RUN.
 *
 * ROLLBACK
 * --------
 *   ALTER TABLE `clickrecord` DROP INDEX `uniq_click_id_date`;
 *   ALTER TABLE `clickrecord` ADD KEY `idx_click_id_date` (`click_id`(64), `click_date`);
 *   (Row-merge cannot be auto-undone — restore from the backup taken beforehand.)
 *
 * VERIFY (run before applying)
 * ----------------------------
 *   EXPLAIN SELECT clicks FROM clickrecord WHERE click_id = 'X' AND click_date = '2026-06-25';
 *   -- expect key: idx_click_id_date (before) / uniq_click_id_date (after), type ref.
 *
 * Usage:  php migrations/004_clickrecord_unique_click_date.php [--dry-run]
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("CLI only.\n");
}

$dryRun = in_array('--dry-run', $argv, true);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection_pdo.php';

// Already enforced? (idempotent re-run)
$idx = $pdo->prepare(
    'SELECT 1 FROM information_schema.statistics
     WHERE table_schema = DATABASE()
       AND table_name = :t
       AND index_name = :i
     LIMIT 1'
);
$idx->execute(['t' => 'clickrecord', 'i' => 'uniq_click_id_date']);
if ($idx->fetchColumn() !== false) {
    printf('%s: clickrecord.uniq_click_id_date already present — nothing to do.%s', $dryRun ? 'DRY RUN' : 'DONE', PHP_EOL);

    return;
}

// Duplicate groups on the FULL (click_id, click_date) — these will be merged.
$dupGroups = (int) $pdo->query(
    'SELECT COUNT(*) FROM (
        SELECT click_id, click_date FROM clickrecord
        GROUP BY click_id, click_date HAVING COUNT(*) > 1
     ) d'
)->fetchColumn();

// Prefix-only collisions: distinct full click_ids that share the first 64 chars
// on the same date. These would be WRONGLY merged by a (64)-prefix UNIQUE key.
$prefixCollisions = (int) $pdo->query(
    "SELECT COUNT(*) FROM (
        SELECT LEFT(click_id, 64) AS p, click_date
        FROM clickrecord
        GROUP BY LEFT(click_id, 64), click_date
        HAVING COUNT(DISTINCT click_id) > 1
     ) d"
)->fetchColumn();

if ($dryRun) {
    printf('DRY RUN: %d duplicate (click_id, click_date) group(s) would be merged.%s', $dupGroups, PHP_EOL);
    printf('DRY RUN: %d prefix-only (LEFT 64) collision group(s) detected.%s', $prefixCollisions, PHP_EOL);
    if ($prefixCollisions > 0) {
        printf('DRY RUN: ABORT CONDITION — prefix collisions present; review before applying.%s', PHP_EOL);
    }
    printf('DRY RUN: would then DROP idx_click_id_date and ADD UNIQUE uniq_click_id_date (click_id(64), click_date).%s', PHP_EOL);

    return;
}

if ($prefixCollisions > 0) {
    fwrite(STDERR, sprintf(
        'ABORT: %d prefix-only collision group(s) on LEFT(click_id,64). A (64)-prefix UNIQUE key would merge distinct click_ids. Resolve manually first.%s',
        $prefixCollisions,
        PHP_EOL
    ));
    exit(1);
}

try {
    $pdo->beginTransaction();

    if ($dupGroups > 0) {
        // Merge numeric totals into the lowest-id keeper of each duplicate group.
        $pdo->exec(
            'UPDATE clickrecord k
             JOIN (
                SELECT MIN(id) AS keep_id, click_id, click_date,
                       SUM(clicks)                          AS s_clicks,
                       SUM(CAST(leads  AS DECIMAL(20,2)))   AS s_leads,
                       SUM(CAST(payout AS DECIMAL(20,2)))   AS s_payout
                FROM clickrecord
                GROUP BY click_id, click_date
                HAVING COUNT(*) > 1
             ) a ON k.id = a.keep_id
             SET k.clicks = a.s_clicks,
                 k.leads  = a.s_leads,
                 k.payout = a.s_payout'
        );

        // Delete the non-keeper duplicate rows.
        $pdo->exec(
            'DELETE c FROM clickrecord c
             JOIN (
                SELECT MIN(id) AS keep_id, click_id, click_date
                FROM clickrecord
                GROUP BY click_id, click_date
                HAVING COUNT(*) > 1
             ) a ON c.click_id = a.click_id AND c.click_date = a.click_date
             WHERE c.id <> a.keep_id'
        );
    }

    // Swap the non-unique index for a UNIQUE one on the same columns/prefix.
    $pdo->exec('ALTER TABLE `clickrecord` DROP INDEX `idx_click_id_date`');
    $pdo->exec('ALTER TABLE `clickrecord` ADD UNIQUE KEY `uniq_click_id_date` (`click_id`(64), `click_date`)');

    $pdo->commit();
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    fwrite(STDERR, 'MIGRATION 004 FAILED: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

printf('DONE: merged %d duplicate group(s); clickrecord now UNIQUE on (click_id(64), click_date).%s', $dupGroups, PHP_EOL);
