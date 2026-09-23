<?php

declare(strict_types=1);

/**
 * Migration 009 — add `generate.block_vpn_asn`.
 *
 * Per-tracker default for the portal's "Block VPN / proxy / datacenter
 * (blocked-ASN) traffic" toggle. The generate API bakes the flag into every
 * generated link, so a tracker can pin the block ON/OFF independently of the
 * global redirect-decision toggle. Default 1 (block, fail-closed).
 *
 * Idempotent: checks information_schema first and skips if the column already
 * exists. public/index.php reads the column defensively, so deploying the app
 * code before running this migration is safe — the portal simply falls back to
 * ON until the column is present.
 *
 * Usage:  php migrations/009_add_generate_block_vpn_asn.php [--dry-run]
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
$check->execute(['table_name' => 'generate', 'column_name' => 'block_vpn_asn']);
$exists = $check->fetchColumn() !== false;

if ($exists) {
    printf('%s: generate.block_vpn_asn already present — nothing to do.%s', $dryRun ? 'DRY RUN' : 'DONE', PHP_EOL);

    return;
}

$ddl = 'ALTER TABLE `generate`
        ADD COLUMN `block_vpn_asn` TINYINT(1) NOT NULL DEFAULT 1 AFTER `cf_account_id`';

if ($dryRun) {
    printf('DRY RUN: would run:%s%s%s', PHP_EOL, $ddl, PHP_EOL);

    return;
}

$pdo->exec($ddl);

printf('DONE: added generate.block_vpn_asn (default 1).%s', PHP_EOL);
