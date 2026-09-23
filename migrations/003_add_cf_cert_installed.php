<?php

declare(strict_types=1);

/**
 * Migration 003 — add `addondomain.cf_cert_installed`.
 *
 * Durable, per-domain marker that the CF Origin Certificate has been installed.
 * Backs the "auto-install SSL once when a domain first becomes active" feature
 * in public/addondomain/ so the guarantee survives across browsers/sessions
 * (the client-side localStorage guard is only a cache).
 *
 * Idempotent: checks information_schema first and skips if the column already
 * exists. The request path detects the column at runtime, so deploying the app
 * code before running this migration is safe — the feature simply degrades to
 * the client-side guard until the column is present.
 *
 * Usage:  php migrations/003_add_cf_cert_installed.php [--dry-run]
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
$check->execute(['table_name' => 'addondomain', 'column_name' => 'cf_cert_installed']);
$exists = $check->fetchColumn() !== false;

if ($exists) {
    printf('%s: addondomain.cf_cert_installed already present — nothing to do.%s', $dryRun ? 'DRY RUN' : 'DONE', PHP_EOL);

    return;
}

$ddl = 'ALTER TABLE `addondomain`
        ADD COLUMN `cf_cert_installed` TINYINT(1) NOT NULL DEFAULT 0 AFTER `cf_ns`';

if ($dryRun) {
    printf('DRY RUN: would run:%s%s%s', PHP_EOL, $ddl, PHP_EOL);

    return;
}

$pdo->exec($ddl);

printf('DONE: added addondomain.cf_cert_installed (default 0).%s', PHP_EOL);
