<?php

declare(strict_types=1);

/**
 * Migration 007 - enforce one addon-domain row per sub_domain/domain pair.
 *
 * Run with --dry-run first and take a database backup before applying.
 *
 * Rollback:
 *   ALTER TABLE `addondomain` DROP INDEX `uniq_addondomain_sub_domain_domain`;
 *
 * Duplicate rows are collapsed into the lowest id. Cloudflare metadata from the
 * keeper row is preserved; duplicate rows are removed after the count is shown.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("CLI only.\n");
}

$dryRun = in_array('--dry-run', $argv, true);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection_pdo.php';

$indexStmt = $pdo->prepare(
    'SELECT 1 FROM information_schema.statistics
     WHERE table_schema = DATABASE()
       AND table_name = :table_name
       AND index_name = :index_name
     LIMIT 1',
);
$indexStmt->execute([
    'table_name' => 'addondomain',
    'index_name' => 'uniq_addondomain_sub_domain_domain',
]);
if ($indexStmt->fetchColumn() !== false) {
    printf("%s: unique addon-domain index already present.%s", $dryRun ? 'DRY RUN' : 'DONE', PHP_EOL);
    return;
}

$duplicateGroups = (int) $pdo->query(
    'SELECT COUNT(*) FROM (
        SELECT sub_domain, domain
        FROM addondomain
        GROUP BY sub_domain, domain
        HAVING COUNT(*) > 1
    ) duplicates',
)->fetchColumn();

if ($dryRun) {
    printf('DRY RUN: %d duplicate addon-domain group(s) would be collapsed.%s', $duplicateGroups, PHP_EOL);
    printf("DRY RUN: would add UNIQUE uniq_addondomain_sub_domain_domain (sub_domain, domain).%s", PHP_EOL);
    return;
}

try {
    $pdo->beginTransaction();

    if ($duplicateGroups > 0) {
        $pdo->exec(
            'DELETE duplicate_rows
             FROM addondomain duplicate_rows
             INNER JOIN addondomain keeper
               ON keeper.sub_domain = duplicate_rows.sub_domain
              AND keeper.domain = duplicate_rows.domain
              AND keeper.id < duplicate_rows.id',
        );
    }

    $pdo->exec(
        'ALTER TABLE `addondomain`
         ADD UNIQUE KEY `uniq_addondomain_sub_domain_domain` (`sub_domain`, `domain`)',
    );

    $pdo->commit();
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    fwrite(STDERR, 'MIGRATION 007 FAILED: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

printf('DONE: collapsed %d duplicate group(s); addon-domain uniqueness enforced.%s', $duplicateGroups, PHP_EOL);
