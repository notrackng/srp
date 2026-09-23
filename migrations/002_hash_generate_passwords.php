<?php

declare(strict_types=1);

/**
 * Migration 002 — hash existing plaintext `generate.password` rows.
 *
 * bcrypt cannot be expressed in SQL, so this backfill runs in PHP. It is
 * idempotent: rows already stored as a bcrypt hash are skipped. Trackers that
 * log in before this runs are upgraded transparently by public/index.php; this
 * script covers rows that never log in.
 *
 * Usage:  php migrations/002_hash_generate_passwords.php [--dry-run]
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("CLI only.\n");
}

$dryRun = in_array('--dry-run', $argv, true);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection_pdo.php';
require_once __DIR__ . '/../public/tracker_password.php';

$rows = $pdo->query('SELECT id, password FROM generate')->fetchAll(PDO::FETCH_ASSOC);

$update = $pdo->prepare('UPDATE generate SET password = :password WHERE id = :id LIMIT 1');

$total = count($rows);
$hashed = 0;
$skipped = 0;

foreach ($rows as $row) {
    $stored = (string) ($row['password'] ?? '');

    if ($stored === '' || srp_tracker_password_is_hashed($stored)) {
        $skipped++;

        continue;
    }

    if (!$dryRun) {
        $update->execute([
            'password' => srp_tracker_password_hash($stored),
            'id' => (int) $row['id'],
        ]);
    }
    $hashed++;
}

printf(
    "%s: %d rows, %d %s, %d already hashed/empty.%s",
    $dryRun ? 'DRY RUN' : 'DONE',
    $total,
    $hashed,
    $dryRun ? 'would be hashed' : 'hashed',
    $skipped,
    PHP_EOL,
);
