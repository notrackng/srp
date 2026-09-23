<?php

declare(strict_types=1);

/**
 * Migration 005 — encrypt existing plaintext `generate.cf_token` values at rest.
 *
 * One-off backfill for the at-rest encryption added in public/api/cf_token_crypto.php.
 * The app reads both plaintext (legacy) and ciphertext transparently, so running
 * this is optional — it just converts rows that predate encryption instead of
 * waiting for each user to re-save their Cloudflare token.
 *
 * Safety properties:
 *   - CLI-only: refuses to run over HTTP (it handles secrets).
 *   - Idempotent: rows already stored as "enc:v1:…" are skipped, so re-running is
 *     safe and converges. NULL/empty tokens are ignored.
 *   - Verified writes: every ciphertext is decrypted back and compared to the
 *     original BEFORE the UPDATE. A row is never overwritten with a value that
 *     cannot be read back, so a misconfigured key can only skip, never corrupt.
 *   - Optimistic update: the UPDATE matches the original value, so a token changed
 *     concurrently (user re-saving in the portal) is left untouched.
 *   - No secrets in output: only sub_id identifiers and counts are printed.
 *
 * Preconditions (abort with a clear message if unmet):
 *   - ext-sodium available, and CF_TOKEN_ENC_KEY set to a valid 32-byte hex key.
 *     Without both, encryption would silently fall back to plaintext (a no-op),
 *     so the migration refuses rather than pretend to have encrypted anything.
 *
 * Reverse: forward-only. The app still reads any row this leaves in place. To undo
 * the data change you would need a decrypt-back script (re-exposing plaintext) run
 * with the same key — reverting the app code alone leaves enc:v1: rows unreadable.
 *
 * Usage:  php migrations/005_encrypt_cf_tokens.php [--dry-run]
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("CLI only.\n");
}

$dryRun = in_array('--dry-run', $argv, true);

// Load .env before the precondition checks so CF_TOKEN_ENC_KEY is visible and a
// misconfiguration is reported without first opening a DB connection. Both calls
// are idempotent (load_env_file caches per file), so requiring connection_pdo.php
// afterwards re-runs them harmlessly.
require_once __DIR__ . '/../env.php';
load_env_file(__DIR__ . '/../.env');
require_once __DIR__ . '/../public/api/cf_token_crypto.php';

// --- Preconditions ----------------------------------------------------------
if (!cf_token_crypto_available()) {
    fwrite(STDERR, "ABORT: ext-sodium is not available; cannot encrypt. Enable the sodium extension and retry.\n");
    exit(1);
}

if (cf_token_enc_key() === null) {
    fwrite(STDERR, "ABORT: CF_TOKEN_ENC_KEY is missing or invalid (need 64 hex chars). Set it in .env and retry.\n");
    exit(1);
}

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection_pdo.php';

// --- Load candidate rows ----------------------------------------------------
$select = $pdo->query(
    "SELECT id, sub_id, cf_token
     FROM `generate`
     WHERE cf_token IS NOT NULL AND cf_token <> ''"
);

/** @var array<int, array{id: int, sub_id: string, cf_token: string}> $rows */
$rows = $select !== false ? $select->fetchAll(PDO::FETCH_ASSOC) : [];

$update = $pdo->prepare(
    'UPDATE `generate` SET cf_token = :enc WHERE id = :id AND cf_token = :orig'
);

$scanned = 0;
$alreadyEncrypted = 0;
$converted = 0;
$skippedUnchanged = 0;
/** @var array<int, string> $failures */
$failures = [];

foreach ($rows as $row) {
    $scanned++;
    $id = (int) $row['id'];
    $subId = (string) ($row['sub_id'] ?? '');
    $current = (string) ($row['cf_token'] ?? '');

    // Idempotent: leave anything already in the enc:v1: envelope alone.
    if (str_starts_with($current, CF_TOKEN_ENC_PREFIX)) {
        $alreadyEncrypted++;
        continue;
    }

    $encrypted = cf_token_encrypt($current);

    // Guard against the plaintext-fallback path (would be a silent no-op) and
    // verify we can read the value back before committing it.
    if (!str_starts_with($encrypted, CF_TOKEN_ENC_PREFIX) || cf_token_decrypt($encrypted) !== $current) {
        $failures[] = $subId !== '' ? $subId : ('id#' . $id);
        continue;
    }

    if ($dryRun) {
        $converted++;
        continue;
    }

    // Optimistic: only overwrite if the plaintext is still the exact value we read
    // (a concurrent portal re-save would already be encrypted → matched=0 → skip).
    $update->execute(['enc' => $encrypted, 'id' => $id, 'orig' => $current]);

    if ($update->rowCount() === 1) {
        $converted++;
    } else {
        $skippedUnchanged++;
    }
}

$mode = $dryRun ? 'DRY RUN' : 'DONE';
printf(
    '%s: scanned=%d already_encrypted=%d %s=%d skipped_changed_meanwhile=%d failed=%d%s',
    $mode,
    $scanned,
    $alreadyEncrypted,
    $dryRun ? 'would_convert' : 'converted',
    $converted,
    $skippedUnchanged,
    count($failures),
    PHP_EOL
);

if ($failures !== []) {
    fwrite(
        STDERR,
        'WARN: could not encrypt/verify rows for: ' . implode(', ', $failures)
        . ' (left unchanged — investigate the key/sodium config).' . PHP_EOL
    );
    exit(2);
}
