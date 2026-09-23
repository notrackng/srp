<?php

declare(strict_types=1);

/**
 * Migration 010 — rotate the CF_TOKEN_ENC_KEY used to encrypt `generate.cf_token`.
 *
 * INSTALL.md warns "Jangan rotasi CF_TOKEN_ENC_KEY di deployment hidup" for a
 * reason: cf_token_decrypt() (public/api/cf_token_crypto.php) reads the key
 * straight from .env, so swapping .env's value alone makes every already-
 * stored "enc:v1:…" row undecryptable in place — every user's stored
 * Cloudflare token would silently disappear (cf_token_decrypt() fails closed,
 * returning ''). This migration re-encrypts each row under a new key BEFORE
 * you touch .env, so the swap is safe.
 *
 * Deliberately does not modify public/api/cf_token_crypto.php or read
 * CF_TOKEN_ENC_KEY for the "new" side from .env — it stays a small,
 * self-contained script using explicit key material for both the old key
 * (read from the CURRENT .env, i.e. what every row is encrypted with right
 * now) and the new key (passed in explicitly, never touches .env). The
 * request-path encryption module (already audited, handles real traffic) is
 * left completely untouched by this change.
 *
 * Safety properties (mirrors migrations/005_encrypt_cf_tokens.php):
 *   - CLI-only: refuses to run over HTTP (it handles secrets).
 *   - Idempotent / resumable: a row already re-encrypted under the new key
 *     (from an interrupted previous run) is detected — by trying the new key
 *     when the old key fails to decrypt — and left untouched, not re-migrated
 *     and not reported as a failure.
 *   - Verified writes: every new ciphertext is decrypted back with the new
 *     key and compared to the original plaintext BEFORE the UPDATE. A row is
 *     never overwritten with a value that cannot be read back.
 *   - Optimistic update: the UPDATE matches the original ciphertext, so a
 *     token changed concurrently (user re-saving in the portal mid-migration)
 *     is left untouched rather than clobbered.
 *   - No secrets in output, ever: only sub_id identifiers and counts are
 *     printed. Neither key nor any plaintext/ciphertext token value is
 *     logged or echoed under any circumstance, including on error.
 *
 * Preconditions (abort with a clear message if unmet):
 *   - ext-sodium available.
 *   - CF_TOKEN_ENC_KEY set in .env to a valid 32-byte hex key (the OLD key —
 *     what every row is currently encrypted with).
 *   - --new-key=<64 hex chars> given, or CF_TOKEN_ENC_KEY_NEW set in the
 *     process environment (CLI flag wins if both given). Generate one with:
 *       php -r "echo bin2hex(random_bytes(32));"
 *   - The new key must differ from the old key.
 *
 * Deploy sequence:
 *   1. Generate a new key; do NOT put it in .env yet.
 *   2. php migrations/010_rotate_cf_token_enc_key.php --new-key=<new> --dry-run
 *   3. php migrations/010_rotate_cf_token_enc_key.php --new-key=<new>
 *   4. Only once that reports 0 failures: set CF_TOKEN_ENC_KEY in .env to the
 *      new key. Not before — the app is still reading the OLD key from .env
 *      throughout steps 2-3, and every row this migration touches remains
 *      correctly decryptable under the old key until you flip it in step 4.
 *
 * Reverse: forward-only in the sense that step 4 is a separate, manual,
 * one-line .env edit — reverting it (restoring the old key value) makes the
 * app decrypt correctly again immediately, since this migration re-encrypts
 * every row, it does not delete the old key material anywhere.
 *
 * Usage:
 *   php migrations/010_rotate_cf_token_enc_key.php --new-key=<64hex> [--dry-run]
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("CLI only.\n");
}

$dryRun = in_array('--dry-run', $argv, true);

require_once __DIR__ . '/../env.php';
load_env_file(__DIR__ . '/../.env');
require_once __DIR__ . '/../public/api/cf_token_crypto.php';

// --- Resolve the new key (explicit only — never read from .env) -------------
$newKeyHex = null;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--new-key=')) {
        $newKeyHex = substr($arg, strlen('--new-key='));
        break;
    }
}
if ($newKeyHex === null) {
    $envNewKey = getenv('CF_TOKEN_ENC_KEY_NEW');
    $newKeyHex = $envNewKey !== false && $envNewKey !== '' ? $envNewKey : null;
}

// --- Preconditions ------------------------------------------------------------
if (!cf_token_crypto_available()) {
    fwrite(STDERR, "ABORT: ext-sodium is not available; cannot decrypt/re-encrypt. Enable the sodium extension and retry.\n");
    exit(1);
}

$oldKeyRaw = cf_token_enc_key();
if ($oldKeyRaw === null) {
    fwrite(STDERR, "ABORT: CF_TOKEN_ENC_KEY (the current/old key) is missing or invalid in .env (need 64 hex chars).\n");
    exit(1);
}

if ($newKeyHex === null || trim($newKeyHex) === '') {
    fwrite(STDERR, "ABORT: no new key given. Pass --new-key=<64hex> or set CF_TOKEN_ENC_KEY_NEW in the environment.\n");
    fwrite(STDERR, "Generate one with:  php -r \"echo bin2hex(random_bytes(32));\"\n");
    exit(1);
}
$newKeyHex = trim($newKeyHex);
if (preg_match('/\A[0-9a-fA-F]{64}\z/', $newKeyHex) !== 1) {
    fwrite(STDERR, "ABORT: --new-key must be exactly 64 hex characters (32 bytes).\n");
    exit(1);
}
$newKeyRaw = hex2bin($newKeyHex);
if (!is_string($newKeyRaw) || strlen($newKeyRaw) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
    fwrite(STDERR, "ABORT: new key did not decode to a valid secretbox key.\n");
    exit(1);
}

if (hash_equals($oldKeyRaw, $newKeyRaw)) {
    fwrite(STDERR, "ABORT: the new key is identical to the current CF_TOKEN_ENC_KEY in .env — nothing to rotate.\n");
    sodium_memzero($oldKeyRaw);
    sodium_memzero($newKeyRaw);
    exit(1);
}

// --- Local decrypt/encrypt with an explicit key (mirrors cf_token_crypto.php's
// --- secretbox logic exactly, but parameterized on $key instead of reading
// --- CF_TOKEN_ENC_KEY from the environment — that file is intentionally left
// --- untouched by this migration). -------------------------------------------
function migration010Decrypt(string $stored, string $key): ?string
{
    if (!str_starts_with($stored, CF_TOKEN_ENC_PREFIX)) {
        return null;
    }

    $blob = base64_decode(substr($stored, strlen(CF_TOKEN_ENC_PREFIX)), true);
    if (!is_string($blob) || strlen($blob) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        return null;
    }

    $nonce = substr($blob, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = substr($blob, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    try {
        $plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);
    } catch (Throwable $e) {
        return null;
    }

    return is_string($plain) ? $plain : null;
}

function migration010Encrypt(string $plaintext, string $key): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);

    return CF_TOKEN_ENC_PREFIX . base64_encode($nonce . $cipher);
}

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection_pdo.php';

// --- Load candidate rows ------------------------------------------------------
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
$legacyPlaintext = 0;
$alreadyOnNewKey = 0;
$rotated = 0;
$skippedChangedMeanwhile = 0;
/** @var array<int, string> $failures */
$failures = [];

foreach ($rows as $row) {
    $scanned++;
    $id = (int) $row['id'];
    $subId = (string) ($row['sub_id'] ?? '');
    $current = (string) ($row['cf_token'] ?? '');
    $label = $subId !== '' ? $subId : ('id#' . $id);

    // Not encrypted at all (legacy plaintext row, or one that predates
    // migration 005 running) — nothing for a key rotation to do here.
    if (!str_starts_with($current, CF_TOKEN_ENC_PREFIX)) {
        $legacyPlaintext++;
        continue;
    }

    $plaintext = migration010Decrypt($current, $oldKeyRaw);

    if ($plaintext === null) {
        // Old key didn't work. Before calling this a failure, check whether
        // it's already on the new key — from an interrupted previous run of
        // this same migration — in which case there is nothing to do.
        $alreadyMigrated = migration010Decrypt($current, $newKeyRaw);
        if ($alreadyMigrated !== null) {
            $alreadyOnNewKey++;
            continue;
        }

        $failures[] = $label;
        continue;
    }

    $reEncrypted = migration010Encrypt($plaintext, $newKeyRaw);

    // Verify-before-write: decrypt the value we are about to store, with the
    // new key, and confirm it matches the plaintext we started with.
    if (migration010Decrypt($reEncrypted, $newKeyRaw) !== $plaintext) {
        $failures[] = $label;
        $plaintext = '';
        continue;
    }
    $plaintext = '';

    if ($dryRun) {
        $rotated++;
        continue;
    }

    // Optimistic: only overwrite if the ciphertext is still the exact value
    // we read (a concurrent portal re-save would already differ → matched=0).
    $update->execute(['enc' => $reEncrypted, 'id' => $id, 'orig' => $current]);

    if ($update->rowCount() === 1) {
        $rotated++;
    } else {
        $skippedChangedMeanwhile++;
    }
}

sodium_memzero($oldKeyRaw);
sodium_memzero($newKeyRaw);

$mode = $dryRun ? 'DRY RUN' : 'DONE';
printf(
    '%s: scanned=%d legacy_plaintext=%d already_on_new_key=%d %s=%d skipped_changed_meanwhile=%d failed=%d%s',
    $mode,
    $scanned,
    $legacyPlaintext,
    $alreadyOnNewKey,
    $dryRun ? 'would_rotate' : 'rotated',
    $rotated,
    $skippedChangedMeanwhile,
    count($failures),
    PHP_EOL
);

if ($failures !== []) {
    fwrite(
        STDERR,
        'WARN: could not decrypt/verify rows for: ' . implode(', ', $failures)
        . ' (left unchanged — investigate before proceeding; do NOT update .env until this is 0).' . PHP_EOL
    );
    exit(2);
}

if (!$dryRun && $failures === []) {
    fwrite(STDERR, "\nAll rows migrated successfully. You may now set CF_TOKEN_ENC_KEY in .env to the new key.\n");
}
