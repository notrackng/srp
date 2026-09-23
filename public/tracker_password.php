<?php

/**
 * Per-tracker (user portal) password helpers.
 *
 * The `generate.password` column historically stored plaintext. These helpers
 * hash new/changed passwords with bcrypt and transparently verify legacy
 * plaintext rows, flagging them for in-place upgrade on the next successful
 * login (zero-downtime migration — no flag day, no lockout).
 */

declare(strict_types=1);

const TRACKER_PASSWORD_COST = 10;

function srp_tracker_password_hash(string $plain): string
{
    return password_hash($plain, PASSWORD_BCRYPT, ['cost' => TRACKER_PASSWORD_COST]);
}

/**
 * True when $stored is already a bcrypt hash (so it must not be re-hashed
 * or compared as plaintext).
 */
function srp_tracker_password_is_hashed(string $stored): bool
{
    return strlen($stored) === 60 && preg_match('/^\$2[aby]\$\d{2}\$/', $stored) === 1;
}

/**
 * Verify a submitted password against the stored value.
 *
 * @return array{ok: bool, needs_rehash: bool} `needs_rehash` is true when the
 *         stored value should be replaced with a fresh bcrypt hash of $input
 *         (legacy plaintext, or an outdated cost factor).
 */
function srp_tracker_password_verify(string $input, string $stored): array
{
    if ($input === '' || $stored === '') {
        return ['ok' => false, 'needs_rehash' => false];
    }

    if (srp_tracker_password_is_hashed($stored)) {
        $ok = password_verify($input, $stored);
        $needsRehash = $ok && password_needs_rehash($stored, PASSWORD_BCRYPT, ['cost' => TRACKER_PASSWORD_COST]);

        return ['ok' => $ok, 'needs_rehash' => $needsRehash];
    }

    // Legacy plaintext row: constant-time compare, upgrade on success.
    $ok = hash_equals($stored, $input);

    return ['ok' => $ok, 'needs_rehash' => $ok];
}
