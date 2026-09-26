<?php

/**
 * At-rest encryption for the display-only `generate.password_plain` mirror
 * column (the admin dashboard's show/hide toggle — the bcrypt `password`
 * column, hashed via tracker_password.php, remains the sole value ever used
 * for actual login verification). Same libsodium secretbox pattern as
 * public/api/cf_token_crypto.php, with its own key so the two secrets are
 * never derived from one another and rotating one never affects the other.
 *
 * Backward compatible by design — no DB migration required:
 *   - tracker_password_plain_decrypt() returns legacy plaintext rows unchanged
 *     (rows without the "enc:v1:" prefix pass through), so an existing
 *     database keeps working after this ships.
 *   - tracker_password_plain_encrypt() falls back to storing plaintext when
 *     the key or the sodium extension is unavailable, so shipping this code
 *     before an operator sets TRACKER_PASSWORD_ENC_KEY never breaks the admin
 *     panel. The degraded condition is logged once per process.
 *
 * Stored ciphertext format:
 *   enc:v1:<base64( nonce(24B) || secretbox_ciphertext )>
 */

declare(strict_types=1);

const TRACKER_PASSWORD_PLAIN_ENC_PREFIX = 'enc:v1:';

if (!function_exists('tracker_password_plain_crypto_available')) {
    function tracker_password_plain_crypto_available(): bool
    {
        return function_exists('sodium_crypto_secretbox')
            && function_exists('sodium_crypto_secretbox_open')
            && defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')
            && defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES');
    }
}

if (!function_exists('tracker_password_plain_crypto_warn')) {
    function tracker_password_plain_crypto_warn(string $reason): void
    {
        /** @var array<string, true> $seen */
        static $seen = [];

        if (isset($seen[$reason])) {
            return;
        }

        $seen[$reason] = true;
        error_log('[tracker_password_plain_crypto] degraded: ' . $reason);
    }
}

if (!function_exists('tracker_password_plain_enc_key')) {
    /**
     * Resolve the raw 32-byte key from TRACKER_PASSWORD_ENC_KEY, or null when
     * absent/invalid. Reads getenv/$_ENV/$_SERVER so it works regardless of
     * which .env loader populated the environment.
     */
    function tracker_password_plain_enc_key(): ?string
    {
        $hex = getenv('TRACKER_PASSWORD_ENC_KEY');
        if ($hex === false || $hex === '') {
            $hex = $_ENV['TRACKER_PASSWORD_ENC_KEY'] ?? $_SERVER['TRACKER_PASSWORD_ENC_KEY'] ?? '';
        }

        $hex = is_string($hex) ? trim($hex) : '';
        if ($hex === '' || preg_match('/\A[0-9a-fA-F]{64}\z/', $hex) !== 1) {
            return null;
        }

        $key = hex2bin($hex);
        if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return null;
        }

        return $key;
    }
}

if (!function_exists('tracker_password_plain_encrypt')) {
    /**
     * Encrypt a tracker password for storage in password_plain. Returns '' for
     * empty input. Falls back to returning the plaintext unchanged when
     * encryption is unavailable so the save path never fails hard.
     */
    function tracker_password_plain_encrypt(string $plaintext): string
    {
        if ($plaintext === '') {
            return '';
        }

        if (!tracker_password_plain_crypto_available()) {
            tracker_password_plain_crypto_warn('sodium-unavailable');

            return $plaintext;
        }

        $key = tracker_password_plain_enc_key();
        if ($key === null) {
            tracker_password_plain_crypto_warn('key-missing-or-invalid');

            return $plaintext;
        }

        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
        } catch (Throwable $e) {
            tracker_password_plain_crypto_warn('encrypt-failed');

            return $plaintext;
        } finally {
            sodium_memzero($key);
        }

        return TRACKER_PASSWORD_PLAIN_ENC_PREFIX . base64_encode($nonce . $cipher);
    }
}

if (!function_exists('tracker_password_plain_decrypt')) {
    /**
     * Decrypt a stored password_plain value. Legacy plaintext (no "enc:v1:"
     * prefix) is returned as-is. Returns '' when a prefixed value cannot be
     * decrypted (wrong key, tampering, unavailable extension) so callers fail
     * closed rather than display garbage.
     */
    function tracker_password_plain_decrypt(string $stored): string
    {
        if ($stored === '' || !str_starts_with($stored, TRACKER_PASSWORD_PLAIN_ENC_PREFIX)) {
            return $stored;
        }

        if (!tracker_password_plain_crypto_available()) {
            tracker_password_plain_crypto_warn('sodium-unavailable-decrypt');

            return '';
        }

        $key = tracker_password_plain_enc_key();
        if ($key === null) {
            tracker_password_plain_crypto_warn('key-missing-decrypt');

            return '';
        }

        $blob = base64_decode(substr($stored, strlen(TRACKER_PASSWORD_PLAIN_ENC_PREFIX)), true);
        if (!is_string($blob) || strlen($blob) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            sodium_memzero($key);

            return '';
        }

        $nonce = substr($blob, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = substr($blob, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        try {
            $plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);
        } catch (Throwable $e) {
            $plain = false;
        } finally {
            sodium_memzero($key);
        }

        if (!is_string($plain)) {
            tracker_password_plain_crypto_warn('decrypt-failed');

            return '';
        }

        return $plain;
    }
}
