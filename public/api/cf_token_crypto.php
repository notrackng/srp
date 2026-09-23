<?php

/**
 * At-rest encryption for the per-user Cloudflare API token stored in
 * `generate.cf_token`. Uses libsodium secretbox (XSalsa20-Poly1305, authenticated)
 * with a 32-byte key derived from CF_TOKEN_ENC_KEY (64 hex chars in .env).
 *
 * Backward compatible by design — no DB migration required:
 *   - cf_token_decrypt() returns legacy plaintext rows unchanged (rows without the
 *     "enc:v1:" prefix are passed through), so an existing database keeps working.
 *   - cf_token_encrypt() falls back to storing plaintext when the key or the sodium
 *     extension is unavailable, so shipping this code before the operator sets
 *     CF_TOKEN_ENC_KEY never breaks the portal. The degraded condition is logged
 *     once per process so the misconfiguration is visible.
 *
 * Stored ciphertext format:
 *   enc:v1:<base64( nonce(24B) || secretbox_ciphertext )>
 *
 * The `generate.cf_token` column (VARCHAR(500)) is wide enough for the encrypted
 * form of any real Cloudflare token, so no schema change is needed.
 */

declare(strict_types=1);

const CF_TOKEN_ENC_PREFIX = 'enc:v1:';

if (!function_exists('cf_token_crypto_available')) {
    function cf_token_crypto_available(): bool
    {
        return function_exists('sodium_crypto_secretbox')
            && function_exists('sodium_crypto_secretbox_open')
            && defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES')
            && defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES');
    }
}

if (!function_exists('cf_token_crypto_warn')) {
    function cf_token_crypto_warn(string $reason): void
    {
        /** @var array<string, true> $seen */
        static $seen = [];

        if (isset($seen[$reason])) {
            return;
        }

        $seen[$reason] = true;
        error_log('[cf_token_crypto] degraded: ' . $reason);
    }
}

if (!function_exists('cf_token_enc_key')) {
    /**
     * Resolve the raw 32-byte key from CF_TOKEN_ENC_KEY, or null when it is
     * absent/invalid. Reads getenv/$_ENV/$_SERVER so it works regardless of which
     * .env loader populated the environment.
     */
    function cf_token_enc_key(): ?string
    {
        $hex = getenv('CF_TOKEN_ENC_KEY');
        if ($hex === false || $hex === '') {
            $hex = $_ENV['CF_TOKEN_ENC_KEY'] ?? $_SERVER['CF_TOKEN_ENC_KEY'] ?? '';
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

if (!function_exists('cf_token_encrypt')) {
    /**
     * Encrypt a Cloudflare token for storage. Returns '' for empty input. Falls
     * back to returning the plaintext unchanged when encryption is unavailable so
     * the save path never fails hard.
     */
    function cf_token_encrypt(string $plaintext): string
    {
        if ($plaintext === '') {
            return '';
        }

        if (!cf_token_crypto_available()) {
            cf_token_crypto_warn('sodium-unavailable');

            return $plaintext;
        }

        $key = cf_token_enc_key();
        if ($key === null) {
            cf_token_crypto_warn('key-missing-or-invalid');

            return $plaintext;
        }

        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $cipher = sodium_crypto_secretbox($plaintext, $nonce, $key);
        } catch (Throwable $e) {
            cf_token_crypto_warn('encrypt-failed');

            return $plaintext;
        } finally {
            sodium_memzero($key);
        }

        return CF_TOKEN_ENC_PREFIX . base64_encode($nonce . $cipher);
    }
}

if (!function_exists('cf_token_decrypt')) {
    /**
     * Decrypt a stored Cloudflare token. Legacy plaintext (no "enc:v1:" prefix) is
     * returned as-is. Returns '' when a prefixed value cannot be decrypted (wrong
     * key, tampering, unavailable extension) so callers fail closed.
     */
    function cf_token_decrypt(string $stored): string
    {
        if ($stored === '' || !str_starts_with($stored, CF_TOKEN_ENC_PREFIX)) {
            return $stored;
        }

        if (!cf_token_crypto_available()) {
            cf_token_crypto_warn('sodium-unavailable-decrypt');

            return '';
        }

        $key = cf_token_enc_key();
        if ($key === null) {
            cf_token_crypto_warn('key-missing-decrypt');

            return '';
        }

        $blob = base64_decode(substr($stored, strlen(CF_TOKEN_ENC_PREFIX)), true);
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
            cf_token_crypto_warn('decrypt-failed');

            return '';
        }

        return $plain;
    }
}

if (!function_exists('cf_token_mask')) {
    /**
     * Build a display mask (20 bullets + last 4 chars) from a stored token without
     * exposing the leading characters. Returns '' when the token cannot be read.
     */
    function cf_token_mask(string $stored): string
    {
        $plain = cf_token_decrypt($stored);
        $length = strlen($plain);
        if ($length === 0) {
            return '';
        }

        $bullets = str_repeat("\u{2022}", 20);
        $tail = $length >= 4 ? substr($plain, -4) : str_repeat("\u{2022}", $length);

        return $bullets . $tail;
    }
}
