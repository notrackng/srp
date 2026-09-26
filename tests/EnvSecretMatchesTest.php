<?php

declare(strict_types=1);

require_once __DIR__ . '/../env.php';

use PHPUnit\Framework\TestCase;

/**
 * Tests for env.php's srp_env_secret_matches() (the shared "_HASH-or-plain"
 * secret comparator behind every configurable password: ADMIN_PASSWORD,
 * A2ROOT_PASSWORD, ENV_EDITOR_PASSWORD, RD_PASSWORD) and app_required_env()
 * (the fail-closed required-config guard used throughout the codebase).
 *
 * Deterministic by construction: uses a private, uniquely-prefixed env key so
 * it can never collide with a real secret name, and every test clears all
 * three environment sources (getenv/$_ENV/$_SERVER) in tearDown.
 */
final class EnvSecretMatchesTest extends TestCase
{
    private const KEY = 'SRP_TEST_ENV_SECRET_MATCHES_KEY';

    protected function tearDown(): void
    {
        $this->clearEnv(self::KEY);
        $this->clearEnv(self::KEY . '_HASH');
    }

    public function testFailsClosedWhenNothingConfigured(): void
    {
        $this->assertFalse(srp_env_secret_matches(self::KEY, ''));
        $this->assertFalse(srp_env_secret_matches(self::KEY, 'anything'));
    }

    public function testFailsClosedOnEmptyCandidateEvenIfConfigured(): void
    {
        $this->setEnv(self::KEY, 'correct-horse-battery-staple');

        $this->assertFalse(srp_env_secret_matches(self::KEY, ''));
    }

    public function testPlainSecretMatchesExactCandidateOnly(): void
    {
        $this->setEnv(self::KEY, 'correct-horse-battery-staple');

        $this->assertTrue(srp_env_secret_matches(self::KEY, 'correct-horse-battery-staple'));
        $this->assertFalse(srp_env_secret_matches(self::KEY, 'wrong-guess'));
        $this->assertFalse(srp_env_secret_matches(self::KEY, 'correct-horse-battery-staplE'));
    }

    public function testBcryptHashVerifiesCorrectAndIncorrectCandidates(): void
    {
        $hash = password_hash('my-real-password', PASSWORD_BCRYPT);
        $this->setEnv(self::KEY . '_HASH', $hash);

        $this->assertTrue(srp_env_secret_matches(self::KEY, 'my-real-password'));
        $this->assertFalse(srp_env_secret_matches(self::KEY, 'not-the-password'));
    }

    public function testArgon2HashVerifiesCorrectCandidate(): void
    {
        if (!defined('PASSWORD_ARGON2I') && !defined('PASSWORD_ARGON2ID')) {
            self::markTestSkipped('No argon2 password algorithm available in this PHP build.');
        }

        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_ARGON2I;
        $hash = password_hash('my-real-password', $algo);
        $this->setEnv(self::KEY . '_HASH', $hash);

        $this->assertTrue(srp_env_secret_matches(self::KEY, 'my-real-password'));
        $this->assertFalse(srp_env_secret_matches(self::KEY, 'not-the-password'));
    }

    public function testHashTakesPriorityOverPlainWhenBothConfigured(): void
    {
        // A deployment mid-migration to the _HASH form (or one where an
        // operator set both by mistake) must not fall back to comparing the
        // plaintext candidate against the stale plain value once a hash is
        // present — the hash is the source of truth.
        $this->setEnv(self::KEY, 'stale-plaintext-value');
        $this->setEnv(self::KEY . '_HASH', password_hash('current-password', PASSWORD_BCRYPT));

        $this->assertTrue(srp_env_secret_matches(self::KEY, 'current-password'));
        $this->assertFalse(srp_env_secret_matches(self::KEY, 'stale-plaintext-value'));
    }

    public function testRequiredEnvThrowsWhenMissing(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Missing required environment variable: ' . self::KEY);

        app_required_env(self::KEY);
    }

    public function testRequiredEnvThrowsWhenSetToEmptyString(): void
    {
        $this->setEnv(self::KEY, '');

        $this->expectException(RuntimeException::class);

        app_required_env(self::KEY);
    }

    public function testRequiredEnvReturnsValueWhenSet(): void
    {
        $this->setEnv(self::KEY, 'some-config-value');

        $this->assertSame('some-config-value', app_required_env(self::KEY));
    }

    private function setEnv(string $key, string $value): void
    {
        putenv($key . '=' . $value);
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
    }

    private function clearEnv(string $key): void
    {
        putenv($key);
        unset($_ENV[$key], $_SERVER[$key]);
    }
}
