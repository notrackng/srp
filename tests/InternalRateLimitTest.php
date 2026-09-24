<?php

declare(strict_types=1);

require_once __DIR__ . '/../redirect/internal/engine.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the /internal/v1/* request throttle.
 *
 * The limiter is fixed-window per client IP, keyed by the window index, and
 * fail-open by contract — so the cases worth pinning are: it actually trips
 * above the ceiling, it never trips below it, it disables cleanly at 0, it
 * cannot be bypassed by forging a client-IP header, and one client cannot
 * consume another's budget.
 *
 * Deterministic by construction: REMOTE_ADDR is set to a TEST-NET-3 address
 * (never a Cloudflare range, so forwarded headers are ignored), and the
 * counter files this test touches are removed before and after it runs.
 */
final class InternalRateLimitTest extends TestCase
{
    /** TEST-NET-3 (RFC 5737) — a peer address that is never a trusted proxy. */
    private const CLIENT_IP = '203.0.113.9';

    /** A second distinct client, for the per-identity isolation case. */
    private const OTHER_IP = '203.0.113.77';

    private const PREFIX = 'rl_int_';

    protected function setUp(): void
    {
        $this->setRatePerMin('300');
        $this->setClientIp(self::CLIENT_IP);
        $this->clearCounters(self::CLIENT_IP, self::OTHER_IP);
    }

    protected function tearDown(): void
    {
        $this->clearCounters(self::CLIENT_IP, self::OTHER_IP);

        putenv('INTERNAL_RATE_PER_MIN');
        unset(
            $_ENV['INTERNAL_RATE_PER_MIN'],
            $_SERVER['INTERNAL_RATE_PER_MIN'],
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_CF_CONNECTING_IP'],
            $_SERVER['HTTP_TRUE_CLIENT_IP'],
            $_SERVER['HTTP_X_FORWARDED_FOR'],
            $_SERVER['HTTP_X_REAL_IP'],
        );
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function ratePerMinProvider(): iterable
    {
        yield 'plain number' => ['150', 150];
        yield 'padded number' => [' 45 ', 45];
        yield 'zero disables' => ['0', 0];
        yield 'negative clamps to zero' => ['-5', 0];
        yield 'non-numeric falls back' => ['abc', 300];
        yield 'empty falls back' => ['', 300];
    }

    #[DataProvider('ratePerMinProvider')]
    public function testRatePerMinParsing(string $value, int $expected): void
    {
        $this->setRatePerMin($value);

        $this->assertSame($expected, internal_rate_per_min());
    }

    public function testRatePerMinDefaultsWhenUnset(): void
    {
        putenv('INTERNAL_RATE_PER_MIN');
        unset($_ENV['INTERNAL_RATE_PER_MIN'], $_SERVER['INTERNAL_RATE_PER_MIN']);

        $this->assertSame(300, internal_rate_per_min());
    }

    public function testDisabledLimitNeverThrottles(): void
    {
        $this->setRatePerMin('0');

        for ($i = 0; $i < 50; $i++) {
            $this->assertFalse(internal_rate_exceeded(), "call $i should pass while disabled");
        }
    }

    public function testRequestsAboveTheCeilingAreThrottled(): void
    {
        $this->setRatePerMin('3');
        $this->clearCounters(self::CLIENT_IP);

        // The ceiling is inclusive: three requests pass, the fourth does not.
        for ($i = 1; $i <= 3; $i++) {
            $this->assertFalse(internal_rate_exceeded(), "request $i is within the ceiling");
        }

        $this->assertTrue(internal_rate_exceeded(), 'request 4 is over the ceiling');
    }

    public function testUnidentifiableClientIsNeverThrottled(): void
    {
        $this->setRatePerMin('1');
        $_SERVER['REMOTE_ADDR'] = 'not-an-ip';

        // Fail-open: with no usable client identity every request is allowed,
        // because throttling a bucket that cannot be attributed would punish
        // unrelated visitors sharing it.
        for ($i = 0; $i < 5; $i++) {
            $this->assertFalse(internal_rate_exceeded(), "call $i should fail open");
        }
    }

    public function testForwardedClientHeaderIsIgnoredFromAnUntrustedPeer(): void
    {
        // REMOTE_ADDR is the only unforgeable signal; the limiter keys on it, so
        // a forged CF-Connecting-IP must not be usable to rotate identities and
        // escape the bucket.
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.5';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.6';

        $this->assertSame(self::CLIENT_IP, getUserIP());
    }

    public function testCountersAreIsolatedPerClientIdentity(): void
    {
        $this->setRatePerMin('1');

        $this->setClientIp(self::CLIENT_IP);
        $this->clearCounters(self::CLIENT_IP, self::OTHER_IP);
        $this->assertFalse(internal_rate_exceeded());
        $this->assertTrue(internal_rate_exceeded(), 'first client is now over its ceiling');

        // A different client starts with a fresh bucket rather than inheriting
        // the exhausted one — one visitor cannot lock out another.
        $this->setClientIp(self::OTHER_IP);
        $this->assertFalse(internal_rate_exceeded(), 'second client has its own budget');
    }

    private function setRatePerMin(string $value): void
    {
        putenv('INTERNAL_RATE_PER_MIN=' . $value);
        $_ENV['INTERNAL_RATE_PER_MIN'] = $value;
        $_SERVER['INTERNAL_RATE_PER_MIN'] = $value;
    }

    private function setClientIp(string $ip): void
    {
        $_SERVER['REMOTE_ADDR'] = $ip;
        unset(
            $_SERVER['HTTP_CF_CONNECTING_IP'],
            $_SERVER['HTTP_TRUE_CLIENT_IP'],
            $_SERVER['HTTP_X_FORWARDED_FOR'],
            $_SERVER['HTTP_X_REAL_IP'],
        );
    }

    /**
     * Remove the counter for the current window and the previous one, so a run
     * that straddles a minute boundary cannot inherit a partial count.
     */
    private function clearCounters(string ...$ips): void
    {
        $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
            . (defined('SRP_CACHE_DIR_NAME') ? SRP_CACHE_DIR_NAME : 'srp_bb');

        foreach ($ips as $ip) {
            foreach ([(int) (time() / 60), (int) (time() / 60) - 1] as $window) {
                @unlink($dir . DIRECTORY_SEPARATOR . self::PREFIX . md5($ip . '|' . $window) . '.json');
            }
        }
    }
}
