<?php

declare(strict_types=1);

require_once __DIR__ . '/../login_throttle.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for login_throttle.php: the per-IP lockout ladder
 * (srp_login_lockout_seconds()) and the file-based failure counter it reads
 * (srp_login_throttle_state()/register_fail()/reset()) shared by every
 * password/token surface in this codebase (admin login, tracker portal,
 * installer token gate, and — since a recent patch — the postback endpoint).
 *
 * Deterministic by construction: REMOTE_ADDR is set to a TEST-NET-3 address
 * (never a Cloudflare range, so forwarded headers are ignored — same
 * reasoning as InternalRateLimitTest), and every counter file this test
 * touches is removed before and after it runs.
 */
final class LoginThrottleTest extends TestCase
{
    /** TEST-NET-3 (RFC 5737) — a peer address that is never a trusted proxy. */
    private const CLIENT_IP = '203.0.113.21';

    private const OTHER_IP = '203.0.113.22';

    private const SCOPE = 'srp_test_scope_a';

    private const OTHER_SCOPE = 'srp_test_scope_b';

    protected function setUp(): void
    {
        $_SERVER['REMOTE_ADDR'] = self::CLIENT_IP;
        unset(
            $_SERVER['HTTP_CF_CONNECTING_IP'],
            $_SERVER['HTTP_TRUE_CLIENT_IP'],
            $_SERVER['HTTP_X_FORWARDED_FOR'],
            $_SERVER['HTTP_X_REAL_IP'],
        );

        $this->resetAll();
    }

    protected function tearDown(): void
    {
        $this->resetAll();
        unset($_SERVER['REMOTE_ADDR']);
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function lockoutLadderProvider(): iterable
    {
        yield 'zero failures -> not locked' => [0, 0];
        yield 'just below first tier' => [4, 0];
        yield 'first tier threshold (5)' => [5, 900];
        yield 'inside first tier' => [7, 900];
        yield 'just below second tier' => [9, 900];
        yield 'second tier threshold (10)' => [10, 1800];
        yield 'well past second tier' => [50, 1800];
    }

    #[DataProvider('lockoutLadderProvider')]
    public function testLockoutLadder(int $fails, int $expectedSeconds): void
    {
        $this->assertSame($expectedSeconds, srp_login_lockout_seconds($fails));
    }

    public function testStateStartsAtZeroWithNoPriorFailures(): void
    {
        $state = srp_login_throttle_state(self::SCOPE);

        $this->assertSame(0, $state['fails']);
        $this->assertSame(0, $state['last']);
    }

    public function testRegisterFailIncrementsCount(): void
    {
        srp_login_throttle_register_fail(self::SCOPE);
        $this->assertSame(1, srp_login_throttle_state(self::SCOPE)['fails']);

        srp_login_throttle_register_fail(self::SCOPE);
        srp_login_throttle_register_fail(self::SCOPE);
        $this->assertSame(3, srp_login_throttle_state(self::SCOPE)['fails']);
    }

    public function testResetClearsFailureCount(): void
    {
        srp_login_throttle_register_fail(self::SCOPE);
        srp_login_throttle_register_fail(self::SCOPE);
        $this->assertSame(2, srp_login_throttle_state(self::SCOPE)['fails']);

        srp_login_throttle_reset(self::SCOPE);

        $this->assertSame(0, srp_login_throttle_state(self::SCOPE)['fails']);
    }

    public function testStateOutsideTheWindowIsTreatedAsNoFailures(): void
    {
        srp_login_throttle_register_fail(self::SCOPE);
        $this->assertSame(1, srp_login_throttle_state(self::SCOPE, 3600)['fails']);

        // Backdate the counter file's timestamp past the window instead of
        // waiting an hour: srp_login_throttle_state() must treat a stale
        // record as zero failures rather than as a permanent lock.
        $this->rewriteCounterTimestamp(self::SCOPE, time() - 7200);

        $state = srp_login_throttle_state(self::SCOPE, 3600);
        $this->assertSame(0, $state['fails']);
        $this->assertSame(0, $state['last']);
    }

    public function testDifferentScopesDoNotShareState(): void
    {
        srp_login_throttle_register_fail(self::SCOPE);
        srp_login_throttle_register_fail(self::SCOPE);

        $this->assertSame(2, srp_login_throttle_state(self::SCOPE)['fails']);
        $this->assertSame(0, srp_login_throttle_state(self::OTHER_SCOPE)['fails'], 'an unrelated scope must start clean');
    }

    public function testDifferentClientIpsDoNotShareState(): void
    {
        $_SERVER['REMOTE_ADDR'] = self::CLIENT_IP;
        srp_login_throttle_register_fail(self::SCOPE);
        srp_login_throttle_register_fail(self::SCOPE);
        $this->assertSame(2, srp_login_throttle_state(self::SCOPE)['fails']);

        $_SERVER['REMOTE_ADDR'] = self::OTHER_IP;
        $this->assertSame(0, srp_login_throttle_state(self::SCOPE)['fails'], 'a different client IP must have its own bucket');
    }

    /**
     * Rewrite the on-disk counter's timestamp directly — same file path
     * srp_login_throttle_file() computes — without going through the public
     * API, which has no way to backdate a record.
     */
    private function rewriteCounterTimestamp(string $scope, int $timestamp): void
    {
        $file = $this->counterFile($scope, self::CLIENT_IP);
        $this->assertFileExists($file, 'expected a counter file to already exist for this scope/IP');

        $data = json_decode((string) file_get_contents($file), true);
        $this->assertIsArray($data);
        $data['t'] = $timestamp;
        file_put_contents($file, json_encode($data));
    }

    private function counterFile(string $scope, string $ip): string
    {
        $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'srp_bb';

        return $dir . DIRECTORY_SEPARATOR . 'lf_' . md5($scope . '|' . $ip) . '.json';
    }

    /**
     * Unconditionally clears every (scope, IP) combination this test class
     * uses, regardless of what $_SERVER['REMOTE_ADDR'] happens to be set to
     * right now — srp_login_throttle_reset() keys off the CURRENT REMOTE_ADDR,
     * so resetting "current + one other" (rather than both fixed IPs by name)
     * silently skips CLIENT_IP's counter whenever a test body's last write
     * left REMOTE_ADDR pointed at OTHER_IP.
     */
    private function resetAll(): void
    {
        $previousIp = $_SERVER['REMOTE_ADDR'] ?? null;

        foreach ([self::CLIENT_IP, self::OTHER_IP] as $ip) {
            $_SERVER['REMOTE_ADDR'] = $ip;
            srp_login_throttle_reset(self::SCOPE);
            srp_login_throttle_reset(self::OTHER_SCOPE);
        }

        if ($previousIp !== null) {
            $_SERVER['REMOTE_ADDR'] = $previousIp;
        } else {
            unset($_SERVER['REMOTE_ADDR']);
        }
    }
}
