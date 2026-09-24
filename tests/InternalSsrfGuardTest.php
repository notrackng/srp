<?php

declare(strict_types=1);

require_once __DIR__ . '/../redirect/internal/engine.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for the /internal/v1/* SSRF guard.
 *
 * internal_ip_is_forbidden() and internal_url_allowed() gate every server-side
 * fetch the silent cloak makes, so a hole here is a request-forgery primitive.
 * It was previously untested: the logic is a hand-written CIDR table where one
 * wrong hex digit silently widens a range, and the boundary values below are
 * chosen to catch exactly that kind of drift (each range is probed just inside
 * and just outside its edge, not merely at a comfortable midpoint).
 *
 * Everything here is hermetic: no DB, no cache, no DNS. Destinations are IP
 * literals so the resolver branch is never entered, and the offer allowlist is
 * always set explicitly rather than inherited from the environment.
 */
final class InternalSsrfGuardTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('SRP_OFFER_ALLOWED_DOMAINS');
        unset(
            $_ENV['SRP_OFFER_ALLOWED_DOMAINS'],
            $_SERVER['SRP_OFFER_ALLOWED_DOMAINS'],
            $_SERVER['HTTP_HOST'],
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function forbiddenIpProvider(): iterable
    {
        $cases = [
            // 0.0.0.0/8
            '0.0.0.0', '0.1.2.3', '0.255.255.255',
            // 10.0.0.0/8
            '10.0.0.0', '10.255.255.255',
            // 100.64.0.0/10 (CGNAT)
            '100.64.0.0', '100.127.255.255',
            // 127.0.0.0/8 (loopback)
            '127.0.0.1', '127.255.255.255',
            // 169.254.0.0/16 (link-local, incl. the cloud metadata address)
            '169.254.0.1', '169.254.169.254', '169.254.255.255',
            // 172.16.0.0/12
            '172.16.0.0', '172.31.255.255',
            // 192.0.0.0/24 and 192.0.2.0/24
            '192.0.0.1', '192.0.0.255', '192.0.2.1', '192.0.2.255',
            // 192.168.0.0/16
            '192.168.0.0', '192.168.1.1', '192.168.255.255',
            // 198.18.0.0/15 (benchmark)
            '198.18.0.1', '198.19.255.255',
            // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved)
            '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255',
            // IPv6: unspecified, loopback, IPv4-mapped
            '::', '::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1',
            // IPv6: fc00::/7 unique-local, fe80::/10 link-local, ff00::/8 multicast
            'fc00::1', 'fd12:3456:789a::1', 'fe80::1', 'febf::1', 'ff00::1', 'ff02::1',
        ];

        foreach ($cases as $ip) {
            yield $ip => [$ip];
        }
    }

    /**
     * Values immediately outside each reserved range. These are the cells that
     * fail if a mask is off by a single hex digit or a bit short.
     *
     * @return iterable<string, array{string}>
     */
    public static function publicIpProvider(): iterable
    {
        $cases = [
            '9.255.255.255', '11.0.0.0',            // either side of 10.0.0.0/8
            '100.63.255.255', '100.128.0.0',        // either side of 100.64.0.0/10
            '126.255.255.255', '128.0.0.0',         // either side of 127.0.0.0/8
            '169.253.255.255', '169.255.0.0',       // either side of 169.254.0.0/16
            '172.15.255.255', '172.32.0.0',         // either side of 172.16.0.0/12
            '192.0.1.0', '192.0.1.255', '192.0.3.0', // between the two /24s, and past the second
            '192.167.255.255', '192.169.0.0',       // either side of 192.168.0.0/16
            '198.17.255.255', '198.20.0.0',         // either side of 198.18.0.0/15
            '223.255.255.255',                      // last address before multicast
            '1.1.1.1', '8.8.8.8', '93.184.216.34', '199.1.1.1',
            '2001:4860:4860::8888', '2606:4700:4700::1111', '2400:cb00::1',
        ];

        foreach ($cases as $ip) {
            yield $ip => [$ip];
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function nonIpProvider(): iterable
    {
        foreach (['', 'not-an-ip', '999.1.1.1', '1.2.3', 'localhost', '::gg', '10.0.0.256'] as $value) {
            yield var_export($value, true) => [$value];
        }
    }

    #[DataProvider('forbiddenIpProvider')]
    public function testReservedAndPrivateAddressesAreForbidden(string $ip): void
    {
        $this->assertTrue(
            internal_ip_is_forbidden($ip),
            "should be forbidden: $ip",
        );
    }

    #[DataProvider('publicIpProvider')]
    public function testPublicAddressesArePermitted(string $ip): void
    {
        $this->assertFalse(
            internal_ip_is_forbidden($ip),
            "should be permitted: $ip",
        );
    }

    #[DataProvider('nonIpProvider')]
    public function testNonIpInputFailsClosed(string $value): void
    {
        // Anything that is not a valid IP literal is treated as forbidden: an
        // unparseable host must never be assumed safe.
        $this->assertTrue(
            internal_ip_is_forbidden($value),
            'should fail closed: ' . var_export($value, true),
        );
    }

    public function testUrlMustBeHttps(): void
    {
        $this->setAllowlist('93.184.216.34');

        $this->assertTrue(internal_url_allowed('https://93.184.216.34/x'));
        $this->assertFalse(internal_url_allowed('http://93.184.216.34/x'));
        $this->assertFalse(internal_url_allowed('ftp://93.184.216.34/x'));
        $this->assertFalse(internal_url_allowed(''));
        $this->assertFalse(internal_url_allowed('not-a-url'));
    }

    public function testUrlMustUseTheDefaultHttpsPort(): void
    {
        $this->setAllowlist('93.184.216.34');

        // No port, or 443, is fine.
        $this->assertTrue(internal_url_allowed('https://93.184.216.34/x'));
        $this->assertTrue(internal_url_allowed('https://93.184.216.34:443/x'));

        // Any other explicit port is refused rather than probed.
        $this->assertFalse(internal_url_allowed('https://93.184.216.34:8443/x'));
        $this->assertFalse(internal_url_allowed('https://93.184.216.34:80/x'));
        $this->assertFalse(internal_url_allowed('https://93.184.216.34:22/x'));
    }

    public function testUrlLengthCapIsEnforcedAtTheBoundary(): void
    {
        $this->setAllowlist('93.184.216.34');

        $prefix = 'https://93.184.216.34/';
        $atCap = $prefix . str_repeat('a', INTERNAL_URL_MAX - strlen($prefix));
        $overCap = $prefix . str_repeat('a', INTERNAL_URL_MAX - strlen($prefix) + 1);

        $this->assertSame(INTERNAL_URL_MAX, strlen($atCap));
        $this->assertSame(INTERNAL_URL_MAX + 1, strlen($overCap));

        $this->assertTrue(internal_url_allowed($atCap), 'exactly at the cap should pass');
        $this->assertFalse(internal_url_allowed($overCap), 'one over the cap should fail');
    }

    public function testSelfHostAndItsSubdomainsAreRefused(): void
    {
        // A destination on our own host would recurse back into this proxy.
        $_SERVER['HTTP_HOST'] = 'cloak.example';

        $this->assertFalse(internal_url_allowed('https://cloak.example/internal/v1/x'));
        $this->assertFalse(internal_url_allowed('https://sub.cloak.example/x'));

        // Host comparison is case-insensitive.
        $this->assertFalse(internal_url_allowed('https://CLOAK.EXAMPLE/x'));

        // A different host is unaffected. IP literal so no resolver is involved.
        $this->setAllowlist('93.184.216.34');
        $this->assertTrue(internal_url_allowed('https://93.184.216.34/x'));
    }

    public function testPrivateAndLoopbackLiteralsInUrlsAreRefused(): void
    {
        $this->setAllowlist('169.254.169.254,127.0.0.1,10.0.0.1,::1,fd00::1');

        // Even when the allowlist explicitly names them, the SSRF guard wins:
        // the allowlist is defence in depth, not an override.
        $this->assertFalse(internal_url_allowed('https://169.254.169.254/latest/meta-data/'));
        $this->assertFalse(internal_url_allowed('https://127.0.0.1:443/x'));
        $this->assertFalse(internal_url_allowed('https://10.0.0.1/x'));
        $this->assertFalse(internal_url_allowed('https://192.168.1.1/x'));
        $this->assertFalse(internal_url_allowed('https://[::1]/x'));
        $this->assertFalse(internal_url_allowed('https://[fd00::1]/x'));
        $this->assertFalse(internal_url_allowed('https://0.0.0.0/x'));
    }

    public function testAllowlistGovernsPublicDestinations(): void
    {
        $this->setAllowlist('offers.example,ads.example');
        $this->assertFalse(internal_url_allowed('https://93.184.216.34/x'));

        $this->setAllowlist('93.184.216.34');
        $this->assertTrue(internal_url_allowed('https://93.184.216.34/x'));

        // An explicit but unparseable override denies everything, and that denial
        // must reach the SSRF guard rather than falling open.
        $this->setAllowlist(',');
        $this->assertFalse(internal_url_allowed('https://93.184.216.34/x'));
    }

    private function setAllowlist(string $value): void
    {
        putenv('SRP_OFFER_ALLOWED_DOMAINS=' . $value);
        $_ENV['SRP_OFFER_ALLOWED_DOMAINS'] = $value;
        $_SERVER['SRP_OFFER_ALLOWED_DOMAINS'] = $value;
    }
}
