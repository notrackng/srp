<?php

declare(strict_types=1);

require_once __DIR__ . '/../redirect/internal/engine.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the /internal/v1/* cloak's SSRF guard: internal_ip_is_forbidden()
 * (IPv4 + IPv6 private/loopback/link-local/reserved detection) and
 * internal_url_allowed() (the destination validator built on top of it).
 *
 * Deterministic by construction: no case here depends on a real DNS lookup.
 * internal_url_allowed() only resolves DNS for hostname destinations; every
 * case that exercises the SSRF/IP branch uses an IP-literal host instead, so
 * the hostname + dns_get_record() plumbing is exercised by production traffic
 * but intentionally left untested here rather than made to depend on network
 * access in CI.
 */
final class InternalSsrfGuardTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('SRP_OFFER_ALLOWED_DOMAINS');
        unset($_ENV['SRP_OFFER_ALLOWED_DOMAINS'], $_SERVER['HTTP_HOST']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function forbiddenIpProvider(): iterable
    {
        yield 'IPv4 unspecified' => ['0.0.0.0'];
        yield 'IPv4 10/8' => ['10.1.2.3'];
        yield 'IPv4 10/8 broadcast edge' => ['10.255.255.255'];
        yield 'IPv4 CGNAT 100.64/10 start' => ['100.64.0.0'];
        yield 'IPv4 CGNAT 100.64/10 end' => ['100.127.255.255'];
        yield 'IPv4 loopback' => ['127.0.0.1'];
        yield 'IPv4 link-local' => ['169.254.1.1'];
        yield 'IPv4 172.16/12 start' => ['172.16.0.0'];
        yield 'IPv4 172.16/12 end' => ['172.31.255.255'];
        yield 'IPv4 192.0.0.0/24' => ['192.0.0.1'];
        yield 'IPv4 TEST-NET-1 192.0.2.0/24' => ['192.0.2.55'];
        yield 'IPv4 192.168/16' => ['192.168.1.1'];
        yield 'IPv4 benchmark 198.18/15' => ['198.19.255.255'];
        yield 'IPv4 multicast' => ['224.0.0.1'];
        yield 'IPv4 reserved 240/4' => ['240.0.0.1'];
        yield 'IPv4 broadcast' => ['255.255.255.255'];
        yield 'IPv6 unspecified' => ['::'];
        yield 'IPv6 loopback' => ['::1'];
        yield 'IPv6 link-local' => ['fe80::1'];
        yield 'IPv6 unique-local fc00::/7 low' => ['fc00::1'];
        yield 'IPv6 unique-local fc00::/7 high' => ['fdff::1'];
        yield 'IPv6 multicast' => ['ff02::1'];
        yield 'IPv6-mapped IPv4 loopback' => ['::ffff:127.0.0.1'];
        yield 'IPv6-mapped IPv4 10/8' => ['::ffff:10.0.0.5'];
        yield 'empty string' => [''];
        yield 'not an IP at all' => ['not-an-ip'];
        yield 'hostname, not a literal' => ['example.com'];
    }

    #[DataProvider('forbiddenIpProvider')]
    public function testIpIsForbidden(string $ip): void
    {
        $this->assertTrue(internal_ip_is_forbidden($ip), "expected forbidden: $ip");
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function publicIpProvider(): iterable
    {
        yield 'IPv4 public (Google DNS)' => ['8.8.8.8'];
        yield 'IPv4 public (Cloudflare DNS)' => ['1.1.1.1'];
        yield 'IPv4 just below 10/8' => ['9.255.255.255'];
        yield 'IPv4 just below CGNAT range' => ['100.63.255.255'];
        yield 'IPv4 just above CGNAT range' => ['100.128.0.0'];
        yield 'IPv4 just below 172.16/12' => ['172.15.255.255'];
        yield 'IPv4 just above 172.16/12' => ['172.32.0.0'];
        yield 'IPv4 just below 192.168/16' => ['192.167.255.255'];
        yield 'IPv6 public (Google DNS)' => ['2001:4860:4860::8888'];
        yield 'IPv6-mapped IPv4 public' => ['::ffff:8.8.8.8'];
    }

    #[DataProvider('publicIpProvider')]
    public function testIpIsNotForbidden(string $ip): void
    {
        $this->assertFalse(internal_ip_is_forbidden($ip), "expected NOT forbidden: $ip");
    }

    public function testUrlAllowedRejectsNonHttps(): void
    {
        $this->assertFalse(internal_url_allowed('http://8.8.8.8/'));
        $this->assertFalse(internal_url_allowed('ftp://8.8.8.8/'));
        $this->assertFalse(internal_url_allowed('not-a-url'));
    }

    public function testUrlAllowedRejectsNonDefaultPort(): void
    {
        $this->assertFalse(internal_url_allowed('https://8.8.8.8:8443/'));
    }

    public function testUrlAllowedAcceptsExplicitDefaultPort(): void
    {
        $this->assertTrue(internal_url_allowed('https://8.8.8.8:443/'));
    }

    public function testUrlAllowedRejectsOversizedUrl(): void
    {
        $overlong = 'https://8.8.8.8/' . str_repeat('a', 2048);
        $this->assertFalse(internal_url_allowed($overlong));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function forbiddenIpUrlProvider(): iterable
    {
        yield 'loopback' => ['https://127.0.0.1/x'];
        yield 'private 10/8' => ['https://10.1.2.3/x'];
        yield 'private 192.168/16' => ['https://192.168.1.1/x'];
        yield 'link-local' => ['https://169.254.1.1/x'];
        yield 'IPv6 loopback (bracketed)' => ['https://[::1]/x'];
    }

    #[DataProvider('forbiddenIpUrlProvider')]
    public function testUrlAllowedRejectsForbiddenIpLiteralHost(string $url): void
    {
        $this->assertFalse(internal_url_allowed($url));
    }

    public function testUrlAllowedAcceptsPublicIpLiteralHost(): void
    {
        $this->assertTrue(internal_url_allowed('https://8.8.8.8/x'));
    }

    public function testUrlAllowedRejectsSelfLoop(): void
    {
        $_SERVER['HTTP_HOST'] = 'r.example.com';

        $this->assertFalse(internal_url_allowed('https://r.example.com/x'));
        $this->assertFalse(internal_url_allowed('https://sub.r.example.com/x'));
    }

    public function testUrlAllowedHonorsSharedOfferAllowlist(): void
    {
        // The IP literal itself is the "host" srp_url_host_allowed() compares
        // against — an allowlist of unrelated domains must reject it, and an
        // allowlist that names the literal must accept it. Both directions are
        // exercised with an IP literal (never a hostname) so neither path
        // triggers a live DNS lookup.
        putenv('SRP_OFFER_ALLOWED_DOMAINS=offers.example,ads.example');
        $_ENV['SRP_OFFER_ALLOWED_DOMAINS'] = 'offers.example,ads.example';

        $this->assertFalse(internal_url_allowed('https://8.8.8.8/x'));

        putenv('SRP_OFFER_ALLOWED_DOMAINS=8.8.8.8');
        $_ENV['SRP_OFFER_ALLOWED_DOMAINS'] = '8.8.8.8';

        $this->assertTrue(internal_url_allowed('https://8.8.8.8/x'));
    }
}
