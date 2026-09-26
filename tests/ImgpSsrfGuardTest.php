<?php

declare(strict_types=1);

require_once __DIR__ . '/../imgp_ssrf_guard.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for imgp_handler.php's SSRF guard: imgp_is_private_ip() (IPv4 + IPv6
 * private/loopback/link-local/reserved/CGNAT detection for the image proxy's
 * fetch target). Mirrors InternalSsrfGuardTest.php's IP-literal cases against
 * the /internal/v1/* cloak's equivalent guard — the two are separate
 * implementations with similar intent, so both get the same coverage.
 *
 * Deterministic by construction: imgp_is_private_ip() only ever receives an
 * IP literal (imgp_handler.php resolves hostnames via gethostbynamel() and
 * checks each resolved address before calling this), so no case here depends
 * on a real DNS lookup.
 */
final class ImgpSsrfGuardTest extends TestCase
{
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
        yield 'IPv4 link-local (cloud metadata address)' => ['169.254.169.254'];
        yield 'IPv4 172.16/12 start' => ['172.16.0.0'];
        yield 'IPv4 172.16/12 end' => ['172.31.255.255'];
        yield 'IPv4 192.168/16' => ['192.168.1.1'];
        yield 'IPv4 TEST-NET-1 192.0.2.0/24' => ['192.0.2.55'];
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
        // imgp_is_private_ip() fails closed on anything that is not a valid
        // IP literal at all — unlike internal_ip_is_forbidden(), it is never
        // asked to resolve a hostname (the caller does that separately).
        yield 'empty string' => [''];
        yield 'not an IP at all' => ['not-an-ip'];
        yield 'hostname, not a literal' => ['example.com'];
    }

    #[DataProvider('forbiddenIpProvider')]
    public function testIpIsPrivate(string $ip): void
    {
        $this->assertTrue(imgp_is_private_ip($ip), "expected blocked: $ip");
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
    public function testIpIsNotPrivate(string $ip): void
    {
        $this->assertFalse(imgp_is_private_ip($ip), "expected NOT blocked: $ip");
    }
}
