<?php

declare(strict_types=1);

require_once __DIR__ . '/../Base64URL.php';
require_once __DIR__ . '/../redirect/functions.php';
require_once __DIR__ . '/../redirect/redirect_payload.php';

use PHPUnit\Framework\TestCase;

final class Base64URLTest extends TestCase
{
    public function testEmptyBase64UrlRoundTrip(): void
    {
        $this->assertSame('', base64url_encode(''));
        $this->assertSame('', base64url_decode(''));
        $this->assertSame('', srp_redirect_base64url_decode(''));
    }

    public function testRoundTripsStandardAndUrlSafeValues(): void
    {
        $value = 'hello/world+test';
        $encoded = base64url_encode($value);
        $expectedEncoded = rtrim(strtr(base64_encode($value), '+/', '-_'), '=');

        $this->assertSame($expectedEncoded, $encoded);
        $this->assertSame($value, base64url_decode($encoded));
        $this->assertSame($value, srp_redirect_base64url_decode($encoded));
    }

    public function testEnsurePrivateTempDirAndFile(): void
    {
        $baseDir = sys_get_temp_dir() . '/srp_secure_cache_test_' . bin2hex(random_bytes(8));
        $dirCreated = srp_ensure_private_dir($baseDir);
        $this->assertTrue($dirCreated);
        $this->assertDirectoryExists($baseDir);
        if (DIRECTORY_SEPARATOR === '/') {
            $this->assertSame(0700, fileperms($baseDir) & 0777);
        }

        $filePath = $baseDir . '/payload.json';
        $this->assertTrue(srp_write_private_file($filePath, '{"ok":true}'));
        if (DIRECTORY_SEPARATOR === '/') {
            $this->assertSame(0600, fileperms($filePath) & 0777);
        }

        @unlink($filePath);
        @rmdir($baseDir);
    }
}
