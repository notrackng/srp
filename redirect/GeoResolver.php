<?php

declare(strict_types=1);

namespace Srp\Redirect;

require_once __DIR__ . '/functions.php';

/**
 * GeoResolver — GeoIP country lookup with file-based caching.
 *
 * Resolves IP → country code using MaxMind GeoLite2 MMDB with a 24-hour
 * file cache in sys_get_temp_dir() to avoid opening the MMDB on every request.
 *
 * Usage:
 *   $resolver = new GeoResolver(SRP_GEOIP2LITE_DB, 'srp_bb');
 *   $result = $resolver->resolve('8.8.8.8');
 *   // → ['countryCode' => 'US', 'countryName' => 'United States']
 */
final class GeoResolver
{
    private string $mmdbPath;
    private string $cacheDir;
    private int $cacheTtl;

    public function __construct(string $mmdbPath, string $cacheSubDir, int $cacheTtl = 86400)
    {
        $this->mmdbPath = $mmdbPath;
        $this->cacheDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR . $cacheSubDir;
        $this->cacheTtl = $cacheTtl;
    }

    /**
     * Resolve country code for an IP address.
     *
     * @return array{countryCode?: string, countryName?: string}
     */
    public function resolve(string $ip): array
    {
        if ($ip === '' || !$this->isValidIp($ip)) {
            return [];
        }

        $cached = $this->readCache($ip);
        if ($cached !== null) {
            return $cached;
        }

        $result = $this->lookupMaxMind($ip);
        $this->writeCache($ip, $result);

        return $result;
    }

    /**
     * Resolve ASN data for an IP address using a separate GeoLite2-ASN database.
     *
     * @return array{asn?: int, org?: string}
     */
    public function resolveAsn(string $asnMmdbPath, string $ip): array
    {
        if ($ip === '' || !$this->isValidIp($ip) || !is_file($asnMmdbPath) || !is_readable($asnMmdbPath)) {
            return [];
        }

        $cached = $this->readAsnCache($ip);
        if ($cached !== null) {
            return $cached;
        }

        $result = $this->lookupMaxMindAsn($asnMmdbPath, $ip);
        $this->writeAsnCache($ip, $result);

        return $result;
    }

    /**
     * @return array{countryCode?: string, countryName?: string}|null
     */
    private function readCache(string $ip): ?array
    {
        $cacheFile = $this->cacheFilePath($ip);

        if (!is_file($cacheFile)) {
            return null;
        }

        $mtime = filemtime($cacheFile);
        if ($mtime === false || (time() - $mtime) >= $this->cacheTtl) {
            return null;
        }

        $content = file_get_contents($cacheFile);
        if (!is_string($content)) {
            return null;
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return null;
        }

        $result = [];
        if (isset($data['countryCode']) && is_string($data['countryCode'])) {
            $result['countryCode'] = $data['countryCode'];
        }
        if (isset($data['countryName']) && is_string($data['countryName'])) {
            $result['countryName'] = $data['countryName'];
        }

        return $result;
    }

    /**
     * @return array{countryCode?: string, countryName?: string}
     */
    private function lookupMaxMind(string $ip): array
    {
        if (!is_file($this->mmdbPath) || !is_readable($this->mmdbPath)) {
            return [];
        }

        $readerClass = 'GeoIp2\\Database\\Reader';
        if (!class_exists($readerClass)) {
            return [];
        }

        set_error_handler(
            static function (int $severity, string $message, string $file, int $line): never {
                throw new \ErrorException($message, 0, $severity, $file, $line);
            },
        );

        $reader = null;
        $result = [];

        try {
            $reader = new $readerClass($this->mmdbPath);
            $record = $reader->country($ip);
            $countryCode = strtoupper((string) ($record->country->isoCode ?? ''));

            if ($countryCode !== '') {
                $result = [
                    'countryCode' => $countryCode,
                    'countryName' => (string) ($record->country->name ?? ''),
                ];
            }
        } catch (\Throwable $e) {
            if ($e::class !== 'GeoIp2\\Exception\\AddressNotFoundException') {
                error_log('GeoIP lookup failed: ' . $e->getMessage());
            }
            $result = [];
        } finally {
            if (isset($reader)) {
                $reader->close();
            }

            // Pop the single handler this method pushed, restoring whatever was
            // active before (custom handler or default). Re-pushing the previous
            // handler instead would leak a frame on every uncached lookup.
            restore_error_handler();
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $result
     */
    private function writeCache(string $ip, array $result): void
    {
        $cacheDir = dirname($this->cacheFilePath($ip));

        if (!\srp_ensure_private_dir($cacheDir)) {
            return;
        }

        $payload = $result !== [] ? $result : ['countryCode' => 'XX'];

        if (!function_exists('\srp_write_private_file')) {
            @file_put_contents(
                $this->cacheFilePath($ip),
                json_encode($payload),
                LOCK_EX,
            );

            return;
        }

        \srp_write_private_file(
            $this->cacheFilePath($ip),
            json_encode($payload),
        );
    }

    private function cacheFilePath(string $ip): string
    {
        return $this->cacheDir . DIRECTORY_SEPARATOR . 'geo_' . md5($ip) . '.json';
    }

    // ── ASN methods ───────────────────────────────────────────────────────

    /**
     * @return array{asn?: int, org?: string}|null
     */
    private function readAsnCache(string $ip): ?array
    {
        $cacheFile = $this->asnCacheFilePath($ip);

        if (!is_file($cacheFile)) {
            return null;
        }

        $mtime = filemtime($cacheFile);
        if ($mtime === false || (time() - $mtime) >= $this->cacheTtl) {
            return null;
        }

        $content = file_get_contents($cacheFile);
        if (!is_string($content)) {
            return null;
        }

        $data = json_decode($content, true);
        if (!is_array($data)) {
            return null;
        }

        $result = [];
        if (isset($data['asn']) && is_int($data['asn'])) {
            $result['asn'] = $data['asn'];
        }
        if (isset($data['org']) && is_string($data['org'])) {
            $result['org'] = $data['org'];
        }

        return $result !== [] ? $result : null;
    }

    /**
     * @return array{asn?: int, org?: string}
     */
    private function lookupMaxMindAsn(string $asnMmdbPath, string $ip): array
    {
        $readerClass = 'GeoIp2\\Database\\Reader';
        if (!class_exists($readerClass)) {
            return [];
        }

        set_error_handler(
            static function (int $severity, string $message, string $file, int $line): never {
                throw new \ErrorException($message, 0, $severity, $file, $line);
            },
        );

        $reader = null;
        $result = [];

        try {
            $reader = new $readerClass($asnMmdbPath);
            $record = $reader->asn($ip);
            $asn = $record->autonomousSystemNumber;
            $org = $record->autonomousSystemOrganization;

            if ($asn !== null) {
                $result['asn'] = $asn;
            }
            if ($org !== null && $org !== '') {
                $result['org'] = $org;
            }
        } catch (\Throwable $e) {
            if ($e::class !== 'GeoIp2\\Exception\\AddressNotFoundException') {
                error_log('GeoIP ASN lookup failed: ' . $e->getMessage());
            }
            $result = [];
        } finally {
            if (isset($reader)) {
                $reader->close();
            }
            restore_error_handler();
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $result
     */
    private function writeAsnCache(string $ip, array $result): void
    {
        $cacheDir = dirname($this->asnCacheFilePath($ip));

        if (!\srp_ensure_private_dir($cacheDir)) {
            return;
        }

        if (!function_exists('\srp_write_private_file')) {
            @file_put_contents(
                $this->asnCacheFilePath($ip),
                json_encode($result),
                LOCK_EX,
            );

            return;
        }

        \srp_write_private_file(
            $this->asnCacheFilePath($ip),
            json_encode($result),
        );
    }

    private function asnCacheFilePath(string $ip): string
    {
        return $this->cacheDir . DIRECTORY_SEPARATOR . 'asn_' . md5($ip) . '.json';
    }

    private function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}
