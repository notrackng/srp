<?php

/**
 * SSRF guard for imgp_handler.php's image proxy — extracted to its own file
 * (no top-level side effects) so it can be required directly in tests
 * without triggering imgp_handler.php's request-handling code (which reads
 * $_GET and exits immediately outside a real HTTP request).
 */

declare(strict_types=1);

if (!function_exists('imgp_is_private_ip')) {
    /**
     * True when an IP literal is private, loopback, link-local, CGNAT,
     * multicast, or otherwise reserved/non-routable — never a legitimate
     * target for this proxy to fetch. Fails closed on anything that isn't a
     * valid IP literal at all.
     *
     * Bitmask logic mirrors redirect/internal/engine.php's
     * internal_ip_is_forbidden() (the /internal/v1/* cloak's equivalent
     * guard) rather than relying on PHP's FILTER_FLAG_NO_RES_RANGE, which
     * does not cover the TEST-NET ranges or multicast, and — for an
     * IPv4-mapped IPv6 literal like ::ffff:8.8.8.8 — does not unwrap to the
     * embedded IPv4 address first, so it misclassifies some genuinely public
     * v4-mapped-v6 addresses as blocked and would misclassify some genuinely
     * private ones as allowed had this ever been asked to check one.
     */
    function imgp_is_private_ip(string $ip): bool
    {
        $ip = trim($ip);
        if ($ip === '') {
            return true;
        }

        // IPv4
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $long = ip2long($ip);
            if ($long === false) {
                return true;
            }

            return ($long & 0xFF000000) === 0x00000000   // 0.0.0.0/8
                || ($long & 0xFF000000) === 0x0A000000   // 10.0.0.0/8
                || ($long & 0xFFC00000) === 0x64400000   // 100.64.0.0/10 (CGNAT)
                || ($long & 0xFF000000) === 0x7F000000   // 127.0.0.0/8 loopback
                || ($long & 0xFFFF0000) === 0xA9FE0000   // 169.254.0.0/16 link-local (incl. cloud metadata)
                || ($long & 0xFFF00000) === 0xAC100000   // 172.16.0.0/12
                || ($long & 0xFFFFFF00) === 0xC0000000   // 192.0.0.0/24
                || ($long & 0xFFFFFF00) === 0xC0000200   // 192.0.2.0/24 (TEST-NET-1)
                || ($long & 0xFFFF0000) === 0xC0A80000   // 192.168.0.0/16
                || ($long & 0xFFFE0000) === 0xC6120000   // 198.18.0.0/15 benchmark
                || ($long & 0xF0000000) === 0xE0000000   // 224.0.0.0/4 multicast
                || ($long & 0xF0000000) === 0xF0000000;  // 240.0.0.0/4 reserved
        }

        // IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $bin = @inet_pton($ip);
            if ($bin === false || strlen($bin) !== 16) {
                return true;
            }
            $bytes = array_values(unpack('C*', $bin)); // 16 ints, 0-indexed

            $allZero = true;
            foreach ($bytes as $byte) {
                if ($byte !== 0) {
                    $allZero = false;
                    break;
                }
            }
            if ($allZero) {
                return true; // :: unspecified
            }

            // ::ffff:a.b.c.d mapped IPv4 → run the IPv4 checks on the
            // unwrapped address instead of the IPv6 literal itself.
            $mapped = true;
            for ($i = 0; $i < 10; $i++) {
                if ($bytes[$i] !== 0) {
                    $mapped = false;
                    break;
                }
            }
            if ($mapped && $bytes[10] === 0xFF && $bytes[11] === 0xFF) {
                $v4 = sprintf('%d.%d.%d.%d', $bytes[12], $bytes[13], $bytes[14], $bytes[15]);

                return imgp_is_private_ip($v4);
            }

            // ::1 loopback
            $loopback = true;
            for ($i = 0; $i < 15; $i++) {
                if ($bytes[$i] !== 0) {
                    $loopback = false;
                    break;
                }
            }
            if ($loopback && $bytes[15] === 1) {
                return true;
            }

            if (($bytes[0] & 0xFE) === 0xFC) {
                return true; // fc00::/7 unique-local
            }
            if ($bytes[0] === 0xFE && ($bytes[1] & 0xC0) === 0x80) {
                return true; // fe80::/10 link-local
            }
            if ($bytes[0] === 0xFF) {
                return true; // ff00::/8 multicast
            }

            return false;
        }

        return true; // not a valid IP
    }
}
