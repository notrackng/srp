<?php

declare(strict_types=1);

if (!function_exists('srp_ip_in_cidr')) {
    /**
     * Match an IP (v4 or v6) against a single CIDR range.
     */
    function srp_ip_in_cidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return false;
        }

        [$subnet, $bitsRaw] = explode('/', $cidr, 2);
        $bits = (int) $bitsRaw;

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $maxBits = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $wholeBytes = intdiv($bits, 8);
        $remainder = $bits % 8;

        if ($wholeBytes > 0 && strncmp($ipBin, $subnetBin, $wholeBytes) !== 0) {
            return false;
        }

        if ($remainder === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainder)) & 0xFF;

        return (ord($ipBin[$wholeBytes]) & $mask) === (ord($subnetBin[$wholeBytes]) & $mask);
    }
}

if (!function_exists('srp_trusted_proxy_ranges')) {
    /**
     * Cloudflare edge ranges (https://www.cloudflare.com/ips/) plus any extra
     * CIDRs from the SRP_TRUSTED_PROXY_IPS env var (comma-separated) for
     * non-Cloudflare fronting. Client-IP headers are honoured only when the
     * connecting peer (REMOTE_ADDR) falls inside one of these ranges.
     *
     * @return list<string>
     */
    function srp_trusted_proxy_ranges(): array
    {
        static $ranges = null;
        if ($ranges !== null) {
            return $ranges;
        }

        $ranges = [
            // Cloudflare IPv4
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            // Cloudflare IPv6
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
            '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
        ];

        $extra = $_ENV['SRP_TRUSTED_PROXY_IPS']
            ?? $_SERVER['SRP_TRUSTED_PROXY_IPS']
            ?? getenv('SRP_TRUSTED_PROXY_IPS');

        if (is_string($extra) && $extra !== '') {
            foreach (explode(',', $extra) as $cidr) {
                $cidr = trim($cidr);
                if ($cidr !== '') {
                    $ranges[] = $cidr;
                }
            }
        }

        return $ranges;
    }
}

if (!function_exists('srp_ip_is_trusted_proxy')) {
    function srp_ip_is_trusted_proxy(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        foreach (srp_trusted_proxy_ranges() as $cidr) {
            if (srp_ip_in_cidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }
}

if (!function_exists('getUserIP')) {
    function getUserIP(): string
    {
        $remoteAddr = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
            ? trim($_SERVER['REMOTE_ADDR'])
            : '';

        // Proxy-supplied client-IP headers (CF-Connecting-IP, X-Forwarded-For, …)
        // are attacker-forgeable when the origin is reachable directly. Trust them
        // only when the connecting peer is a known edge (Cloudflare by default,
        // extendable via SRP_TRUSTED_PROXY_IPS). Otherwise use REMOTE_ADDR.
        if ($remoteAddr !== '' && srp_ip_is_trusted_proxy($remoteAddr)) {
            $sources = [
                'HTTP_CF_CONNECTING_IP',
                'HTTP_TRUE_CLIENT_IP',
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_REAL_IP',
            ];

            foreach ($sources as $source) {
                if (!isset($_SERVER[$source]) || !is_string($_SERVER[$source])) {
                    continue;
                }

                $value = trim($_SERVER[$source]);
                if ($value === '') {
                    continue;
                }

                $candidates = $source === 'HTTP_X_FORWARDED_FOR'
                    ? explode(',', $value)
                    : [$value];

                foreach ($candidates as $candidate) {
                    $candidate = trim($candidate);

                    if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                        return $candidate;
                    }
                }
            }
        }

        if ($remoteAddr !== '' && filter_var($remoteAddr, FILTER_VALIDATE_IP) !== false) {
            return $remoteAddr;
        }

        return '';
    }
}
