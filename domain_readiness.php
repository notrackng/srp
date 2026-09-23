<?php

declare(strict_types=1);

/**
 * Derive the traffic-readiness status for an addon-domain row.
 *
 * @param array<string, mixed> $row
 * @param (callable(string): list<string>)|null $resolver
 */
function srpAddonDomainStatus(array $row, string $originIp, ?callable $resolver = null): string
{
    $domain = strtolower(trim((string) ($row['domain'] ?? '')));
    $originIp = trim($originIp);
    $zoneId = trim((string) ($row['cf_zone_id'] ?? ''));

    if ($zoneId !== '') {
        $cloudflareStatus = strtolower(trim((string) ($row['cf_status'] ?? '')));

        return $cloudflareStatus !== '' ? $cloudflareStatus : 'none';
    }

    if (
        $domain === ''
        || filter_var($originIp, FILTER_VALIDATE_IP) === false
    ) {
        return 'none';
    }
    $originBinary = inet_pton($originIp);
    if ($originBinary === false) {
        return 'none';
    }

    if ($resolver === null) {
        $resolver = static function (string $hostname): array {
            $addresses = [];
            $ipv4Addresses = @gethostbynamel($hostname);
            if (is_array($ipv4Addresses)) {
                $addresses = $ipv4Addresses;
            }

            $ipv6Records = @dns_get_record($hostname, DNS_AAAA);
            if (is_array($ipv6Records)) {
                foreach ($ipv6Records as $record) {
                    $ipv6Address = trim((string) ($record['ipv6'] ?? ''));
                    if ($ipv6Address !== '') {
                        $addresses[] = $ipv6Address;
                    }
                }
            }

            return array_values(array_unique($addresses));
        };
    }

    foreach ($resolver($domain) as $address) {
        $addressBinary = inet_pton(trim((string) $address));
        if ($addressBinary !== false && $addressBinary === $originBinary) {
            return 'active';
        }
    }

    return 'none';
}

/**
 * Pick one traffic-ready domain, scanning once from a randomized start point.
 *
 * @param list<array<string, mixed>> $rows
 * @param (callable(string): list<string>)|null $resolver
 */
function srpPickReadyAddonDomain(
    array $rows,
    string $originIp,
    ?callable $resolver = null,
    ?int $startIndex = null,
): ?string
{
    $count = count($rows);
    if ($count === 0) {
        return null;
    }

    $startIndex ??= random_int(0, $count - 1);
    $startIndex = (($startIndex % $count) + $count) % $count;

    for ($offset = 0; $offset < $count; $offset++) {
        $row = $rows[($startIndex + $offset) % $count];
        if (srpAddonDomainStatus($row, $originIp, $resolver) !== 'active') {
            continue;
        }

        $domain = strtolower(trim((string) ($row['domain'] ?? '')));
        if ($domain !== '') {
            return $domain;
        }
    }

    return null;
}

/**
 * Attach a computed traffic status while retaining inactive domains for display.
 *
 * @param list<array<string, mixed>> $rows
 * @param (callable(string): list<string>)|null $resolver
 * @return list<array<string, mixed>>
 */
function srpAnnotateAddonDomainRows(array $rows, string $originIp, ?callable $resolver = null): array
{
    foreach ($rows as &$row) {
        $row['domain_status'] = srpAddonDomainStatus($row, $originIp, $resolver);
    }
    unset($row);

    return $rows;
}
