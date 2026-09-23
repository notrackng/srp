<?php

/**
 * Shared sanitization functions for the _meetups click pipeline.
 * Used by both _meetups/index.php and _meetups/r.php.
 *
 * All functions accept mixed input — callers may pass raw $_GET values.
 * Return null when validation fails; callers must check before use.
 */

declare(strict_types=1);

/**
 * Fallback destination for blocked countries.
 *
 * Keep in sync with SRP_BLOCK_URL in redirect/index.php. It cannot be shared:
 * that constant is declared inside index.php, which the _meetups hop never
 * loads (it is a separate request).
 */
const MEETUP_BLOCK_URL_FALLBACK = 'https://www.youtube.com/';

/**
 * Blocked countries, read from the same SRP_BLOCK_COUNTRIES env value the
 * redirect entry point uses, so one setting governs both places.
 *
 * @return list<string> uppercase ISO codes
 */
function meetup_blocked_countries(): array
{
    return array_values(
        array_filter(
            array_map(
                static fn (string $code): string => strtoupper(trim($code)),
                explode(',', (string) app_env('SRP_BLOCK_COUNTRIES', 'ID')),
            ),
            static fn (string $code): bool => $code !== '',
        ),
    );
}

/**
 * Where blocked visitors are sent. Mirrors the resolution in redirect/index.php:
 * SRP_BLOCK_URL from .env when it is a valid https URL, otherwise the fallback —
 * never an unvalidated value, because it goes straight into a Location header.
 */
function meetup_block_url(): string
{
    $url = trim((string) app_env('SRP_BLOCK_URL', ''));

    if (
        $url !== ''
        && strlen($url) <= 2048
        && filter_var($url, FILTER_VALIDATE_URL) !== false
        && strtolower((string) parse_url($url, PHP_URL_SCHEME)) === 'https'
        && !srp_url_is_self($url)
    ) {
        return $url;
    }

    return MEETUP_BLOCK_URL_FALLBACK;
}

function meetup_sanitize_token(mixed $value, int $maxLength): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);
    if ($value === '' || strlen($value) > $maxLength) {
        return null;
    }

    return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1 ? $value : null;
}

function meetup_sanitize_country_code(mixed $value): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = strtolower(trim((string) $value));
    if ($value === '') {
        return null;
    }

    return preg_match('/^[a-z]{2}$/', $value) === 1 ? $value : null;
}

function meetup_sanitize_ip(mixed $value): string
{
    if (!is_scalar($value)) {
        return '';
    }

    $value = trim((string) $value);
    if ($value === '') {
        return '';
    }

    return filter_var($value, FILTER_VALIDATE_IP) !== false ? $value : '';
}
