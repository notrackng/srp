<?php

declare(strict_types=1);

/*
 * The `rk` redirect token carries state between the internal redirect hops
 * (redirect/index.php → _meetups/index.php → _meetups/r.php). It is server-
 * generated and consumed within a single redirect chain, so it is HMAC-signed:
 *
 *   token = <base64url(csv)>.<base64url(HMAC-SHA256(payload, key))>
 *
 * A "." separates the two parts (never present in the base64url alphabet).
 * srp_redirect_payload_decode() rejects any token without a valid signature, so
 * a forged `rk` can no longer be replayed against _meetups/ to inflate click
 * counts. The signing key comes from SRP_RK_SECRET (preferred) or an existing
 * app secret, with domain separation (see srp_redirect_payload_key()).
 */

/**
 * @return array{click_id: string, country_code: string, device_type: string, ip_address: string, user_lp: string}|null
 */
function srp_redirect_payload_decode(mixed $value): ?array
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);
    if ($value === '' || strlen($value) > 1024) {
        return null;
    }

    // Split "<payload>.<signature>". A missing "." (legacy unsigned token) is
    // rejected — the whole point is that unsigned tokens are no longer accepted.
    $separator = strrpos($value, '.');
    if ($separator === false) {
        return null;
    }

    $payloadPart = substr($value, 0, $separator);
    $signaturePart = substr($value, $separator + 1);
    if ($payloadPart === '' || $signaturePart === '') {
        return null;
    }

    $expectedSignature = srp_redirect_base64url_encode(
        hash_hmac('sha256', $payloadPart, srp_redirect_payload_key(), true),
    );

    if (!hash_equals($expectedSignature, $signaturePart)) {
        return null;
    }

    $decoded = srp_redirect_base64url_decode($payloadPart);

    if (!is_string($decoded) || $decoded === '') {
        return null;
    }

    $parts = str_getcsv($decoded, escape: '\\');

    if (count($parts) !== 5) {
        return null;
    }

    return [
        'click_id' => is_string($parts[0]) ? $parts[0] : '',
        'country_code' => is_string($parts[1]) ? $parts[1] : '',
        'device_type' => is_string($parts[2]) ? $parts[2] : '',
        'ip_address' => is_string($parts[3]) ? $parts[3] : '',
        'user_lp' => is_string($parts[4]) ? $parts[4] : '',
    ];
}

function srp_redirect_payload_encode(
    string $clickId,
    string $countryCode,
    string $deviceType,
    string $ipAddress,
    string $userLp,
): string {
    $payload = srp_redirect_base64url_encode(
        implode(',', [$clickId, $countryCode, $deviceType, $ipAddress, $userLp]),
    );
    $signature = srp_redirect_base64url_encode(
        hash_hmac('sha256', $payload, srp_redirect_payload_key(), true),
    );

    return $payload . '.' . $signature;
}

/**
 * Resolve the raw HMAC key for `rk` signing. Prefers SRP_RK_SECRET and accepts
 * the documented application-secret fallbacks for older deployments. The
 * chosen secret is domain-separated via SHA-256 so reusing another feature's
 * secret cannot produce a colliding key. Self-contained (reads the environment
 * directly) so this file has no include dependencies.
 */
function srp_redirect_payload_key(): string
{
    $base = '';
    foreach (['SRP_RK_SECRET', 'AF_SECRET', 'SRP_API_KEY', 'POSTBACK_SECRET'] as $name) {
        $value = getenv($name);
        if ($value === false || $value === '') {
            $value = $_ENV[$name] ?? $_SERVER[$name] ?? '';
        }
        if (is_string($value) && $value !== '') {
            $base = $value;
            break;
        }
    }

    if ($base === '') {
        error_log('[srp_rk] no signing secret configured; redirect chain disabled');
        throw new RuntimeException('Redirect signing secret is not configured.');
    }

    return hash('sha256', 'srp|rk|v1|' . $base, true);
}

function srp_redirect_base64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function srp_redirect_base64url_decode(string $value): string|false
{
    if ($value === '') {
        return '';
    }

    if (preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) {
        return false;
    }

    $padding = (4 - (strlen($value) % 4)) % 4;
    $decoded = base64_decode(
        strtr($value . str_repeat('=', $padding), '-_', '+/'),
        true,
    );

    return $decoded === false ? false : $decoded;
}
