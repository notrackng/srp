<?php

declare(strict_types=1);

/**
 * Resolve effective tracker sub_id from session and optional request value.
 *
 * Returns null when session is missing/invalid or when a provided request
 * sub_id does not match the authenticated session owner.
 */
function generateApiResolveAuthorizedSubId(string $sessionSubId, ?string $requestedSubId): ?string
{
    $normalizedSession = strtoupper(trim($sessionSubId));
    if ($normalizedSession === '') {
        return null;
    }

    $normalizedRequested = strtoupper(trim((string) $requestedSubId));
    if ($normalizedRequested !== '' && $normalizedRequested !== $normalizedSession) {
        return null;
    }

    return $normalizedSession;
}
