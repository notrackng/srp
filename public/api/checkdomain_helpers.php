<?php

declare(strict_types=1);

function checkdomainGuardStatus(bool $isAdminAuthed, string $requestMethod, bool $csrfValid): int
{
    if (!$isAdminAuthed) {
        return 403;
    }

    if ($requestMethod !== 'POST') {
        return 405;
    }

    if (!$csrfValid) {
        return 419;
    }

    return 200;
}

function checkdomainRequestMethod(mixed $requestMethod): string
{
    return is_string($requestMethod) ? $requestMethod : '';
}
