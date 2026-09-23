<?php

declare(strict_types=1);

if (!function_exists('base64url_encode')) {
    function base64url_encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}

if (!function_exists('base64url_decode')) {
    function base64url_decode(string $value): string|false
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
}
