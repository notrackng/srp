<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';

if (!function_exists('guardIsHttpsRequest')) {
    /**
     * Is this request HTTPS from the visitor's point of view?
     *
     * Delegates to srp_request_is_https() in env.php, the single rule for the
     * whole codebase. Kept as a named wrapper so existing call sites and this
     * module's vocabulary stay unchanged.
     */
    function guardIsHttpsRequest(): bool
    {
        return srp_request_is_https();
    }
}

if (!function_exists('startNamedGuardSession')) {
    function startNamedGuardSession(string $name): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        session_name($name);
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => guardIsHttpsRequest(),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }
}

if (!function_exists('startAdminGuardSession')) {
    function startAdminGuardSession(): void
    {
        startNamedGuardSession('sslmgr_admin');
    }
}

if (!function_exists('startUserGuardSession')) {
    function startUserGuardSession(): void
    {
        startNamedGuardSession('sslmgr_user');
    }
}

if (!function_exists('sessionCsrfToken')) {
    function sessionCsrfToken(string $namespace): string
    {
        if (!isset($_SESSION['csrf'][$namespace]) || !is_string($_SESSION['csrf'][$namespace])) {
            $_SESSION['csrf'][$namespace] = bin2hex(random_bytes(32));
        }

        return $_SESSION['csrf'][$namespace];
    }
}

if (!function_exists('requestCsrfToken')) {
    function requestCsrfToken(): string
    {
        $headerToken = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
        if ($headerToken !== '') {
            return $headerToken;
        }

        return (string) ($_POST['csrf_token'] ?? '');
    }
}

if (!function_exists('hasValidSessionCsrf')) {
    function hasValidSessionCsrf(string $namespace, string $providedToken): bool
    {
        $storedToken = $_SESSION['csrf'][$namespace] ?? null;

        return $providedToken !== '' && is_string($storedToken) && hash_equals($storedToken, $providedToken);
    }
}

if (!function_exists('jsonError')) {
    function jsonError(int $status, string $message): never
    {
        header('Content-Type: application/json; charset=utf-8');
        http_response_code($status);
        echo json_encode(['ok' => false, 'err' => $message]);
        exit;
    }
}

if (!function_exists('authenticatedUserSubId')) {
    function authenticatedUserSubId(): string
    {
        $subId = strtoupper((string) ($_SESSION['user_sub_id'] ?? ''));
        if ($subId !== '') {
            return $subId;
        }
        // Fallback for sessions created before user_sub_id was stored
        $authMap = $_SESSION['user_auth'] ?? [];
        if (is_array($authMap)) {
            foreach ($authMap as $key => $state) {
                if (is_array($state) && !empty($state['authenticated'])) {
                    $subId = strtoupper((string) $key);
                    $_SESSION['user_sub_id'] = $subId;

                    return $subId;
                }
            }
        }

        return '';
    }
}
