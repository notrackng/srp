<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require_once __DIR__ . '/../session_guards.php';
require_once __DIR__ . '/cpanel_addon_lib.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    jsonError(405, 'method-not-allowed');
}

function addonCallJsonSuccess(array $payload): never
{
    echo json_encode($payload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
    exit;
}

try {
    startUserGuardSession();

    $sessionSubId = strtoupper(trim(authenticatedUserSubId()));
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }

    if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    $domain = addonNormalizeDomain((string) ($_POST['domain'] ?? ''));
    $userid = strtoupper(trim((string) ($_POST['sub_domain'] ?? $_POST['userid'] ?? '')));

    if ($domain === null || $userid === '') {
        jsonError(422, 'missing-fields');
    }

    if ($userid !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    $result = addonPerformCpanelAddonDomain($domain);
    if (!$result['ok']) {
        $errorDetail = isset($result['error']) && is_string($result['error']) ? trim($result['error']) : '';
        if ($errorDetail !== '') {
            error_log('addon-domain-call-legacy: cpanel failure ' . $errorDetail);
        }

        jsonError(502, 'cpanel-operation-failed');
    }

    addonCallJsonSuccess([
        [
            'domain' => $domain,
            'userid' => $userid,
        ],
    ]);
} catch (JsonException $e) {
    error_log('addon-domain-call: json encode failed');
    jsonError(500, 'server-error');
} catch (Throwable $e) {
    error_log('addon-domain-call: server-error ' . get_class($e));
    jsonError(500, 'server-error');
}
