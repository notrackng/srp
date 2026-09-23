<?php

declare(strict_types=1);

include_once __DIR__ . '/../session_guards.php';
include_once __DIR__ . '/../api/cpanel_addon_lib.php';

header('Content-Type: application/json; charset=utf-8');

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        jsonError(405, 'method-not-allowed');
    }

    startAdminGuardSession();
    if (empty($_SESSION['admin_authenticated'])) {
        jsonError(403, 'unauthorized');
    }

    if (!hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    $domain = addonNormalizeDomain((string) ($_POST['domain'] ?? ($_POST['url'] ?? '')));
    if ($domain === null) {
        jsonError(422, 'invalid-domain');
    }

    // addonPerformCpanelAddonDomain() verifies the wildcard actually exists in
    // cPanel before reporting success, so its result can be trusted directly —
    // we never report "wildcard enabled" on an unconfirmed timeout.
    $result = addonPerformCpanelAddonDomain($domain);
    if (!$result['ok']) {
        $error = $result['error'] !== '' ? $result['error'] : 'cpanel-request-failed';
        echo json_encode(
            ['ok' => false, 'domain' => $domain, 'wildcard' => false, 'err' => $error],
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
        );
        exit;
    }

    echo json_encode(
        ['ok' => true, 'domain' => $domain, 'wildcard' => true],
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
    );
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
