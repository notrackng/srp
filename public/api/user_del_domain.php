<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

include_once __DIR__ . '/../session_guards.php';
require_once __DIR__ . '/../cf-lib.php';
require_once __DIR__ . '/cpanel_addon_lib.php';
require_once __DIR__ . '/cf_token_crypto.php';

header('Content-Type: application/json; charset=utf-8');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonError(405, 'method-not-allowed');
    }

    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }
    if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    $domain = addonNormalizeDomain((string) ($_POST['domain'] ?? ''));
    if ($domain === null) {
        jsonError(422, 'invalid-domain');
    }

    // Ownership check — only the owning tracker may delete its domain. The row
    // also carries the CF zone id we need before removing it.
    $lookup = $pdo->prepare(
        'SELECT cf_zone_id FROM addondomain WHERE domain = :domain AND sub_domain = :sub_domain LIMIT 1',
    );
    $lookup->execute(['domain' => $domain, 'sub_domain' => $sessionSubId]);
    $row = $lookup->fetch(PDO::FETCH_ASSOC);

    if (!is_array($row)) {
        jsonError(404, 'domain-not-found');
    }

    $zoneId = trim((string) ($row['cf_zone_id'] ?? ''));

    // Per-tracker Cloudflare token (zones are created under the tracker's own CF
    // account in cf_sync.php). Fall back to CF_API_TOKEN when absent.
    $tokStmt = $pdo->prepare('SELECT cf_token FROM `generate` WHERE sub_id = :sub_id LIMIT 1');
    $tokStmt->execute(['sub_id' => $sessionSubId]);
    $cfToken = trim(cf_token_decrypt((string) ($tokStmt->fetchColumn() ?: '')));

    $cfRemoved = false;
    $cpanelRemoved = false;

    // 1) Cloudflare zone — best-effort (the local record is removed regardless).
    try {
        if ($zoneId === '') {
            $found  = cfApi('GET', '/zones?name=' . rawurlencode($domain), null, $cfToken);
            $zoneId = is_string($found['result'][0]['id'] ?? null) ? $found['result'][0]['id'] : '';
        }
        if ($zoneId !== '') {
            $del = cfApi('DELETE', '/zones/' . $zoneId, null, $cfToken);
            $cfRemoved = (bool) ($del['success'] ?? false);
        }
    } catch (Throwable $e) {
        error_log('user_del_domain: cf zone delete failed domain=' . $domain);
    }

    // 2) cPanel wildcard subdomain + parked domain — best-effort.
    try {
        $cpResult = addonPerformCpanelDeleteDomain($domain);
        $cpanelRemoved = (bool) $cpResult['ok'];
    } catch (Throwable $e) {
        error_log('user_del_domain: cpanel delete failed domain=' . $domain);
    }

    // 3) Local record — always remove so the panel reflects the deletion.
    $del = $pdo->prepare('DELETE FROM addondomain WHERE domain = :domain AND sub_domain = :sub_domain');
    $del->execute(['domain' => $domain, 'sub_domain' => $sessionSubId]);

    echo json_encode(
        ['ok' => true, 'domain' => $domain, 'cf_removed' => $cfRemoved, 'cpanel_removed' => $cpanelRemoved],
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
    );
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
