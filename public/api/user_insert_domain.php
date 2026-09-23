<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

include_once __DIR__ . '/../session_guards.php';
// addonDnsResolves(): the row must not be written for a domain that does not
// resolve at all. The portal only calls this endpoint after api/call.php succeeds,
// but that ordering lives in JavaScript — this endpoint is reachable directly,
// so the rule is enforced here as well.
require_once __DIR__ . '/cpanel_addon_lib.php';
require_once dirname(__DIR__, 2) . '/domain_readiness.php';

header('Content-Type: application/json; charset=utf-8');

function userNormalizeAddonDomainInput(string $value): ?string
{
    $domain = strtolower(trim($value));
    $domain = preg_replace('/^https?:\/\//i', '', $domain) ?? '';
    $domain = trim($domain, " \t\n\r\0\x0B./");

    if ($domain === '' || strlen($domain) > 253) {
        return null;
    }

    if (preg_match('/[\/\\:@?#\[\]]/', $domain) === 1) {
        return null;
    }

    if (preg_match('/^(localhost|localdomain)$/i', $domain) === 1) {
        return null;
    }

    if (filter_var($domain, FILTER_VALIDATE_IP) !== false) {
        return null;
    }

    if (preg_match('/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain) !== 1) {
        return null;
    }

    return $domain;
}

function userDomainRows(PDO $pdo, string $subDomain): array
{
    $stmt = $pdo->prepare(
        'SELECT sub_domain, domain, COALESCE(cf_status, \'\') AS cf_status, '
        . 'COALESCE(cf_zone_id, \'\') AS cf_zone_id '
        . 'FROM addondomain WHERE sub_domain = :sub_domain ORDER BY domain ASC',
    );
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare user domain list query.');
    }

    $stmt->execute(['sub_domain' => $subDomain]);

    $rows = [];
    $counter = 1;
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $rows[] = [
            'id' => $counter++,
            'sub_domain' => (string) ($row['sub_domain'] ?? ''),
            'domain' => (string) ($row['domain'] ?? ''),
            'cf_status' => (string) ($row['cf_status'] ?? ''),
            'cf_zone_id' => (string) ($row['cf_zone_id'] ?? ''),
        ];
    }

    return srpAnnotateAddonDomainRows($rows, trim(app_env('CF_SERVER_IP', '')));
}

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

    $subDomain = strtoupper(trim((string) ($_POST['sub_domain'] ?? '')));
    $domain = userNormalizeAddonDomainInput((string) ($_POST['domain'] ?? ''));
    if ($subDomain === '') {
        jsonError(422, 'missing-fields');
    }
    if ($domain === null) {
        jsonError(422, 'invalid-domain');
    }
    if ($subDomain !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    $existingStmt = $pdo->prepare(
        'SELECT id FROM addondomain WHERE sub_domain = :sub_domain AND domain = :domain ORDER BY id ASC LIMIT 1',
    );
    if (!$existingStmt) {
        throw new RuntimeException('Failed to prepare duplicate domain query.');
    }
    $existingStmt->execute(['sub_domain' => $subDomain, 'domain' => $domain]);
    if ($existingStmt->fetchColumn() !== false) {
        echo json_encode(
            userDomainRows($pdo, $subDomain),
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
        );
        exit;
    }

    // Storage uses the light gate: at this point the domain is not expected to
    // point here yet — the operator still needs the Cloudflare nameservers that
    // zone creation produces. Only a name that does not resolve at all is refused.
    //
    // Checked after the duplicate lookup on purpose: a domain already stored
    // stays listed even if its DNS changes later, so re-adding is not an error.
    $dns = addonDnsResolves($domain);
    if (!$dns['ok']) {
        error_log('user_insert_domain: refused unresolvable domain=' . $domain . ' reason=' . addonSafeLogText($dns['error']));
        jsonError(422, $dns['error']);
    }

    try {
        $stmt = $pdo->prepare('INSERT INTO addondomain (sub_domain, domain) VALUES (:sub_domain, :domain)');
        if (!$stmt) {
            throw new RuntimeException('Failed to prepare insert query.');
        }

        $stmt->execute(['sub_domain' => $subDomain, 'domain' => $domain]);
    } catch (PDOException $e) {
        if ($e->getCode() !== '23000') {
            throw $e;
        }
    }

    echo json_encode(userDomainRows($pdo, $subDomain), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
