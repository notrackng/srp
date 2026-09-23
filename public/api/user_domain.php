<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

include_once __DIR__ . '/../session_guards.php';
require_once dirname(__DIR__, 2) . '/domain_readiness.php';

header('Content-Type: application/json; charset=utf-8');

try {
    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }

    $subDomain = strtoupper(trim((string) ($_GET['sub_domain'] ?? '')));
    if ($subDomain === '' || $subDomain !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    $stmt = $pdo->prepare(
        'SELECT sub_domain, domain, cf_status, cf_zone_id '
        . 'FROM addondomain WHERE sub_domain = :sub_domain '
        . 'ORDER BY domain ASC',
    );
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare user domain query.');
    }

    $stmt->execute(['sub_domain' => $subDomain]);

    $rows    = [];
    $counter = 1;
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $rows[] = [
            'id'         => $counter++,
            'sub_domain' => (string) ($row['sub_domain'] ?? ''),
            'domain'     => (string) ($row['domain']     ?? ''),
            'cf_status'  => (string) ($row['cf_status']  ?? ''),
            'cf_zone_id' => (string) ($row['cf_zone_id'] ?? ''),
        ];
    }

    $rows = srpAnnotateAddonDomainRows($rows, trim(app_env('CF_SERVER_IP', '')));

    echo json_encode($rows, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
