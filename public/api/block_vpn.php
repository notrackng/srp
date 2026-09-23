<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

include_once __DIR__ . '/../session_guards.php';

header('Content-Type: application/json; charset=utf-8');

try {
    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($method === 'GET') {
        $stmt = $pdo->prepare('SELECT block_vpn_asn FROM `generate` WHERE sub_id = :sub_id LIMIT 1');
        if (!$stmt) {
            jsonError(500, 'db-error');
        }
        $stmt->execute(['sub_id' => $sessionSubId]);
        $value = $stmt->fetchColumn();

        $flag = ($value === false || $value === null) ? 1 : (int) $value;

        echo json_encode(
            ['ok' => true, 'block_vpn_asn' => $flag],
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
        );
        exit;
    }

    if ($method !== 'POST') {
        jsonError(405, 'method-not-allowed');
    }

    if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    $raw = $_POST['block_vpn_asn'] ?? '1';
    $flag = (!is_string($raw)
        || !in_array(strtolower(trim($raw)), ['0', 'false', 'off', 'no'], true)) ? 1 : 0;

    $stmt = $pdo->prepare('UPDATE `generate` SET block_vpn_asn = :block_vpn_asn WHERE sub_id = :sub_id');
    if (!$stmt) {
        jsonError(500, 'db-error');
    }
    $stmt->execute(['block_vpn_asn' => $flag, 'sub_id' => $sessionSubId]);

    echo json_encode(
        ['ok' => true, 'block_vpn_asn' => $flag],
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
    );
    exit;
} catch (Throwable $e) {
    error_log('[block_vpn] ' . $e->getMessage());
    jsonError(500, 'server-error');
}
