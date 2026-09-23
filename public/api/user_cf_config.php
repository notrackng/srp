<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

include_once __DIR__ . '/../session_guards.php';
require_once __DIR__ . '/cf_token_crypto.php';

header('Content-Type: application/json; charset=utf-8');

function requireGenerateCfSchema(PDO $pdo): void
{
    foreach (['cf_token', 'cf_account_id'] as $column) {
        $stmt = $pdo->prepare(
            'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = :table_name AND column_name = :column_name LIMIT 1',
        );
        if (!$stmt) {
            jsonError(500, 'schema-check-failed');
        }

        $stmt->execute(['table_name' => 'generate', 'column_name' => $column]);
        $exists = $stmt->fetchColumn() !== false;

        if (!$exists) {
            jsonError(500, 'schema-not-installed');
        }
    }
}

try {
    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }
    requireGenerateCfSchema($pdo);

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($method === 'GET') {
        $stmt = $pdo->prepare('SELECT cf_token, cf_account_id FROM `generate` WHERE sub_id = :sub_id LIMIT 1');
        if (!$stmt) {
            jsonError(500, 'db-error');
        }
        $stmt->execute(['sub_id' => $sessionSubId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $hasToken = !empty($row['cf_token']);
        echo json_encode([
            'ok'             => true,
            'has_token'      => $hasToken,
            'token_masked'   => $hasToken ? cf_token_mask((string) ($row['cf_token'] ?? '')) : '',
            'account_id'     => (string) ($row['cf_account_id'] ?? ''),
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
        exit;
    }

    if ($method === 'POST') {
        if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
            jsonError(419, 'invalid-csrf');
        }

        $action    = trim((string) ($_POST['action'] ?? 'save'));
        $token     = trim((string) ($_POST['cf_token'] ?? ''));
        $accountId = trim((string) ($_POST['cf_account_id'] ?? ''));

        if ($action === 'clear') {
            $stmt = $pdo->prepare('UPDATE `generate` SET cf_token = NULL, cf_account_id = NULL WHERE sub_id = :sub_id');
            if (!$stmt) {
                jsonError(500, 'db-error');
            }
            $stmt->execute(['sub_id' => $sessionSubId]);
            echo json_encode(['ok' => true, 'cleared' => true], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
            exit;
        }

        // action=detect — verify token + auto-detect Account ID from CF API
        if ($action === 'detect') {
            if ($token === '') {
                jsonError(422, 'token-required');
            }
            if (!extension_loaded('curl')) {
                jsonError(500, 'curl-unavailable');
            }

            $ch = curl_init('https://api.cloudflare.com/client/v4/accounts?per_page=5');
            if ($ch === false) {
                jsonError(502, 'curl-init-failed');
            }
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_HTTPHEADER     => [
                    'Authorization: Bearer ' . $token,
                    'Content-Type: application/json',
                ],
            ]);
            $raw   = curl_exec($ch);
            $errno = curl_errno($ch);
            curl_close($ch);

            if ($errno !== 0 || $raw === false) {
                jsonError(502, 'cf-unreachable');
            }

            $data = json_decode((string) $raw, true);
            if (!($data['success'] ?? false)) {
                $msg = (string) ($data['errors'][0]['message'] ?? 'Token invalid or no account access');
                error_log('[user_cf_config] Cloudflare account detect failed: ' . $msg);
                jsonError(401, 'cf-account-detect-failed');
            }

            $accounts = $data['result'] ?? [];
            $firstAccount = $accounts[0] ?? [];
            echo json_encode([
                'ok'           => true,
                'account_id'   => (string) ($firstAccount['id']   ?? ''),
                'account_name' => (string) ($firstAccount['name'] ?? ''),
                'accounts'     => array_map(static fn($a) => [
                    'id'   => (string) ($a['id']   ?? ''),
                    'name' => (string) ($a['name'] ?? ''),
                ], $accounts),
            ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
            exit;
        }

        // action=save
        if ($token === '') {
            jsonError(422, 'token-required');
        }

        $stmt = $pdo->prepare('UPDATE `generate` SET cf_token = :cf_token, cf_account_id = :cf_account_id WHERE sub_id = :sub_id');
        if (!$stmt) {
            jsonError(500, 'db-error');
        }
        $stmt->execute(['cf_token' => cf_token_encrypt($token), 'cf_account_id' => $accountId, 'sub_id' => $sessionSubId]);
        echo json_encode(['ok' => true, 'saved' => true], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
        exit;
    }

    jsonError(405, 'method-not-allowed');
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
