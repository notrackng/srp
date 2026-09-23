<?php

declare(strict_types=1);

include_once __DIR__ . '/../session_guards.php';
require_once __DIR__ . '/checkdomain_helpers.php';

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Require admin session — Facebook access token must not be accessible to unauthenticated callers.
startAdminGuardSession();
$_checkdomainGuardStatus = checkdomainGuardStatus(
    !empty($_SESSION['admin_authenticated']),
    checkdomainRequestMethod($_SERVER['REQUEST_METHOD'] ?? null),
    hasValidSessionCsrf('admin_panel', requestCsrfToken()),
);

if ($_checkdomainGuardStatus !== 200) {
    http_response_code($_checkdomainGuardStatus);
    echo json_encode([]);
    exit;
}

/**
 * @return list<array{id: int, info: string, domain: string}>
 */
function fetchDomainCheckRows(PDO $pdo, string $accessToken): array
{
    $stmt = $pdo->prepare('SELECT domain FROM addondomain WHERE sub_domain = :sub_domain ORDER BY domain ASC');
    if (!$stmt) {
        return [];
    }

    $stmt->execute(['sub_domain' => 'GLOBAL']);

    $rows = [];
    $counter = 1;

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $domain = isset($row['domain']) && is_string($row['domain']) ? trim($row['domain']) : '';
        if ($domain === '') {
            continue;
        }

        $rows[] = [
            'id' => $counter++,
            'info' => graphDomainStatusHtml($domain, $accessToken),
            'domain' => '<footer class="text-muted" style="text-decoration:none;">' . escapeHtml($domain) . '</footer>',
        ];
    }

    return $rows;
}

function graphDomainStatusHtml(string $domain, string $accessToken): string
{
    $response = requestGraphScrapeStatus($domain, $accessToken);
    $safeDomain = escapeHtml($domain);

    if (isset($response['url']) && is_string($response['url']) && $response['url'] !== '') {
        return $safeDomain . '<footer class="text-muted" style="text-decoration:none;color:#6c757d"><i class="fa fa-check" aria-hidden="true"> Domain Aman!</i></footer>';
    }

    $message = '';
    if (isset($response['error']['message']) && is_string($response['error']['message'])) {
        $message = $response['error']['message'];
    }

    if ($message === '(#6b6f72) The action attempted has been deemed abusive or is otherwise disallowed') {
        return $safeDomain . '<footer class="text-muted" style="text-decoration:none;color:#6c757d"><i class="fa fa-times" aria-hidden="true"> Domain Fraud!</i></footer>';
    }

    if ($message !== '') {
        error_log('[checkdomain] Graph API error for domain=' . $domain . ' message=' . $message);
    }

    return $safeDomain . '<footer class="text-muted" style="text-decoration:none;color:#6c757d"><i class="fa fa-exclamation-triangle" aria-hidden="true"> Domain check failed.</i></footer>';
}

/**
 * @return array<string, mixed>
 */
function requestGraphScrapeStatus(string $domain, string $accessToken): array
{
    $curl = curl_init('https://graph.facebook.com/');
    if ($curl === false) {
        return [];
    }

    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'id' => 'http://' . $domain,
            'scrape' => 'true',
            'access_token' => $accessToken,
        ], '', '&', PHP_QUERY_RFC3986),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HEADER => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12,
    ]);

    $data = curl_exec($curl);
    curl_close($curl);

    if (!is_string($data) || trim($data) === '') {
        return [];
    }

    try {
        $decoded = json_decode($data, true, 32, JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        return [];
    }

    return is_array($decoded) ? $decoded : [];
}

function escapeHtml(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Accept token from POST only — keeps the Facebook access token out of server
// access logs, browser history, and Referer headers. (GET fallback removed.)
$accessToken = '';
if (isset($_POST['accessToken']) && is_scalar($_POST['accessToken'])) {
    $accessToken = trim((string) $_POST['accessToken']);
}

if ($accessToken === '') {
    http_response_code(400);
    echo json_encode([]);
    exit;
}

echo json_encode(fetchDomainCheckRows($pdo, $accessToken), JSON_UNESCAPED_SLASHES);
