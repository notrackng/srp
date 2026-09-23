<?php

/**
 * POST /api/cf_create_token.php
 *
 * Creates a Cloudflare API token with permission rows matching the dashboard UI.
 *
 * Works from:
 * - Admin panel: sslmgr_admin + admin_panel CSRF.
 * - User portal: sslmgr_user + user_portal CSRF.
 *
 * Root fix:
 * - Do not include files that may start a default PHP session before selecting
 * the expected session name.
 * - Open the session whose cookie actually exists and whose stored CSRF matches
 * the submitted token.
 * - Keep CSRF strict; no bypass/fallback-to-accept behavior.
 */

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/env.php';

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require_once __DIR__ . '/cf_token_crypto.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

const CF_TOKEN_API_BASE = 'https://api.cloudflare.com/client/v4';
const ADMIN_SESSION_NAME = 'sslmgr_admin';
const USER_SESSION_NAME = 'sslmgr_user';
const LEGACY_SESSION_NAME = 'PHPSESSID';
const ADMIN_CSRF_NAMESPACE = 'admin_panel';
const USER_CSRF_NAMESPACE = 'user_portal';

function jsonFail(int $statusCode, string $error, array $extra = []): never
{
    http_response_code($statusCode);

    echo json_encode(
        array_merge(['ok' => false, 'err' => $error, 'error' => $error], $extra),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
    );

    exit;
}

function jsonSuccess(array $payload): never
{
    http_response_code(200);

    echo json_encode(
        array_merge(['ok' => true], $payload),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
    );

    exit;
}

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function isHttpsRequest(): bool
{
    return srp_request_is_https();
}

function secureSessionCookieParams(): array
{
    return [
        'lifetime' => 0,
        'path' => '/',
        'secure' => isHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ];
}

function requestCsrfToken(): ?string
{
    foreach (['HTTP_X_CSRF_TOKEN', 'HTTP_X_CSRFTOKEN', 'HTTP_X_XSRF_TOKEN'] as $serverKey) {
        $headerToken = $_SERVER[$serverKey] ?? null;
        if (is_string($headerToken) && trim($headerToken) !== '') {
            return trim($headerToken);
        }
    }

    foreach (['csrf_token', '_csrf', '_token'] as $postKey) {
        $postedToken = $_POST[$postKey] ?? null;
        if (is_string($postedToken) && trim($postedToken) !== '') {
            return trim($postedToken);
        }
    }

    return null;
}

function csrfIsValidInCurrentSession(?string $token): bool
{
    if (!is_string($token) || $token === '') {
        return false;
    }

    $csrfStore = $_SESSION['csrf'] ?? null;
    if (!is_array($csrfStore)) {
        return false;
    }

    foreach ([ADMIN_CSRF_NAMESPACE, USER_CSRF_NAMESPACE] as $namespace) {
        $storedToken = $csrfStore[$namespace] ?? null;
        if (is_string($storedToken) && hash_equals($storedToken, $token)) {
            return true;
        }
    }

    return false;
}

function currentSessionHasAuth(): bool
{
    if (!empty($_SESSION['admin_authenticated'])) {
        return true;
    }

    $authMap = $_SESSION['user_auth'] ?? null;
    if (!is_array($authMap)) {
        return false;
    }

    foreach ($authMap as $authState) {
        if (is_array($authState) && !empty($authState['authenticated'])) {
            return true;
        }
    }

    return false;
}

function openNamedSession(string $sessionName): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }

    session_name($sessionName);
    session_set_cookie_params(secureSessionCookieParams());
    session_start();
}

function requestedCsrfContext(): string
{
    $context = $_SERVER['HTTP_X_CSRF_CONTEXT'] ?? ($_POST['csrf_context'] ?? '');
    if (!is_string($context)) {
        return '';
    }

    $context = trim($context);

    return in_array($context, [ADMIN_CSRF_NAMESPACE, USER_CSRF_NAMESPACE], true) ? $context : '';
}

function addUniqueSessionCandidate(array &$candidates, string $sessionName): void
{
    if ($sessionName === '' || in_array($sessionName, $candidates, true)) {
        return;
    }

    $candidates[] = $sessionName;
}

function candidateSessionNames(): array
{
    $context = requestedCsrfContext();
    $candidates = [];

    if ($context === ADMIN_CSRF_NAMESPACE) {
        addUniqueSessionCandidate($candidates, ADMIN_SESSION_NAME);
        addUniqueSessionCandidate($candidates, LEGACY_SESSION_NAME);
        addUniqueSessionCandidate($candidates, USER_SESSION_NAME);
    } elseif ($context === USER_CSRF_NAMESPACE) {
        addUniqueSessionCandidate($candidates, USER_SESSION_NAME);
        addUniqueSessionCandidate($candidates, ADMIN_SESSION_NAME);
        addUniqueSessionCandidate($candidates, LEGACY_SESSION_NAME);
    } else {
        addUniqueSessionCandidate($candidates, USER_SESSION_NAME);
        addUniqueSessionCandidate($candidates, ADMIN_SESSION_NAME);
        addUniqueSessionCandidate($candidates, LEGACY_SESSION_NAME);
    }

    foreach ([USER_SESSION_NAME, ADMIN_SESSION_NAME, LEGACY_SESSION_NAME] as $sessionName) {
        if (isset($_COOKIE[$sessionName])) {
            addUniqueSessionCandidate($candidates, $sessionName);
        }
    }

    return $candidates;
}

function startExpectedSession(): string
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return session_name() ?: 'PHPSESSID';
    }

    $requestedCsrf = requestCsrfToken();
    $fallbackSessionName = '';

    foreach (candidateSessionNames() as $sessionName) {
        if (!isset($_COOKIE[$sessionName])) {
            continue;
        }

        if ($fallbackSessionName === '') {
            $fallbackSessionName = $sessionName;
        }

        openNamedSession($sessionName);

        if (currentSessionHasAuth() && csrfIsValidInCurrentSession($requestedCsrf)) {
            return $sessionName;
        }

        session_write_close();
    }

    if ($fallbackSessionName !== '') {
        openNamedSession($fallbackSessionName);

        return $fallbackSessionName;
    }

    openNamedSession(USER_SESSION_NAME);

    return USER_SESSION_NAME;
}

function csrfIsValid(?string $token): bool
{
    return csrfIsValidInCurrentSession($token);
}

function authenticatedContext(): array
{
    if (!empty($_SESSION['admin_authenticated'])) {
        return ['type' => 'admin', 'sub_id' => ''];
    }

    $sessionSubId = isset($_SESSION['user_sub_id']) && is_string($_SESSION['user_sub_id'])
        ? trim($_SESSION['user_sub_id'])
        : '';

    $authMap = $_SESSION['user_auth'] ?? null;
    if (is_array($authMap)) {
        foreach ($authMap as $key => $authState) {
            if (is_array($authState) && !empty($authState['authenticated'])) {
                if ($sessionSubId === '') {
                    $sessionSubId = is_string($key) ? $key : '';
                }

                return ['type' => 'user', 'sub_id' => strtoupper($sessionSubId)];
            }
        }
    }

    return ['type' => '', 'sub_id' => ''];
}

function loadPdoConnection(): ?PDO
{
    $connectionFile = __DIR__ . '/../../connection_pdo.php';
    if (!is_file($connectionFile)) {
        return null;
    }

    $pdo = require $connectionFile;

    return $pdo instanceof PDO ? $pdo : null;
}

function loadEnvironment(): void
{
    $envFile = __DIR__ . '/../../env.php';
    if (!is_file($envFile)) {
        return;
    }

    include_once $envFile;

    if (function_exists('load_env_file')) {
        load_env_file(dirname(__DIR__, 2) . '/.env');
    }
}

function envValue(string $key, string $default = ''): string
{
    if (function_exists('app_env')) {
        return (string) app_env($key, $default);
    }

    $value = $_ENV[$key] ?? getenv($key);

    return is_string($value) ? $value : $default;
}

function sanitizeCreatorToken(string $token): string
{
    $token = trim($token);

    if ($token === '' || strlen($token) < 20 || strlen($token) > 512) {
        return '';
    }

    if (preg_match('/[\x00-\x1F\x7F<>"\'\\\\]/', $token) === 1) {
        return '';
    }

    if (str_contains($token, '••') || str_contains($token, '***')) {
        return '';
    }

    return $token;
}

function sanitizeAccountId(string $accountId): string
{
    $accountId = trim($accountId);

    if ($accountId === '') {
        return '';
    }

    return preg_match('/^[a-f0-9]{32}$/i', $accountId) === 1 ? $accountId : '';
}

function sanitizeTokenName(string $rawName, string $fallbackSubject): string
{
    $name = trim($rawName);
    if ($name === '') {
        $name = 'Genv2 ' . $fallbackSubject . ' ' . gmdate('Ymd-His');
    }

    $name = preg_replace('/[^a-zA-Z0-9 \-_.]/', '', $name) ?? '';
    $name = trim(substr($name, 0, 100));

    return $name !== '' ? $name : 'Genv2 ' . gmdate('Ymd-His');
}

function cfTokenRequest(string $method, string $path, string $token, ?array $payload = null): array
{
    if (!function_exists('curl_init')) {
        throw new RuntimeException('curl-extension-missing');
    }

    $ch = curl_init(CF_TOKEN_API_BASE . $path);
    if ($ch === false) {
        throw new RuntimeException('curl-init-failed');
    }

    $headers = [
        'Authorization: Bearer ' . $token,
        'Accept: application/json',
    ];

    $options = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => false,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 40,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ];

    if ($payload !== null) {
        $headers[] = 'Content-Type: application/json';
        $options[CURLOPT_POSTFIELDS] = json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );
    }

    $options[CURLOPT_HTTPHEADER] = $headers;
    curl_setopt_array($ch, $options);

    $raw = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if (!is_string($raw) || $raw === '') {
        throw new RuntimeException($curlError !== '' ? 'cf-network-error' : 'cf-empty-response');
    }

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('cf-invalid-json');
    }

    if ($httpCode < 200 || $httpCode >= 300 || empty($decoded['success'])) {
        $message = 'cf-api-error';
        if (isset($decoded['errors'][0]['message']) && is_string($decoded['errors'][0]['message'])) {
            $message = preg_replace(
                '/Bearer\s+[A-Za-z0-9._-]+/i',
                'Bearer [redacted]',
                $decoded['errors'][0]['message'],
            ) ?? 'cf-api-error';
        }

        throw new RuntimeException($message);
    }

    return $decoded;
}

function normalizePermissionName(string $value): string
{
    $value = strtolower($value);
    $value = str_replace(['&', '/', '-', '_', ':', '(', ')'], ' ', $value);
    $value = preg_replace('/[^a-z0-9]+/', ' ', $value) ?? '';
    $value = preg_replace('/\s+/', ' ', trim($value)) ?? '';

    return $value;
}

/**
 * @return list<string>
 */
function permissionNameTokens(string $value): array
{
    $normalized = normalizePermissionName($value);

    if ($normalized === '') {
        return [];
    }

    return explode(' ', $normalized);
}

function permissionNameContainsPhrase(string $name, string $phrase): bool
{
    $nameTokens = permissionNameTokens($name);
    $phraseTokens = permissionNameTokens($phrase);
    $phraseCount = count($phraseTokens);

    if ($nameTokens === [] || $phraseTokens === [] || $phraseCount > count($nameTokens)) {
        return false;
    }

    $lastStart = count($nameTokens) - $phraseCount;
    for ($offset = 0; $offset <= $lastStart; $offset++) {
        if (array_slice($nameTokens, $offset, $phraseCount) === $phraseTokens) {
            return true;
        }
    }

    return false;
}

function containsEveryKeyword(string $name, array $keywords): bool
{
    foreach ($keywords as $keyword) {
        if (!permissionNameContainsPhrase($name, (string) $keyword)) {
            return false;
        }
    }

    return true;
}

/**
 * @return list<array<string, mixed>>
 */
function desiredPermissionRows(): array
{
    return [
        [
            'ui_scope' => 'Account',
            'ui_permission' => 'Account Settings',
            'ui_access' => 'Read',
            'resource' => 'account',
            'api_scope' => 'com.cloudflare.api.account',
            'aliases' => ['Account Settings Read'],
            'keywords' => ['account', 'settings'],
            'access_aliases' => ['read'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Account',
            'ui_permission' => 'Zone',
            'ui_access' => 'Edit',
            'resource' => 'account',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Zone Write', 'Zone Edit'],
            'keywords' => ['zone'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Zone',
            'ui_access' => 'Read',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Zone Read'],
            'keywords' => ['zone'],
            'access_aliases' => ['read'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Zone',
            'ui_access' => 'Edit',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Zone Write', 'Zone Edit'],
            'keywords' => ['zone'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Zone Settings',
            'ui_access' => 'Read',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Zone Settings Read'],
            'keywords' => ['zone', 'settings'],
            'access_aliases' => ['read'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Zone Settings',
            'ui_access' => 'Edit',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Zone Settings Write', 'Zone Settings Edit'],
            'keywords' => ['zone', 'settings'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Cache Rules',
            'ui_access' => 'Read',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Cache Rules Read', 'Cache Rule Read', 'Zone Cache Rules Read'],
            'keywords' => ['cache rules'],
            'access_aliases' => ['read'],
            'keyword_fallback' => false,
            'required' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Cache Rules',
            'ui_access' => 'Edit',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Cache Rules Write', 'Cache Rules Edit', 'Cache Rule Write', 'Cache Rule Edit'],
            'keywords' => ['cache rules'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => false,
            'required' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'SSL and Certificates',
            'ui_access' => 'Edit',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => [
                'SSL and Certificates Write',
                'SSL and Certificates Edit',
                'SSL/TLS Write',
                'SSL/TLS Edit',
            ],
            'keywords' => ['ssl'],
            'access_aliases' => ['write', 'edit'],
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'DNS',
            'ui_access' => 'Edit',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['DNS Write', 'DNS Edit'],
            'keywords' => ['dns'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'DNS',
            'ui_access' => 'Read',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['DNS Read'],
            'keywords' => ['dns'],
            'access_aliases' => ['read'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Account',
            'ui_permission' => 'Rulesets',
            'ui_access' => 'Edit',
            'resource' => 'account',
            'api_scope' => 'com.cloudflare.api.account',
            'aliases' => ['Account Rulesets Write', 'Account Rulesets Edit', 'Rulesets Write', 'Rulesets Edit'],
            'keywords' => ['rulesets'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => true,
        ],
        [
            'ui_scope' => 'Account',
            'ui_permission' => 'Filter Lists',
            'ui_access' => 'Edit',
            'resource' => 'account',
            'api_scope' => 'com.cloudflare.api.account',
            'aliases' => ['Account Filter Lists Write', 'Account Filter Lists Edit', 'Filter Lists Write', 'Filter Lists Edit'],
            'keywords' => ['filter', 'lists'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => true,
            'required' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Cache Purge',
            'ui_access' => 'Purge',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Cache Purge', 'Cache Purge Purge', 'Purge Cache'],
            'keywords' => ['cache purge'],
            'access_aliases' => ['purge'],
            'keyword_fallback' => false,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Managed Headers',
            'ui_access' => 'Edit',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Managed Headers Write', 'Managed Headers Edit', 'Managed Transforms Write'],
            'keywords' => ['managed', 'headers'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => true,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Transform Rules',
            'ui_access' => 'Edit',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Transform Rules Write', 'Transform Rules Edit', 'Zone Transform Rules Write'],
            'keywords' => ['transform', 'rules'],
            'access_aliases' => ['write', 'edit'],
            'keyword_fallback' => true,
        ],
        [
            'ui_scope' => 'Zone',
            'ui_permission' => 'Zone WAF',
            'ui_access' => 'Edit',
            'resource' => 'zone',
            'api_scope' => 'com.cloudflare.api.account.zone',
            'aliases' => ['Zone WAF Write', 'Zone WAF Edit', 'WAF Write', 'WAF Edit'],
            'keywords' => ['waf'],
            'access_aliases' => ['write', 'edit'],
        ],
    ];
}

function groupAccessMatches(string $groupName, array $accessAliases): bool
{
    if ($accessAliases === []) {
        return true;
    }

    foreach ($accessAliases as $accessAlias) {
        $normalizedAccess = normalizePermissionName((string) $accessAlias);
        if ($normalizedAccess !== '' && permissionNameContainsPhrase($groupName, $normalizedAccess)) {
            return true;
        }
    }

    return false;
}

function aliasMatchesPermissionGroup(string $groupName, array $aliases): bool
{
    foreach ($aliases as $alias) {
        $aliasName = normalizePermissionName((string) $alias);

        if ($aliasName === '') {
            continue;
        }

        if ($groupName === $aliasName) {
            return true;
        }

        if (permissionNameContainsPhrase($groupName, $aliasName)) {
            return true;
        }
    }

    return false;
}

function groupMatches(
    array $group,
    string $scope,
    array $aliases,
    array $keywords,
    array $accessAliases,
    bool $keywordFallback,
): bool {
    $scopes = $group['scopes'] ?? null;
    if (!is_array($scopes) || !in_array($scope, $scopes, true)) {
        return false;
    }

    $groupName = isset($group['name']) && is_string($group['name']) ? normalizePermissionName($group['name']) : '';
    if ($groupName === '') {
        return false;
    }

    if (aliasMatchesPermissionGroup($groupName, $aliases)) {
        return true;
    }

    if (!$keywordFallback) {
        return false;
    }

    return $keywords !== []
        && containsEveryKeyword($groupName, $keywords)
        && groupAccessMatches($groupName, $accessAliases);
}

function resolveDesiredPermissionGroups(string $creatorToken): array
{
    $response = cfTokenRequest('GET', '/user/tokens/permission_groups', $creatorToken);
    $available = $response['result'] ?? [];

    if (!is_array($available)) {
        throw new RuntimeException('cf-permission-groups-unavailable');
    }

    $accountGroups = [];
    $zoneGroups = [];
    $missingRows = [];
    $optionalMissingRows = [];
    $matchedRows = [];
    $usedGroupIds = [];

    foreach (desiredPermissionRows() as $row) {
        $matched = null;

        foreach ($available as $group) {
            if (!is_array($group)) {
                continue;
            }

            if (
                groupMatches(
                    $group,
                    $row['api_scope'],
                    $row['aliases'],
                    $row['keywords'],
                    $row['access_aliases'] ?? [],
                    (bool) ($row['keyword_fallback'] ?? true),
                )
            ) {
                $matched = $group;
                break;
            }
        }

        if (!is_array($matched) || !isset($matched['id']) || !is_string($matched['id'])) {
            $missingRow = [
                'scope' => $row['ui_scope'],
                'permission' => $row['ui_permission'],
                'access' => $row['ui_access'],
            ];

            if (($row['required'] ?? true) === false) {
                $optionalMissingRows[] = $missingRow;
            } else {
                $missingRows[] = $missingRow;
            }

            continue;
        }

        $groupId = $matched['id'];
        if (isset($usedGroupIds[$groupId])) {
            continue;
        }

        $usedGroupIds[$groupId] = true;

        $permissionGroup = [
            'id' => $groupId,
            'name' => isset($matched['name']) && is_string($matched['name'])
                ? $matched['name']
                : $row['ui_permission'] . ' ' . $row['ui_access'],
        ];

        $matchedRows[] = [
            'scope' => $row['ui_scope'],
            'permission' => $row['ui_permission'],
            'access' => $row['ui_access'],
            'cloudflare_name' => $permissionGroup['name'],
        ];

        if ($row['resource'] === 'account') {
            $accountGroups[] = $permissionGroup;
        } else {
            $zoneGroups[] = $permissionGroup;
        }
    }

    return [
        'account_groups' => $accountGroups,
        'zone_groups' => $zoneGroups,
        'missing_rows' => $missingRows,
        'optional_missing_rows' => $optionalMissingRows,
        'matched_rows' => $matchedRows,
    ];
}

function createCloudflareToken(string $creatorToken, string $tokenName, array $resolvedGroups): array
{
    $policies = [];

    if (!empty($resolvedGroups['account_groups'])) {
        $policies[] = [
            'effect' => 'allow',
            'resources' => [
                'com.cloudflare.api.account.*' => '*',
            ],
            'permission_groups' => $resolvedGroups['account_groups'],
        ];
    }

    if (!empty($resolvedGroups['zone_groups'])) {
        $policies[] = [
            'effect' => 'allow',
            'resources' => [
                'com.cloudflare.api.account.zone.*' => '*',
            ],
            'permission_groups' => $resolvedGroups['zone_groups'],
        ];
    }

    if ($policies === []) {
        throw new RuntimeException('no-permission-groups-resolved');
    }

    $response = cfTokenRequest('POST', '/user/tokens', $creatorToken, [
        'name' => $tokenName,
        'policies' => $policies,
    ]);

    $result = isset($response['result']) && is_array($response['result']) ? $response['result'] : [];

    $newToken = '';
    foreach (['value', 'token', 'api_token'] as $key) {
        if (isset($result[$key]) && is_string($result[$key]) && $result[$key] !== '') {
            $newToken = $result[$key];
            break;
        }
    }

    if ($newToken === '') {
        throw new RuntimeException('cf-token-value-missing');
    }

    return [
        'token' => $newToken,
        'id' => isset($result['id']) && is_string($result['id']) ? $result['id'] : '',
        'name' => isset($result['name']) && is_string($result['name']) ? $result['name'] : $tokenName,
    ];
}

/**
 * @return array{err:string, status:int}
 */
function describeCfTokenFailure(string $message): array
{
    $normalized = strtolower($message);

    if (
        str_contains($normalized, 'unauthorized to access')
        || (str_contains($normalized, 'user') && str_contains($normalized, 'token') && str_contains($normalized, 'permission'))
        || str_contains($normalized, '9109')
    ) {
        return [
            'err' => 'Token CF ini tidak boleh membuat API token. Pakai token dengan izin "User → API Tokens → Edit", atau Global API Key, sebagai creator token.',
            'status' => 403,
        ];
    }

    if (
        str_contains($normalized, 'authentication error')
        || str_contains($normalized, 'invalid api token')
        || str_contains($normalized, 'invalid request headers')
        || str_contains($normalized, '6003')
        || str_contains($normalized, '1000')
    ) {
        return [
            'err' => 'Creator token tidak valid atau kedaluwarsa. Periksa kembali token CF yang dipakai.',
            'status' => 401,
        ];
    }

    if ($normalized === 'cf-network-error' || $normalized === 'cf-empty-response') {
        return [
            'err' => 'Gagal menghubungi Cloudflare (jaringan/timeout). Coba lagi.',
            'status' => 504,
        ];
    }

    return ['err' => 'cf-token-create-failed', 'status' => 502];
}

if (defined('CF_CREATE_TOKEN_TEST')) {
    return;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    jsonFail(405, 'method-not-allowed');
}

try {
    startExpectedSession();

    $context = authenticatedContext();
    if ($context['type'] === '') {
        jsonFail(403, 'unauthorized');
    }

    if (!csrfIsValid(requestCsrfToken())) {
        jsonFail(419, 'invalid-csrf');
    }

    /** @var PDO|null $pdo */
    $pdo = loadPdoConnection();
    loadEnvironment();

    $creatorToken = sanitizeCreatorToken((string) ($_POST['creator_token'] ?? ''));
    $accountId = sanitizeAccountId((string) ($_POST['cf_account_id'] ?? ''));

    if ($creatorToken === '' && $context['type'] === 'user' && $pdo instanceof PDO && $context['sub_id'] !== '') {
        $stmt = $pdo->prepare('SELECT cf_token, cf_account_id FROM `generate` WHERE sub_id = :sub_id LIMIT 1');
        $stmt->execute(['sub_id' => $context['sub_id']]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (is_array($row)) {
            $creatorToken = sanitizeCreatorToken(cf_token_decrypt((string) ($row['cf_token'] ?? '')));
            if ($accountId === '') {
                $accountId = sanitizeAccountId((string) ($row['cf_account_id'] ?? ''));
            }
        }
    }

    // CF_CREATOR_TOKEN is an account-wide Cloudflare credential — only an admin
    // session may fall back to it. A 'user' context with no stored cf_token and
    // no posted creator_token must stop at "missing-creator-token" below, not
    // silently mint a token from the shared admin credential.
    if ($creatorToken === '' && $context['type'] === 'admin') {
        $creatorToken = sanitizeCreatorToken(envValue('CF_CREATOR_TOKEN'));
    }

    if ($creatorToken === '') {
        jsonFail(422, 'missing-creator-token');
    }

    $rawTokenName = (string) ($_POST['token_name'] ?? '');
    $fallbackSubject = $context['type'] === 'user' ? $context['sub_id'] : 'ADMIN';
    $tokenName = sanitizeTokenName($rawTokenName, $fallbackSubject);

    $resolvedGroups = resolveDesiredPermissionGroups($creatorToken);
    $creationResult = createCloudflareToken($creatorToken, $tokenName, $resolvedGroups);

    jsonSuccess([
        'token' => $creationResult['token'],
        'id' => $creationResult['id'],
        'name' => $creationResult['name'],
        'matched_rows' => $resolvedGroups['matched_rows'],
        'missing_rows' => $resolvedGroups['missing_rows'],
    ]);
} catch (Throwable $e) {
    error_log('[CF_TOKEN_CREATE_ERROR] ' . $e->getMessage());
    $failure = describeCfTokenFailure($e->getMessage());
    jsonFail($failure['status'], $failure['err']);
}
