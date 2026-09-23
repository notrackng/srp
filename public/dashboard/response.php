<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/env.php';

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require_once __DIR__ . '/../tracker_password.php';

const ADMIN_PANEL_CSRF_NAMESPACE = 'admin_panel';
// `password_plain` (display-only mirror) is returned for the dashboard show/hide toggle; the bcrypt
// `password` hash is never returned. Neither column is sortable/searchable.
const ADMIN_PANEL_ALLOWED_SORT_COLUMNS = ['id', 'sub_id', 'gen_url', 'sm_url'];

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

function adminPanelJson(array $payload, int $statusCode = 200): never
{
    http_response_code($statusCode);
    echo json_encode(
        $payload,
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
    );
    exit;
}

function adminPanelJsonError(int $statusCode, string $code): never
{
    adminPanelJson(['ok' => false, 'error' => $code], $statusCode);
}

function adminPanelLog(Throwable $e): void
{
    error_log('[admin-panel] response error: ' . $e->getMessage());
}

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function adminPanelIsHttpsRequest(): bool
{
    return srp_request_is_https();
}

function adminPanelFallbackStartSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    session_name('sslmgr_admin');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => adminPanelIsHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function adminPanelStartSession(): void
{
    if (function_exists('startAdminGuardSession')) {
        startAdminGuardSession();

        return;
    }

    adminPanelFallbackStartSession();
}

function adminPanelRequestCsrfToken(): ?string
{
    if (function_exists('requestCsrfToken')) {
        return requestCsrfToken();
    }

    $headerToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
    if (is_string($headerToken) && $headerToken !== '') {
        return $headerToken;
    }

    $postedToken = $_POST['csrf_token'] ?? $_POST['_csrf'] ?? null;

    return is_string($postedToken) && $postedToken !== '' ? $postedToken : null;
}

function adminPanelHasValidCsrf(?string $token): bool
{
    if (function_exists('hasValidSessionCsrf')) {
        return hasValidSessionCsrf(ADMIN_PANEL_CSRF_NAMESPACE, $token);
    }

    $storedToken = $_SESSION['csrf'][ADMIN_PANEL_CSRF_NAMESPACE] ?? null;

    return is_string($token) && is_string($storedToken) && hash_equals($storedToken, $token);
}

function adminPanelLoadSessionGuards(): void
{
    $guardPath = __DIR__ . '/../session_guards.php';
    if (is_file($guardPath) && is_readable($guardPath)) {
        include_once $guardPath;
    }
}

function adminPanelLoadPdo(): PDO
{
    $connectionPath = __DIR__ . '/../../connection_pdo.php';
    if (!is_file($connectionPath) || !is_readable($connectionPath)) {
        throw new RuntimeException('connection_pdo.php is not readable.');
    }

    if (!defined('SRP_DB_THROW_ON_CONNECT_FAILURE')) {
        define('SRP_DB_THROW_ON_CONNECT_FAILURE', true);
    }

    $pdo = require $connectionPath;
    if (!$pdo instanceof PDO) {
        throw new RuntimeException('connection_pdo.php did not return a PDO instance.');
    }

    return $pdo;
}

function adminPanelParams(): array
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        return $_POST;
    }

    return $_GET;
}

function adminPanelAssertPostForMutation(string $action): void
{
    if (in_array($action, ['add', 'edit', 'delete'], true) && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        adminPanelJsonError(405, 'method-not-allowed');
    }
}

function adminPanelList(PDO $pdo, array $params): array
{
    $rowCount = isset($params['rowCount']) ? (int) $params['rowCount'] : 100;
    if ($rowCount === 0 || $rowCount < -1) {
        $rowCount = 100;
    }

    $page = max(1, (int) ($params['current'] ?? 1));
    $offset = $rowCount === -1 ? 0 : (($page - 1) * $rowCount);
    $search = trim((string) ($params['searchPhrase'] ?? ''));

    $whereSql = '';
    $bindings = [];
    if ($search !== '') {
        $like = $search . '%';
        $whereSql = ' WHERE (sub_id LIKE :like1 OR gen_url LIKE :like2 OR sm_url LIKE :like3)';
        $bindings = [
            'like1' => $like,
            'like2' => $like,
            'like3' => $like,
        ];
    }

    $orderSql = ' ORDER BY id DESC';
    if (!empty($params['sort']) && is_array($params['sort'])) {
        $sortColumn = (string) key($params['sort']);
        $sortDirection = strtoupper((string) current($params['sort'])) === 'DESC' ? 'DESC' : 'ASC';
        if (in_array($sortColumn, ADMIN_PANEL_ALLOWED_SORT_COLUMNS, true)) {
            $orderSql = ' ORDER BY ' . $sortColumn . ' ' . $sortDirection;
        }
    }

    $countStmt = $pdo->prepare('SELECT COUNT(*) AS total FROM generate' . $whereSql);
    foreach ($bindings as $name => $value) {
        $countStmt->bindValue(':' . $name, $value, PDO::PARAM_STR);
    }
    $countStmt->execute();
    $countRow = $countStmt->fetch(PDO::FETCH_ASSOC) ?: ['total' => 0];

    $dataSql = 'SELECT id, sub_id, password_plain, gen_url, sm_url FROM generate' . $whereSql . $orderSql;
    if ($rowCount !== -1) {
        $dataSql .= ' LIMIT :limit_val OFFSET :offset_val';
    }

    $dataStmt = $pdo->prepare($dataSql);
    foreach ($bindings as $name => $value) {
        $dataStmt->bindValue(':' . $name, $value, PDO::PARAM_STR);
    }
    if ($rowCount !== -1) {
        $dataStmt->bindValue(':limit_val', $rowCount, PDO::PARAM_INT);
        $dataStmt->bindValue(':offset_val', $offset, PDO::PARAM_INT);
    }
    $dataStmt->execute();

    $rows = [];
    while ($row = $dataStmt->fetch(PDO::FETCH_ASSOC)) {
        $rows[] = $row;
    }

    return [
        'current' => $page,
        'rowCount' => $rowCount,
        'total' => (int) ($countRow['total'] ?? 0),
        'rows' => $rows,
    ];
}

function adminPanelInsert(PDO $pdo, array $params): void
{
    $subId = strtoupper(trim((string) ($params['sub_id'] ?? '')));
    $password = trim((string) ($params['password'] ?? ''));
    $genUrl = trim((string) ($params['gen_url'] ?? ''));
    $smUrl = strtoupper(trim((string) ($params['sm_url'] ?? '')));

    if ($subId === '' || $password === '' || $genUrl === '' || $smUrl === '') {
        adminPanelJsonError(422, 'missing-fields');
    }

    $stmt = $pdo->prepare(
        'INSERT INTO generate (sub_id, password, password_plain, gen_url, sm_url)'
        . ' VALUES (:sub_id, :password, :password_plain, :gen_url, :sm_url)',
    );
    $stmt->execute([
        'sub_id' => $subId,
        'password' => srp_tracker_password_hash($password),
        'password_plain' => $password,
        'gen_url' => $genUrl,
        'sm_url' => $smUrl,
    ]);

    adminPanelJson(['ok' => true]);
}

function adminPanelUpdate(PDO $pdo, array $params): void
{
    $id = (int) ($params['edit_id'] ?? 0);
    $subId = strtoupper(trim((string) ($params['edit_sub_id'] ?? '')));
    $password = trim((string) ($params['edit_password'] ?? ''));
    $genUrl = trim((string) ($params['edit_gen_url'] ?? ''));
    $smUrl = strtoupper(trim((string) ($params['edit_sm_url'] ?? '')));

    // Password is optional on edit: blank leaves the existing hash unchanged.
    if ($id < 1 || $subId === '' || $genUrl === '' || $smUrl === '') {
        adminPanelJsonError(422, 'missing-fields');
    }

    // Static column fragments only (no user input) — assemble once and bind values.
    $columns = ['sub_id = :sub_id', 'gen_url = :gen_url', 'sm_url = :sm_url'];
    $args = ['sub_id' => $subId, 'gen_url' => $genUrl, 'sm_url' => $smUrl, 'id' => $id];
    if ($password !== '') {
        $columns[] = 'password = :password';
        $columns[] = 'password_plain = :password_plain';
        $args['password'] = srp_tracker_password_hash($password);
        $args['password_plain'] = $password;
    }

    $stmt = $pdo->prepare('UPDATE generate SET ' . implode(', ', $columns) . ' WHERE id = :id');
    $stmt->execute($args);

    adminPanelJson(['ok' => true]);
}

function adminPanelDelete(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        adminPanelJsonError(422, 'invalid-id');
    }

    $stmt = $pdo->prepare('DELETE FROM generate WHERE id = :id');
    $stmt->bindValue(':id', $id, PDO::PARAM_INT);
    $stmt->execute();

    adminPanelJson(['ok' => true]);
}

try {
    adminPanelLoadSessionGuards();
    adminPanelStartSession();

    if (empty($_SESSION['admin_authenticated'])) {
        adminPanelJsonError(403, 'unauthorized');
    }

    $params = adminPanelParams();
    $action = (string) ($params['action'] ?? '');

    adminPanelAssertPostForMutation($action);

    if (in_array($action, ['add', 'edit', 'delete'], true) && !adminPanelHasValidCsrf(adminPanelRequestCsrfToken())) {
        adminPanelJsonError(419, 'invalid-csrf');
    }

    $pdo = adminPanelLoadPdo();

    switch ($action) {
        case 'add':
            adminPanelInsert($pdo, $params);
            break;
        case 'edit':
            adminPanelUpdate($pdo, $params);
            break;
        case 'delete':
            adminPanelDelete($pdo, $params);
            break;
        default:
            adminPanelJson(adminPanelList($pdo, $params));
    }
} catch (JsonException $e) {
    adminPanelLog($e);
    http_response_code(500);
    echo '{"ok":false,"error":"json-error"}';
    exit;
} catch (Throwable $e) {
    adminPanelLog($e);
    adminPanelJsonError(500, 'server-error');
}
