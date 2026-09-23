<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';
include_once __DIR__ . '/../session_guards.php';

header('Content-Type: application/json; charset=utf-8');

function adminCampaignParams(): array
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        return $_POST;
    }

    return $_GET;
}

function adminCampaignList(PDO $pdo, array $params): array
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
        $whereSql = ' WHERE (country_code LIKE :like1 OR ua LIKE :like2 OR offer LIKE :like3 OR network LIKE :like4)';
        $bindings = ['like1' => $like, 'like2' => $like, 'like3' => $like, 'like4' => $like];
    }

    $orderSql = ' ORDER BY id DESC';
    if (!empty($params['sort']) && is_array($params['sort'])) {
        $sortColumn = (string) key($params['sort']);
        $sortDirection = strtoupper((string) current($params['sort'])) === 'DESC' ? 'DESC' : 'ASC';
        if (in_array($sortColumn, ['id', 'country_code', 'ua', 'offer', 'network'], true)) {
            $orderSql = ' ORDER BY ' . $sortColumn . ' ' . $sortDirection;
        }
    }

    $countStmt = $pdo->prepare('SELECT COUNT(*) AS total FROM offering' . $whereSql);
    if (!$countStmt) {
        throw new RuntimeException('Failed to prepare count query.');
    }
    $countStmt->execute($bindings);
    $countRow = $countStmt->fetch(PDO::FETCH_ASSOC) ?: ['total' => 0];

    $dataSql = 'SELECT id, country_code, ua, offer, network FROM offering' . $whereSql . $orderSql;
    if ($rowCount !== -1) {
        $dataSql .= ' LIMIT :limit_val OFFSET :offset_val';
    }

    $dataStmt = $pdo->prepare($dataSql);
    if (!$dataStmt) {
        throw new RuntimeException('Failed to prepare list query.');
    }
    foreach ($bindings as $name => $value) {
        $dataStmt->bindValue(':' . $name, $value, PDO::PARAM_STR);
    }
    // LIMIT/OFFSET must bind as PDO::PARAM_INT. connection_pdo.php disables
    // emulated prepares, so MySQL parses these placeholders natively and
    // rejects a string-typed value with a 1064 syntax error. Same pattern as
    // public/dashboard/response.php.
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

function adminCampaignInsert(PDO $pdo, array $params): void
{
    $countryCode = strtoupper(trim((string) ($params['country_code'] ?? '')));
    $ua = strtoupper(trim((string) ($params['ua'] ?? '')));
    $offer = trim((string) ($params['offer'] ?? ''));
    $network = trim((string) ($params['network'] ?? ''));

    if ($countryCode === '' || $ua === '' || $offer === '' || $network === '') {
        jsonError(422, 'missing-fields');
    }

    $stmt = $pdo->prepare('INSERT INTO offering (country_code, offer, ua, network) VALUES (:country_code, :offer, :ua, :network)');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare insert query.');
    }
    $stmt->execute(['country_code' => $countryCode, 'offer' => $offer, 'ua' => $ua, 'network' => $network]);

    echo json_encode(['ok' => true], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
}

function adminCampaignUpdate(PDO $pdo, array $params): void
{
    $id = (int) ($params['edit_id'] ?? 0);
    $countryCode = strtoupper(trim((string) ($params['edit_country_code'] ?? '')));
    $ua = strtoupper(trim((string) ($params['edit_ua'] ?? '')));
    $offer = trim((string) ($params['edit_offer'] ?? ''));
    $network = trim((string) ($params['edit_network'] ?? ''));

    if ($id < 1 || $countryCode === '' || $ua === '' || $offer === '' || $network === '') {
        jsonError(422, 'missing-fields');
    }

    $stmt = $pdo->prepare('UPDATE offering SET country_code = :country_code, ua = :ua, offer = :offer, network = :network WHERE id = :id');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare update query.');
    }
    $stmt->execute(['country_code' => $countryCode, 'ua' => $ua, 'offer' => $offer, 'network' => $network, 'id' => $id]);

    echo json_encode(['ok' => true], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
}

function adminCampaignDelete(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $stmt = $pdo->prepare('DELETE FROM offering WHERE id = :id');
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare delete query.');
    }
    $stmt->execute(['id' => $id]);

    echo json_encode(['ok' => true], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
}

try {
    startAdminGuardSession();
    if (empty($_SESSION['admin_authenticated'])) {
        jsonError(403, 'unauthorized');
    }

    $params = adminCampaignParams();
    $action = (string) ($params['action'] ?? '');

    if (in_array($action, ['add', 'edit', 'delete'], true) && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        jsonError(405, 'method-not-allowed');
    }

    if (in_array($action, ['add', 'edit', 'delete'], true) && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    switch ($action) {
        case 'add':
            adminCampaignInsert($pdo, $params);
            break;
        case 'edit':
            adminCampaignUpdate($pdo, $params);
            break;
        case 'delete':
            adminCampaignDelete($pdo, $params);
            break;
        default:
            echo json_encode(adminCampaignList($pdo, $params), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
            break;
    }
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
