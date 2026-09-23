<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';
include_once __DIR__ . '/../session_guards.php';
// addonDnsResolves(): this path stores the row first and provisions cPanel
// later ("deferred"), so without a check here a domain that can never be
// attached is persisted anyway.
require_once __DIR__ . '/../api/cpanel_addon_lib.php';
require_once dirname(__DIR__, 2) . '/domain_readiness.php';

header('Content-Type: application/json; charset=utf-8');

function adminDomainParams(): array
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        return $_POST;
    }

    return $_GET;
}

function ensureCfColumns(PDO $pdo): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    foreach (['cf_zone_id', 'cf_status', 'cf_ns'] as $column) {
        $stmt = $pdo->prepare(
            'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = :table_name AND column_name = :column_name LIMIT 1',
        );
        $stmt->execute(['table_name' => 'addondomain', 'column_name' => $column]);
        $exists = $stmt->fetchColumn() !== false;

        if (!$exists) {
            jsonError(500, 'schema-not-installed');
        }
    }
}

function adminHasCertColumn(PDO $pdo): bool
{
    static $cache = null;
    if (is_bool($cache)) {
        return $cache;
    }

    $stmt = $pdo->prepare(
        'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = :table_name AND column_name = :column_name LIMIT 1',
    );
    $stmt->execute(['table_name' => 'addondomain', 'column_name' => 'cf_cert_installed']);
    $result = $stmt->fetchColumn() !== false;
    $cache = $result;

    return $result;
}

function adminNormalizeSubDomain(string $value): ?string
{
    $subDomain = strtoupper(trim($value));
    if ($subDomain === '') {
        return null;
    }

    if ($subDomain === 'GLOBAL') {
        return 'GLOBAL';
    }

    if (preg_match('/^[A-Z0-9_-]{1,64}$/', $subDomain) !== 1) {
        return null;
    }

    return $subDomain;
}

function adminNormalizeAddonDomainInput(string $value): ?string
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

function adminBoolParam(array $params, string $key, bool $default): bool
{
    if (!array_key_exists($key, $params)) {
        return $default;
    }

    $value = strtolower(trim((string) $params[$key]));
    if (in_array($value, ['0', 'false', 'off', 'no'], true)) {
        return false;
    }

    if (in_array($value, ['1', 'true', 'on', 'yes'], true)) {
        return true;
    }

    return $default;
}

/**
 * @return array<string, mixed>
 */
function adminSyncCloudflareForDomain(PDO $pdo, int $id): array
{
    if (!defined('ADDON_CF_NO_ROUTER')) {
        define('ADDON_CF_NO_ROUTER', true);
    }

    require_once __DIR__ . '/cf.php';

    if (!function_exists('cfProvisionAddonDomainZone')) {
        return ['ok' => false, 'err' => 'cf-sync-unavailable'];
    }

    $result = cfProvisionAddonDomainZone($pdo, $id);
    if (empty($result['ok'])) {
        return [
            'ok' => false,
            'err' => (string) ($result['err'] ?? 'cf-sync-failed'),
            'status_code' => (int) ($result['status_code'] ?? 500),
        ];
    }

    return $result;
}

function adminDomainList(PDO $pdo, array $params): array
{
    ensureCfColumns($pdo);

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
        $whereSql = ' WHERE (sub_domain LIKE :like1 OR domain LIKE :like2)';
        $bindings = ['like1' => $like, 'like2' => $like];
    }

    $orderSql = ' ORDER BY id DESC';
    if (!empty($params['sort']) && is_array($params['sort'])) {
        $sortColumn = (string) key($params['sort']);
        $sortDirection = strtoupper((string) current($params['sort'])) === 'DESC' ? 'DESC' : 'ASC';
        if (in_array($sortColumn, ['id', 'sub_domain', 'domain'], true)) {
            $orderSql = ' ORDER BY ' . $sortColumn . ' ' . $sortDirection;
        }
    }

    $countStmt = $pdo->prepare('SELECT COUNT(*) AS total FROM addondomain' . $whereSql);
    $countStmt->execute($bindings);
    $countRow = $countStmt->fetch(PDO::FETCH_ASSOC) ?: ['total' => 0];

    $certSelect = adminHasCertColumn($pdo)
        ? ', COALESCE(cf_cert_installed, 0) AS cf_cert_installed'
        : ', 0 AS cf_cert_installed';
    $dataSql = 'SELECT id, sub_domain, domain, COALESCE(cf_zone_id,\'\') AS cf_zone_id, COALESCE(cf_status,\'\') AS cf_status, COALESCE(cf_ns,\'\') AS cf_ns' . $certSelect . ' FROM addondomain' . $whereSql . $orderSql;
    if ($rowCount !== -1) {
        $dataSql .= ' LIMIT :limit_val OFFSET :offset_val';
    }

    $dataStmt = $pdo->prepare($dataSql);
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
    $rows = srpAnnotateAddonDomainRows($rows, trim(app_env('CF_SERVER_IP', '')));

    return [
        'current' => $page,
        'rowCount' => $rowCount,
        'total' => (int) ($countRow['total'] ?? 0),
        'rows' => $rows,
    ];
}

function adminDomainInsert(PDO $pdo, array $params): void
{
    ensureCfColumns($pdo);

    $subDomain = adminNormalizeSubDomain((string) ($params['sub_domain'] ?? ''));
    $domain = adminNormalizeAddonDomainInput((string) ($params['domain'] ?? ''));
    $syncCf = adminBoolParam($params, 'sync_cf', true);

    if ($subDomain === null || $domain === null) {
        jsonError(422, 'invalid-domain');
    }

    $existingStmt = $pdo->prepare(
        'SELECT id FROM addondomain WHERE sub_domain = :sub_domain AND domain = :domain ORDER BY id ASC LIMIT 1',
    );
    $existingStmt->execute(['sub_domain' => $subDomain, 'domain' => $domain]);
    $existingId = (int) ($existingStmt->fetchColumn() ?: 0);
    $inserted = false;

    if ($existingId > 0) {
        $id = $existingId;
    } else {
        // Light gate only — this path defers cPanel on purpose, so the domain is
        // not expected to point here yet; cPanel's own park step is the final say.
        // Only a new row is gated; an already-stored domain stays listed even if
        // its DNS changes later, so re-submitting it is not turned into an error.
        $dns = addonDnsResolves($domain);
        if (!$dns['ok']) {
            error_log('adminDomainInsert: refused unresolvable domain=' . $domain . ' reason=' . addonSafeLogText($dns['error']));
            jsonError(422, $dns['error']);
        }

        try {
            $stmt = $pdo->prepare('INSERT INTO addondomain (sub_domain, domain) VALUES (:sub_domain, :domain)');
            $stmt->execute(['sub_domain' => $subDomain, 'domain' => $domain]);
            $id = (int) $pdo->lastInsertId();
            $inserted = true;
        } catch (PDOException $e) {
            if ($e->getCode() !== '23000') {
                throw $e;
            }

            $existingStmt->execute(['sub_domain' => $subDomain, 'domain' => $domain]);
            $id = (int) ($existingStmt->fetchColumn() ?: 0);
            if ($id < 1) {
                throw $e;
            }
        }
    }

    // cPanel stays deferred here on purpose: the admin UI chains this insert to
    // cpanel-add.php (cpanelSync) and then to the Cloudflare sync. Provisioning
    // here as well would run park + wildcard twice for every add.
    echo json_encode([
        'ok' => true,
        'id' => $id,
        'domain' => $domain,
        'existing' => !$inserted,
        'cpanel' => ['ok' => false, 'deferred' => true],
        'cf' => ['ok' => false, 'deferred' => $syncCf],
    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
}

function adminDomainUpdate(PDO $pdo, array $params): void
{
    $id = (int) ($params['edit_id'] ?? 0);
    $subDomain = adminNormalizeSubDomain((string) ($params['edit_sub_domain'] ?? ''));
    $domain = adminNormalizeAddonDomainInput((string) ($params['edit_domain'] ?? ''));

    if ($id < 1 || $subDomain === null || $domain === null) {
        jsonError(422, 'missing-fields');
    }

    $currentStmt = $pdo->prepare(
        'SELECT sub_domain, domain FROM addondomain WHERE id = :id LIMIT 1',
    );
    $currentStmt->execute(['id' => $id]);
    $current = $currentStmt->fetch(PDO::FETCH_ASSOC);
    if (!is_array($current)) {
        jsonError(404, 'not-found');
    }

    $duplicateStmt = $pdo->prepare(
        'SELECT 1 FROM addondomain WHERE sub_domain = :sub_domain AND domain = :domain AND id <> :id LIMIT 1',
    );
    $duplicateStmt->execute([
        'sub_domain' => $subDomain,
        'domain' => $domain,
        'id' => $id,
    ]);
    if ($duplicateStmt->fetchColumn() !== false) {
        jsonError(409, 'domain-already-exists');
    }

    $domainChanged = strtolower((string) ($current['domain'] ?? '')) !== $domain
        || strtoupper((string) ($current['sub_domain'] ?? '')) !== $subDomain;
    $setSql = 'sub_domain = :sub_domain, domain = :domain';
    $bindings = [
        'sub_domain' => $subDomain,
        'domain' => $domain,
        'id' => $id,
    ];

    // A zone belongs to the old hostname. Clear its local association when the
    // hostname changes so the next sync cannot apply the old zone to the new one.
    if ($domainChanged) {
        $setSql .= ', cf_zone_id = :cf_zone_id, cf_status = :cf_status, cf_ns = :cf_ns';
        $bindings['cf_zone_id'] = '';
        $bindings['cf_status'] = '';
        $bindings['cf_ns'] = '[]';
        if (adminHasCertColumn($pdo)) {
            $setSql .= ', cf_cert_installed = :cf_cert_installed';
            $bindings['cf_cert_installed'] = 0;
        }
    }

    $stmt = $pdo->prepare('UPDATE addondomain SET ' . $setSql . ' WHERE id = :id');
    $stmt->execute($bindings);

    echo json_encode(
        ['ok' => true, 'domain' => $domain, 'cf_reset' => $domainChanged],
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
    );
}

function adminDomainDelete(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $stmt = $pdo->prepare('DELETE FROM addondomain WHERE id = :id');
    $stmt->execute(['id' => $id]);

    echo json_encode(['ok' => true], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
}

try {
    startAdminGuardSession();
    if (empty($_SESSION['admin_authenticated'])) {
        jsonError(403, 'unauthorized');
    }

    $params = adminDomainParams();
    $action = (string) ($params['action'] ?? '');

    if (in_array($action, ['add', 'edit', 'delete'], true) && ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        jsonError(405, 'method-not-allowed');
    }

    if (in_array($action, ['add', 'edit', 'delete'], true) && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    switch ($action) {
        case 'add':
            adminDomainInsert($pdo, $params);
            break;
        case 'edit':
            adminDomainUpdate($pdo, $params);
            break;
        case 'delete':
            adminDomainDelete($pdo, $params);
            break;
        default:
            echo json_encode(adminDomainList($pdo, $params), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
            break;
    }
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
