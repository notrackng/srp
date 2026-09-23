<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';
include_once __DIR__ . '/../session_guards.php';

header('Content-Type: application/json; charset=utf-8');

function slEnsureTable(PDO $pdo): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    foreach (['code', 'long_url', 'og_title', 'og_image', 'created_at'] as $column) {
        $stmt = $pdo->prepare(
            'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = :table_name AND column_name = :column_name LIMIT 1',
        );
        $stmt->execute(['table_name' => 'shortlinks', 'column_name' => $column]);
        $exists = $stmt->fetchColumn() !== false;

        if (!$exists) {
            jsonError(500, 'schema-not-installed');
        }
    }
}

try {
    startAdminGuardSession();
    if (empty($_SESSION['admin_authenticated'])) {
        jsonError(403, 'unauthorized');
    }

    $params = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
    $action = trim((string) ($params['action'] ?? ''));

    if ($action !== '' && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    slEnsureTable($pdo);

    if ($action === 'delete') {
        $code = trim((string) ($params['code'] ?? ''));
        if ($code === '' || preg_match('/^[A-Za-z0-9_-]{1,14}$/', $code) !== 1) {
            jsonError(422, 'invalid-code');
        }
        $stmt = $pdo->prepare('DELETE FROM shortlinks WHERE code = :code');
        $stmt->execute(['code' => $code]);
        echo json_encode(['ok' => true]);
        exit;
    }

    // List (paginated)
    $rowCount = isset($params['rowCount']) ? (int) $params['rowCount'] : 25;
    if ($rowCount === 0 || $rowCount < -1) {
        $rowCount = 25;
    }
    $page    = max(1, (int) ($params['current'] ?? 1));
    $offset  = $rowCount === -1 ? 0 : (($page - 1) * $rowCount);
    $search  = trim((string) ($params['searchPhrase'] ?? ''));

    $where    = '';
    $bindings = [];
    if ($search !== '') {
        $like     = '%' . $search . '%';
        $where    = ' WHERE (code LIKE :like1 OR og_title LIKE :like2 OR long_url LIKE :like3)';
        $bindings = ['like1' => $like, 'like2' => $like, 'like3' => $like];
    }

    $cStmt = $pdo->prepare('SELECT COUNT(*) AS total FROM shortlinks' . $where);
    if (!$cStmt) {
        jsonError(500, 'db-error');
    }
    $cStmt->execute($bindings);
    $cRow  = $cStmt->fetch(PDO::FETCH_ASSOC);
    $total = (int) ($cRow['total'] ?? 0);

    $sql   = 'SELECT code, long_url, og_title, created_at FROM shortlinks' . $where . ' ORDER BY created_at DESC';
    if ($rowCount !== -1) {
        $sql       .= ' LIMIT :limit_val OFFSET :offset_val';
    }

    $dStmt = $pdo->prepare($sql);
    if (!$dStmt) {
        jsonError(500, 'db-error');
    }
    foreach ($bindings as $name => $value) {
        $dStmt->bindValue(':' . $name, $value, PDO::PARAM_STR);
    }
    // LIMIT/OFFSET must bind as PDO::PARAM_INT. connection_pdo.php disables
    // emulated prepares, so MySQL parses these placeholders natively and
    // rejects a string-typed value with a 1064 syntax error. Same pattern as
    // public/dashboard/response.php.
    if ($rowCount !== -1) {
        $dStmt->bindValue(':limit_val', $rowCount, PDO::PARAM_INT);
        $dStmt->bindValue(':offset_val', $offset, PDO::PARAM_INT);
    }
    $dStmt->execute();

    $rows = [];
    while ($row = $dStmt->fetch(PDO::FETCH_ASSOC)) {
        $host      = (string) parse_url((string) $row['long_url'], PHP_URL_HOST);
        // Display-only: shown as http:// per operator preference. Does not
        // affect Cloudflare's always_use_https zone setting or actual TLS/
        // redirect behavior for the link itself — only this admin-panel text.
        $shortUrl  = $host !== '' ? 'http://' . $host . '/s-' . $row['code'] : '';
        $ts        = (int) $row['created_at'];
        $rows[] = [
            'code'       => $row['code'],
            'short_url'  => $shortUrl,
            'og_title'   => $row['og_title'],
            'long_url'   => $row['long_url'],
            'created_at' => $ts > 0 ? date('Y-m-d H:i', $ts) : '',
        ];
    }

    echo json_encode(['rows' => $rows, 'total' => $total, 'current' => $page]);
} catch (Throwable $e) {
    jsonError(500, 'server-error');
}
