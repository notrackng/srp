<?php

declare(strict_types=1);

include_once __DIR__ . '/../login.php';

// Auth is settled; drop the session lock immediately. PHP holds an EXCLUSIVE
// lock on the session file for the whole request, and the realtime page runs
// several pollers at once — without this they serialise behind each other and
// a slow one can stall the rest into an origin timeout. This endpoint never
// touches $_SESSION again.
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode([
        'ok'    => false,
        'error' => 'Method not allowed',
    ]);
    exit;
}

if (!isset($_GET['start'], $_GET['end'])) {
    http_response_code(400);
    echo json_encode([
        'ok'    => false,
        'error' => 'Missing start or end parameter',
    ]);
    exit;
}

$start = trim((string) ($_GET['start'] ?? ''));
$end   = trim((string) ($_GET['end'] ?? ''));

if (!isValidDateYmd($start) || !isValidDateYmd($end)) {
    http_response_code(400);
    echo json_encode([
        'ok'    => false,
        'error' => 'Invalid date format, expected YYYY-MM-DD',
    ]);
    exit;
}

$scope    = stat_scope_sub_id();
$scopeSql = $scope !== null ? ' AND click_id = :scope' : '';

$sql = <<<SQL
SELECT
    click_id,
    SUM(clicks)                             AS clicks,
    SUM(leads)                              AS leads,
    SUM(CAST(payout AS DECIMAL(18,2)))      AS payout,
    MAX(click_date)                         AS last_click_date
FROM clickrecord
WHERE click_date BETWEEN :start AND :end{$scopeSql}
GROUP BY click_id
ORDER BY last_click_date DESC
SQL;

$params = ['start' => $start, 'end' => $end];
if ($scope !== null) {
    $params['scope'] = $scope;
}

try {
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        'ok'    => false,
        'error' => 'Database error',
    ]);
    exit;
}

$response = [
    'ok'   => true,
    'data' => [],
];

$index = 1;

while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $clicks = isset($row['clicks']) ? (int) $row['clicks'] : 0;
    $leads  = isset($row['leads']) ? (int) $row['leads'] : 0;
    $payout = isset($row['payout']) ? (float) $row['payout'] : 0.0;

    $cr = 0.0;
    if ($clicks > 0) {
        $cr = ($leads / $clicks) * 100.0;
    }

    $rawClickId = (string) ($row['click_id'] ?? '');
    $cleanClickId = strtoupper(preg_replace('/[^A-Za-z0-9_\-]/', '', $rawClickId));

    $response['data'][] = [
        'id'       => $index++,
        'click_id' => $cleanClickId,
        'clicks'   => $clicks,
        'leads'    => $leads,
        'payout'   => $payout,
        'cr'       => round($cr, 2),
    ];
}

echo json_encode(
    $response,
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES,
);
exit;

/**
 * Validasi format tanggal YYYY-MM-DD.
 */
function isValidDateYmd(string $date): bool
{
    if ($date === '') {
        return false;
    }

    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
        return false;
    }

    $parts = explode('-', $date);
    if (count($parts) !== 3) {
        return false;
    }

    [$year, $month, $day] = $parts;

    return checkdate((int) $month, (int) $day, (int) $year);
}
