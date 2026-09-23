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

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

$lastId = (int) ($_GET['id'] ?? 0);
$scope  = stat_scope_sub_id();

// Cross-device claim: when this poller and another device's poller both see
// the same new lead within the same ~10s window, only the one that wins this
// atomic UPDATE plays audio/push — the other still receives the row (so its
// notification dock/lastId stay in sync) but is told to stay silent. Degrades
// to "everyone alerts" (pre-migration behavior) if the column isn't there yet.
function leadNotifiedAtColumnExists(PDO $pdo): bool
{
    static $exists = null;
    if ($exists !== null) {
        return $exists;
    }

    try {
        $stmt = $pdo->query(
            "SELECT 1 FROM information_schema.columns
             WHERE table_schema = DATABASE() AND table_name = 'leadreport' AND column_name = 'notified_at'
             LIMIT 1"
        );
        $exists = $stmt !== false && $stmt->fetchColumn() !== false;
    } catch (Throwable $e) {
        $exists = false;
    }

    return $exists;
}

try {
    $sql    = 'SELECT id, click_id, country, payout, currency_symbol, network, traffic, conversion_date FROM leadreport WHERE id > :last_id AND conversion_date = :today';
    $params = ['last_id' => $lastId, 'today' => gmdate('Y-m-d')]; // UTC "today": match conversion_date written in UTC
    if ($scope !== null) {
        $sql .= ' AND click_id = :scope';
        $params['scope'] = $scope;
    }
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
} catch (Throwable $e) {
    echo json_encode([]);
    exit;
}

$claimStmt = leadNotifiedAtColumnExists($pdo)
    ? $pdo->prepare('UPDATE leadreport SET notified_at = NOW() WHERE id = :id AND notified_at IS NULL')
    : null;

$rows = [];
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $silent = false;
    if ($claimStmt !== null) {
        try {
            $claimStmt->execute(['id' => (int) $row['id']]);
            $silent = $claimStmt->rowCount() === 0;
        } catch (Throwable $e) {
            $silent = false;
        }
    }

    $country = strtoupper((string) ($row['country'] ?? ''));
    if ($country === 'INVALID IP ADDRESS.') {
        $country = '';
    }

    $rawClickId = (string) ($row['click_id'] ?? '');
    if (!mb_check_encoding($rawClickId, 'UTF-8')) {
        $rawClickId = mb_convert_encoding($rawClickId, 'UTF-8', 'ISO-8859-1');
    }
    $clickId = strtoupper($rawClickId);

    $rows[] = [
        'id'              => (int) $row['id'],
        'click_id'        => $clickId,
        'audio'           => statUrl('/realtime/asd.mp3'),
        'img'             => statAssetUrl('/dist/notify.svg'),
        'country'         => $country,
        'payout'          => ((string) ($row['currency_symbol'] ?? '$')) . number_format((float) ($row['payout'] ?? 0), 2),
        'network'         => strtoupper((string) ($row['network'] ?? '')),
        'traffic'         => strtoupper((string) ($row['traffic'] ?? '')),
        'conversion_date' => (string) ($row['conversion_date'] ?? ''),
        'silent'          => $silent,
    ];
}

echo json_encode($rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
