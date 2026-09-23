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

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

function cleanText(mixed $value, int $maxLength = 160): string
{
    if (!is_scalar($value)) {
        return '';
    }

    $text = trim((string) $value);
    $text = preg_replace('/[\x00-\x1F\x7F]/', '', $text) ?? '';
    $text = strip_tags($text);

    if (strlen($text) > $maxLength) {
        $text = substr($text, 0, $maxLength);
    }

    return $text;
}

function cleanCode(mixed $value, int $maxLength = 32): string
{
    $text = strtoupper(cleanText($value, $maxLength));
    $text = preg_replace('/[^A-Z0-9_-]/', '', $text) ?? '';

    return substr($text, 0, $maxLength);
}

function cleanKey(mixed $value, int $maxLength = 64): string
{
    $text = strtolower(cleanText($value, $maxLength));
    $text = preg_replace('/[^a-z0-9_-]/', '', $text) ?? '';

    return substr($text, 0, $maxLength);
}

function cleanIp(mixed $value): string
{
    $text = cleanText($value, 64);

    if (filter_var($text, FILTER_VALIDATE_IP)) {
        return $text;
    }

    return '';
}

function readJsonRows(string $filename): array
{
    if (!is_file($filename) || !is_readable($filename)) {
        return [];
    }

    $json = file_get_contents($filename);
    if (!is_string($json) || trim($json) === '') {
        return [];
    }

    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        return [];
    }

    return $decoded;
}

function networkMeta(string $key): array
{
    // PNG, matching the network icons the realtime grid already serves via
    // data.php (/dist/lp.png etc. resolve to these same /assets/img files), so
    // the notification and the table show the identical artwork.
    $map = [
        'lospollos' => [
            'label' => 'LosPollos',
            'icon' => statAssetUrl('/assets/img/lp.png'),
        ],
        'imonetizeit' => [
            'label' => 'iMonetizeIt',
            'icon' => statAssetUrl('/assets/img/imo.png'),
        ],
        'trafee' => [
            'label' => 'Trafee',
            'icon' => statAssetUrl('/assets/img/tf.png'),
        ],
        'torazzo' => [
            'label' => 'Torazzo',
            'icon' => statAssetUrl('/assets/img/custom.svg'),
        ],
        'custom' => [
            'label' => 'Custom',
            'icon' => statAssetUrl('/assets/img/custom.svg'),
        ],
    ];

    return $map[$key] ?? [
        'label' => $key,
        'icon' => '',
    ];
}

$lastId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!is_int($lastId) || $lastId < 0) {
    $lastId = 0;
}

// Click log is always at {project_root}/statistics/temp/YYYY-MM-DD.json
$filename = dirname(__DIR__, 2) . '/statistics/temp/' . gmdate('Y-m-d') . '.json'; // UTC: match the click-log writer's day
$result = readJsonRows($filename);

$page = [];

// Per-tracker partition. The click log is shared by every tracker, so a scoped
// session must not be served another tracker's rows. Out-of-scope rows are
// skipped and the poller advances past them: the next IN-SCOPE id greater than
// $lastId is selected instead of exactly $lastId + 1, otherwise a scoped
// session would stall forever on the first foreign row. The client already
// takes max(id) of the response as its new cursor, so a skipped id is safe.
// For an admin session (null scope) the ids are sequential, so the selected
// row is $lastId + 1 exactly as before. See stat_path.php.
$nextRow = null;
$nextRowId = 0;

foreach ($result as $row) {
    if (!is_array($row)) {
        continue;
    }

    $rowId = isset($row['id']) ? (int) $row['id'] : 0;

    if ($rowId <= $lastId || !stat_click_log_row_in_scope($row)) {
        continue;
    }

    if ($nextRow === null || $rowId < $nextRowId) {
        $nextRow = $row;
        $nextRowId = $rowId;
    }
}

if ($nextRow !== null) {
    $row = $nextRow;
    $rowId = $nextRowId;

    $clickId = cleanCode($row['click_id'] ?? '', 80);
    // The client derives the sprite class from country_code alone
    // (flagClassName in realtime/index.php), so no flag class or emoji is sent.
    $countryCode = cleanCode($row['country_code'] ?? '', 2);

    $networkKey = cleanKey($row['info'] ?? '', 80);
    $network = networkMeta($networkKey);

    $ipAddress = cleanIp($row['ip_address'] ?? '');
    $rowTime = cleanText($row['time'] ?? '', 32);

    // $rowId is already > $lastId >= 0 by the selector above, so only the
    // click id still needs checking.
    if ($clickId !== '') {
        $page[] = [
            'id' => $rowId,
            'click_id' => $clickId,

            'country_code' => $countryCode,

            'network' => $network['label'],
            'network_icon' => $network['icon'],

            'ip_address' => $ipAddress,
            'time' => $rowTime,
        ];
    }
}

echo json_encode(
    $page,
    JSON_UNESCAPED_SLASHES
    | JSON_UNESCAPED_UNICODE
    | JSON_INVALID_UTF8_SUBSTITUTE,
);
