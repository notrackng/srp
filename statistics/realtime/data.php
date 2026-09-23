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

function rtSendSecurityHeaders(string $nonce = ''): void
{
    if (headers_sent()) {
        return;
    }

    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
}

function rtOutputJson(array $payload): void
{
    $json = json_encode(
        $payload,
        JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE,
    );

    if ($json === false) {
        echo '{"data":[]}';

        return;
    }

    echo $json;
}

function rtNormalizeUtf8(string $value): string
{
    if ($value === '') {
        return '';
    }

    if (preg_match('//u', $value) === 1) {
        return $value;
    }

    if (function_exists('mb_convert_encoding')) {
        $converted = mb_convert_encoding($value, 'UTF-8', 'UTF-8, ISO-8859-1, Windows-1252');

        if (is_string($converted) && preg_match('//u', $converted) === 1) {
            return $converted;
        }
    }

    if (function_exists('iconv')) {
        $converted = iconv('Windows-1252', 'UTF-8//IGNORE', $value);

        if (is_string($converted) && preg_match('//u', $converted) === 1) {
            return $converted;
        }

        $converted = iconv('ISO-8859-1', 'UTF-8//IGNORE', $value);

        if (is_string($converted) && preg_match('//u', $converted) === 1) {
            return $converted;
        }
    }

    return '';
}

function rtEscapeHtml(string $value): string
{
    return htmlspecialchars(rtNormalizeUtf8($value), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function rtSvgImg(string $src, string $title = '', int $size = 12): string
{
    return '<img src="' . rtEscapeHtml(statAssetUrl($src)) . '" width="' . $size . '" height="' . $size . '" class="rt-icon" alt="" title="' . rtEscapeHtml($title) . '">';
}

function rtStringLength(string $value): int
{
    $normalized = rtNormalizeUtf8($value);

    if (function_exists('mb_strlen')) {
        return mb_strlen($normalized, 'UTF-8');
    }

    return strlen($normalized);
}

rtSendSecurityHeaders();

try {
    /** @var PDO $pdo */
    $pdo = require __DIR__ . '/../../connection_pdo.php';

    if (!isset($_GET['date']) || !is_string($_GET['date'])) {
        rtOutputJson(['data' => []]);
        exit;
    }

    $dateRaw = $_GET['date'];
    $dateParam = $dateRaw === '2' ? 'yesterday' : 'today';
    $conversionDate = date('Y-m-d', strtotime($dateParam));

    $scope       = stat_scope_sub_id();
    $scopeSql    = $scope !== null ? ' AND click_id = :scope' : '';
    $scopeParams = $scope !== null ? ['scope' => $scope] : [];

    $topClickId = null;

    try {
        $sqlTop = '
            SELECT click_id, SUM(payout) AS total_payout
            FROM leadreport
            WHERE conversion_date = :date' . $scopeSql . '
            GROUP BY click_id
            ORDER BY total_payout DESC
            LIMIT 1
        ';

        $stmtTop = $pdo->prepare($sqlTop);
        $stmtTop->execute(array_merge(['date' => $conversionDate], $scopeParams));
        $rowTop = $stmtTop->fetch(PDO::FETCH_ASSOC);

        if ($rowTop !== false && $rowTop !== null) {
            $topClickId = (string) ($rowTop['click_id'] ?? '');
        }
    } catch (Throwable $e) {
        // Silently proceed without top click ID
    }

    $sql = '
    SELECT
        id,
        click_id,
        ip_address,
        country,
        traffic,
        currency_symbol,
        payout,
        conversion_date,
        network
    FROM leadreport
    WHERE conversion_date = :date' . $scopeSql . '
    ORDER BY id DESC
';

    $stmt = $pdo->prepare($sql);
    $stmt->execute(array_merge(['date' => $conversionDate], $scopeParams));

    $response = [
        'data' => [],
    ];

    $number = 1;

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $clickIdRaw = rtNormalizeUtf8((string) ($row['click_id'] ?? ''));
        $networkRaw = strtoupper(rtNormalizeUtf8((string) ($row['network'] ?? '')));
        $trafficRaw = strtoupper(rtNormalizeUtf8((string) ($row['traffic'] ?? '')));
        $countryRaw = strtoupper(rtNormalizeUtf8((string) ($row['country'] ?? '')));

        $idClickDisplay = rtSvgImg('/dist/flag_placeholder.png', 'User') . ' ' . rtEscapeHtml($clickIdRaw);

        if ($topClickId !== null && $clickIdRaw === $topClickId) {
            $idClickDisplay = rtSvgImg('/dist/top.svg', 'Top Earner') . ' ' . rtEscapeHtml($clickIdRaw);
        }

        if ($clickIdRaw === '') {
            $idClickDisplay = rtSvgImg('/dist/favicon.svg', 'NGIX') . ' NGIX';
        }

        if (rtStringLength($clickIdRaw) > 20) {
            $idClickDisplay = rtSvgImg('/dist/flag_placeholder.png', 'User') . ' YELLOW';
        }

        $trafficDisplay = statDeviceIconHtml($trafficRaw, 'rt-device-ico');

        if ($trafficDisplay === '') {
            $trafficDisplay = '<code class="rt-code">' . rtEscapeHtml($trafficRaw) . '</code>';
        }

        $networkSvg = [
            'LOSPOLLOS' => '/dist/lp.png',
            'IMONETIZEIT' => '/dist/imo.png',
            'TRAFEE' => '/dist/tf.png',
            'TORAZZO' => '/dist/tr.png',
            'CUSTOM' => '/dist/custom.svg',
            'OFFER' => '/dist/custom.svg',
        ];

        if (isset($networkSvg[$networkRaw])) {
            $networkDisplay = rtSvgImg($networkSvg[$networkRaw], $networkRaw, 14);
        } else {
            $networkDisplay = rtEscapeHtml($networkRaw);
        }

        $ipAddress = rtNormalizeUtf8((string) ($row['ip_address'] ?? ''));

        $ipDisplay = '<a href="#" class="js-ip rt-ip" id="' . rtEscapeHtml($ipAddress) . '" data-ip="'
            . rtEscapeHtml($ipAddress) . '"><span> ' . rtEscapeHtml($ipAddress) . '</span></a>';

        // CSS sprite flag (assets/css/flags.css). statFlagSpriteCode() returns
        // either a whitelisted [a-z]{2} code that exists in the sprite or '', so
        // the class attribute can never carry caller-controlled text and an
        // unknown country renders the flag-doesnt-exist placeholder instead of
        // the wrong flag. The <img> src is the blank/transparent sprite anchor
        // (assets/img/flag_placeholder.png); the flag itself is painted by the
        // .flag-xx background-position rule in flags.css.
        $countryCode = statFlagSpriteCode($countryRaw);
        $flagPlaceholder = rtEscapeHtml(statAssetUrl('/assets/img/flag_placeholder.png'));
        $countryDisplay = '<img src="' . $flagPlaceholder . '" class="rt-flag flag flag-'
            . ($countryCode !== '' ? $countryCode : 'doesnt-exist') . '" alt="">'
            . ' ' . rtEscapeHtml($countryRaw);

        $currencySymbol = rtNormalizeUtf8((string) ($row['currency_symbol'] ?? '$'));
        $payoutValue = (float) ($row['payout'] ?? 0.0);
        $payoutDisplay = rtEscapeHtml($currencySymbol) . number_format($payoutValue, 2);

        $conversionDateValue = rtNormalizeUtf8((string) ($row['conversion_date'] ?? ''));
        $conversionDateDisplay = '<span class="text-muted">' . rtEscapeHtml($conversionDateValue) . '</span>';

        $response['data'][] = [
            'id' => $number++,
            'click_id' => $idClickDisplay,
            'ip_address' => $ipDisplay,
            'country' => $countryDisplay,
            'traffic' => $trafficDisplay,
            'payout' => $payoutDisplay,
            'conversion_date' => $conversionDateDisplay,
            'network' => $networkDisplay,
        ];
    }

    rtOutputJson($response);
} catch (Throwable $e) {
    error_log('[realtime/data] ' . $e->getMessage());
    rtOutputJson(['data' => []]);
}
