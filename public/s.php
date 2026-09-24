<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection_pdo.php';

$code = preg_replace('/[^A-Za-z0-9]/', '', (string) ($_GET['c'] ?? ''));

if ($code === '') {
    http_response_code(404);
    exit;
}

$stmt = $pdo->prepare('SELECT long_url, og_title, og_image FROM shortlinks WHERE code = :code LIMIT 1');
if (!$stmt) {
    http_response_code(500);
    exit;
}

$stmt->execute(['code' => $code]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);

if (!is_array($row) || empty($row['long_url'])) {
    http_response_code(404);
    exit;
}

$longUrl = trim((string) $row['long_url']);
$scheme  = strtolower((string) parse_url($longUrl, PHP_URL_SCHEME));
$target  = null;

if (filter_var($longUrl, FILTER_VALIDATE_URL) !== false && $scheme === 'https') {
    if (!srp_url_is_self($longUrl) && srp_url_host_allowed($longUrl)) {
        $target = $longUrl;
    } else {
        error_log('[srp] shortlink target blocked — self/host not allowed: ' . strtolower((string) parse_url($longUrl, PHP_URL_HOST)));
    }
}

if ($target === null) {
    http_response_code(404);
    exit;
}

$ogTitle = trim((string) ($row['og_title'] ?? ''));
$ogImage = trim((string) ($row['og_image'] ?? ''));

// ── Bot / OG-scraper detection ────────────────────────────────────────────────
// Kept in sync with srp_is_social_bot() in redirect/functions.php (the canonical
// crawler list). s.php lives in public/ and does not bootstrap redirect/functions.php
// (which pulls env.php), so the pattern is mirrored here rather than delegated.
// The previous hand-rolled list was a strict SUBSET, so crawlers like bingbot,
// Amazonbot, Threads and the Google/Meta variants below fell through to the plain
// 302 on this path instead of receiving the OG preview.
$ua = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
$isSocialBot = $ua !== ''
    && preg_match('/\b(FBAN|FBAV)\b/', $ua) !== 1
    && preg_match(
        '/facebookexternalhit|facebookcatalog|Facebot|FacebookBot|facebookplatform'
        . '|Facebookscraper|meta-externalagent|meta-externalfetcher|ThreadsExternalAgent'
        . '|Twitterbot|WhatsApp|TelegramBot|LinkedInBot|Slackbot|Discordbot|Applebot'
        . '|Googlebot|APIs-Google|Mediapartners-Google|AdsBot-Google|FeedFetcher-Google'
        . '|Google-Read-Aloud|DuplexWeb-Google|Google-InspectionTool|Storebot-Google'
        . '|google-extended|googleweblight|Google Favicon|google keyword|google page speed'
        . '|bingbot|Amazonbot|vkShare|CheckMarkNetwork|W3C-checklink'
        . '|Go-http-client|HttpClient|ScaleBot/i',
        $ua,
    ) === 1;

if ($isSocialBot) {
    $esc = static function (string $s): string {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    };
    $rawHost  = isset($_SERVER['HTTP_HOST']) && is_string($_SERVER['HTTP_HOST'])
        ? preg_replace('/[^a-zA-Z0-9.\-:]/', '', $_SERVER['HTTP_HOST'])
        : '';
    $shortUrl = $rawHost !== '' ? 'https://' . $rawHost . '/s-' . $code : '';

    // https only: the imgp proxy this URL is handed (imgp_handler.php) rejects any
    // other scheme with 403, and the redirect root normalises og images to https
    // (srp_public_link_normalize_https_url: https + <=2048). Accepting http emitted
    // an og:image the proxy then refused to fetch. Match that canonical rule.
    $validImage = '';
    if (
        $ogImage !== ''
        && strlen($ogImage) <= 2048
        && filter_var($ogImage, FILTER_VALIDATE_URL) !== false
        && strtolower((string) parse_url($ogImage, PHP_URL_SCHEME)) === 'https'
    ) {
        $validImage = $ogImage;
    }
    $proxiedImage = '';
    if ($validImage !== '' && $rawHost !== '') {
        $proxiedImage = 'https://' . $rawHost . '/imgp?u='
            . rtrim(strtr(base64_encode($validImage), '+/', '-_'), '=');
    }

    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo '<!DOCTYPE html><html prefix="og: https://ogp.me/ns#"><head>';
    echo '<meta charset="utf-8">';
    echo '<title>' . $esc($ogTitle ?: 'Preview') . '</title>';
    echo '<meta property="og:type" content="website">';
    echo '<meta property="og:url" content="' . $esc($shortUrl) . '">';
    if ($ogTitle !== '') {
        echo '<meta property="og:title" content="' . $esc($ogTitle) . '">';
        echo '<meta property="og:description" content="' . $esc($ogTitle) . '">';
        echo '<meta prefix="fb: https://ogp.me/ns/fb#" property="fb:app_id" content="115190258555800">';
    }
    if ($proxiedImage !== '') {
        echo '<meta property="og:image" content="' . $esc($proxiedImage) . '">';
        echo '<meta property="og:image:secure_url" content="' . $esc($proxiedImage) . '">';
        echo '<meta property="og:image:width" content="1200">';
        echo '<meta property="og:image:height" content="630">';
        echo '<meta name="twitter:card" content="summary_large_image">';
        echo '<meta name="twitter:image" content="' . $esc($proxiedImage) . '">';
    }
    if ($ogTitle !== '') {
        echo '<meta name="twitter:title" content="' . $esc($ogTitle) . '">';
    }
    echo '<meta http-equiv="refresh" content="0;url=' . $esc($target) . '">';
    echo '</head><body></body></html>';
    exit;
}

header('Location: ' . $target, true, 302);
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
exit;
