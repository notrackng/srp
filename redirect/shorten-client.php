<?php

/**
 * Client CLI — membuat short link publik via POST /api/shorten.
 *
 * Usage (dari legacy sub_id):
 *   php shorten-client.php --sub-id=TOKEN --base-url=https://domain.tld
 *
 * Usage (dari fields):
 *   php shorten-client.php \
 *     --click-id=ABC123 \
 *     --user-lp=IMONETIZEIT \
 *     --canonical-url=https://example.com \
 *     --title="My Offer" \
 *     --image-url=https://example.com/img.jpg \
 *     --lg=landing \
 *     --code=slug-kustom \
 *     --api-url=https://domain.tld/api/shorten \
 *     --api-key=SECRET
 *
 * Opsi ENV: SRP_API_KEY, SRP_API_URL
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Not Found');
}

$opts = getopt('', [
    'sub-id::', 'click-id::', 'user-lp::', 'canonical-url::',
    'title::', 'image-url::', 'lg::', 'code::', 'base-url::',
    'api-url::', 'api-key::', 'help',
]);

if ($opts === false || array_key_exists('help', $opts)) {
    srp_client_usage();
    exit(0);
}

// ── Load .env bila tersedia ───────────────────────────────────────────────────
$envFile = __DIR__ . '/.env';
if (is_file($envFile) && is_readable($envFile)) {
    foreach ((array) file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim((string) $line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        $sep = strpos($line, '=');
        if ($sep === false) {
            continue;
        }

        $k = trim(substr($line, 0, $sep));
        $v = trim(substr($line, $sep + 1));

        if (preg_match('/^[A-Z0-9_]+$/', $k) === 1 && getenv($k) === false) {
            putenv($k . '=' . trim($v, '"\''));
        }
    }
}

// ── Resolve API endpoint + key ────────────────────────────────────────────────
$apiUrl = srp_client_str($opts['api-url'] ?? null)
    ?? (string) (getenv('SRP_API_URL') ?: '');

$apiKey = srp_client_str($opts['api-key'] ?? null)
    ?? (string) (getenv('SRP_API_KEY') ?: '');

if ($apiUrl === '') {
    fwrite(STDERR, "Missing --api-url (atau set SRP_API_URL di .env)\n");
    exit(1);
}

if ($apiKey === '') {
    fwrite(STDERR, "Missing --api-key (atau set SRP_API_KEY di .env)\n");
    exit(1);
}

// ── Bangun body request ───────────────────────────────────────────────────────
$subId = srp_client_str($opts['sub-id'] ?? null);

if ($subId !== null) {
    if (preg_match('/^[A-Za-z0-9_-]+$/', $subId) !== 1) {
        fwrite(STDERR, "Invalid --sub-id.\n");
        exit(1);
    }

    $body = ['sub_id' => $subId];
} else {
    $clickId = srp_client_str($opts['click-id'] ?? null);
    $userLp  = srp_client_str($opts['user-lp'] ?? null);

    if ($clickId === null || $userLp === null) {
        fwrite(STDERR, "Berikan --sub-id ATAU keduanya --click-id + --user-lp.\n\n");
        srp_client_usage();
        exit(1);
    }

    $body = [
        'click_id' => $clickId,
        'user_lp'  => $userLp,
    ];

    $canonicalUrl = srp_client_str($opts['canonical-url'] ?? null);
    if ($canonicalUrl !== null) {
        $body['canonical_url'] = $canonicalUrl;
    }

    $title = srp_client_str($opts['title'] ?? null);
    if ($title !== null) {
        $body['title'] = $title;
    }

    $imageUrl = srp_client_str($opts['image-url'] ?? null);
    if ($imageUrl !== null) {
        $body['image_url'] = $imageUrl;
    }

    $lg = srp_client_str($opts['lg'] ?? null);
    if ($lg !== null) {
        $body['lg'] = $lg;
    }
}

$code = srp_client_str($opts['code'] ?? null);
if ($code !== null) {
    $body['code'] = $code;
}

$baseUrl = srp_client_str($opts['base-url'] ?? null);
if ($baseUrl !== null) {
    $body['base_url'] = $baseUrl;
}

// ── cURL ──────────────────────────────────────────────────────────────────────
$jsonBody = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

$ch = curl_init();

curl_setopt_array($ch, [
    CURLOPT_URL            => $apiUrl,
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $jsonBody,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_HTTPHEADER     => [
        'Content-Type: application/json',
        'Accept: application/json',
        'Authorization: Bearer ' . $apiKey,
    ],
    CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS | CURLPROTO_HTTP,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
]);

$rawResponse = curl_exec($ch);
$httpStatus  = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError   = curl_error($ch);

if ($rawResponse === false || $curlError !== '') {
    fwrite(STDERR, "cURL error: {$curlError}\n");
    exit(1);
}

// ── Parse + tampilkan ─────────────────────────────────────────────────────────
try {
    $response = json_decode((string) $rawResponse, true, 8, JSON_THROW_ON_ERROR);
} catch (JsonException $e) {
    fwrite(STDERR, "Response bukan JSON valid (HTTP {$httpStatus}):\n{$rawResponse}\n");
    exit(1);
}

if (!is_array($response)) {
    fwrite(STDERR, "Response tidak terduga (HTTP {$httpStatus}).\n");
    exit(1);
}

if ($httpStatus === 201 && ($response['ok'] ?? false) === true) {
    echo "Short link berhasil dibuat!\n";
    echo '  Code  : ' . (is_string($response['code'] ?? null) ? $response['code'] : '-') . "\n";
    echo '  Token : ' . (is_string($response['token'] ?? null) ? $response['token'] : '-') . "\n";
    echo '  URL   : ' . (is_string($response['url'] ?? null) ? $response['url'] : '-') . "\n";
    exit(0);
}

$errorMsg = is_string($response['error'] ?? null) ? $response['error'] : 'Unknown error';
fwrite(STDERR, "Gagal (HTTP {$httpStatus}): {$errorMsg}\n");
exit(1);

// ── Helpers ───────────────────────────────────────────────────────────────────

function srp_client_str(mixed $value): ?string
{
    if (!is_scalar($value)) {
        return null;
    }

    $value = trim((string) $value);

    return $value !== '' ? $value : null;
}

function srp_client_usage(): void
{
    $out = <<<'USAGE'
Usage:
  # Dari legacy sub_id token:
  php shorten-client.php --sub-id=TOKEN --api-url=https://domain.tld/api/shorten

  # Dari fields manual:
  php shorten-client.php \
    --click-id=ABC123 --user-lp=IMONETIZEIT \
    --canonical-url=https://example.com \
    --title="My Offer" --image-url=https://example.com/img.jpg \
    --lg=landing --code=slug-kustom \
    --api-url=https://domain.tld/api/shorten

Options:
  --sub-id          Legacy base64url sub_id token (alternatif manual fields)
  --click-id        Click ID (wajib jika tanpa --sub-id)
  --user-lp         User LP / network (wajib jika tanpa --sub-id)
  --canonical-url   URL canonical HTTPS
  --title           Judul halaman
  --image-url       URL gambar OG HTTPS
  --lg              landing | direct
  --code            Short code kustom (opsional, 4-32 char [A-Za-z0-9_-])
  --base-url        Base URL untuk short link (default: auto dari host API)
  --api-url         URL endpoint API (atau set SRP_API_URL di .env)
  --api-key         API key Bearer (atau set SRP_API_KEY di .env)
  --help            Tampilkan pesan ini

USAGE;
    echo $out;
}
