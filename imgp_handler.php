<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

/**
 * Image proxy — shared handler.
 *
 * Single source of truth for both entry points (public/imgp.php and
 * redirect/imgp.php), each of which is a thin shim that requires this file.
 * Do NOT duplicate this logic back into the shims.
 *
 * Fetches a remote image and re-serves it on the same origin so Facebook's OG
 * scraper (and other social bots) can read images that would otherwise be
 * blocked by CORS, geo-restrictions, or bot filters on the origin CDN.
 *
 * Usage: /imgp?u=<base64url-encoded-image-url>
 * Resizes to max 1200×630 and re-encodes as JPEG (≤85 quality) if GD is available.
 */

if (!function_exists('imgp_is_private_ip')) {
    function imgp_is_private_ip(string $ip): bool
    {
        // Fail closed on anything that isn't a valid IP literal.
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return true;
        }

        // Reject RFC1918 private ranges, loopback, link-local (incl. the cloud
        // metadata address 169.254.169.254), 0.0.0.0/8, other reserved ranges,
        // and the IPv6 equivalents (ULA, ::1, fe80::/10). Covers IPv4 and IPv6,
        // which the previous hand-rolled IPv4-only range list did not.
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return true;
        }

        // Carrier-grade NAT (100.64.0.0/10) is not covered by the reserved-range
        // flag but can still reach internal infrastructure — block it explicitly.
        $long = ip2long($ip);
        if ($long !== false && $long >= ip2long('100.64.0.0') && $long <= ip2long('100.127.255.255')) {
            return true;
        }

        return false;
    }
}

// ── Decode the URL parameter ──────────────────────────────────────────────────
$encoded = isset($_GET['u']) && is_string($_GET['u']) ? trim($_GET['u']) : '';
if ($encoded === '') {
    http_response_code(400);
    exit;
}

// base64url → base64 → string
$url = base64_decode(strtr($encoded, '-_', '+/'), true);
if ($url === false || $url === '') {
    http_response_code(400);
    exit;
}
$url = trim($url);

// ── Validate URL ──────────────────────────────────────────────────────────────
if (filter_var($url, FILTER_VALIDATE_URL) === false) {
    http_response_code(400);
    exit;
}

$scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
if ($scheme !== 'https') {
    http_response_code(403);
    exit;
}

$host = (string) parse_url($url, PHP_URL_HOST);
if ($host === '') {
    http_response_code(400);
    exit;
}

// ── SSRF guard ────────────────────────────────────────────────────────────────
// Block literal private IPs, and resolve hostnames to check for internal targets.
$port = (int) (parse_url($url, PHP_URL_PORT) ?: 443);

if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
    if (imgp_is_private_ip($host)) {
        http_response_code(403);
        exit;
    }
    $pinnedIp = $host;
} else {
    // Resolve hostname and block if it points to a private/loopback IP.
    // Fail closed when resolution fails or returns nothing — an unresolvable
    // host can indicate an internal name or a DNS-rebinding attempt.
    $resolved = @gethostbynamel($host);
    if (!is_array($resolved) || $resolved === []) {
        http_response_code(403);
        exit;
    }
    foreach ($resolved as $resolvedIp) {
        if (imgp_is_private_ip($resolvedIp)) {
            http_response_code(403);
            exit;
        }
    }
    // Pin cURL to a validated IP so it cannot re-resolve the host to a
    // different (internal) address after this check — closes the DNS-rebinding
    // TOCTOU window.
    $pinnedIp = $resolved[0];
}

// ── Fetch image ───────────────────────────────────────────────────────────────
$ch = curl_init($url);
if ($ch === false) {
    http_response_code(502);
    exit;
}

// Hard byte cap enforced in the write callback so it holds even when the origin
// omits Content-Length (chunked transfer). CURLOPT_MAXFILESIZE alone only acts
// on the advertised Content-Length and would let a length-less response stream
// unbounded into memory until the timeout.
$maxBytes = 5 * 1024 * 1024; // 5 MB
$body = '';
$overflow = false;

curl_setopt_array($ch, [
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_CONNECTTIMEOUT => 5,
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_USERAGENT      => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
    CURLOPT_HTTPHEADER     => ['Accept: image/webp,image/apng,image/*,*/*;q=0.8'],
    CURLOPT_MAXFILESIZE     => $maxBytes, // fast-path reject when Content-Length is present
    CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
    CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
    CURLOPT_RESOLVE         => [$host . ':' . $port . ':' . $pinnedIp],
    // $ch (the curl handle) is unused but required: curl passes it positionally,
    // so it must be declared for $chunk to land in the second parameter.
    CURLOPT_WRITEFUNCTION   => static function ($ch, string $chunk) use (&$body, &$overflow, $maxBytes): int {
        $body .= $chunk;
        if (strlen($body) > $maxBytes) {
            $overflow = true;

            return 0; // returning < chunk length aborts the transfer
        }

        return strlen($chunk);
    },
]);

$ok       = curl_exec($ch);
$httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
$rawCt    = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
curl_close($ch);

if ($overflow || $ok === false || $body === '' || $httpCode < 200 || $httpCode >= 400) {
    http_response_code(502);
    exit;
}

// ── Validate content-type ─────────────────────────────────────────────────────
$ct = strtolower(trim(explode(';', $rawCt)[0]));
$allowed = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
if (!in_array($ct, $allowed, true)) {
    http_response_code(415);
    exit;
}

// ── Optional GD compress / resize (max 1200×630 for OG) ──────────────────────
$rasterTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
if (function_exists('imagecreatefromstring') && in_array($ct, $rasterTypes, true)) {
    $img = @imagecreatefromstring((string) $body);
    if ($img !== false) {
        $origW = imagesx($img);
        $origH = imagesy($img);
        $maxW  = 1200;
        $maxH  = 630;

        if ($origW > $maxW || $origH > $maxH) {
            $ratio  = min($maxW / $origW, $maxH / $origH);
            $newW   = max(1, (int) round($origW * $ratio));
            $newH   = max(1, (int) round($origH * $ratio));
            $canvas = imagecreatetruecolor($newW, $newH);

            if ($canvas !== false) {
                if ($ct === 'image/png') {
                    imagealphablending($canvas, false);
                    imagesavealpha($canvas, true);
                }
                imagecopyresampled($canvas, $img, 0, 0, 0, 0, $newW, $newH, $origW, $origH);
                imagedestroy($img);

                ob_start();
                if ($ct === 'image/png') {
                    imagepng($canvas, null, 6);
                } else {
                    imagejpeg($canvas, null, 85);
                    $ct = 'image/jpeg';
                }
                $compressed = ob_get_clean();
                imagedestroy($canvas);

                if ($compressed !== false && $compressed !== '') {
                    $body = $compressed;
                }
            }
        } else {
            imagedestroy($img);
        }
    }
}

// ── Serve ─────────────────────────────────────────────────────────────────────
header('Content-Type: ' . $ct);
header('Content-Length: ' . strlen((string) $body));
header('Cache-Control: public, max-age=86400, immutable');
header('X-Content-Type-Options: nosniff');
echo $body;
exit;
