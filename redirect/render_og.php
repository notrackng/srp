<?php

declare(strict_types=1);

/**
 * Open Graph HTML rendering for social media crawlers.
 * Included by redirect/index.php after constants and helpers are defined.
 *
 * Depends on (from index.php):
 *   srp_server_string(), srp_validate_host(), app_env(),
 *   srp_e(), srp_proxy_image_url(), SRP_FB_APP_ID
 */
/**
 * @param array<string, string> $debugInfo Diagnostic rows shown on the page when
 *        cloak debugging is enabled. Empty array (the default) renders the same
 *        crawler-facing preview as before, with no diagnostic rows.
 */
function srp_render_og(string $title, string $imageUrl, array $debugInfo = []): void
{
    $proxiedImage = srp_proxy_image_url($imageUrl);
    $nonce        = bin2hex(random_bytes(16));

    header('Content-Type: text/html; charset=UTF-8');
    header(
        "Content-Security-Policy: default-src 'none'; "
        . "img-src 'self' https:; "
        . "style-src 'nonce-{$nonce}'; "
        . "object-src 'none'; "
        . "base-uri 'self'; "
        . "frame-ancestors 'none'",
    );

    $displayTitle = $title !== '' ? $title : 'Preview';
    $titleEsc     = srp_e($displayTitle);
    $ogHost       = srp_server_string('HTTP_HOST');
    $siteName     = srp_validate_host($ogHost)
        ? (preg_replace('/:\d+$/', '', $ogHost) ?? $ogHost)
        : '';
    $siteNameEsc  = srp_e($siteName);
    $currentUrl   = srp_validate_host($ogHost)
        ? 'https://' . $ogHost . srp_server_string('REQUEST_URI')
        : '';
    $urlEsc       = srp_e($currentUrl);
    // Configurable via SRP_OG_DESCRIPTION. A neutral built-in default keeps the
    // og:description / meta description / twitter:description and the body text
    // populated even when the env key is absent — an empty meta-only page is
    // exactly what social platforms flag as cloaking.
    $description  = trim((string) app_env('SRP_OG_DESCRIPTION', 'Open this link to view the content.'));
    $descEsc      = srp_e($description);
    $imageEsc     = srp_e($proxiedImage);

    $markup = [
        '<!DOCTYPE html>',
        '<html lang="en" prefix="og: https://ogp.me/ns# fb: https://ogp.me/ns/fb#"><head>',
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>' . $titleEsc . '</title>',
        '<meta prefix="fb: https://ogp.me/ns/fb#" property="fb:app_id" content="' . SRP_FB_APP_ID . '">',
        '<meta property="og:type" content="website">',
        '<meta property="og:site_name" content="' . $siteNameEsc . '">',
        '<meta property="og:url" content="' . $urlEsc . '">',
        '<meta property="og:title" content="' . $titleEsc . '">',
        '<meta name="twitter:card" content="' . ($proxiedImage !== '' ? 'summary_large_image' : 'summary') . '">',
        '<meta name="twitter:title" content="' . $titleEsc . '">',
    ];

    if ($description !== '') {
        $markup[] = '<meta name="description" content="' . $descEsc . '">';
        $markup[] = '<meta property="og:description" content="' . $descEsc . '">';
        $markup[] = '<meta name="twitter:description" content="' . $descEsc . '">';
    }

    if ($proxiedImage !== '') {
        $markup[] = '<meta property="og:image" content="' . $imageEsc . '">';
        $markup[] = '<meta property="og:image:secure_url" content="' . $imageEsc . '">';
        $markup[] = '<meta name="twitter:image" content="' . $imageEsc . '">';
    }

    // Visible body: an empty, meta-only page is a classic cloaking/spam
    // fingerprint that Facebook / WhatsApp / Instagram flag under community
    // standards. Render a minimal real page (title, description, image, site
    // name) so the preview URL looks like ordinary content to a crawler, while
    // the offer itself is still never emitted on this path.
    $markup[] = '</head><body>';
    $markup[] = '<style nonce="' . srp_e($nonce) . '">'
        . 'html{color-scheme:light}'
        . 'body{margin:0;padding:32px 16px;background:#f7f5f1;color:#1b1d20;'
        . 'font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;'
        . 'text-align:center;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased}'
        . '.og{max-width:560px;margin:0 auto;background:#fff;border:1px solid #e4e0d9;'
        . 'border-radius:8px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.08)}'
        . 'h1{margin:0 0 8px;font-size:20px;line-height:1.3;overflow-wrap:anywhere}'
        . 'p{margin:0;color:#5a5f66}'
        . 'img{max-width:100%;height:auto;border-radius:6px;margin-top:16px;display:block}'
        . 'footer{margin-top:20px;font-size:12px;color:#8a8f96}'
        . '</style>';
    $markup[] = '<main class="og">';
    $markup[] = '<h1>' . $titleEsc . '</h1>';
    if ($description !== '') {
        $markup[] = '<p>' . $descEsc . '</p>';
    }
    if ($proxiedImage !== '') {
        $markup[] = '<img src="' . $imageEsc . '" alt="' . $titleEsc . '">';
    }
    if ($siteNameEsc !== '') {
        $markup[] = '<footer>' . $siteNameEsc . '</footer>';
    }
    $markup[] = '</main>';

    // Diagnostic panel. Rendered as a plain <pre> on purpose: no inline styles
    // beyond the nonce'd block above and no external asset, so the CSP stays
    // intact. Every value is escaped — these are attacker-controlled inputs
    // (user agent, host) as much as they are our own.
    if ($debugInfo !== []) {
        $markup[] = '<pre>';
        $width = 0;
        foreach (array_keys($debugInfo) as $key) {
            $width = max($width, strlen($key));
        }
        foreach ($debugInfo as $key => $value) {
            $markup[] = srp_e(str_pad($key, $width)) . ' : ' . srp_e($value) . "\n";
        }
        $markup[] = '</pre>';
    }

    $markup[] = '</body></html>';

    echo implode('', $markup);
}
