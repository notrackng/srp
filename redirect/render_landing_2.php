<?php

declare(strict_types=1);

/**
 * Landing page #2 ("Hello Beautiful") HTML rendering with CTA overlay.
 *
 * Soft-pink profile landing with a single "Continue to Profile" CTA. Same
 * signature and preview/safe-CTA semantics as render_landing.php, so the
 * redirect entry point can swap templates without changing its call sites.
 *
 * Depends on (from index.php):
 *   srp_server_string(), srp_validate_host(), srp_e(), SRP_FB_APP_ID
 */

/**
 * Deterministically pick a dating-profile identity (name, quote, photo) from
 * the built-in pools. Seeded by a stable per-link value so the crawler preview
 * and the real-user page agree; a blank seed falls back to random.
 *
 * @return array{0: string, 1: string, 2: string} [name, quote, photoUrl]
 */
function srp_landing_2_profile(string $seed): array
{
    $names = [
        'Grace', 'Maya', 'Luna', 'Chloe', 'Sophie', 'Emma', 'Olivia', 'Ava',
        'Isabella', 'Mia', 'Amelia', 'Harper', 'Evelyn', 'Scarlett', 'Aria',
        'Layla', 'Zoe', 'Nora', 'Lily', 'Violet', 'Hazel', 'Aurora', 'Stella',
        'Camila', 'Sofia', 'Bella',
    ];

    $quotes = [
        'Looking for someone who loves deep conversations and spontaneous adventures.',
        'Swipe right if you believe in love at first coffee.',
        'Chasing sunsets and good vibes — maybe you will join me?',
        'Life is too short for boring conversations. Entertain me.',
        'Adventurous soul seeking a partner in crime.',
        'Here for the butterflies and the late-night talks.',
        'Fluent in sarcasm and spontaneous road trips.',
        'Tell me your favorite movie and I will tell you if we would work.',
        'Just a girl who loves her coffee a little too much.',
        'Searching for someone who can keep up with my playlist.',
        'Quality time is my love language. What is yours?',
        'Let us skip the small talk and find our favorite song.',
        'I believe in slow dancing in the kitchen.',
        'Good vibes only — and maybe a little chaos.',
        'Here to find my plus one for every adventure.',
        'Sun-kissed and looking for my better half.',
        'Looking for a reason to delete this app — be it.',
        'Hopeless romantic with a practical side.',
        'Cooking for one is sad. Be my taste tester?',
        'Let us make our own love story, one playlist at a time.',
    ];

    // Self-hosted profile photos. Drop one woman portrait per file (square,
    // ~800×800px works best) into assets/img/women/1.jpg … 10.jpg.
    $photos = [
        '/assets/img/women/1.jpg',
        '/assets/img/women/2.jpg',
        '/assets/img/women/3.jpg',
        '/assets/img/women/4.jpg',
        '/assets/img/women/5.jpg',
        '/assets/img/women/6.jpg',
        '/assets/img/women/7.jpg',
        '/assets/img/women/8.jpg',
        '/assets/img/women/9.jpg',
        '/assets/img/women/10.jpg',
    ];

    $key = $seed !== '' ? $seed : bin2hex(random_bytes(8));

    $nameIdx  = abs((int) crc32($key . '|name')) % count($names);
    $quoteIdx = abs((int) crc32($key . '|quote')) % count($quotes);
    $photoIdx = abs((int) crc32($key . '|photo')) % count($photos);

    return [$names[$nameIdx], $quotes[$quoteIdx], $photos[$photoIdx]];
}

/**
 * @param string $seed Stable per-link value (click_id) used to pick the
 *        profile deterministically, so the crawler preview and the real-user
 *        page show the same name / photo / quote. Empty = random per request.
 */
function srp_render_landing_2(
    string $targetUrl,
    bool $allowCloudflareInsights,
    string $deviceType = 'WEB',
    bool $isPreview = false,
    string $seed = '',
): void {
    [$profileName, $profileQuote, $profilePhoto] = srp_landing_2_profile($seed);

    $nonce            = bin2hex(random_bytes(16));
    $nonceEsc         = srp_e($nonce);
    $targetEsc        = srp_e($targetUrl);
    $facebookAppIdEsc = srp_e((string) SRP_FB_APP_ID);

    $nameEsc  = srp_e($profileName);
    $quoteEsc = srp_e($profileQuote);
    $photoEsc = srp_e($profilePhoto);

    $host = srp_server_string('HTTP_HOST');
    $siteNameEsc = srp_validate_host($host)
        ? srp_e(preg_replace('/:\d+$/', '', $host) ?? $host)
        : '';
    $currentUrl = srp_validate_host($host)
        ? 'https://' . $host . srp_server_string('REQUEST_URI')
        : '';
    $urlEsc = srp_e($currentUrl);

    $ogMetaMarkup = ['<meta property="og:type" content="website">'];
    if ($siteNameEsc !== '') {
        $ogMetaMarkup[] = '<meta property="og:site_name" content="' . $siteNameEsc . '">';
    }
    if ($urlEsc !== '') {
        $ogMetaMarkup[] = '<meta property="og:url" content="' . $urlEsc . '">';
    }
    $ogMetaMarkup[] = '<meta property="og:title" content="' . $nameEsc . '">';
    $ogMetaMarkup[] = '<meta property="og:description" content="' . $quoteEsc . '">';
    $ogMetaMarkup[] = '<meta name="description" content="' . $quoteEsc . '">';
    $ogMetaMarkup[] = '<meta name="twitter:card" content="summary_large_image">';
    $ogMetaMarkup[] = '<meta name="twitter:title" content="' . $nameEsc . '">';
    $ogMetaMarkup[] = '<meta name="twitter:description" content="' . $quoteEsc . '">';
    $ogMetaMarkup[] = '<meta property="og:image" content="' . $photoEsc . '">';
    $ogMetaMarkup[] = '<meta property="og:image:secure_url" content="' . $photoEsc . '">';
    $ogMetaMarkup[] = '<meta name="twitter:image" content="' . $photoEsc . '">';

    $inlineCss = <<<'CSS'
*,::before,::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Plus Jakarta Sans',system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif;background:#fff;color:#4a4a4a;min-height:100vh;overflow-x:hidden;display:flex;flex-direction:column;align-items:center;justify-content:space-between;padding:4rem 2rem;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
.serif{font-family:'Playfair Display',Georgia,'Times New Roman',serif}
.blob{position:fixed;background:#fff0f3;border-radius:9999px;filter:blur(3rem);opacity:.6;z-index:0;pointer-events:none}
.blob--tl{top:-10%;right:-10%;width:16rem;height:16rem}
.blob--br{bottom:-5%;left:-5%;width:20rem;height:20rem}
.main{max-width:28rem;width:100%;display:flex;flex-direction:column;align-items:center;text-align:center;gap:2rem;position:relative;z-index:10;animation:fadeUp 1s ease-out forwards}
.profile{position:relative;margin-bottom:1rem}
.image-wrap{position:relative}
.image-wrap::after{content:'';position:absolute;inset:-10px;border:1px solid #ff8fa3;border-radius:9999px;z-index:-1;opacity:.5}
.profile-img{width:8rem;height:8rem;border-radius:9999px;object-fit:cover;border:4px solid #fff;box-shadow:0 1px 2px rgba(0,0,0,.08);display:block;background:#ffe4ec}
.sparkles{position:absolute;top:-.5rem;right:-.5rem;color:#f9a8d4;line-height:0}
.kicker{text-transform:uppercase;letter-spacing:.3em;font-size:10px;font-weight:700;color:#9ca3af}
.headline{font-family:'Playfair Display',Georgia,'Times New Roman',serif;font-size:2.25rem;color:#1f2937;font-weight:400}
.headline em{font-style:italic;color:#f472b6}
.quote{font-size:.875rem;color:#6b7280;line-height:1.625;padding:0 1rem}
.socials{display:flex;gap:1.5rem;padding-top:1rem;color:#d1d5db}
.socials a,.socials .icon{color:#d1d5db;transition:color .2s;text-decoration:none;display:inline-flex;align-items:center;justify-content:center}
.socials a:hover,.socials .icon:hover{color:#f472b6}
.cta-wrap{width:100%;max-width:28rem;margin-top:3rem;position:relative;z-index:10;animation:fadeUp 1s ease-out .3s forwards;opacity:0}
.cta{position:relative;overflow:hidden;display:flex;align-items:center;justify-content:center;gap:.75rem;width:100%;padding:1.25rem;border-radius:1rem;background:linear-gradient(135deg,#1a1a1a 0%,#333 100%);color:#fff;text-decoration:none;text-align:center;font-weight:700;letter-spacing:.2em;text-transform:uppercase;font-size:.75rem;box-shadow:0 10px 15px rgba(0,0,0,.15);transition:all .4s cubic-bezier(.23,1,.32,1);border:0;cursor:pointer}
.cta:hover{background:linear-gradient(135deg,#ff758f 0%,#ff8fa3 100%);transform:translateY(-3px) scale(1.02);box-shadow:0 15px 30px rgba(255,143,163,.4)}
.cta::before{content:'';position:absolute;top:0;left:-100%;width:50%;height:100%;background:linear-gradient(120deg,transparent,rgba(255,255,255,.2),transparent);transition:left .6s}
.cta:hover::before{left:200%}
.heart{display:inline-block;animation:heartBeat 1.5s infinite;color:#f9a8d4;line-height:0}
.fineprint{text-align:center;font-size:10px;color:#d1d5db;margin-top:1.5rem;text-transform:uppercase;letter-spacing:.2em}
@keyframes fadeUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
@keyframes heartBeat{0%{transform:scale(1)}14%{transform:scale(1.3)}28%{transform:scale(1)}42%{transform:scale(1.3)}70%{transform:scale(1)}}
@media(max-width:480px){body{padding:2.5rem 1.25rem}.headline{font-size:1.75rem}.profile-img{width:7rem;height:7rem}}
CSS;

    $connectSrc = "connect-src 'self'";
    if ($allowCloudflareInsights) {
        $connectSrc .= ' ' . SRP_CF_INSIGHTS_SCRIPT . ' ' . SRP_CF_INSIGHTS_BEACON;
    }

    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, no-transform');
    header(
        "Content-Security-Policy: default-src 'self'; "
        . "style-src 'self' 'nonce-{$nonce}' https://fonts.googleapis.com; "
        . "font-src 'self' https://fonts.gstatic.com; "
        . "img-src 'self' data: https:; "
        . "media-src 'self'; "
        . $connectSrc . '; '
        . "object-src 'none'; "
        . "base-uri 'self'; "
        . "frame-ancestors 'none'; "
        . "form-action 'self'"
    );

    // Inline SVGs for the three social marks + the decorative heart. Inline SVG
    // avoids an external icon font (no extra CSP origin) and keeps the markup
    // self-contained.
    $instagramSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="5"/><circle cx="12" cy="12" r="4"/><circle cx="17.5" cy="6.5" r="1" fill="currentColor" stroke="none"/></svg>';
    $pinterestSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2C6.5 2 2 6.5 2 12c0 4.2 2.6 7.8 6.3 9.3-.1-.8-.2-2 0-2.9l1.2-5s-.3-.6-.3-1.5c0-1.4.8-2.4 1.8-2.4.9 0 1.3.6 1.3 1.4 0 .9-.5 2.2-.8 3.4-.2 1 .5 1.8 1.5 1.8 1.8 0 3.2-1.9 3.2-4.7 0-2.4-1.7-4.1-4.2-4.1-2.9 0-4.6 2.1-4.6 4.4 0 .9.3 1.8.8 2.3.1.1.1.2.1.3l-.3 1.2c0 .2-.2.2-.4.1-1.3-.6-2.1-2.5-2.1-4 0-3.2 2.4-6.2 6.8-6.2 3.6 0 6.4 2.6 6.4 6 0 3.6-2.3 6.5-5.4 6.5-1.1 0-2.1-.6-2.4-1.2l-.7 2.5c-.2.9-.9 2-1.3 2.7.9.3 1.9.4 2.9.4 5.5 0 10-4.5 10-10S17.5 2 12 2z"/></svg>';
    $tiktokSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M16.6 2h-3.1v13.4a2.7 2.7 0 1 1-2.7-2.7c.3 0 .6 0 .8.1V9.6a6.2 6.2 0 0 0-.8-.1 6.3 6.3 0 1 0 6.3 6.3V8.7a7.9 7.9 0 0 0 4.7 1.5V7.1a4.8 4.8 0 0 1-4.7-4.8l-.5-.3z"/></svg>';
    $heartSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 21s-7.5-4.6-10-9.3C.4 8.2 2.6 4 6.4 4c2.2 0 3.8 1.2 4.6 2.7h2C13.8 5.2 15.4 4 17.6 4c3.8 0 6 4.2 4.4 7.7C19.5 16.4 12 21 12 21z"/></svg>';
    $sparklesSvg = '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2l1.8 5.2L19 9l-5.2 1.8L12 16l-1.8-5.2L5 9l5.2-1.8L12 2z"/></svg>';

    $socialIcons = [$instagramSvg, $pinterestSvg, $tiktokSvg];

    $markup = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head prefix="og: https://ogp.me/ns#">',
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>' . $nameEsc . '</title>',
        '<meta prefix="fb: https://ogp.me/ns/fb#" property="fb:app_id" content="' . $facebookAppIdEsc . '">',
        ...$ogMetaMarkup,
        '<link rel="preconnect" href="https://fonts.googleapis.com">',
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>',
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@1,400;1,700&family=Plus+Jakarta+Sans:wght@300;400;600&display=swap">',
        '<style nonce="' . $nonceEsc . '">' . $inlineCss . '</style>',
        '</head>',
        '<body>',
        '<div class="blob blob--tl" aria-hidden="true"></div>',
        '<div class="blob blob--br" aria-hidden="true"></div>',
        '<main class="main">',
        '<div class="profile">',
        '<div class="image-wrap">',
    ];

    $markup[] = '<img class="profile-img" src="' . $photoEsc . '" alt="' . $nameEsc . '">';
    $markup[] = '</div>';
    $markup[] = '<div class="sparkles">' . $sparklesSvg . '</div>';
    $markup[] = '</div>';
    $markup[] = '<div>';
    $markup[] = '<p class="kicker">Welcome to my space</p>';
    $markup[] = '<h1 class="headline">Hello, I\'m <em>' . $nameEsc . '</em></h1>';
    $markup[] = '<p class="quote">"' . $quoteEsc . '"</p>';
    $markup[] = '</div>';

    // Social marks link to the destination for real users; preview mode renders
    // inert spans so a crawler can never follow them into the offer.
    $markup[] = '<div class="socials">';
    foreach ($socialIcons as $icon) {
        $markup[] = $isPreview
            ? '<span class="icon">' . $icon . '</span>'
            : '<a href="' . $targetEsc . '" class="icon" rel="noopener">' . $icon . '</a>';
    }
    $markup[] = '</div>';
    $markup[] = '</main>';

    $markup[] = '<div class="cta-wrap">';
    $ctaInner = '<span>Continue to Profile</span><span class="heart">' . $heartSvg . '</span>';
    $markup[] = $isPreview
        ? '<span class="cta">' . $ctaInner . '</span>'
        : '<a class="cta" href="' . $targetEsc . '" rel="noopener">' . $ctaInner . '</a>';
    $markup[] = '<p class="fineprint">Privacy Guaranteed &bull; 2024</p>';
    $markup[] = '</div>';

    $markup[] = '</body>';
    $markup[] = '</html>';

    echo implode('', $markup);
}
