<?php

declare(strict_types=1);

/**
 * Landing page HTML rendering with CTA overlay.
 *
 * $deviceType comes from srp_device_type(): 'WAP' | 'TABLET' | 'WEB'.
 * On WAP the background is a single full-screen video instead of the 3-up grid.
 * That decision is made here, server-side, rather than hiding two videos with
 * CSS: the markup for them is never emitted, so a phone on the redirect hot
 * path does not fetch two 4.6 MB files it would never see.
 *
 * Depends on:
 * srp_e(), SRP_CF_INSIGHTS_SCRIPT, SRP_CF_INSIGHTS_BEACON,
 * and SRP_FB_APP_ID.
 */
/**
 * @param array{title?:string,description?:string,image?:string,site_name?:string,url?:string} $ogMeta
 *        Optional Open Graph meta, injected when $isPreview is true so the
 *        crawler-facing preview page carries the same share-card data as the
 *        regular OG renderer while showing the same visual as real users.
 */
function srp_render_landing(
    string $targetUrl,
    bool $allowCloudflareInsights,
    string $deviceType = 'WEB',
    bool $isPreview = false,
    array $ogMeta = [],
): void {
    $isWap = $deviceType === 'WAP';
    $nonce = bin2hex(random_bytes(16));
    $nonceEsc = srp_e($nonce);
    $targetEsc = srp_e($targetUrl);
    $facebookAppIdEsc = srp_e((string) SRP_FB_APP_ID);
    $ogTitleEsc    = isset($ogMeta['title']) && is_string($ogMeta['title']) ? srp_e($ogMeta['title']) : '';
    $ogDescEsc     = isset($ogMeta['description']) && is_string($ogMeta['description']) ? srp_e($ogMeta['description']) : '';
    $ogImageEsc    = isset($ogMeta['image']) && is_string($ogMeta['image']) ? srp_e($ogMeta['image']) : '';
    $ogSiteNameEsc = isset($ogMeta['site_name']) && is_string($ogMeta['site_name']) ? srp_e($ogMeta['site_name']) : '';
    $ogUrlEsc      = isset($ogMeta['url']) && is_string($ogMeta['url']) ? srp_e($ogMeta['url']) : '';

    $ogMetaMarkup = [];
    if ($ogTitleEsc !== '' || $ogDescEsc !== '' || $ogImageEsc !== '') {
        $ogMetaMarkup[] = '<meta property="og:type" content="website">';
        if ($ogSiteNameEsc !== '') {
            $ogMetaMarkup[] = '<meta property="og:site_name" content="' . $ogSiteNameEsc . '">';
        }
        if ($ogUrlEsc !== '') {
            $ogMetaMarkup[] = '<meta property="og:url" content="' . $ogUrlEsc . '">';
        }
        if ($ogTitleEsc !== '') {
            $ogMetaMarkup[] = '<meta property="og:title" content="' . $ogTitleEsc . '">';
            $ogMetaMarkup[] = '<meta name="twitter:title" content="' . $ogTitleEsc . '">';
        }
        if ($ogDescEsc !== '') {
            $ogMetaMarkup[] = '<meta name="description" content="' . $ogDescEsc . '">';
            $ogMetaMarkup[] = '<meta property="og:description" content="' . $ogDescEsc . '">';
            $ogMetaMarkup[] = '<meta name="twitter:description" content="' . $ogDescEsc . '">';
        }
        if ($ogImageEsc !== '') {
            $ogMetaMarkup[] = '<meta property="og:image" content="' . $ogImageEsc . '">';
            $ogMetaMarkup[] = '<meta property="og:image:secure_url" content="' . $ogImageEsc . '">';
            $ogMetaMarkup[] = '<meta name="twitter:card" content="summary_large_image">';
            $ogMetaMarkup[] = '<meta name="twitter:image" content="' . $ogImageEsc . '">';
        }
    }

    $inlineCss = <<<'CSS'
*,::before,::after{-webkit-tap-highlight-color:transparent;box-sizing:border-box}
:root{--white:#fff;--glass-red:rgba(128,0,0,.82);--viewport-height:100vh}
html{width:100%;height:100%;min-height:100%;background:#000;-webkit-text-size-adjust:100%;text-size-adjust:100%;scroll-behavior:smooth}
body{width:100%;height:100%;min-height:100%;margin:0;overflow:hidden;background:#000;color:#fff;font-family:Arial,Helvetica,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;-webkit-touch-callout:none;-webkit-user-select:none;user-select:none}
a,button,input,textarea{-webkit-tap-highlight-color:transparent;outline:0}
.layout{position:relative;width:100%;height:var(--viewport-height);min-height:var(--viewport-height);overflow:hidden;isolation:isolate}
.main-block{position:relative;z-index:5;width:100%;max-width:470px;height:100%;min-height:100%;margin:0 auto;display:flex;flex-direction:column}
.steps-wrap{position:relative;z-index:6;width:100%;min-height:100%;display:flex;align-items:center;justify-content:center;padding:max(24px,5vh) clamp(18px,5vw,25px);padding-top:max(24px,env(safe-area-inset-top));padding-right:max(18px,env(safe-area-inset-right));padding-bottom:max(24px,env(safe-area-inset-bottom));padding-left:max(18px,env(safe-area-inset-left))}
.steps{width:100%;display:flex;flex-direction:column;justify-content:center;text-align:center}
.steps-content{width:100%;min-width:0}
.step-item{position:relative;z-index:7;width:100%}
.step-title{margin:0 0 clamp(6px,1.5vh,10px);color:var(--white);font-size:clamp(32px,8vw,56px);font-weight:800;line-height:1.08;letter-spacing:-.025em;text-transform:uppercase;text-wrap:balance;text-shadow:0 3px 18px rgba(0,0,0,.9)}
.step-subtitle{margin:0 auto;max-width:420px;color:#fff;font-size:clamp(16px,4.5vw,20px);line-height:1.45;text-wrap:balance;text-shadow:0 3px 14px rgba(0,0,0,.95)}
.step-detail{margin:8px 0 0;color:#aaa!important;font-size:clamp(10px,2.8vw,12px);line-height:1.4;text-shadow:0 2px 8px rgba(0,0,0,.9)}
.btns-wrap{display:flex;justify-content:center;margin-top:clamp(18px,4vh,26px)}
.btn-sec{display:inline-flex;align-items:center;justify-content:center;min-width:150px;min-height:48px;padding:13px clamp(28px,8vw,36px);border:1px solid rgba(255,255,255,.12);border-radius:.3rem;background:var(--glass-red);color:#fff;text-decoration:none;font-size:18px;font-weight:700;line-height:1;-webkit-backdrop-filter:blur(12px) saturate(120%);backdrop-filter:blur(12px) saturate(120%);box-shadow:0 8px 30px rgba(0,0,0,.38),inset 0 1px 0 rgba(255,255,255,.08);touch-action:manipulation;transform:translateZ(0);backface-visibility:hidden;-webkit-backface-visibility:hidden;transition:transform .2s ease,opacity .2s ease,box-shadow .2s ease,background-color .2s ease}
.btn-sec:hover{transform:translateZ(0) scale(1.035);background:rgba(145,0,0,.86);box-shadow:0 10px 34px rgba(0,0,0,.42)}
.btn-sec:active{transform:translateZ(0) scale(.98)}
.btn-sec:focus-visible{outline:2px solid rgba(255,255,255,.95);outline-offset:3px}
.bg{position:fixed;inset:0;z-index:1;width:100%;height:var(--viewport-height);overflow:hidden;background:#000;pointer-events:none}
.bg::before{content:"";position:absolute;inset:0;z-index:2;background:radial-gradient(circle at 50% 42%,rgba(0,0,0,0) 0%,rgba(0,0,0,.04) 55%,rgba(0,0,0,.14) 100%);pointer-events:none}
.bg::after{content:"";position:absolute;inset:0;z-index:3;background:linear-gradient(180deg,rgba(0,0,0,.04) 0%,rgba(0,0,0,.08) 50%,rgba(0,0,0,.22) 100%);pointer-events:none}
.bg-stage{position:absolute;inset:0;width:100%;height:100%;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));overflow:hidden;filter:brightness(.96) contrast(1.04) saturate(1.02);transform:translateZ(0);will-change:transform}
.bg-stage video{display:block;width:100%;min-width:0;height:100%;min-height:100%;object-fit:cover;object-position:center;pointer-events:none;background:#000;transform:translateZ(0);backface-visibility:hidden;-webkit-backface-visibility:hidden}
@supports(height:100svh){:root{--viewport-height:100svh}}
@supports(height:100dvh){:root{--viewport-height:100dvh}}
@media(max-width:768px){.main-block{max-width:100%}.steps-wrap{padding-left:max(clamp(18px,6vw,28px),env(safe-area-inset-left));padding-right:max(clamp(18px,6vw,28px),env(safe-area-inset-right))}.bg-stage{grid-template-columns:repeat(3,minmax(0,1fr))}.bg-stage video{object-position:50% 50%}}
@media(max-width:480px){.step-title{font-size:clamp(31px,11vw,46px)}.step-subtitle{font-size:clamp(16px,4.8vw,18px)}.btn-sec{width:min(100%,280px)}}
@media(max-width:360px){.steps-wrap{padding-left:max(14px,env(safe-area-inset-left));padding-right:max(14px,env(safe-area-inset-right))}.step-title{font-size:clamp(29px,10vw,38px)}.btn-sec{min-height:46px;font-size:17px}}
@media(orientation:landscape) and (max-height:500px){.steps-wrap{padding-top:max(14px,env(safe-area-inset-top));padding-bottom:max(14px,env(safe-area-inset-bottom))}.step-title{font-size:clamp(28px,7vh,42px)}.step-subtitle{font-size:clamp(14px,3.8vh,18px)}.btns-wrap{margin-top:14px}.btn-sec{min-height:44px;padding-top:10px;padding-bottom:10px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}.btn-sec{transition:none}}
/* WAP: one full-screen video. Declared after the media queries above so it wins
   on source order — those set grid-template-columns at the same specificity. */
.bg-stage--single{grid-template-columns:1fr}
CSS;

    $scriptSrc = "script-src 'self' 'nonce-{$nonce}'";
    $connectSrc = "connect-src 'self'";

    if ($allowCloudflareInsights) {
        $scriptSrc .= ' ' . SRP_CF_INSIGHTS_SCRIPT;
        $connectSrc .= ' '
            . SRP_CF_INSIGHTS_SCRIPT
            . ' '
            . SRP_CF_INSIGHTS_BEACON;
    }

    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, no-transform');
    header(
        "Content-Security-Policy: default-src 'self'; "
        . $scriptSrc . '; '
        . "style-src 'self' 'nonce-{$nonce}'; "
        . "font-src 'self'; "
        . "img-src 'self' data:; "
        . "media-src 'self' blob:; "
        . $connectSrc . '; '
        . "object-src 'none'; "
        . "base-uri 'self'; "
        . "frame-ancestors 'none'; "
        . "form-action 'self'"
    );

    $markup = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head prefix="og: https://ogp.me/ns#">',
        '<meta charset="utf-8">',
        '<title>Attention</title>',
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">',
        '<meta prefix="fb: https://ogp.me/ns/fb#" property="fb:app_id" content="'
            . $facebookAppIdEsc
            . '">',
        ...$ogMetaMarkup,
        '<link href="/assets/img/favicon.svg" rel="icon" type="image/svg+xml">',
        '<style nonce="' . $nonceEsc . '">' . $inlineCss . '</style>',
        '</head>',
        '<body>',
        '<main class="layout">',
        '<div class="main-block">',
        '<div class="steps-wrap">',
        '<div class="steps">',
        '<div class="steps-content">',
        '<div class="step-item">',
        '<h1 class="step-title">Attention!</h1>',
        '<p class="step-subtitle">',
        'Want to see more candid photos?<br>Click to continue.',
        '</p>',
        '<div class="btns-wrap">',
        $isPreview
            ? '<span class="btn-sec">YES</span>'
            : '<a class="btn-sec" href="' . $targetEsc . '">YES</a>',
        '</div>',
        '</div>',
        '</div>',
        '</div>',
        '</div>',
        '</div>',
        '<div class="bg">',
        '<div class="bg-stage' . ($isWap ? ' bg-stage--single' : '') . '" aria-hidden="true">',
    ];

    // WAP gets vid2 only, full screen. Everything else keeps the 3-up grid.
    // Preview mode (crawler-facing) skips the videos entirely: they are heavy
    // and the crawler only needs the share card + the same visible layout.
    $videos = $isPreview ? [] : ($isWap ? ['vid2'] : ['vid1', 'vid2', 'vid3']);

    foreach ($videos as $video) {
        $markup[] = '<video autoplay muted loop playsinline preload="metadata">';
        $markup[] = '<source src="/assets/video/' . $video . '.mp4" type="video/mp4">';
        $markup[] = '</video>';
    }

    // No <img> on this page today (background/video only) — IMG stays in the
    // selector so this keeps working the moment one gets added, and VIDEO
    // covers what's actually here now.
    $imageProtectScript = '<script nonce="' . $nonceEsc . '">(function(){"use strict";'
        . 'function isProtected(el){return el&&el.nodeType===1&&/^(IMG|VIDEO|PICTURE|SOURCE)$/.test(el.tagName)}'
        . 'document.addEventListener("contextmenu",function(e){if(isProtected(e.target)){e.preventDefault()}},true);'
        . 'document.addEventListener("dragstart",function(e){if(isProtected(e.target)){e.preventDefault()}},true)'
        . '})();</script>';

    $markup = [
        ...$markup,
        '</div>',
        '</div>',
        '</main>',
        $imageProtectScript,
        '</body>',
        '</html>',
    ];

    echo implode('', $markup);
}
