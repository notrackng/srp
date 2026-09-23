<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/env.php';

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

include_once __DIR__ . '/../password.login.php';

const ADMIN_CSRF_NAMESPACE = 'admin_panel';

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function adminIsHttpsRequest(): bool
{
    return srp_request_is_https();
}

function startAdminSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    session_name('sslmgr_admin');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => adminIsHttpsRequest(), 'httponly' => true, 'samesite' => 'Strict']);
    session_start();
}

function adminEsc(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function adminCsrfToken(): string
{
    if (!isset($_SESSION['csrf'][ADMIN_CSRF_NAMESPACE]) || !is_string($_SESSION['csrf'][ADMIN_CSRF_NAMESPACE])) {
        $_SESSION['csrf'][ADMIN_CSRF_NAMESPACE] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf'][ADMIN_CSRF_NAMESPACE];
}

function adminHasValidCsrf(?string $token): bool
{
    $storedToken = $_SESSION['csrf'][ADMIN_CSRF_NAMESPACE] ?? null;

    return is_string($token) && is_string($storedToken) && hash_equals($storedToken, $token);
}

function showLoginPasswordProtect(string $errorMsg, string $nonce, string $csrfToken): never
{
    header('Location: /login.php');
    exit;
}

startAdminSession();

$nonce     = base64_encode(random_bytes(18));
$csrfToken = adminCsrfToken();

header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header(
    "Content-Security-Policy: default-src 'self'; "
    . "base-uri 'self'; form-action 'self'; frame-ancestors 'self'; "
    . "img-src 'self' data: https:; font-src 'self' data: https:; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    . "script-src 'self' 'nonce-{$nonce}'; connect-src 'self';",
);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    if (!adminHasValidCsrf(is_string($_POST['csrf_token'] ?? null) ? $_POST['csrf_token'] : null)) {
        http_response_code(419);
        exit('Session expired. Reload the page and try again.');
    }

    unset($_SESSION['admin_authenticated']);
    session_regenerate_id(true);
    header('Location: /login.php');
    exit;
}

if (empty($_SESSION['admin_authenticated'])) {
    showLoginPasswordProtect('', $nonce, $csrfToken);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Shortlinks — Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="<?= adminEsc($csrfToken); ?>">
<link href="/favicon.ico" rel="icon" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Caveat:wght@500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/bootstrap.min.css" type="text/css" media="all">
<link href="//fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style nonce="<?= adminEsc($nonce); ?>">
:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Roboto Mono", "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Roboto Mono", "Geist Mono", Consolas, monospace !important;--bg:var(--porcelain);--light:var(--porcelain);--surface:var(--porcelain);--panel2:var(--paper);--panel-soft:var(--paper);--panel-raised:var(--panel);--panel-fade:rgba(252, 251, 248, 0.7);--nav:var(--paper);--line:var(--soft-steel);--line2:var(--border);--line-soft:var(--border);--stroke:var(--soft-steel);--text:var(--graphite);--btn:var(--graphite);--primary:var(--graphite);--primary2:var(--ink);--text-strong:var(--ink);--strong:var(--ink);--dark:var(--ink);--muted:var(--steel-gray);--faded:var(--steel-gray);--accent:var(--burnt-copper);--accent-h:#8f5236;--accent-hover:#8f5236;--accent-s:var(--burnt-copper-soft);--accent-soft:var(--burnt-copper-soft);--on:var(--paper);--on-accent:var(--paper);--inverse:var(--paper);--good:var(--graphite);--ok:var(--graphite);--success:var(--graphite);--ok-soft:var(--burnt-copper-soft);--success-soft:var(--burnt-copper-soft);--bad:var(--burnt-copper);--danger:var(--burnt-copper);--danger-soft:var(--burnt-copper-soft);--warn:var(--steel-gray);--blue-soft:var(--burnt-copper-soft);--blue-line:rgba(168, 100, 66, 0.28);--shadow-modal:var(--shadow);--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}@media (prefers-color-scheme:dark){}

*{box-sizing:border-box}html,body{width:100%;height:100dvh;margin:0;}html{background:var(--bg);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}body{padding:58px 8px 18px!important;background:linear-gradient(180deg,var(--paper) 0%,var(--porcelain) 100%)!important;color:var(--text)!important;font-family:var(--font);font-size:var(--fs-base);line-height:var(--lh-normal);-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}.container{width:100%;max-width:1280px;margin:0 auto}
.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:var(--paper)!important;box-shadow:var(--shadow)!important;backdrop-filter:blur(18px) saturate(180%);-webkit-backdrop-filter:blur(18px) saturate(180%)}.navbar .container{max-width:1280px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:var(--fs-base);line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;color:var(--text)!important;font-size:var(--fs-sm)}.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{box-shadow:none!important;background:transparent!important;color:var(--text-strong)!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:none!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}
.panel,.panel-default{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;backdrop-filter:blur(16px) saturate(180%);-webkit-backdrop-filter:blur(16px) saturate(180%);overflow:visible!important}.panel-body{padding:0!important;background:transparent!important;overflow:visible!important}
.btn,button{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm);font-weight:var(--fw-bold);line-height:var(--lh-tight);box-shadow:none!important;outline:none;transition:background .12s,border-color .12s,color .12s}.btn:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.btn-primary:hover{background:var(--accent-hover)!important;border-color:var(--accent-hover)!important;color:var(--on-accent)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(102,113,122,.16)!important}
.form-control,input,select{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-family:inhe!important;font-size:var(--fs-sm)!important;box-shadow:none!important}.form-control:focus,input:focus,select:focus{outline:none;border-color:var(--accent)!important}.input-group-addon{height:31px;padding:5px 8px;background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:var(--fs-sm)}
.table{width:100%;border-collapse:collapse;font-size:var(--fs-base);margin:0!important;border:0!important;border-radius:0!important;background:transparent!important}.table>thead>tr>th{height:34px;padding:0 10px!important;text-align:left;font-size:var(--fs-xs);font-weight:var(--fw-semibold);color:var(--text-strong);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--line)!important;border-top:0!important;background:var(--panel-soft)!important;white-space:nowrap;position:static}.table>tbody>tr>td{padding:7px 10px!important;vertical-align:middle;border-bottom:1px solid var(--line-soft)!important;border-top:0!important;font-size:var(--fs-base);color:var(--text)!important;background:transparent!important}.table>tbody>tr:last-child>td{border-bottom:0!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}
.tbl-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;flex-wrap:wrap;border-bottom:1px solid var(--soft-steel);background:var(--porcelain)}.tbl-toolbar-left{display:flex;align-items:center;gap:6px}.tbl-footer{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;border-top:1px solid var(--soft-steel);font-size:var(--fs-sm);color:var(--text);flex-wrap:wrap;background:var(--porcelain)}
.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.pagination{margin:0!important}
.admin-toast-root{position:fixed;right:12px;bottom:12px;z-index:10050;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.admin-toast{font-family:var(--mono);max-width:340px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm);line-height:var(--lh-snug)}.admin-toast strong{display:block;margin-bottom:2px;color:var(--text-strong)}.admin-toast--error{border-color:rgba(102,113,122,.34);background:var(--danger-soft);color:var(--danger)}.admin-toast--success{border-color:var(--blue-line);background:var(--blue-soft)}
.admin-fallback-backdrop{position:fixed;inset:0;z-index:10040;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(37,42,46,.36)}.admin-fallback-dialog{width:min(400px,100%);border:1px solid var(--line);border-radius:var(--radius);background:var(--paper);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.admin-fallback-head{padding:10px;border-bottom:1px solid var(--line-soft);font-weight:var(--fw-bold);color:var(--text-strong);background:var(--paper)}.admin-fallback-body{padding:10px;font-size:var(--fs-sm);background:var(--paper)}.admin-fallback-actions{display:flex;gap:6px;justify-content:flex-end;padding:10px;border-top:1px solid var(--line-soft);background:var(--paper)}
.sl-code{font-family:var(--mono);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.03em;display:inline-block;padding:2px 7px;background:var(--panel-soft);border:1px solid var(--line);border-radius:var(--radius)}.sl-short{font-family:var(--mono);font-size:var(--fs-sm);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}.sl-long{font-family:var(--mono);font-size:var(--fs-xs);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;color:color-mix(in srgb,var(--text) 64%,transparent)}.sl-title{font-size:var(--fs-sm);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block}.sl-date{font-size:var(--fs-xs);white-space:nowrap;color:color-mix(in srgb,var(--text) 62%,transparent)}.sl-actions{display:flex;align-items:center;gap:4px;justify-content:flex-end;white-space:nowrap}
.action-btn{display:inline-flex;align-items:center;justify-content:center;padding:4px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:transparent!important;color:var(--text)!important}.action-btn:hover{background:transparent!important;border-color:var(--text)!important;color:var(--text-strong)!important}.action-btn svg{display:block;width:14px;height:14px;pointer-events:none}
#tbl-shortlinks{table-layout:fixed;width:100%;min-width:820px}#tbl-shortlinks th:nth-child(1),#tbl-shortlinks td:nth-child(1){width:44px;text-align:center}#tbl-shortlinks th:nth-child(2),#tbl-shortlinks td:nth-child(2){width:100px}#tbl-shortlinks th:nth-child(3),#tbl-shortlinks td:nth-child(3){width:260px}#tbl-shortlinks th:nth-child(4),#tbl-shortlinks td:nth-child(4){width:190px}#tbl-shortlinks th:nth-child(5),#tbl-shortlinks td:nth-child(5){width:270px}#tbl-shortlinks th:nth-child(6),#tbl-shortlinks td:nth-child(6){width:110px}#tbl-shortlinks th:nth-child(7),#tbl-shortlinks td:nth-child(7){width:90px;text-align:right}
.td-num{display:block;font-size:var(--fs-xs);font-weight:var(--fw-semibold);font-family:var(--mono);color:color-mix(in srgb,var(--text) 44%,transparent);text-align:center}
#logout-toast{position:fixed;bottom:20px;right:20px;background:rgba(37,42,46,.88);color:var(--paper);padding:7px 15px;border-radius:6px;font-size:var(--fs-sm);font-weight:var(--fw-semibold);z-index:99999;opacity:0;pointer-events:none;transition:opacity .2s;box-shadow:none}#logout-toast.show{opacity:1}
@media(max-width:768px){body{padding:58px 6px 12px!important}.container{width:100%!important;max-width:100%!important;padding:0 6px!important}.navbar .container{padding:0 8px!important}.tbl-toolbar{flex-wrap:wrap}.tbl-toolbar-left{flex:1 0 100%}.table{display:block;overflow-x:auto}}
*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}/* ── Extended components ── */.card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius)}.btn-ghost{background:var(--faded)!important;color:var(--inverse)!important;border-color:var(--line)!important;box-shadow:none!important}.btn-ghost:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.chip{display:inline-flex;align-items:center;padding:2px 8px;border:1px solid var(--line-soft);background:var(--panel-soft);border-radius:var(--radius);font-size:var(--fs-xs);color:var(--text);line-height:var(--lh-snug)}.toast{position:fixed;right:18px;bottom:18px;z-index:10070;display:none;align-items:center;gap:8px;background:var(--inverse);color:var(--faded);padding:10px 12px;font-size:var(--fs-sm);border:1px solid var(--line-soft);border-radius:var(--radius);box-shadow:var(--shadow-modal)}.toast.show{display:flex}canvas{display:block;width:100%;height:430px;border:1px solid var(--line);background:var(--panel);border-radius:var(--radius)}
select hr{border:none;border-top:1px solid rgba(37,42,46,.06)!important;color:rgba(37,42,46,.06)!important;opacity:.45;margin:1px 4px}.app-sign{text-align:right;padding:3px 0 2px}.app-sign footer{font-family:var(--mono);text-decoration:none;letter-spacing:.09em;font-size:10px;font-weight:900;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;user-select:none;text-transform:uppercase;-webkit-user-select:none}input[type=url]{font-family:var(--mono)!important}body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none}body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)}
/* ngix xctd image backdrop */
.panel.panel-default:has(> .ngix-image-backdrop){position:relative!important;overflow:hidden!important;isolation:isolate!important;background:rgba(252,251,248,.74)!important}
.panel.panel-default>.ngix-image-backdrop{position:absolute!important;inset:0!important;z-index:0!important;pointer-events:none!important;background-image:linear-gradient(rgba(252,251,248,.82),rgba(252,251,248,.82)),url('/assets/img/bg-intro.png')!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,cover!important;filter:saturate(.72) contrast(.86) blur(.22px)!important;opacity:.42;transform:translateZ(0)}
.panel.panel-default:has(> .ngix-image-backdrop)>*:not(.ngix-image-backdrop){position:relative!important;z-index:2!important}
.panel.panel-default:has(> .ngix-image-backdrop)>.tbl-toolbar,.panel.panel-default:has(> .ngix-image-backdrop)>.tbl-footer{background:rgba(244,241,236,.82)!important}
.panel.panel-default:has(> .ngix-image-backdrop)>.tbl-toolbar{backdrop-filter:saturate(110%) blur(1px)!important}
.panel.panel-default:has(> .ngix-image-backdrop) .table{position:relative!important;z-index:3!important;background:rgba(252,251,248,.46)!important}
.panel.panel-default:has(> .ngix-image-backdrop) .table>thead>tr>th{background:rgba(244,241,236,.86)!important}
.panel.panel-default:has(> .ngix-image-backdrop) .table>tbody>tr>td{background:rgba(252,251,248,.30)!important}
.panel.panel-default:has(> .ngix-image-backdrop) .table.table-hover>tbody>tr:hover>td{background:rgba(244,241,236,.72)!important}
@media screen and (max-width:768px){.panel.panel-default>.ngix-image-backdrop{background-size:100% 100%,cover!important;background-position:center center,center center!important;opacity:.34}}
.noise {
    position: fixed;
    z-index: 90;
    inset: 0;
    pointer-events: none;
    opacity: 0.035;
    mix-blend-mode: soft-light;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 180 180' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.7'/%3E%3C/svg%3E");
}
.scanline {
    position: fixed;
    z-index: -2;
    inset: 0;
    pointer-events: none;
    background-image: linear-gradient(rgba(102,113,122,0.07) 1px, transparent 1px),
        linear-gradient(90deg, rgba(102,113,122,0.07) 1px, transparent 1px);
    background-size: 44px 44px;
    mask-image: linear-gradient(to bottom, black, transparent 92%);
}
</style>
</head>
<body>
<script nonce="<?= adminEsc($nonce); ?>" src="/assets/js/jquery-1.11.1.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>" src="/assets/js/bootstrap.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>">
(function($){ 'use strict'; $.ajaxSetup({ headers: { 'X-CSRF-Token': <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?> } }); }(jQuery));
</script>
<script nonce="<?= adminEsc($nonce); ?>">
(function(w,d){
'use strict';
function ensureToastRoot(){var r=d.querySelector('.admin-toast-root');if(r)return r;r=d.createElement('div');r.className='admin-toast-root';r.setAttribute('aria-live','polite');d.body.appendChild(r);return r;}
function showToast(type,title,text){var r=ensureToastRoot();var el=d.createElement('div');el.className='admin-toast admin-toast--'+(type==='error'?'error':type==='success'?'success':'info');if(title){var s=d.createElement('strong');s.textContent=title;el.appendChild(s);}if(text){var sp=d.createElement('span');sp.textContent=text;el.appendChild(sp);}r.appendChild(el);w.setTimeout(function(){if(el.parentNode)el.parentNode.removeChild(el);},2400);}
function confirmDialog(opts){return new Promise(function(resolve){var bd=d.createElement('div');bd.className='admin-fallback-backdrop';var dl=d.createElement('div');dl.className='admin-fallback-dialog';var hd=d.createElement('div');hd.className='admin-fallback-head';hd.textContent=opts.title||'Confirm';var bo=d.createElement('div');bo.className='admin-fallback-body';bo.textContent=opts.text||'';var ac=d.createElement('div');ac.className='admin-fallback-actions';var cn=d.createElement('button');cn.className='btn btn-xs';cn.textContent='Cancel';var ok=d.createElement('button');ok.className='btn btn-xs btn-danger';ok.textContent=opts.confirmText||'Delete';cn.onclick=function(){if(bd.parentNode)bd.parentNode.removeChild(bd);resolve(false);};ok.onclick=function(){if(bd.parentNode)bd.parentNode.removeChild(bd);resolve(true);};ac.appendChild(cn);ac.appendChild(ok);dl.appendChild(hd);dl.appendChild(bo);dl.appendChild(ac);bd.appendChild(dl);d.body.appendChild(bd);});}
w._adminUI={showToast:showToast,confirmDialog:confirmDialog};
}(window,document));
</script>

<div role="navigation" class="navbar navbar-default navbar-fixed-top">
    <div class="container">
        <div class="navbar-header">
            <button data-target=".navbar-collapse" data-toggle="collapse" class="navbar-toggle" type="button">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span><span class="icon-bar"></span><span class="icon-bar"></span>
            </button>
            <a href="#" class="navbar-brand"><strong>Admin Panel</strong></a>
        </div>
        <div class="navbar-collapse collapse navbar-right">
            <ul class="nav navbar-nav">
                <li><a href="/dashboard/"><strong>Dashboard</strong></a></li>
                <li><a href="/campaigns/"><strong>Campaigns</strong></a></li>
                <li><a href="/addondomain/"><strong>Addon Domain</strong></a></li>
                <li class="active"><a href="#"><strong>Shortlinks</strong></a></li>
                <li>
                    <form method="post">
                        <input type="hidden" name="action" value="logout">
                        <input type="hidden" name="csrf_token" value="<?= adminEsc($csrfToken); ?>">
                        <button type="submit" class="navbar-btn btn-link"><strong>Logout</strong></button>
                    </form>
                </li>
            </ul>
        </div>
    </div>
</div>

<div class="container">
<div class="noise" aria-hidden="true"></div>
<div class="scanline" aria-hidden="true"></div>
    <div class="panel panel-default">
        <div class="ngix-image-backdrop" aria-hidden="true"></div>
        <div class="tbl-toolbar">
            <div class="tbl-toolbar-left">
                <div class="input-group" style="width:200px;">
                    <span class="input-group-addon"><span class="glyphicon glyphicon-search"></span></span>
                    <input type="text" class="form-control" id="tbl-search" placeholder="Search code / title / URL…">
                </div>
                <select id="tbl-rowcount" class="form-control" style="width:70px;height:31px;display:inline-block;">
                    <option value="25">25</option>
                    <hr>
                    <option value="50">50</option>
                    <hr>
                    <option value="100">100</option>
                    <hr>
                    <option value="-1">All</option>
                </select>
            </div>
            <span id="tbl-total-badge" style="font-size:var(--fs-sm);color:var(--text);"></span>
        </div>
        <div style="overflow-x:auto;">
            <table id="tbl-shortlinks" class="table table-hover">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Code</th>
                        <th>Short URL</th>
                        <th>OG Title</th>
                        <th>Long URL</th>
                        <th>Created</th>
                        <th style="text-align:right;">Action</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>
        <div class="tbl-footer">
            <span id="tbl-info" style="font-size:var(--fs-sm);"></span>
            <ul class="pagination" id="tbl-pagination"></ul>
        </div>
    </div>
</div>

<div id="logout-toast">Logging out…</div>

<script nonce="<?= adminEsc($nonce); ?>">
$(document).ready(function() {
    'use strict';

    var SVG_COPY   = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
    var SVG_DELETE = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M6 7l1 13h10l1-13"/><path d="M9 7V4h6v3"/></svg>';
    var SVG_OPEN   = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>';

    function escHtml(v) {
        return String(v == null ? '' : v)
            .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    var state = { current: 1, rowCount: 25, search: '', rows: [] };

    function renderRow(row, idx) {
        var shortEsc = escHtml(row.short_url);
        var longEsc  = escHtml(row.long_url);
        var titleEsc = escHtml(row.og_title);
        var codeEsc  = escHtml(row.code);
        return '<tr>' +
            '<td><span class="td-num">' + ((state.current - 1) * (state.rowCount === -1 ? 0 : state.rowCount) + idx + 1) + '</span></td>' +
            '<td><span class="sl-code">' + codeEsc + '</span></td>' +
            '<td><span class="sl-short" title="' + shortEsc + '">' + shortEsc + '</span></td>' +
            '<td><span class="sl-title" title="' + titleEsc + '">' + (titleEsc || '<span style="opacity:.4">—</span>') + '</span></td>' +
            '<td><span class="sl-long" title="' + longEsc + '">' + longEsc + '</span></td>' +
            '<td><span class="sl-date">' + escHtml(row.created_at) + '</span></td>' +
            '<td>' +
                '<div class="sl-actions">' +
                    '<button type="button" class="action-btn btn-copy" title="Copy short URL" data-url="' + shortEsc + '">' + SVG_COPY + '</button>' +
                    '<a href="' + shortEsc + '" target="_blank" rel="noopener noreferrer" class="action-btn" title="Open">' + SVG_OPEN + '</a>' +
                    '<button type="button" class="action-btn btn-del" title="Delete" data-code="' + codeEsc + '">' + SVG_DELETE + '</button>' +
                '</div>' +
            '</td></tr>';
    }

    function renderPagination(total, current, rowCount) {
        var $pg = $('#tbl-pagination');
        if (rowCount === -1 || total === 0) { $pg.empty(); return; }
        var pages = Math.ceil(total / rowCount);
        if (pages <= 1) { $pg.empty(); return; }
        var html = '', start = Math.max(1, current - 2), end = Math.min(pages, current + 2);
        html += '<li class="' + (current <= 1 ? 'disabled' : '') + '"><a href="#" data-page="' + (current - 1) + '">&laquo;</a></li>';
        if (start > 1) { html += '<li><a href="#" data-page="1">1</a></li>' + (start > 2 ? '<li class="disabled"><span>…</span></li>' : ''); }
        for (var p = start; p <= end; p++) {
            html += '<li class="' + (p === current ? 'active' : '') + '"><a href="#" data-page="' + p + '">' + p + '</a></li>';
        }
        if (end < pages) { html += (end < pages - 1 ? '<li class="disabled"><span>…</span></li>' : '') + '<li><a href="#" data-page="' + pages + '">' + pages + '</a></li>'; }
        html += '<li class="' + (current >= pages ? 'disabled' : '') + '"><a href="#" data-page="' + (current + 1) + '">&raquo;</a></li>';
        $pg.html(html).off('click','a').on('click','a',function(e){
            e.preventDefault();
            var pg = parseInt($(this).data('page'));
            if (!isNaN(pg) && pg >= 1 && pg <= pages && pg !== state.current) {
                state.current = pg; loadData();
            }
        });
    }

    function bindRowActions() {
        var $tbody = $('#tbl-shortlinks tbody');

        $tbody.find('.btn-copy').off('click').on('click', function() {
            var url = $(this).data('url');
            if (!url) return;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(url).then(function() {
                    window._adminUI.showToast('success', 'Copied', url);
                }).catch(function() {
                    fallbackCopy(url);
                });
            } else {
                fallbackCopy(url);
            }
        });

        $tbody.find('.btn-del').off('click').on('click', function() {
            var code = $(this).data('code');
            window._adminUI.confirmDialog({
                title: 'Delete shortlink?',
                text: 'Code: ' + code + ' — this cannot be undone.',
                confirmText: 'Delete'
            }).then(function(confirmed) {
                if (!confirmed) return;
                $.ajax({
                    type: 'POST', url: 'response.php',
                    data: { action: 'delete', code: code },
                    dataType: 'json',
                    success: function(res) {
                        if (res && res.ok) {
                            window._adminUI.showToast('success', 'Deleted', 'Code ' + code + ' removed.');
                            loadData();
                        } else {
                            window._adminUI.showToast('error', 'Error', 'Delete failed.');
                        }
                    },
                    error: function() {
                        window._adminUI.showToast('error', 'Error', 'Request failed.');
                    }
                });
            });
        });
    }

    function fallbackCopy(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); window._adminUI.showToast('success', 'Copied', text); }
        catch(e) { window._adminUI.showToast('error', 'Copy failed', ''); }
        document.body.removeChild(ta);
    }

    function loadData() {
        $.ajax({
            type: 'POST', url: 'response.php',
            data: { current: state.current, rowCount: state.rowCount, searchPhrase: state.search },
            dataType: 'json',
            success: function(data) {
                state.rows = data.rows || [];
                var total  = data.total || 0;
                var html   = '';
                for (var i = 0; i < state.rows.length; i++) { html += renderRow(state.rows[i], i); }
                $('#tbl-shortlinks tbody').html(html || '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--text);opacity:.6;">No shortlinks found.</td></tr>');
                var from = total === 0 ? 0 : ((state.current - 1) * (state.rowCount === -1 ? total : state.rowCount)) + 1;
                var to   = state.rowCount === -1 ? total : Math.min(state.current * state.rowCount, total);
                $('#tbl-info').text('Showing ' + from + '–' + to + ' of ' + total);
                $('#tbl-total-badge').text(total + ' total');
                renderPagination(total, state.current, state.rowCount);
                bindRowActions();
            },
            error: function() {
                window._adminUI.showToast('error', 'Load failed', 'Could not fetch data.');
            }
        });
    }

    var searchTimer;
    $('#tbl-search').on('input', function() {
        clearTimeout(searchTimer);
        var val = $(this).val();
        searchTimer = setTimeout(function() { state.search = val; state.current = 1; loadData(); }, 280);
    });
    $('#tbl-rowcount').on('change', function() {
        state.rowCount = parseInt(this.value) || 25; state.current = 1; loadData();
    });

    document.addEventListener('click', function(e) {
        var target = e.target;
        var btn = target && typeof target.closest === 'function' ? target.closest('#btn-logout') : null;

        if (!btn) {
            return;
        }

        e.preventDefault();

        var href = btn.getAttribute('href') || btn.getAttribute('data-href') || '/logout';
        var toast = document.getElementById('logout-toast');

        if (toast) {
            toast.classList.add('show');
        }

        window.setTimeout(function() {
            window.location.href = href;
        }, 900);
    });

    loadData();
});
</script>
<style nonce="<?= adminEsc($nonce); ?>">.admin-toast-root{right:14px!important;bottom:14px!important;gap:6px!important;z-index:10070!important}.admin-toast{font-family:var(--mono);position:relative!important;display:grid!important;grid-template-columns:3px minmax(0,1fr)!important;column-gap:9px!important;align-items:start!important;min-width:190px!important;max-width:320px!important;padding:8px 10px 8px 0!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--paper)!important;color:var(--text)!important;box-shadow:0 4px 14px rgba(22,25,28,.08)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important}.admin-toast:before{content:"";grid-row:1/3;width:3px;align-self:stretch;background:var(--muted);border-radius:var(--radius) 0 0 var(--radius)}.admin-toast strong{margin:0 0 1px!important;color:var(--text-strong)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)}.admin-toast span{min-width:0;color:var(--text)!important;opacity:.84;word-break:break-word}.admin-toast--success:before{background:var(--success)!important}.admin-toast--error:before{background:var(--danger)!important}.admin-toast--info:before{background:var(--muted)!important}#logout-toast{right:14px!important;bottom:14px!important;padding:8px 10px!important;border:1px solid var(--line)!important;border-left:3px solid var(--accent)!important;border-radius:var(--radius)!important;background:var(--paper)!important;color:var(--text-strong)!important;box-shadow:0 4px 14px rgba(22,25,28,.08)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important}</style>
<div class="app-sign"><footer>Ngix · xctd</footer></div>
<style nonce="<?= adminEsc($nonce); ?>">
/* NGIX patch: fullscreen background/backdrop override */
html,body{min-height:100svh!important}
body{background-color:var(--bg,var(--porcelain))!important;background-attachment:fixed!important}
body::after{content:""!important;position:fixed!important;inset:0!important;width:100vw!important;min-width:100vw!important;height:100vh!important;height:100dvh!important;z-index:0!important;pointer-events:none!important;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png')!important;background-repeat:no-repeat,no-repeat!important;background-position:right 14px bottom 12px,center center!important;background-size:28px 28px,cover!important;opacity:.30!important;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px)!important;transform:translateZ(0)!important}
body>.container,body>.app-shell,body>.navbar,body>.panel,body>.panel_m,main,.container,.navbar,.panel,.panel_m,.app-footer{position:relative;z-index:1}
.panel_m.panel>.ngix-image-backdrop{position:fixed!important;inset:0!important;width:100vw!important;min-width:100vw!important;height:100vh!important;height:100dvh!important;z-index:0!important;pointer-events:none!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,cover!important;opacity:.40!important;filter:saturate(.72) contrast(.86) blur(.22px)!important;transform:translateZ(0)!important}
.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body{position:relative!important;z-index:2!important}
@media (prefers-color-scheme:dark){body::after{opacity:.24!important;filter:saturate(.62) contrast(.78) brightness(.88) blur(.34px)!important}.panel_m.panel>.ngix-image-backdrop{opacity:.34!important;filter:saturate(.66) contrast(.80) blur(.24px)!important}}
@media screen and (max-width:768px){body::after{background-position:right 10px bottom 10px,center center!important;background-size:24px 24px,cover!important;opacity:.24!important}.panel_m.panel>.ngix-image-backdrop{background-size:100% 100%,cover!important;opacity:.30!important}}

/* NGIX patch: viewport/navbar correction */
html{width:100%!important;min-width:100%!important;max-width:none!important;min-height:100%!important;margin:0!important;padding:0!important;overflow-x:hidden!important;background:var(--bg,var(--porcelain))!important;zoom:1!important}
body{width:100%!important;min-width:100vw!important;max-width:none!important;min-height:100vh!important;min-height:100svh!important;min-height:100dvh!important;margin:0!important;overflow-x:hidden!important;background-color:var(--bg,var(--porcelain))!important;background-attachment:fixed!important}
body::after{top:0!important;right:0!important;bottom:0!important;left:0!important;inset:0!important;width:100vw!important;min-width:100vw!important;max-width:none!important;height:100vh!important;height:100svh!important;height:100dvh!important;background-size:28px 28px,cover!important;background-position:right 14px bottom 12px,center center!important}
.navbar.navbar-fixed-top,.navbar-fixed-top{position:fixed!important;top:0!important;right:0!important;left:0!important;width:100vw!important;max-width:none!important;margin:0!important;border-radius:0!important;transform:none!important;z-index:1055!important}
body>.navbar.navbar-fixed-top{position:fixed!important;z-index:1055!important}.navbar.navbar-default.navbar-fixed-top{top:0!important}
.panel_m.panel{overflow:visible!important;isolation:auto!important}.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{position:fixed!important;top:0!important;right:0!important;bottom:0!important;left:0!important;width:100vw!important;min-width:100vw!important;max-width:none!important;height:100vh!important;height:100svh!important;height:100dvh!important;z-index:0!important;background-size:100% 100%,cover!important;background-position:center center,center center!important;pointer-events:none!important}.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body,.panel_m.panel>.table-responsive{position:relative!important;z-index:2!important}
@supports (height:100lvh){body{min-height:100lvh!important}body::after,.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{height:100lvh!important;min-height:100lvh!important}}
@media screen and (max-width:768px){html{zoom:1!important}.navbar.navbar-fixed-top,.navbar-fixed-top{top:0!important;width:100vw!important}.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{width:100vw!important;height:100svh!important;height:100dvh!important;min-height:100svh!important;background-size:100% 100%,cover!important}}
</style>
<style nonce="<?= adminEsc($nonce); ?>">
/* NGIX patch: disable image/background right-click */
img,picture,svg,canvas,.ngix-image-backdrop,.image-protect,.app-banner,.brand-logo,.logo{
  -webkit-user-drag:none!important;
  -webkit-touch-callout:none!important;
  -webkit-user-select:none!important;
  user-select:none!important;
}
</style>
<script nonce="<?= adminEsc($nonce); ?>">
/* NGIX patch: disable image/background right-click */
(function(){
    'use strict';

    var protectedSelector = 'img,picture,svg,canvas,.ngix-image-backdrop,.image-protect,.app-banner,.brand-logo,.logo';
    var editableSelector = 'input,textarea,select,[contenteditable="true"],[contenteditable=""]';

    function closest(node, selector) {
        return node && typeof node.closest === 'function' ? node.closest(selector) : null;
    }

    function hasProtectedBackground(node) {
        var current = node && node.nodeType === 1 ? node : null;

        while (current && current !== document.documentElement) {
            if (current.classList && (
                current.classList.contains('ngix-image-backdrop')
                || current.classList.contains('image-protect')
                || current.classList.contains('app-banner')
                || current.classList.contains('brand-logo')
            )) {
                return true;
            }

            var backgroundImage = window.getComputedStyle(current).backgroundImage;
            if (backgroundImage && backgroundImage !== 'none' && backgroundImage.indexOf('url(') !== -1) {
                return true;
            }

            if (current === document.body) {
                break;
            }

            current = current.parentElement;
        }

        return false;
    }

    function isProtectedTarget(node) {
        if (!node || closest(node, editableSelector)) {
            return false;
        }

        return !!closest(node, protectedSelector) || hasProtectedBackground(node);
    }

    function blockImageAction(event) {
        if (!isProtectedTarget(event.target)) {
            return;
        }

        event.preventDefault();
        event.stopPropagation();
    }

    function hardenImages() {
        document.querySelectorAll('img,picture,svg,canvas').forEach(function(node) {
            node.setAttribute('draggable', 'false');
        });
    }

    document.addEventListener('contextmenu', blockImageAction, true);
    document.addEventListener('dragstart', blockImageAction, true);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', hardenImages, {once: true});
        return;
    }

    hardenImages();
}());
</script>

<style nonce="<?= adminEsc($nonce); ?>">
/* NGIX patch: public modal/backdrop/logout spinner correction */
html {
  zoom: 1 !important;
  width: 100% !important;
  min-width: 100% !important;
  overflow-x: hidden !important;
}
body {
  width: 100% !important;
  min-width: 100vw !important;
  max-width: none !important;
  overflow-x: hidden !important;
}
body.modal-open {
  overflow: hidden !important;
  padding-right: 0 !important;
}
.modal-backdrop {
  position: fixed !important;
  inset: 0 !important;
  width: 100vw !important;
  max-width: none !important;
  height: 100vh !important;
  height: 100dvh !important;
  margin: 0 !important;
  background: var(--ink) !important;
  z-index: 1060 !important;
}
.modal-backdrop.in {
  opacity: .48 !important;
}
.modal {
  position: fixed !important;
  inset: 0 !important;
  width: 100vw !important;
  max-width: none !important;
  height: 100vh !important;
  height: 100dvh !important;
  margin: 0 !important;
  padding: 58px 12px 14px !important;
  overflow-x: hidden !important;
  overflow-y: auto !important;
  text-align: center !important;
  z-index: 1070 !important;
  -webkit-overflow-scrolling: touch !important;
}
.modal.fade .modal-dialog,
.modal.in .modal-dialog {
  transform: none !important;
}
.modal-dialog {
  display: block !important;
  width: auto !important;
  max-width: min(560px, calc(100vw - 24px)) !important;
  margin: 0 auto !important;
  text-align: left !important;
}
.modal-wide {
  max-width: min(860px, calc(100vw - 24px)) !important;
}
#cf_config_modal .modal-dialog {
  max-width: min(440px, calc(100vw - 24px)) !important;
}
#cf_ns_modal .modal-dialog {
  max-width: min(480px, calc(100vw - 24px)) !important;
}
.modal-content {
  width: 100% !important;
  max-height: calc(100dvh - 76px) !important;
  display: flex !important;
  flex-direction: column !important;
  overflow: hidden !important;
}
.modal-header,
.modal-footer {
  flex: 0 0 auto !important;
}
.modal-body {
  flex: 1 1 auto !important;
  overflow-y: auto !important;
  max-height: calc(100dvh - 158px) !important;
}
.modal-footer {
  display: flex !important;
  align-items: center !important;
  justify-content: flex-end !important;
  gap: 7px !important;
  flex-wrap: wrap !important;
}
.navbar.navbar-fixed-top,
.navbar-fixed-top {
  position: fixed !important;
  top: 0 !important;
  right: 0 !important;
  left: 0 !important;
  width: 100% !important;
  max-width: 100% !important;
  margin: 0 !important;
  padding-right: 0 !important;
  z-index: 1055 !important;
}
#btn-logout,
.logout-btn {
  display: inline-flex !important;
  align-items: center !important;
  justify-content: center !important;
  gap: 6px !important;
  min-height: 31px !important;
  text-decoration: none !important;
  white-space: nowrap !important;
}
.navbar-nav > li > #btn-logout,
.navbar-nav > li > .logout-btn {
  height: 44px !important;
  padding: 12px 10px !important;
  margin: 0 !important;
  border: 0 !important;
  background: transparent !important;
  color: var(--text) !important;
}
.navbar-nav > li > #btn-logout:hover,
.navbar-nav > li > .logout-btn:hover {
  background: transparent !important;
  color: var(--text-strong) !important;
}
#btn-logout.is-loading,
.logout-btn.is-loading,
.btn.is-loading {
  pointer-events: none !important;
  opacity: .78 !important;
}
.btn-spin {
  display: inline-block !important;
  flex: 0 0 auto !important;
  vertical-align: -2px !important;
  animation: btn-spin .7s linear infinite !important;
}
@keyframes btn-spin {
  to { transform: rotate(360deg); }
}
@supports (height: 100lvh) {
  .modal,
  .modal-backdrop {
    height: 100lvh !important;
  }
  .modal-content {
    max-height: calc(100lvh - 76px) !important;
  }
  .modal-body {
    max-height: calc(100lvh - 158px) !important;
  }
}
@media screen and (max-width: 560px) {
  .modal {
    padding: 50px 8px 10px !important;
  }
  .modal-dialog,
  .modal-wide,
  #cf_config_modal .modal-dialog,
  #cf_ns_modal .modal-dialog {
    max-width: calc(100vw - 16px) !important;
  }
  .modal-content {
    max-height: calc(100dvh - 60px) !important;
  }
  .modal-body {
    max-height: calc(100dvh - 138px) !important;
  }
}
</style>

<script nonce="<?= adminEsc($nonce); ?>">
/* NGIX patch: public logout/button spinner correction */
(function() {
    'use strict';

    var spinner = '<svg class="btn-spin" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="8" cy="8" r="6" stroke-opacity=".3"></circle><path d="M8 2a6 6 0 0 1 6 6"></path></svg> ';

    function closest(node, selector) {
        return node && typeof node.closest === 'function' ? node.closest(selector) : null;
    }

    function setLoading(button, label) {
        if (!button || button.dataset.ngixLoading === '1') {
            return;
        }

        button.dataset.ngixLoading = '1';
        button.dataset.ngixOriginalHtml = button.innerHTML;
        button.classList.add('is-loading');
        button.setAttribute('aria-busy', 'true');
        button.innerHTML = spinner + label;
    }

    function ensureLogoutToast() {
        var toast = document.getElementById('logout-toast');
        if (toast) {
            return toast;
        }

        toast = document.createElement('div');
        toast.id = 'logout-toast';
        toast.textContent = 'Logging out…';
        document.body.appendChild(toast);
        return toast;
    }

    document.addEventListener('click', function(event) {
        var button = closest(event.target, '#btn-logout,.logout-btn');
        if (!button) {
            return;
        }

        var href = button.getAttribute('href') || button.getAttribute('data-href') || '?logout';
        if (href === '#' || href === '') {
            return;
        }

        event.preventDefault();
        event.stopImmediatePropagation();

        if (button.dataset.ngixSubmitting === '1') {
            return;
        }

        button.dataset.ngixSubmitting = '1';
        setLoading(button, 'Logout…');

        var toast = ensureLogoutToast();
        toast.classList.add('show');

        window.setTimeout(function() {
            window.location.href = href;
        }, 650);
    }, true);
}());
</script>

<style nonce="<?= adminEsc($nonce); ?>">
/* NGIX patch: public panel backdrop deglitch */
.panel.panel-default,
.panel:has(> .ngix-image-backdrop) {
  position: relative !important;
  overflow: hidden !important;
  isolation: isolate !important;
}
.panel.panel-default > .ngix-image-backdrop,
.panel > .ngix-image-backdrop {
  position: absolute !important;
  inset: 0 !important;
  width: 100% !important;
  min-width: 0 !important;
  max-width: 100% !important;
  height: 100% !important;
  min-height: 100% !important;
  max-height: none !important;
  z-index: 0 !important;
  pointer-events: none !important;
  background-repeat: no-repeat, no-repeat !important;
  background-position: center center, center center !important;
  background-size: 100% 100%, contain !important;
  filter: saturate(.72) contrast(.86) blur(.18px) !important;
  /* Not !important: the smooth-fog animation below needs to override
     these two. CSS animations cannot win against an !important author
     declaration, so opacity/transform must stay normal-weight here. */
  opacity: .24;
  transform: none;
}
.panel.panel-default > *:not(.ngix-image-backdrop),
.panel:has(> .ngix-image-backdrop) > *:not(.ngix-image-backdrop) {
  position: relative !important;
  z-index: 2 !important;
}
/* Smooth fog drift: very subtle ambient motion, opt-in via
   prefers-reduced-motion so it never fights a user's motion preference.
   transform/opacity only (compositor-friendly, no layout properties) —
   a ~1% translate plus a hairline opacity pulse over a slow 28s cycle. */
@keyframes ngixFogDrift {
  0%, 100% { transform: translate3d(0, 0, 0) scale(1.015); opacity: .22; }
  50%      { transform: translate3d(0.6%, -0.4%, 0) scale(1.015); opacity: .26; }
}
@media (prefers-reduced-motion: no-preference) {
  .panel.panel-default > .ngix-image-backdrop,
  .panel > .ngix-image-backdrop {
    animation: ngixFogDrift 28s ease-in-out infinite;
  }
}
.modal,
.modal * {
  isolation: auto;
}
@media screen and (max-width: 768px) {
  .panel.panel-default > .ngix-image-backdrop,
  .panel > .ngix-image-backdrop {
    background-size: 100% 100%, contain !important;
    /* Not !important — see the smooth-fog animation rule above. */
    opacity: .20;
  }
}
</style>
<style nonce="<?= adminEsc($nonce); ?>">
/* NGIX patch: public modal/dropdown z-order final fix */
html,
body {
  overflow-x: hidden !important;
}
body.modal-open {
  overflow: hidden !important;
  padding-right: 0 !important;
}
/* Bootstrap backdrop is attached to body. Keep it below the modal, but above the page. */
.modal-backdrop {
  position: fixed !important;
  inset: 0 !important;
  width: 100vw !important;
  max-width: none !important;
  height: 100vh !important;
  height: 100dvh !important;
  margin: 0 !important;
  background: var(--ink) !important;
  z-index: 12000 !important;
}
.modal-backdrop.in,
.modal-backdrop.fade.in {
  opacity: .48 !important;
}
/* Modals are moved to body by JS below; this prevents parent stacking contexts from putting the backdrop above them. */
.modal {
  position: fixed !important;
  inset: 0 !important;
  width: 100vw !important;
  max-width: none !important;
  height: 100vh !important;
  height: 100dvh !important;
  margin: 0 !important;
  padding: 58px 12px 14px !important;
  overflow-x: hidden !important;
  overflow-y: auto !important;
  text-align: center !important;
  z-index: 12010 !important;
  -webkit-overflow-scrolling: touch !important;
}
.modal.in,
.modal.show {
  display: block !important;
}
.modal.fade .modal-dialog,
.modal.in .modal-dialog,
.modal.show .modal-dialog {
  transform: none !important;
}
.modal-dialog {
  position: relative !important;
  z-index: 12020 !important;
  display: block !important;
  width: auto !important;
  max-width: min(560px, calc(100vw - 24px)) !important;
  margin: 0 auto !important;
  text-align: left !important;
}
.modal-wide {
  max-width: min(860px, calc(100vw - 24px)) !important;
}
#cf_config_modal .modal-dialog {
  max-width: min(440px, calc(100vw - 24px)) !important;
}
#cf_ns_modal .modal-dialog {
  max-width: min(480px, calc(100vw - 24px)) !important;
}
.modal-content {
  position: relative !important;
  z-index: 12030 !important;
  width: 100% !important;
  max-height: none !important;
  display: block !important;
  overflow: visible !important;
}
.modal-header,
.modal-footer,
.modal-body {
  position: relative !important;
  z-index: 12031 !important;
}
.modal-body {
  max-height: none !important;
  overflow: visible !important;
}
.modal-footer {
  display: flex !important;
  align-items: center !important;
  justify-content: flex-end !important;
  gap: 7px !important;
  flex-wrap: wrap !important;
}
/* Dropdowns must not be clipped by panel/modal overflow. */
.panel,
.panel-default,
.panel.panel-default,
.panel:has(> .ngix-image-backdrop),
.modal-content,
.modal-body,
.bootgrid-header,
.bootgrid-header .actionBar,
.bootgrid-header .actions,
.tbl-toolbar,
.ddt,
.dropdown,
.btn-group {
  overflow: visible !important;
}
.tbl-toolbar,
.bootgrid-header,
.bootgrid-header .actionBar,
.bootgrid-header .actions,
.ddt.open,
.dropdown.open,
.btn-group.open {
  position: relative !important;
  z-index: 12100 !important;
}
.dropdown-menu,
.open > .dropdown-menu,
.ddt-menu,
.ddt-menu.open,
.modal .dropdown-menu,
.modal .open > .dropdown-menu,
.modal .ddt-menu,
.modal .ddt-menu.open,
.bootgrid-header .actions .dropdown-menu,
.bootgrid-header .actions .open > .dropdown-menu {
  z-index: 12120 !important;
  overflow: visible !important;
}
.modal .dropdown-menu,
.modal .ddt-menu,
.modal .ddt-menu.open {
  z-index: 12140 !important;
}
/* The decorative panel backdrop stays scoped to its panel and never sits above controls/dropdowns. */
.panel.panel-default > .ngix-image-backdrop,
.panel > .ngix-image-backdrop {
  position: absolute !important;
  inset: 0 !important;
  width: 100% !important;
  min-width: 0 !important;
  max-width: 100% !important;
  height: 100% !important;
  min-height: 100% !important;
  z-index: 0 !important;
  pointer-events: none !important;
  background-repeat: no-repeat, no-repeat !important;
  background-position: center center, center center !important;
  background-size: 100% 100%, contain !important;
  filter: saturate(.72) contrast(.86) blur(.18px) !important;
  /* Not !important — see the smooth-fog animation rule above. */
  opacity: .22;
  transform: none;
}
.panel.panel-default > *:not(.ngix-image-backdrop),
.panel:has(> .ngix-image-backdrop) > *:not(.ngix-image-backdrop) {
  position: relative !important;
  z-index: 2 !important;
}
#logout-toast,
.admin-toast-root,
.toast {
  z-index: 13000 !important;
}
@supports (height: 100lvh) {
  .modal,
  .modal-backdrop {
    height: 100lvh !important;
  }
}
@media screen and (max-width: 560px) {
  .modal {
    padding: 50px 8px 10px !important;
  }
  .modal-dialog,
  .modal-wide,
  #cf_config_modal .modal-dialog,
  #cf_ns_modal .modal-dialog {
    max-width: calc(100vw - 16px) !important;
  }
}

/* Unified button appearance — authoritative, keep last. */
.btn,button,.btn-sm,.btn-xs,.page-link,.page-link--primary,
input[type=submit],input[type=button],.swal2-confirm,.swal2-cancel{
    border-color:var(--btn-border)!important;
    color:var(--btn-fg)!important;
    background:var(--btn-bg)!important;
}
.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover,.page-link:hover,
input[type=submit]:hover,input[type=button]:hover{
    border-color:var(--btn-border)!important;
    color:var(--btn-fg)!important;
    background:var(--btn-bg)!important;
    filter:brightness(1.18);
}
.btn:disabled,button:disabled,.btn-sm:disabled,.btn-xs:disabled,
input[type=submit]:disabled,input[type=button]:disabled{
    opacity:.55;
    filter:none;
}
</style>
<script nonce="<?= adminEsc($nonce); ?>">
/* NGIX patch: move public modals to body to avoid backdrop covering modal */
(function() {
    'use strict';

    function moveModalsToBody() {
        document.querySelectorAll('.modal').forEach(function(modal) {
            if (modal.parentElement !== document.body) {
                document.body.appendChild(modal);
            }
        });
    }

    function normalizeDropdowns() {
        document.addEventListener('click', function(event) {
            var button = event.target && typeof event.target.closest === 'function'
                ? event.target.closest('.ddt-btn,[data-toggle="dropdown"]')
                : null;

            if (!button) {
                return;
            }

            var holder = button.closest('.ddt,.dropdown,.btn-group,.actions');
            if (holder) {
                holder.style.position = 'relative';
                holder.style.zIndex = '12100';
            }
        }, true);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            moveModalsToBody();
            normalizeDropdowns();
        }, {once: true});
        return;
    }

    moveModalsToBody();
    normalizeDropdowns();
}());
</script>
</body>
</html>

