<?php

declare(strict_types=1);

require_once __DIR__ . '/stat_path.php';


// Nonce for the inline <style>/<script> emitted below. It must match the one in
// the page's own CSP header, otherwise the browser blocks them.
//
// The including pages keep it in $rtNonce; $nonce is only the *parameter* name
// inside their pcSendSecurityHeaders()/rtSendSecurityHeaders() functions, so it
// never exists in the scope this file is included from. Accept both — reading
// only $nonce silently produced an un-nonced script that CSP then blocked.
$statCspNonce = '';
foreach ([$rtNonce ?? null, $nonce ?? null] as $statNonceCandidate) {
    if (
        is_string($statNonceCandidate)
        && preg_match('/\A[A-Za-z0-9+\/=_.-]{8,160}\z/', $statNonceCandidate) === 1
    ) {
        $statCspNonce = $statNonceCandidate;
        break;
    }
}

if (!function_exists('statNonceAttr')) {
    function statNonceAttr(string $nonce): string
    {
        return $nonce === '' ? '' : ' nonce="' . statH($nonce) . '"';
    }
}

if (!function_exists('statNormalizedPath')) {
    function statNormalizedPath(string $path): string
    {
        $path = trim($path);

        if ($path === '' || preg_match('/[\x00-\x1F\x7F]/', $path) === 1) {
            return '/';
        }

        $pathOnly = parse_url($path, PHP_URL_PATH);
        if (!is_string($pathOnly) || $pathOnly === '') {
            return '/';
        }

        $pathOnly = '/' . trim($pathOnly, '/');

        return $pathOnly === '/' ? '/' : $pathOnly . '/';
    }
}

if (!function_exists('statNavIsActive')) {
    function statNavIsActive(string $targetPath): bool
    {
        $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
        $requestPath = is_string($requestUri) ? $requestUri : '/';

        $current = statNormalizedPath($requestPath);
        $target = statNormalizedPath(statUrl($targetPath));

        return $current === $target;
    }
}

// No 'Postback' entry: /postback/ is the receiver API the affiliate network
// calls, not a page. It answers 403 to any request without a valid token, so the
// menu item only ever produced a FORBIDDEN screen. The postback URL itself is
// shown in the admin Create Campaigns modal (public/campaigns/index.php), which
// is the right place — it embeds POSTBACK_SECRET, a global secret that must not
// be exposed to per-tracker logins on this host.
$statNavItems = [
    ['label' => 'Realtime', 'path' => '/realtime/', 'icon' => 'fa-line-chart'],
    ['label' => 'Performance', 'path' => '/performance/', 'icon' => 'fa-dashboard'],
    ['label' => 'Clicks', 'path' => '/clicks/', 'icon' => 'fa-mouse-pointer'],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Lead Report!</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-cache,no-store,must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">

<link rel="icon" href="<?= statH(statAssetUrl('/favicon.ico')) ?>" type="image/x-icon">

<link rel="stylesheet" href="<?= statH(statAssetUrl('/dist/bootstrap.min.css')) ?>">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.4.1/css/bootstrap-datepicker3.css">
<link rel="stylesheet" href="<?= statH(statAssetUrl('/dist/jquery.bootgrid.css')) ?>">
<link rel="stylesheet" href="<?= statH(statAssetUrl('/dist/div.table.css')) ?>">
<link rel="stylesheet" href="https://cdn.datatables.net/1.10.19/css/dataTables.bootstrap.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet" href="<?= statH(statAssetUrl('/dist/flags.css')) ?>">

<style<?= statNonceAttr($statCspNonce); ?>>:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168,100,66,0.16);--panel:rgba(252,251,248,0.82);--border:rgba(37,42,46,0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--bg:var(--porcelain);--light:var(--porcelain);--surface:var(--porcelain);--panel2:var(--paper);--panel-soft:var(--paper);--panel-raised:var(--panel);--panel-fade:rgba(252,251,248,0.7);--nav:var(--paper);--line:var(--soft-steel);--line2:var(--border);--line-soft:var(--border);--stroke:var(--soft-steel);--text:var(--graphite);--btn:var(--graphite);--primary:var(--graphite);--primary2:var(--ink);--text-strong:var(--ink);--strong:var(--ink);--dark:var(--ink);--muted:var(--steel-gray);--faded:var(--steel-gray);--accent:var(--burnt-copper);--accent-h:#8f5236;--accent-hover:#8f5236;--accent-s:var(--burnt-copper-soft);--accent-soft:var(--burnt-copper-soft);--on:var(--paper);--on-accent:var(--paper);--inverse:var(--paper);--good:var(--graphite);--ok:var(--graphite);--success:var(--graphite);--ok-soft:var(--burnt-copper-soft);--success-soft:var(--burnt-copper-soft);--bad:var(--burnt-copper);--danger:var(--burnt-copper);--danger-soft:var(--burnt-copper-soft);--warn:var(--steel-gray);--blue-soft:var(--burnt-copper-soft);--blue-line:rgba(168,100,66,0.28);--shadow-modal:var(--shadow);--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}*,::before,::after{box-sizing:border-box;-webkit-tap-highlight-color:transparent}html,body{width:100%;height:100dvh;margin:0}html{background:var(--bg);zoom:1;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility;-webkit-font-smoothing: antialiased;}body{font-family:var(--font);padding:58px 6px 14px!important;background:linear-gradient(180deg,var(--paper) 0%,var(--porcelain) 100%)!important;color:var(--text)!important;font-size:var(--fs-base);line-height:var(--lh-normal);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}a{color:inherit;text-decoration:none}.container{width:100%;max-width:min(1180px,96vw);margin:0 auto}code{font-family:var(--mono);font-size:var(--fs-sm);color:var(--text);background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:var(--paper)!important;box-shadow:var(--shadow)!important;backdrop-filter:blur(18px) saturate(180%);-webkit-backdrop-filter:blur(18px) saturate(180%)}.navbar .container{max-width:1180px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:var(--fs-base);line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;line-height:20px!important;color:var(--text)!important;font-size:var(--fs-sm)}.navbar-nav>li>a:hover,.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:focus,.navbar-default .navbar-nav>.active>a:hover{background:var(--accent)!important;color:var(--on-accent)!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.panel,.panel-default,.well,.modal-content{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;backdrop-filter:blur(16px) saturate(180%);-webkit-backdrop-filter:blur(16px) saturate(180%);overflow:hidden}.panel-heading,.panel-footer,.modal-header,.modal-footer{padding:8px 10px!important;background:var(--porcelain)!important;border:0!important;color:var(--text-strong)!important}.panel-body,.modal-body{padding:8px!important;background:transparent!important;color:var(--text)!important}.pull-right{display:flex;align-items:center;gap:6px}.modal-content{box-shadow:var(--shadow-modal)!important}.modal-title{font-size:var(--fs-md);font-weight:var(--fw-bold);color:var(--text-strong)}.close{color:var(--text)!important;opacity:.78;text-shadow:none}.form-group{margin-bottom:8px}.control-label,label{margin-bottom:4px;color:var(--text-strong);font-size:var(--fs-sm)}.form-control,input[type=text],input[type=number],input[type=password],input[type=search],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;box-shadow:none!important}.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)!important;box-shadow:none!important}.form-control::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control[readonly],input[readonly],textarea[readonly]{background:var(--panel-soft)!important;color:var(--text)!important}textarea.form-control{height:auto;min-height:114px;resize:none}.input-group-addon{height:31px;padding:5px 8px;background:transparent!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:var(--fs-sm)}.btn,button,.btn-sm,.btn-xs{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm);font-weight:var(--fw-bold);line-height:var(--lh-tight);box-shadow:none!important;outline:none;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active,.btn.active{background:var(--btn-bg)!important;border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.btn-primary:hover{background:var(--btn-bg)!important;filter:brightness(1.18);border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(102,113,122,.16)!important;color:var(--danger)!important}.glyphicon{top:1px;color:currentColor}.action-ico{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.action-ico svg{display:block}.table-responsive{border:0!important}.table{width:100%;margin:0;border-collapse:collapse;border-spacing:0;border:0;border-radius:0;background:transparent!important}.table>thead>tr>th{height:30px;padding:0 10px!important;text-align:left;font-size:var(--fs-xs);font-weight:var(--fw-semibold);color:var(--text-strong)!important;text-transform:uppercase;letter-spacing:.06em;background:var(--porcelain)!important;border-bottom:1px solid var(--line)!important;border-top:0!important;white-space:nowrap;position:static}.table>tbody>tr>td,.table>tfoot>tr>td{padding:5px 10px!important;vertical-align:middle;border-bottom:1px solid var(--line-soft)!important;border-top:0!important;font-size:var(--fs-base);font-weight:var(--fw-regular);color:var(--text)!important;word-break:break-word;background:transparent!important}.table>tbody>tr:last-child>td{border-bottom:0!important}.table>tfoot>tr>th{padding:7px 12px!important;border-top:1px solid var(--line)!important;border-bottom:0!important;background:var(--porcelain)!important;color:var(--text-strong)!important;font-size:var(--fs-xs)!important;font-weight:var(--fw-semibold);text-transform:uppercase;letter-spacing:.06em}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.table-striped>tbody>tr:nth-of-type(odd)>td{background:transparent!important}.bootgrid-table th>.column-header-anchor{color:var(--text-strong)!important}.bootgrid-header,.bootgrid-footer{margin:6px 0!important;color:var(--text)!important}.bootgrid-header .search .form-control{height:31px}.bootgrid-header .actionBar{text-align:right}.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.dropdown-menu{border:0!important;border-radius:var(--radius)!important;background:var(--paper)!important;box-shadow:var(--shadow-modal)!important}.dropdown-menu>li>a{color:var(--text)!important;font-size:var(--fs-sm)}.dropdown-menu>li>a:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.alert{border-radius:var(--radius)!important}.alert-danger,.error{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.28)!important;color:var(--danger)!important}.alert-success,.success{background:var(--blue-soft)!important;border-color:var(--blue-line)!important;color:var(--text)!important}.label{border-radius:var(--radius)!important}.label-default{background:var(--panel-soft)!important;color:var(--text)!important;border:1px solid var(--line)}blockquote{margin:0 0 10px;padding:7px 10px;border-left:2px solid var(--line)!important;background:var(--panel-fade);border-radius:var(--radius);font-size:var(--fs-sm)}.text-warning{margin:0 0 2px;color:var(--text-strong)!important;font-weight:var(--fw-bold)}.text-muted{color:var(--text)!important}.flag{border-radius:var(--radius)}.method .list-header .header{font-size:var(--fs-xs)!important;font-weight:var(--fw-semibold)!important;color:var(--text-strong)!important;text-transform:uppercase;letter-spacing:.06em;background:var(--panel-soft)!important;padding:6px 12px!important;border-bottom:1px solid var(--line)!important}.method .cell{font-size:var(--fs-base)!important;color:var(--text)!important;padding:5px 12px!important;line-height:var(--lh-snug)}.method .cell code{font-size:var(--fs-sm);color:var(--blue-line)}.method [class^="row"],.method [class*=" row"]{border-bottom:1px solid var(--line-soft)!important}.method [class^="row"]:hover,.method [class*=" row"]:hover{background-color:var(--panel-soft)!important}@media screen and (max-width:768px){body{padding:58px 6px 12px!important;font-size:var(--fs-base)}.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px!important;background:var(--porcelain)!important}.navbar .container{padding-left:8px!important;padding-right:8px!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}.pull-right{float:none!important;justify-content:flex-end}.table{display:block;overflow-x:auto;white-space:nowrap}}.panel,.panel-default{box-shadow:var(--shadow)!important}.modal-content{box-shadow:var(--shadow-modal)!important}.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{box-shadow:none!important;background:transparent!important;color:var(--text-strong)!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:none!important}.panel_m{margin-top:4px}.pn-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}.pn-export{display:flex;align-items:center;justify-content:flex-end;gap:6px;flex:0 0 auto}.tbl-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;flex-wrap:wrap;border-bottom:1px solid var(--soft-steel);background:var(--porcelain)}.tbl-toolbar-left{display:flex;align-items:center;gap:6px}.tbl-footer{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;border-top:1px solid var(--soft-steel);font-size:var(--fs-sm);color:var(--text);flex-wrap:wrap;background:var(--porcelain)}.rg-source .pre-colon{font-weight:var(--fw-bold);color:var(--text-strong)}.rg-source .post-colon{font-family:var(--mono);color:var(--text)}#logout-toast{position:fixed;right:12px;bottom:12px;z-index:10060;display:none;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm)}#logout-toast.show{display:block}.navbar-btn.btn-link{height:44px!important;margin:0!important;padding:12px 10px!important;border:0!important;background:transparent!important;color:var(--text)!important;text-decoration:none!important;box-shadow:none!important}.navbar-btn.btn-link:hover{background:transparent!important;color:var(--text-strong)!important}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}.form-control:focus,input:focus,select:focus,textarea:focus{box-shadow:none!important}*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}.card{border:1px solid var(--line);background:var(--panel);border-radius:var(--radius)}.btn-ghost{background:var(--faded)!important;color:var(--inverse)!important;border-color:var(--line)!important;box-shadow:none!important}.btn-ghost:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.chip{display:inline-flex;align-items:center;padding:2px 8px;border:1px solid var(--line-soft);background:var(--panel-soft);border-radius:var(--radius);font-size:var(--fs-xs);color:var(--text);line-height:var(--lh-snug)}.toast{position:fixed;right:18px;bottom:18px;z-index:10070;display:none;align-items:center;gap:8px;background:var(--inverse);color:var(--faded);padding:10px 12px;font-size:var(--fs-sm);border:1px solid var(--line-soft);border-radius:var(--radius);box-shadow:var(--shadow-modal)}.toast.show{display:flex}canvas{display:block;width:100%;height:430px;border:1px solid var(--line);background:var(--panel);border-radius:var(--radius)}.app-sign{text-align:right;padding:3px 0 2px}.app-sign footer{font-family:var(--mono);text-decoration:none;letter-spacing:.09em;font-size:10px;font-weight:900;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;user-select:none;text-transform:uppercase;-webkit-user-select:none}select hr{border:none;border-top:1px solid rgba(37,42,46,.06)!important;color:rgba(37,42,46,.06)!important;opacity:.45;margin:1px 4px}input[type=url]{font-family:var(--mono)!important}body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none}body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)} html{width:100%!important;min-width:0!important;max-width:100%!important;min-height:100%!important;margin:0!important;padding:0!important;overflow-x:hidden!important;background:var(--bg,var(--porcelain))!important;zoom:1!important;-webkit-tap-highlight-color:transparent} body{position:relative!important;width:100%!important;min-width:0!important;max-width:100%!important;min-height:100vh!important;min-height:100svh!important;min-height:100dvh!important;margin:0!important;overflow-x:hidden!important;background:linear-gradient(rgba(252,251,248,.74),rgba(252,251,248,.90)),url('/assets/img/favicon.svg') right 14px bottom 12px/28px 28px no-repeat fixed,url('/assets/img/bg-intro.png') center center/cover no-repeat fixed,var(--bg,var(--porcelain))!important;background-color:var(--bg,var(--porcelain))!important;color:var(--text,var(--graphite))!important;-webkit-tap-highlight-color:transparent} body::after{content:none!important;display:none!important;background:none!important} body::before{z-index:1!important}::selection{background:rgba(37,42,46,.16);color:inherit}::-moz-selection{background:rgba(37,42,46,.16);color:inherit} a,button,.btn,.navbar-toggle,.dropdown-menu>li>a,.pagination>li>a,.pagination>li>span,.chip,.label,.app-sign,svg{-webkit-user-select:none;user-select:none} input,textarea,select,option,.form-control,.table,.table *,code,pre,blockquote,.modal-body,.panel-body{-webkit-user-select:text;user-select:text} img,picture,svg,canvas{max-width:100%} body>.container,.container,main,.app-shell,.app-footer{position:relative!important;z-index:2!important;max-width:1180px!important;overflow:visible!important} .navbar.navbar-fixed-top,.navbar-fixed-top{position:fixed!important;top:0!important;right:0!important;left:0!important;width:100%!important;max-width:100%!important;margin:0!important;border-radius:0!important;transform:none!important;z-index:1055!important} .navbar.navbar-default{background:rgba(252,251,248,.82)!important} .panel_m.panel{position:relative!important;overflow:hidden!important;isolation:isolate!important;background:rgba(252,251,248,.64)!important} .panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{position:absolute!important;inset:0!important;width:100%!important;min-width:0!important;max-width:100%!important;height:100%!important;min-height:100%!important;z-index:0!important;pointer-events:none!important;background-image:linear-gradient(rgba(252,251,248,.86),rgba(252,251,248,.86)),url('<?= statH(statAssetUrl('/dist/bg-intro.png')) ?>')!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,contain!important;filter:saturate(.62) contrast(.84) blur(.12px)!important;contain:paint!important;opacity:.22;transform:none} @keyframes ngixFogDrift{0%,100%{transform:translate3d(0,0,0) scale(1.015);opacity:.22}50%{transform:translate3d(0.6%,-0.4%,0) scale(1.015);opacity:.26}} @media (prefers-reduced-motion:no-preference){.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{animation:ngixFogDrift 28s ease-in-out infinite}} .panel_m.panel>.panel-heading,.panel_m.panel>.panel-body,.panel_m.panel>.table-responsive,.panel_m.panel>form{position:relative!important;z-index:2!important} .table-responsive{max-width:100%!important;overflow-x:auto!important;overflow-y:visible!important} @supports (height:100lvh){body{min-height:100lvh!important}} @media (prefers-color-scheme:dark){html{background:var(--graphite)!important} body{background:linear-gradient(rgba(37,42,46,.78),rgba(37,42,46,.88)),url('/assets/img/favicon.svg') right 14px bottom 12px/28px 28px no-repeat fixed,url('/assets/img/bg-intro.png') center center/cover no-repeat fixed,var(--graphite)!important} .navbar.navbar-default{background:rgba(37,42,46,.82)!important} .panel_m.panel{background:rgba(37,42,46,.72)!important} .panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{background-image:linear-gradient(rgba(37,42,46,.84),rgba(37,42,46,.84)),url('<?= statH(statAssetUrl('/dist/bg-intro.png')) ?>')!important;filter:saturate(.58) contrast(.78) blur(.16px)!important;opacity:.20}::selection{background:rgba(252,251,248,.16);color:inherit}::-moz-selection{background:rgba(252,251,248,.16);color:inherit}} @media screen and (max-width:768px){body{background-position:0 0,right 10px bottom 10px,center center!important;background-size:auto,24px 24px,cover!important} body>.container,.container{max-width:100%!important} .panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{background-size:100% 100%,contain!important;background-position:center center,center center!important;opacity:.18}} .btn,button,.btn-sm,.btn-xs,.page-link,.page-link--primary,input[type=submit],input[type=button],.swal2-confirm,.swal2-cancel{border-color:var(--btn-border)!important;color:var(--btn-fg)!important;background:var(--btn-bg)!important} .btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover,.page-link:hover,input[type=submit]:hover,input[type=button]:hover{border-color:var(--btn-border)!important;color:var(--btn-fg)!important;background:var(--btn-bg)!important;filter:brightness(1.18)} .btn:disabled,button:disabled,.btn-sm:disabled,.btn-xs:disabled,input[type=submit]:disabled,input[type=button]:disabled{opacity:.55;filter:none} img{-webkit-user-drag:none;-webkit-touch-callout:none;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none;pointer-events:auto}</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Caveat:wght@500;600;700&display=swap">
<link href="https://fonts.googleapis.com/icon?family=Material+Icons"
      rel="stylesheet">
<script src="<?= statH(statAssetUrl('/dist/jquery-1.11.1.min.js')) ?>"></script>
<script src="<?= statH(statAssetUrl('/dist/bootstrap.min.js')) ?>"></script>
<script src="<?= statH(statAssetUrl('/dist/jquery.bootgrid.min.js')) ?>"></script>
<script src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js"></script>
<script src="https://unpkg.com/sweetalert/dist/sweetalert.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@8"></script>
<script src="<?= statH(statAssetUrl('/dist/Blob.min.js')) ?>"></script>
<script src="<?= statH(statAssetUrl('/dist/FileSaver.min.js')) ?>"></script>
<script src="<?= statH(statAssetUrl('/dist/xls.core.min.js')) ?>"></script>
<script src="<?= statH(statAssetUrl('/dist/tableexport.js')) ?>"></script>
</head>
<body>
<nav class="navbar navbar-default navbar-fixed-top" role="navigation" aria-label="Statistics navigation">
    <div class="container">
        <div class="navbar-header">
            <button
                type="button"
                class="navbar-toggle collapsed"
                data-toggle="collapse"
                data-target="#statistics-navbar"
                aria-expanded="false"
                aria-controls="statistics-navbar"
            >
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="<?= statH(statUrl('/realtime/')); ?>">Lead Report</a>
        </div>

        <div class="collapse navbar-collapse" id="statistics-navbar">
            <ul class="nav navbar-nav">
                <?php foreach ($statNavItems as $statNavItem) : ?>
                    <?php
                    $statNavLabel = $statNavItem['label'];
                    $statNavPath = $statNavItem['path'];
                    $statNavIcon = $statNavItem['icon'];
                    $statNavActive = statNavIsActive($statNavPath);
                    ?>
                    <li class="<?= $statNavActive ? 'active' : ''; ?>">
                        <a href="<?= statH(statUrl($statNavPath)); ?>">
                            <i class="fa <?= statH($statNavIcon); ?>" aria-hidden="true"></i>
                            <span><?= statH($statNavLabel); ?></span>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
</nav>
<script<?= statNonceAttr($statCspNonce); ?>>(function(){"use strict";function isImg(el){return el&&el.nodeType===1&&el.tagName==="IMG"}document.addEventListener("contextmenu",function(e){if(isImg(e.target)){e.preventDefault()}},false);document.addEventListener("dragstart",function(e){if(isImg(e.target)){e.preventDefault()}},false)})();</script>

