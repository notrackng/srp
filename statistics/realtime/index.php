<?php

declare(strict_types=1);

include_once('../login.php');

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

$rtNonce = bin2hex(random_bytes(16));

function rtSendSecurityHeaders(string $nonce = ''): void
{
    if (headers_sent()) {
        return;
    }

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    header_remove('Content-Security-Policy');

    $csp = implode('; ', [
        "default-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self'",
        "object-src 'none'",
        "img-src 'self' data: https:",
        "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com",
        "media-src 'self' data: https:",
        "style-src 'self' 'unsafe-inline' https://cdn.datatables.net https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "style-src-elem 'self' 'unsafe-inline' https://cdn.datatables.net https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "style-src-attr 'unsafe-inline'",
        "script-src 'self' 'nonce-{$nonce}' https://cdn.datatables.net https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net https://www.gstatic.com",
        "script-src-elem 'self' 'nonce-{$nonce}' https://cdn.datatables.net https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net https://www.gstatic.com",
        "connect-src 'self' https:",
    ]);

    header('Content-Security-Policy: ' . $csp);
}

function rtEnsureSession(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function rtH(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function rtCsrfToken(): string
{
    rtEnsureSession();

    if (
        !isset($_SESSION['rt_csrf_token'])
        || !is_string($_SESSION['rt_csrf_token'])
        || $_SESSION['rt_csrf_token'] === ''
    ) {
        $_SESSION['rt_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['rt_csrf_token'];
}

function rtVerifyCsrf(?string $token): bool
{
    rtEnsureSession();

    if (!is_string($token) || $token === '') {
        return false;
    }

    if (!isset($_SESSION['rt_csrf_token']) || !is_string($_SESSION['rt_csrf_token'])) {
        return false;
    }

    return hash_equals($_SESSION['rt_csrf_token'], $token);
}

function rtReadJsonArray(string $filename): array
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

function rtHandlePostLogout(string $date): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
    if ($action !== 'logout') {
        return;
    }

    if (!rtVerifyCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        echo 'Invalid CSRF token.';
        exit;
    }

    rtEnsureSession();
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            (string) session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => (string) $params['path'],
                'domain' => (string) $params['domain'],
                'secure' => statIsHttpsRequest(),
                'httponly' => true,
                'samesite' => 'Strict',
            ],
        );
    }

    session_destroy();

    header('Location: ' . statUrl('/realtime/?date=' . rawurlencode($date)));
    exit;
}

rtSendSecurityHeaders($rtNonce);

$date = isset($_GET['date']) && is_string($_GET['date']) ? $_GET['date'] : 'rt_1';

if ($date !== 'rt_1' && $date !== 'rt_2') {
    header('Location: ?date=rt_1', true, 302);
    exit;
}

rtHandlePostLogout($date);

$conversion = $date === 'rt_1' ? 1 : 2;
$time = gmdate('Y-m-d'); // UTC "today": matches the click-log writer and postback conversion_date
$filename = '../temp/' . $time . '.json';
$result = rtReadJsonArray($filename);

include_once('../header.php');
?>
<style nonce="<?= rtH($rtNonce) ?>">
:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--bg:var(--porcelain);--light:var(--porcelain);--surface:var(--porcelain);--panel2:var(--paper);--panel-soft:var(--paper);--panel-raised:var(--panel);--panel-fade:rgba(252, 251, 248, 0.7);--nav:var(--paper);--line:var(--soft-steel);--line2:var(--border);--line-soft:var(--border);--stroke:var(--soft-steel);--text:var(--graphite);--btn:var(--graphite);--primary:var(--graphite);--primary2:var(--ink);--text-strong:var(--ink);--strong:var(--ink);--dark:var(--ink);--muted:var(--steel-gray);--accent:var(--burnt-copper);--accent-h:#8f5236;--accent-hover:#8f5236;--accent-s:var(--burnt-copper-soft);--accent-soft:var(--burnt-copper-soft);--on:var(--paper);--on-accent:var(--paper);--good:var(--graphite);--ok:var(--graphite);--success:var(--graphite);--ok-soft:var(--burnt-copper-soft);--success-soft:var(--burnt-copper-soft);--bad:var(--burnt-copper);--danger:var(--burnt-copper);--danger-soft:var(--burnt-copper-soft);--warn:var(--steel-gray);--blue-soft:var(--burnt-copper-soft);--blue-line:rgba(168, 100, 66, 0.28);--shadow-modal:var(--shadow);--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}@media (prefers-color-scheme:dark){}*{box-sizing:border-box}html,body{width:100%;height:100dvh;margin:0;overflow-x:hidden;}html{background:var(--bg);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}body{font-family:var(--font);padding:58px 8px 18px!important;background:radial-gradient(circle at 50% 8%,rgba(168,100,66,.12),transparent 28rem),radial-gradient(circle at 10% 80%,rgba(22,25,28,.06),transparent 22rem),var(--porcelain)!important;color:var(--text)!important;font-family:var(--mono)!important;font-size:var(--fs-base);line-height:var(--lh-normal);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}a{color:inherit;text-decoration:none}.container{width:100%;max-width:1180px;margin:0 auto}code{font-family:var(--mono);font-size:var(--fs-sm);color:var(--text);background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:var(--paper)!important;box-shadow:var(--shadow)!important}.navbar .container{max-width:1180px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:var(--fs-base);line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;line-height:20px!important;color:var(--text)!important;font-size:var(--fs-sm)}.navbar-nav>li>a:hover,.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:focus,.navbar-default .navbar-nav>.active>a:hover{background:var(--accent)!important;color:var(--on-accent)!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.panel,.panel-default,.well,.modal-content{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading,.panel-footer,.modal-header,.modal-footer{padding:8px 10px!important;background:var(--porcelain)!important;border:0!important;color:var(--text-strong)!important}.panel-body,.modal-body{padding:10px!important;background:transparent!important;color:var(--text)!important}.pull-right{display:flex;align-items:center;gap:6px}.modal-content{box-shadow:var(--shadow-modal)!important}.modal-title{font-size:var(--fs-md);font-weight:var(--fw-bold);color:var(--text-strong)}.close{color:var(--text)!important;opacity:.78;text-shadow:none}.form-group{margin-bottom:8px}.control-label,label{margin-bottom:4px;color:var(--text-strong);font-size:var(--fs-sm)}.form-control,input[type=text],input[type=number],input[type=password],input[type=search],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-family:inhe!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;box-shadow:none!important; }.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)!important;box-shadow:none!important}.form-control::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control[readonly],input[readonly],textarea[readonly]{background:var(--panel-soft)!important;color:var(--text)!important}textarea.form-control{height:auto;min-height:114px;resize:none}.input-group-addon{height:31px;padding:5px 8px;background:transparent!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:var(--fs-sm)}.btn,button,.btn-sm,.btn-xs{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm);font-weight:var(--fw-bold);line-height:var(--lh-tight);box-shadow:none!important;outline:none;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active,.btn.active{background:var(--btn-bg)!important;border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.btn-primary:hover{background:var(--btn-bg)!important;filter:brightness(1.18);border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(102,113,122,.16)!important;color:var(--danger)!important}.glyphicon{top:1px;color:currentColor}.action-ico{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.action-ico svg{display:block}.table-responsive{border:0!important}.table{width:100%;margin:4px 0 0;border-collapse:separate;border-spacing:0;border:0;border-radius:var(--radius);overflow:hidden;background:var(--panel)!important}.table>thead>tr>th{position:sticky;top:0;z-index:20;padding:7px 8px!important;border-bottom:1px solid var(--line)!important;background:var(--porcelain)!important;color:var(--text-strong)!important;font-size:var(--fs-xs)!important;line-height:var(--lh-tight);text-transform:uppercase;letter-spacing:.035em;white-space:nowrap}.table>tbody>tr>td{padding:6px 8px!important;border-top:1px solid var(--line-soft)!important;color:var(--text);font-size:var(--fs-sm);vertical-align:middle;word-break:break-word;background:var(--panel)!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.bootgrid-table th>.column-header-anchor{color:var(--text-strong)!important}.bootgrid-header,.bootgrid-footer{margin:6px 0!important;color:var(--text)!important}.bootgrid-header .search .form-control{height:31px}.bootgrid-header .actionBar{text-align:right}.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.dropdown-menu{border:0!important;border-radius:var(--radius)!important;background:var(--paper)!important;box-shadow:var(--shadow-modal)!important}.dropdown-menu>li>a{color:var(--text)!important;font-size:var(--fs-sm)}.dropdown-menu>li>a:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.alert{border-radius:var(--radius)!important}.alert-danger,.error{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.28)!important;color:var(--danger)!important}.alert-success,.success{background:var(--blue-soft)!important;border-color:var(--blue-line)!important;color:var(--text)!important}.label{border-radius:var(--radius)!important}.label-default{background:var(--panel-soft)!important;color:var(--text)!important;border:1px solid var(--line)}blockquote{margin:0 0 10px;padding:7px 10px;border-left:2px solid var(--line)!important;background:var(--panel-fade);border-radius:var(--radius);font-size:var(--fs-sm)}.text-warning{margin:0 0 2px;color:var(--text-strong)!important;font-weight:var(--fw-bold)}.text-muted{color:var(--text)!important}.flag{border-radius:var(--radius)}.admin-toast-root{position:fixed;right:12px;bottom:12px;z-index:10050;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.admin-toast{font-family:var(--mono);max-width:340px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm);line-height:var(--lh-snug)}.admin-toast strong{display:block;margin-bottom:2px;color:var(--text-strong)}.admin-toast--error{border-color:rgba(102,113,122,.34);background:var(--danger-soft);color:var(--danger)}.admin-toast--success{border-color:var(--blue-line);background:var(--blue-soft);color:var(--text)}.admin-fallback-backdrop{position:fixed;inset:0;z-index:10040;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(37,42,46,.36)}.admin-fallback-dialog{width:min(420px,100%);border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.admin-fallback-head{padding:10px;border-bottom:1px solid var(--line-soft);font-weight:var(--fw-bold);color:var(--text-strong);background:var(--porcelain)}.admin-fallback-body{padding:10px;font-size:var(--fs-sm)}.admin-fallback-actions{display:flex;gap:6px;justify-content:flex-end;padding:10px;border-top:1px solid var(--line-soft);background:var(--porcelain)}@media screen and (max-width:768px){body{padding:58px 6px 12px!important;font-size:var(--fs-base)}.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px!important;background:var(--porcelain)!important}.navbar .container{padding-left:8px!important;padding-right:8px!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}.pull-right{float:none!important;justify-content:flex-end}.input-group{display:block}.input-group>.form-control,.input-group>.input-group-addon,.input-group>.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.input-group-addon{border-bottom:0!important;border-radius:var(--radius) var(--radius) 0 0!important}.input-group>.form-control{border-radius:0 0 var(--radius) var(--radius)!important}.input-group-btn>.btn{margin-top:5px}.table{display:block;overflow-x:auto;white-space:nowrap}.modal-dialog{width:auto!important;margin:8px}}#tbl_trackers{table-layout:fixed;width:100%;min-width:800px}#tbl_trackers th:nth-child(1),#tbl_trackers td:nth-child(1){width:50px;text-align:center;padding-left:4px!important;padding-right:4px!important}#tbl_trackers th:nth-child(2),#tbl_trackers td:nth-child(2){width:120px}#tbl_trackers th:nth-child(3),#tbl_trackers td:nth-child(3){width:120px}#tbl_trackers th:nth-child(5),#tbl_trackers td:nth-child(5){width:120px}.td-num{display:block;font-size:var(--fs-sm);font-weight:var(--fw-semibold);font-family:var(--mono);color:color-mix(in srgb,var(--text) 44%,transparent);text-align:center}.td-tracker{display:inline-block;width:100%;padding:2px 8px;border-radius:.3rem;border:1px solid var(--line);background:var(--panel-soft);font-family:var(--mono);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.03em;white-space:nowrap}.td-subdomain{display:inline-block;padding:2px 8px;border-radius:.3rem!important;width:100%;border:1px solid var(--line);background:var(--panel-soft);font-family:var(--mono);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.03em;white-space:nowrap}.td-url{display:block;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono);font-size:var(--fs-sm)}.td-pass{font-family:var(--mono);font-size:var(--fs-sm);color:color-mix(in srgb,var(--text) 60%,transparent)}
/* bootgrid toolbar search/select fix */.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{background:color-mix(in srgb,var(--accent) 5%,transparent)!important;color:var(--text-strong)!important;box-shadow:none!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:none!important}.panel,.panel-default{overflow:visible!important}.panel-body{overflow:visible!important}.table-responsive{overflow-x:auto!important;overflow-y:visible!important}.bootgrid-header{position:relative!important;z-index:80!important;display:block!important;margin:8px 0 7px!important;color:var(--text)!important}.bootgrid-header .actionBar{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;float:none!important;width:100%!important;margin:0!important;text-align:left!important;white-space:nowrap!important}.bootgrid-header .search{position:relative!important;display:inline-flex!important;align-items:center!important;float:none!important;width:220px!important;min-width:220px!important;max-width:260px!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .search .input-group{display:flex!important;align-items:stretch!important;width:100%!important;border-collapse:separate!important}.bootgrid-header .search .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:32px!important;padding:0!important;border:1px solid var(--line)!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important}.bootgrid-header .search .input-group-addon .glyphicon{top:0!important;font-size:var(--fs-sm)!important}.bootgrid-header .search .search-field,.bootgrid-header .search .form-control{display:block!important;flex:1 1 auto!important;width:100%!important;height:32px!important;min-height:32px!important;padding:5px 9px!important;border:1px solid var(--line)!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{border-color:var(--accent)!important;border-left:0!important;box-shadow:none!important}.bootgrid-header .actions{position:relative!important;display:inline-flex!important;align-items:center!important;gap:6px!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions>.btn-group{position:relative!important;display:inline-flex!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions .btn,.bootgrid-header .actions .dropdown-toggle{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:6px!important;height:32px!important;min-width:38px!important;padding:5px 10px!important;line-height:var(--lh-tight)!important;border-radius:var(--radius)!important}.bootgrid-header .actions .dropdown-toggle{min-width:64px!important}.bootgrid-header .actions .dropdown-toggle .caret{margin-left:2px!important}.bootgrid-header .actions .dropdown-menu{position:absolute!important;top:calc(100% + 4px)!important;right:0!important;left:auto!important;z-index:3000!important;display:none;min-width:112px!important;width:112px!important;margin:0!important;padding:4px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--paper)!important;box-shadow:var(--shadow-modal)!important;list-style:none!important}.bootgrid-header .actions .open>.dropdown-menu{display:block!important}.bootgrid-header .actions .dropdown-menu>li{display:block!important;float:none!important;width:100%!important;margin:0!important;padding:0!important;text-align:left!important}.bootgrid-header .actions .dropdown-menu>li>a{display:block!important;width:100%!important;min-width:0!important;padding:6px 9px!important;border-radius:var(--radius)!important;background:transparent!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-tight)!important;text-align:left!important;white-space:nowrap!important}.bootgrid-header .actions .dropdown-menu>li>a:hover,.bootgrid-header .actions .dropdown-menu>li>a:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.bootgrid-header .actions .dropdown-menu>.active>a,.bootgrid-header .actions .dropdown-menu>.active>a:hover,.bootgrid-header .actions .dropdown-menu>.active>a:focus{background:var(--accent-soft)!important;color:var(--text-strong)!important;box-shadow:none!important}.bootgrid-footer{position:relative!important;z-index:20!important}.bootgrid-footer .pagination{margin:0!important}@media screen and (max-width:768px){.bootgrid-header .actionBar{align-items:stretch!important;justify-content:stretch!important;flex-wrap:wrap!important;gap:6px!important}.bootgrid-header .search{width:100%!important;min-width:0!important;max-width:none!important;flex:1 0 100%!important}.bootgrid-header .actions{margin-left:auto!important}.bootgrid-header .actions .dropdown-menu{right:0!important;left:auto!important}}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
/* final action icon render fix */#tbl_trackers th:last-child,#tbl_trackers td:last-child{text-align:center!important;white-space:nowrap!important;width:108px!important;min-width:108px!important;max-width:108px!important}.bootgrid-table td:last-child{overflow:visible!important}.action-btn,.bootgrid-table .command-edit,.bootgrid-table .command-delete{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:32px!important;height:26px!important;min-width:32px!important;min-height:26px!important;padding:0!important;margin:0 2px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:0!important;line-height:1!important;text-indent:0!important;vertical-align:middle!important;opacity:1!important;visibility:visible!important;box-shadow:none!important;overflow:visible!important}.action-btn:hover,.bootgrid-table .command-edit:hover{background:var(--accent-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.bootgrid-table .command-delete{color:var(--danger)!important}.bootgrid-table .command-delete:hover{background:var(--danger-soft)!important;border-color:color-mix(in srgb,var(--danger) 34%,var(--line))!important;color:var(--danger)!important}.bootgrid-table .command-edit[disabled],.bootgrid-table .command-delete[disabled]{opacity:.58!important;cursor:not-allowed!important}.action-btn .action-ico,.bootgrid-table .command-edit .action-ico,.bootgrid-table .command-delete .action-ico{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;color:currentColor!important;opacity:1!important;visibility:visible!important;overflow:visible!important;pointer-events:none!important}.action-btn svg,.bootgrid-table .command-edit svg,.bootgrid-table .command-delete svg{display:block!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;overflow:visible!important;color:currentColor!important;opacity:1!important;visibility:visible!important;pointer-events:none!important}.action-btn svg *,.bootgrid-table .command-edit svg *,.bootgrid-table .command-delete svg *{vector-effect:non-scaling-stroke!important;stroke:currentColor!important;stroke-width:2!important;stroke-linecap:round!important;stroke-linejoin:round!important;fill:none!important;opacity:1!important;visibility:visible!important}.btn-icon svg,.btn-primary svg{display:block!important;width:13px!important;height:13px!important;fill:currentColor!important;color:currentColor!important;opacity:1!important;visibility:visible!important}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
body,.table,input,select,textarea{font-family:var(--mono)!important}
.table{width:100%;border-collapse:collapse;font-size:var(--fs-base);margin:0!important;border:0!important;border-radius:0!important;background:transparent!important}
.table>thead>tr>th{height:34px;padding:0 12px!important;text-align:left;font-size:var(--fs-xs);font-weight:var(--fw-semibold);color:var(--text-strong);text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--line)!important;border-top:0!important;background:var(--panel-soft)!important;white-space:nowrap;position:static}
.table>tbody>tr>td{padding:6px 12px!important;vertical-align:middle;border-bottom:1px solid var(--line-soft)!important;border-top:0!important;font-size:var(--fs-base);font-weight:var(--fw-regular);color:var(--text)!important;word-break:break-word;background:transparent!important}
.table>tbody>tr:last-child>td{border-bottom:0!important}
.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}
.table-striped>tbody>tr:nth-of-type(odd)>td{background:transparent!important}
.tbl-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;flex-wrap:wrap;border-bottom:1px solid var(--soft-steel);background:var(--porcelain)}
.tbl-toolbar-left{display:flex;align-items:center;gap:6px}
.tbl-footer{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;border-top:1px solid var(--soft-steel);font-size:var(--fs-sm);color:var(--text);flex-wrap:wrap;background:var(--porcelain)}
#tbl_trackers td.url-cell{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;color:var(--text-strong)!important}
.panel,.panel-default{box-shadow:var(--shadow)!important}
.modal-content{box-shadow:var(--shadow-modal)!important}
.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{box-shadow:none!important;background:transparent!important;color:var(--text-strong)!important}
.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:none!important}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
.form-control:focus,input:focus,select:focus,textarea:focus{box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{box-shadow:none!important}*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}
/* realtime page local fixes */
.panel_m{margin-top:4px}.panel-heading .panel-title{gap:10px}.panel-heading .searchbox{display:flex!important;align-items:stretch!important;flex:1 1 auto!important;max-width:520px!important;width:100%!important}.panel-heading .searchbox>.input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:31px!important;padding:0!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important}.panel-heading .searchbox>.form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;border-left:0!important;border-right:0!important;border-radius:0!important}.panel-heading .searchbox>.input-group-btn{display:flex!important;flex:0 0 auto!important;width:auto!important}.panel-heading .searchbox>.input-group-btn>.btn{height:31px!important;margin:0!important;border-radius:0 var(--radius) var(--radius) 0!important;white-space:nowrap!important}.pre-colon{font-weight:var(--fw-bold);color:var(--text-strong)}.post-colon{font-family:var(--mono);color:var(--text)}#notifications{
    position:fixed!important;
    top:50%!important;
    right:12px!important;
    bottom:auto!important;
    left:auto!important;
    z-index:10060!important;
    display:flex!important;
    flex-direction:column!important;
    gap:10px!important;
    align-items:flex-end!important;
    transform:translateY(-50%)!important;
    pointer-events:none!important;
}.notice{max-width:420px;padding:8px 10px;border:1px solid var(--blue-line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm);line-height:var(--lh-snug)}.notice .close{float:right;margin-left:8px;width:14px;height:14px;border:0!important;border-radius:var(--radius)!important;background:var(--panel-soft)!important}#logout-toast{position:fixed;right:12px;bottom:12px;z-index:10070;display:none;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm)}#logout-toast.show{display:block}.navbar-btn.btn-link{margin:0!important;border:0!important;background:transparent!important;box-shadow:none!important}@media screen and (max-width:768px){.panel-heading .panel-title{display:block!important}.panel-heading .searchbox{max-width:none!important}.panel-heading .searchbox>.input-group-addon,.panel-heading .searchbox>.form-control,.panel-heading .searchbox>.input-group-btn,.panel-heading .searchbox>.input-group-btn>.btn{display:flex!important;width:auto!important}.panel-heading .searchbox>.form-control{flex:1 1 auto!important}.panel-heading .searchbox>.input-group-btn>.btn{margin-top:0!important}.navbar-btn.btn-link{padding:12px 10px!important}.table{width:100%!important}}
.navbar-fixed-top{overflow:visible!important;z-index:1040!important}.navbar-collapse{overflow:visible!important}.rt-period-dropdown{position:relative!important}.rt-period-dropdown>.rt-period-toggle{display:flex!important;align-items:center!important;gap:6px!important;min-height:44px!important}.rt-period-dropdown>.rt-period-toggle .caret{margin-left:2px!important}.rt-period-dropdown.open>.rt-period-toggle,.rt-period-dropdown>.rt-period-toggle:hover,.rt-period-dropdown>.rt-period-toggle:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.rt-period-menu{position:absolute!important;top:100%!important;right:0!important;left:auto!important;z-index:5000!important;display:none;min-width:220px!important;width:220px!important;margin:2px 0 0!important;padding:6px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel2)!important;box-shadow:0 10px 24px rgba(22,25,28,.10)!important;list-style:none!important}.rt-period-dropdown.open>.rt-period-menu{display:block!important}.rt-period-menu>li{display:block!important;float:none!important;width:100%!important;margin:0!important;padding:0!important}.rt-period-menu>li>a,.rt-period-menu>.dropdown-header{display:flex!important;align-items:center!important;gap:6px!important;width:100%!important;min-height:30px!important;padding:7px 9px!important;border-radius:var(--radius)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-tight)!important;white-space:nowrap!important}.rt-period-menu>li>a:hover,.rt-period-menu>li>a:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.rt-period-menu>li.active>a,.rt-period-menu>li.active>a:hover,.rt-period-menu>li.active>a:focus{background: rgba(37, 42, 46, 0.14) !important;color: var(--text-strong) !important;}.rt-period-menu>.divider{height:1px!important;min-height:1px!important;margin:4px 2px!important;overflow:hidden!important;background:var(--line-soft)!important}.rt-period-menu>.dropdown-header{color:var(--muted)!important;font-weight:var(--fw-bold)!important;text-transform:uppercase!important;letter-spacing:.04em!important}@media screen and (max-width:768px){.rt-period-dropdown>.rt-period-toggle{justify-content:space-between!important}.rt-period-menu{position:static!important;width:100%!important;min-width:0!important;margin:0 0 8px!important;box-shadow:none!important}.rt-period-dropdown.open>.rt-period-menu{display:block!important}.navbar-collapse.in{max-height:calc(100dvh - 54px)!important;overflow-y:auto!important;-webkit-overflow-scrolling:touch!important}}
.rt-notice-line{display:inline-flex;align-items:center;gap:5px;flex-wrap:wrap}.rt-inline-icon{display:inline-block!important;width:14px!important;height:14px!important;vertical-align:middle!important;object-fit:contain}.rt-network-icon{width:14px!important;height:14px!important}.rt-click-id{color:var(--steel-gray)}.rt-country-code{color:var(--steel-gray)}.notice .close{padding-left:10px!important}
:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}.table>tbody>tr>td{font-family:var(--mono)!important;font-size:var(--fs-sm)!important}.form-control,input,select,textarea,.btn,button{font-family:var(--mono)!important;font-size:var(--fs-sm)!important}
/* prevent DataTables from setting a fixed pixel width on the table */
#userlead{width:100%!important;}
/* realtime #userlead column alignment */
#userlead th:nth-child(1),#userlead td:nth-child(1){width:10px!important;min-width:10px!important;max-width:44px!important;text-align:left!important;padding-left:12px!important;padding-right:8px!important;font-variant-numeric:tabular-nums}
#userlead th:nth-child(6),#userlead td:nth-child(6){width:75px!important;min-width:75px!important;max-width:110px!important;text-align:left!important;white-space:nowrap!important;font-variant-numeric:tabular-nums}
#userlead th:nth-child(7),#userlead td:nth-child(7){width:210px!important;min-width:210px!important;max-width:260px!important;text-align:left!important;white-space:nowrap!important;font-variant-numeric:tabular-nums}
#userlead td:nth-child(7){overflow:hidden!important;text-overflow:ellipsis!important}
#userlead tfoot th#sum{text-align:left!important;font-variant-numeric:tabular-nums}
#notifications{
    position:fixed!important;
    top:50%!important;
    right:12px!important;
    bottom:auto!important;
    left:auto!important;
    z-index:10060!important;
    display:flex!important;
    flex-direction:column!important;
    gap:10px!important;
    align-items:flex-end!important;
    transform:translateY(-50%)!important;
    pointer-events:none!important;
}
.notice{max-width:420px!important;padding:7px 10px!important;border:0!important;box-shadow:none!important;background:var(--panel)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;font-weight:var(--fw-regular)!important}
.notice .close{float:right!important;margin-left:8px!important;width:14px!important;height:14px!important;padding:0!important;border:0!important;box-shadow:none!important;background:transparent!important;color:var(--text)!important;opacity:.65!important;text-decoration:none!important}
.notice .close:hover,.notice .close:focus{background:transparent!important;opacity:1!important;outline:none!important;box-shadow:none!important}
.rt-notice-line{display:inline-flex!important;align-items:center!important;gap:5px!important;flex-wrap:wrap!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;font-weight:var(--fw-regular)!important}
.notice strong,.notice b,.notice span,.notice code,.rt-notice-line,.rt-notice-line strong,.rt-notice-line b,.rt-notice-line span,.rt-click-id,.rt-country-code{font-weight:var(--fw-regular)!important}
.rt-click-id{color:var(--steel-gray)!important}.rt-country-code{color:var(--steel-gray)!important}
.rt-inline-icon{display:inline-block!important;width:14px!important;height:14px!important;min-width:14px!important;min-height:14px!important;vertical-align:middle!important;object-fit:contain!important;filter:none!important;box-shadow:none!important}
.rt-network-icon{width:14px!important;height:14px!important;min-width:14px!important;min-height:14px!important}.rt-info-icon{opacity:.78!important}.notice .flag{display:inline-block!important;vertical-align:middle!important;border-radius:var(--radius)!important;box-shadow:none!important}
.panel-heading .searchbox>.input-group-btn>.pn-refresh-btn{height:31px!important;margin:0!important;border-radius:0 var(--radius) var(--radius) 0!important;white-space:nowrap!important;width:auto!important;min-width:82px!important}


/* final search input-group match + relative realtime assets */
.panel-heading .panel-title{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:10px!important}
.panel-heading .input-group.search.searchbox{display:flex!important;align-items:stretch!important;flex:0 1 540px!important;width:100%!important;max-width:540px!important;height:31px!important;margin:0!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;overflow:hidden!important;box-shadow:none!important;border-collapse:separate!important}
.panel-heading .input-group.search.searchbox>.input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:29px!important;min-height:29px!important;padding:0!important;border:0!important;border-right:1px solid var(--line-soft)!important;border-radius:0!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important;box-shadow:none!important}
.panel-heading .input-group.search.searchbox>.form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;height:29px!important;min-height:29px!important;padding:5px 9px!important;border:0!important;border-radius:0!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;box-shadow:none!important;outline:none!important}
.panel-heading .input-group.search.searchbox>.form-control:focus{border:0!important;box-shadow:none!important;outline:none!important;color:var(--text-strong)!important}
.panel-heading .input-group.search.searchbox>.input-group-btn{display:flex!important;align-items:stretch!important;flex:0 0 auto!important;width:auto!important;min-width:0!important;height:29px!important;white-space:nowrap!important}
.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:5px!important;width:auto!important;min-width:88px!important;height:29px!important;min-height:29px!important;margin:0!important;padding:0 10px!important;border:0!important;border-left:1px solid var(--line-soft)!important;border-radius:0!important;background:var(--panel)!important;color:var(--text-strong)!important;font-size:var(--fs-sm)!important;font-weight:var(--fw-bold)!important;line-height:var(--lh-tight)!important;box-shadow:none!important;outline:none!important;white-space:nowrap!important}
.panel-heading .input-group.search.searchbox>.input-group-btn>.btn:hover,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}
.panel-heading .input-group.search.searchbox img{display:block!important;width:13px!important;height:13px!important;object-fit:contain!important}
@media screen and (max-width:768px){.panel-heading .panel-title{display:block!important}.panel-heading .input-group.search.searchbox{max-width:none!important;flex:1 1 auto!important}.panel-heading .input-group.search.searchbox>.input-group-addon{display:flex!important;width:34px!important;min-width:34px!important}.panel-heading .input-group.search.searchbox>.form-control{display:block!important;width:auto!important;min-width:0!important;flex:1 1 auto!important}.panel-heading .input-group.search.searchbox>.input-group-btn{display:flex!important;width:auto!important;flex:0 0 auto!important}.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{display:inline-flex!important;width:auto!important;margin-top:0!important}}

/* final search border seam fix */
.panel-heading .input-group.search.searchbox{display:flex!important;align-items:stretch!important;width:100%!important;max-width:540px!important;height:31px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;overflow:hidden!important;box-shadow:none!important}
.panel-heading .input-group.search.searchbox>.input-group-addon,.panel-heading .input-group.search.searchbox>.form-control,.panel-heading .input-group.search.searchbox>.input-group-btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{border:0!important;box-shadow:none!important;outline:none!important}
.panel-heading .input-group.search.searchbox>.input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:29px!important;min-height:29px!important;padding:0!important;border-radius:0!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important}
.panel-heading .input-group.search.searchbox>.form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;height:29px!important;min-height:29px!important;padding:5px 9px!important;border-radius:0!important;background:var(--panel)!important;color:var(--text)!important;line-height:var(--lh-snug)!important}
.panel-heading .input-group.search.searchbox>.input-group-btn{display:flex!important;align-items:stretch!important;flex:0 0 auto!important;width:auto!important;height:29px!important;min-height:29px!important;background:var(--panel)!important}
.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:5px!important;width:auto!important;min-width:88px!important;height:29px!important;min-height:29px!important;margin:0!important;padding:0 10px!important;border-radius:0!important;background:var(--panel)!important;color:var(--text-strong)!important;white-space:nowrap!important;font-weight:var(--fw-bold)!important}
.panel-heading .input-group.search.searchbox>.input-group-btn>.btn:hover,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}
.panel-heading .input-group.search.searchbox img{display:block!important;width:13px!important;height:13px!important;box-shadow:none!important;filter:none!important}
@media screen and (max-width:768px){.panel-heading .input-group.search.searchbox{max-width:none!important;flex-wrap:nowrap!important}.panel-heading .input-group.search.searchbox>.input-group-addon{display:flex!important;width:34px!important;min-width:34px!important}.panel-heading .input-group.search.searchbox>.form-control{display:block!important;width:auto!important;min-width:0!important;flex:1 1 auto!important}.panel-heading .input-group.search.searchbox>.input-group-btn{display:flex!important;width:auto!important;flex:0 0 auto!important}.panel-heading .input-group.search.searchbox>.input-group-btn>.btn,.panel-heading .input-group.search.searchbox>.input-group-btn>.pn-refresh-btn{display:inline-flex!important;width:auto!important;margin-top:0!important}}

/* sweetalert2 monospace light final */
:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}.swal2-container{z-index:10090!important}.swal2-modal,.swal2-popup{width:320px!important;max-width:calc(100vw - 24px)!important;padding:14px!important;border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:none!important;overflow:visible!important}.swal2-title{margin:0 0 8px!important;padding:0!important;color:var(--text-strong)!important;font-size:var(--fs-xl)!important;font-weight:var(--fw-regular)!important;line-height:var(--lh-tight)!important;text-align:center!important}.swal2-content,.swal2-html-container{margin:0!important;padding:0!important;color:var(--text)!important;font-size:var(--fs-sm)!important;font-weight:var(--fw-regular)!important;line-height:var(--lh-normal)!important;text-align:left!important;overflow:visible!important}.rt-swal-text{display:block!important;margin:0!important;padding:0!important;color:var(--text)!important;font-size:var(--fs-sm)!important;font-weight:var(--fw-regular)!important;line-height:var(--lh-normal)!important;text-align:left!important}.swal2-actions,.swal2-buttonswrapper{display:flex!important;align-items:center!important;justify-content:center!important;gap:8px!important;margin:12px 0 0!important;padding:0!important;min-height:31px!important;overflow:visible!important}.swal2-confirm,.swal2-cancel,.swal2-styled{display:inline-flex!important;align-items:center!important;justify-content:center!important;position:static!important;width:auto!important;min-width:88px!important;height:31px!important;min-height:31px!important;margin:0!important;padding:0 12px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;box-shadow:none!important;outline:none!important;transform:none!important;writing-mode:horizontal-tb!important;white-space:nowrap!important;text-indent:0!important;text-transform:none!important;font-size:var(--fs-sm)!important;font-weight:var(--fw-regular)!important;line-height:var(--lh-tight)!important;vertical-align:middle!important;overflow:hidden!important}.swal2-confirm,.swal2-confirm:focus,.swal2-confirm:hover{background:var(--btn-bg)!important;border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.swal2-cancel,.swal2-cancel:focus,.swal2-cancel:hover{background:var(--panel)!important;border-color:var(--line)!important;color:var(--text)!important}.swal2-loader{display:inline-block!important;width:22px!important;height:22px!important;min-width:22px!important;min-height:22px!important;margin:0 8px!important;padding:0!important;border-width:3px!important;border-style:solid!important;border-radius:50%!important;box-shadow:none!important;outline:none!important;transform:none!important;vertical-align:middle!important}.swal2-loading .swal2-confirm{display:none!important}.swal2-container pre{width:100%!important;max-width:100%!important;margin:8px 0 0!important;padding:8px!important;border:1px solid var(--line-soft)!important;border-radius:var(--radius)!important;background:var(--panel-soft)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;font-weight:var(--fw-regular)!important;line-height:var(--lh-normal)!important;white-space:pre-wrap!important;word-break:break-word!important;overflow:auto!important;text-align:left!important}.swal2-container strong,.swal2-container b,.swal2-container footer,.swal2-container .text-muted{font-weight:var(--fw-regular)!important}

/* final realtime notice: transparent background + relaxed spacing */
#notifications{
    position:fixed!important;
    top:50%!important;
    right:12px!important;
    bottom:auto!important;
    left:auto!important;
    z-index:10060!important;
    display:flex!important;
    flex-direction:column!important;
    gap:10px!important;
    align-items:flex-end!important;
    transform:translateY(-50%)!important;
    pointer-events:none!important;
}.notice{display:block!important;width:auto!important;max-width:none!important;padding:0!important;margin:0!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;color:var(--text)!important;font-size:var(--fs-sm)!important;font-weight:var(--fw-regular)!important;line-height:var(--lh-normal)!important;pointer-events:auto!important}.notice .close{display:none!important}.rt-notice-line{display:inline-flex!important;align-items:center!important;justify-content:flex-start!important;gap:8px!important;flex-wrap:wrap!important;padding:0!important;margin:0!important;background:transparent!important;border:0!important;box-shadow:none!important;color:var(--text)!important;font-size:var(--fs-sm)!important;font-weight:var(--fw-regular)!important;line-height:var(--lh-relaxed)!important;white-space:normal!important}.rt-click-id,.rt-country-code,.rt-notice-line span,.rt-notice-line code,.rt-notice-line strong,.rt-notice-line b{font-weight:var(--fw-regular)!important}.rt-click-id{color:var(--steel-gray)!important}.rt-country-code{color:var(--steel-gray)!important}.rt-inline-icon{display:inline-block!important;width:14px!important;height:14px!important;min-width:14px!important;min-height:14px!important;vertical-align:middle!important;object-fit:contain!important;margin:0!important;padding:0!important;background:transparent!important;box-shadow:none!important;border:0!important}.rt-network-icon{width:14px!important;height:14px!important;min-width:14px!important;min-height:14px!important}.notice .flag,.rt-notice-line .flag{display:inline-block!important;vertical-align:middle!important;margin:0 1px 0 0!important;border-radius:.15rem!important;box-shadow:none!important}@media screen and (max-width:768px){
    #notifications{
        top:50%!important;
        right:8px!important;
        bottom:auto!important;
        left:auto!important;
        transform:translateY(-50%)!important;
        align-items:flex-end!important;
        gap:8px!important;
    }

    .notice{
        width:auto!important;
        max-width:calc(100vw - 24px)!important;
    }

    .rt-notice-line{
        gap:7px!important;
        line-height:var(--lh-normal)!important;
    }
}
.app-sign{text-align:right;padding:3px 0 2px}.app-sign footer{font-family:var(--mono);text-decoration:none;letter-spacing:.09em;font-size:10px;font-weight:900;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;user-select:none;text-transform:uppercase;-webkit-user-select:none}select hr{border:none;border-top:1px solid rgba(37,42,46,.06)!important;color:rgba(37,42,46,.06)!important;opacity:.45;margin:1px 4px}input[type=url]{font-family:var(--mono)!important}
/* tighten empty DataTables toolbar gap (search ↔ table) */
#userlead_wrapper .top,#userlead_wrapper .dataTables_length,#userlead_wrapper .dataTables_filter{display:none!important;height:0!important;margin:0!important;padding:0!important}
#userlead_wrapper .searchbox{margin:0!important}
#userlead_wrapper{margin:0!important}
.panel_m .panel-body{padding:0 0 2px!important}
#userlead{margin-top:0!important}
/* right-align numeric columns: # (1), TRAFFIC (5), EARNING (6) */
#userlead th:nth-child(1),#userlead td:nth-child(1),
#userlead th:nth-child(5),#userlead td:nth-child(5),
#userlead th:nth-child(6),#userlead td:nth-child(6){text-align:left!important;font-variant-numeric:tabular-nums;white-space:nowrap!important}
/* footer + rg-source block */
.app-footer{width:100%;max-width:1180px;margin:12px auto 0;padding:7px 8px 3px;border-top:1px solid var(--line-soft);text-align:right;line-height:var(--lh-snug)}
.app-footer .app-sign{padding:0!important;font-family:var(--mono)!important;color:var(--graphite)!important;letter-spacing:.02em!important;line-height:1!important;text-decoration:none;font-size:10px!important;font-weight:900!important;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;text-transform:uppercase;user-select:none;-webkit-user-select:none}
.app-footer .rg-source{margin-top:3px;font-size:var(--fs-xs);color:var(--muted)}
.app-footer .rg-source .pre-colon{font-weight:var(--fw-bold);color:var(--text-strong)}
.app-footer .rg-source .post-colon{font-family:var(--mono);color:var(--text)}
/* ngix xctd image backdrop */
.panel_m.panel{position:relative!important;overflow:hidden!important;isolation:isolate!important;background:rgba(252,251,248,.74)!important}
.panel_m.panel>.ngix-image-backdrop{position:absolute!important;inset:0!important;z-index:0!important;pointer-events:none!important;background-image:linear-gradient(rgba(252,251,248,.82),rgba(252,251,248,.82)),url('<?= statH(statAssetUrl('/assets/img/bg-intro.png')) ?>')!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,cover!important;opacity:.42!important;filter:saturate(.72) contrast(.86) blur(.22px)!important;transform:translateZ(0)!important}
.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body{position:relative!important;z-index:2!important}
.panel_m.panel>.panel-heading{background:rgba(244,241,236,.82)!important;backdrop-filter:saturate(110%) blur(1px)!important}
.panel_m.panel>.panel-body{background:rgba(252,251,248,.46)!important}
#userlead{position:relative!important;z-index:3!important;background:rgba(252,251,248,.58)!important}
#userlead>thead>tr>th{background:rgba(244,241,236,.86)!important}
#userlead>tbody>tr>td{background:rgba(252,251,248,.34)!important}
#userlead.table-hover>tbody>tr:hover>td{background:rgba(244,241,236,.72)!important}
@media (prefers-color-scheme:dark){.panel_m.panel{background:rgba(37,42,46,.78)!important}.panel_m.panel>.ngix-image-backdrop{background-image:linear-gradient(rgba(37,42,46,.78),rgba(37,42,46,.78)),url('<?= statH(statAssetUrl('/assets/img/bg-intro.png')) ?>')!important;opacity:.46!important;filter:saturate(.70) contrast(.84) blur(.18px)!important}.panel_m.panel>.panel-heading{background:rgba(37,42,46,.84)!important}.panel_m.panel>.panel-body{background:rgba(37,42,46,.50)!important}#userlead{background:rgba(37,42,46,.50)!important}#userlead>thead>tr>th{background:rgba(37,42,46,.86)!important}#userlead>tbody>tr>td{background:rgba(37,42,46,.34)!important}#userlead.table-hover>tbody>tr:hover>td{background:rgba(37,42,46,.72)!important}}
@media screen and (max-width:768px){.panel_m.panel>.ngix-image-backdrop{background-size:100% 100%,cover!important;background-position:center center,center center!important;opacity:.34!important}}body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none}body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)}.rt-flag{display:inline-block;width:16px;height:11px;vertical-align:-1px;border-radius:.15rem}.rt-flag.flag{width:16px;height:11px;background-repeat:no-repeat;background-size:100%}.rt-flag.flag-doesnt-exist{background-image:none;background-color:var(--panel-soft)}.rt-device-ico{display:inline-block;width:14px;height:14px;vertical-align:-3px;color:var(--graphite);fill:var(--porcelain)}.rt-ip{text-decoration:none}</style>
<link rel="stylesheet" href="<?= statH(statAssetUrl('/assets/css/stat-realtime-1.css')) ?>">
    <!-- Fixed navbar -->
    <nav class="navbar navbar-default navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="#">
            <strong class="text-muted">
              <img src="<?= statH(statAssetUrl('/assets/img/chart.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
              REALTIME CONVERSION <?= $date === 'rt_1' ? 'TODAY' : 'YESTERDAY' ?>
            </strong>
          </a>
        </div>

        <div id="navbar" class="navbar-collapse collapse">
          <ul class="nav navbar-nav navbar-right">
            <li class="dropdown active rt-period-dropdown">
              <a href="#" class="dropdown-toggle rt-period-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">
                <strong>
                  REALTIME CONVERSION
                  <img src="<?= statH(statAssetUrl('/assets/img/chart.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                </strong>
                <span class="caret"></span>
              </a>

              <ul class="dropdown-menu rt-period-menu">
                <li class="dropdown-header">REALTIME CONVERSION</li>
                <li role="separator" class="divider"></li>

                <?php if ($date === 'rt_1') : ?>
                  <li class="active"><a href="#"><strong>TODAY</strong></a></li>
                  <li role="separator" class="divider"></li>
                  <li><a href="<?= statH(statUrl('/realtime/?date=rt_2')) ?>"><strong>YESTERDAY</strong></a></li>
                  <li role="separator" class="divider"></li>
                  <li>
                    <a href="<?= statH(statUrl('/clicks/')) ?>">
                      <strong>
                        PERFORMANCE CLICKS
                        <img src="<?= statH(statAssetUrl('/assets/img/chart.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                      </strong>
                    </a>
                  </li>
                <?php else : ?>
                  <li><a href="<?= statH(statUrl('/realtime/?date=rt_1')) ?>"><strong>TODAY</strong></a></li>
                  <li role="separator" class="divider"></li>
                  <li class="active"><a href="#"><strong>YESTERDAY</strong></a></li>
                  <li role="separator" class="divider"></li>
                  <li>
                    <a href="<?= statH(statUrl('/clicks/')) ?>">
                      <strong>
                        PERFORMANCE CLICKS
                        <img src="<?= statH(statAssetUrl('/assets/img/chart.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                      </strong>
                    </a>
                  </li>
                <?php endif; ?>
              </ul>
            </li>

            <li>
              <a>
                <strong>
                  
                </strong>
              </a>
            </li>

            <li>
              <a href="<?= statH(statUrl('/performance/')) ?>">
                <strong>PERFORMANCE NETWORK</strong>
                
              </a>
            </li>

            <li>
              <form method="post" action="<?= statH(statUrl('/realtime/?date=' . rawurlencode($date))) ?>" id="logout-form" style="margin:0;">
                <input type="hidden" name="csrf_token" value="<?= rtH(rtCsrfToken()) ?>">
                <input type="hidden" name="action" value="logout">
                <button type="submit" id="btn-logout" class="btn btn-link navbar-btn logout-btn">
                  <strong>LOGOUT</strong>
                </button>
              </form>
            </li>
          </ul>
        </div>
      </div>
    </nav>

    <div class="container">
    <div class="noise" aria-hidden="true"></div>
    <div class="scanline" aria-hidden="true"></div>
        <div class="panel_m panel panel-default">
            <div class="ngix-image-backdrop" aria-hidden="true"></div>
            <div class="panel-heading">
                <div class="pn-toolbar">
                    <div class="input-group search searchbox">
                        <span class="input-group-addon">
                            <img src="<?= statH(statAssetUrl('/assets/img/search.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                        </span>
                        <input type="text" class="form-control input-sm" id="search" placeholder="Search...">
                        <span class="input-group-btn">
                            <button class="btn btn-default btn-sm pn-refresh-btn" id="refresh" type="button">
                                <img src="<?= statH(statAssetUrl('/assets/img/refresh.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                                <strong>Refresh</strong>
                            </button>
                        </span>
                    </div>
                    <div id="rt-export" class="pn-export"></div>
                </div>
            </div>

            <div class="panel-body">
                <div class="table-responsive">
                <table
                id="userlead"
                class="table table-condensed table-hover table-striped"
                cellspacing="0"
                data-toggle="bootgrid"
                style="table-layout:auto;"
            >
                    <thead>
                        <tr>
                            <th data-column-id="id" data-type="numeric" data-identifier="true" data-resizable-column-id="id" data-noresize>#</th>
                            <th data-column-id="click_id">ID</th>
                            <th data-column-id="network">NETWORK</th>
                            <th data-column-id="country">COUNTRY</th>
                            <th data-column-id="traffic">TRAFFIC</th>
                            <th data-column-id="payout">EARNING</th>
                            <th data-column-id="ip_address">IPADDRESS</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                    <tfoot>
                        <tr>
                            <th colspan="7" id="sum"></th>
                        </tr>
                    </tfoot>
                </table>
                </div>
            </div>
        </div>
<div id="notifications" class="rt-notification-dock" aria-live="polite" aria-atomic="false" style="height:auto;"></div>
    </div>
<?php
$conversionDate = gmdate('Y-m-d'); // UTC: must equal postback's conversion_date (written in UTC) for the day-join to match
$last = 0;

try {
    $rtScope    = stat_scope_sub_id();
    $rtScopeSql = $rtScope !== null ? ' AND click_id = :scope' : '';
    $stmt = $pdo->prepare(
        'SELECT id FROM leadreport WHERE conversion_date = :date' . $rtScopeSql . ' ORDER BY id DESC LIMIT 1',
    );
    $rtParams = ['date' => $conversionDate];
    if ($rtScope !== null) {
        $rtParams['scope'] = $rtScope;
    }
    $stmt->execute($rtParams);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (is_array($row) && isset($row['id'])) {
        $last = (int) $row['id'];
    }
} catch (Throwable $e) {
    // Silently proceed with $last = 0
}

$lastIdFromJson = 0;

foreach ($result as $rowId) {
    if (is_array($rowId) && isset($rowId['id'])) {
        $lastIdFromJson = (int) $rowId['id'];
    }
}

?>
<script nonce="<?= rtH($rtNonce) ?>">
var lastId = <?= (int) $last ?>;
var last_id = <?= (int) $lastIdFromJson ?>;
var rtConversion = <?= (int) $conversion ?>;

// Cross-tab/cross-device live sync for this realtime page. One tab per
// device (the "leader", elected via a localStorage heartbeat) does the
// actual polling; every tab — leader and followers alike — renders through
// the same BroadcastChannel message handler, so followers stay in sync
// without ever hitting json.parse.php/lead.php/data.php themselves
// ("silent polling"). Falls back to independent per-tab polling
// (pre-existing behavior) when BroadcastChannel/localStorage aren't
// available.
var RT_SYNC = (function () {
    'use strict';

    var ns = 'srp_rt_' + String(rtConversion) + '_';
    var supported = typeof BroadcastChannel === 'function' && typeof localStorage !== 'undefined';

    if (!supported) {
        var localListeners = [];

        return {
            enabled: false,
            isLeader: function () { return true; },
            onMessage: function (fn) { localListeners.push(fn); },
            broadcast: function (msg) {
                for (var i = 0; i < localListeners.length; i++) {
                    try { localListeners[i](msg); } catch (e) {}
                }
            },
            syncCursor: function (name, value) { return Number(value) || 0; }
        };
    }

    var tabId = (window.crypto && typeof window.crypto.randomUUID === 'function')
        ? window.crypto.randomUUID()
        : (Date.now() + '-' + Math.random().toString(36).slice(2));
    var LEADER_KEY = ns + 'leader';
    var HEARTBEAT_MS = 3000;
    var STALE_MS = 7000;
    var channel = new BroadcastChannel('srp-rt-' + String(rtConversion));
    var listeners = [];
    var leader = false;

    function readLeader() {
        try {
            var raw = localStorage.getItem(LEADER_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    function writeLeader() {
        try {
            localStorage.setItem(LEADER_KEY, JSON.stringify({id: tabId, ts: Date.now()}));
        } catch (e) {}
    }

    function tick() {
        var current = readLeader();
        var now = Date.now();

        if (!current || (now - (Number(current.ts) || 0)) > STALE_MS || current.id === tabId) {
            leader = true;
            writeLeader();
            return;
        }

        leader = false;
    }

    tick();
    setInterval(tick, HEARTBEAT_MS);

    window.addEventListener('pagehide', function () {
        if (!leader) {
            return;
        }

        var current = readLeader();
        if (current && current.id === tabId) {
            try {
                localStorage.removeItem(LEADER_KEY);
            } catch (e) {}
        }
    });

    channel.onmessage = function (event) {
        var msg = event && event.data;
        if (!msg || typeof msg !== 'object') {
            return;
        }

        for (var i = 0; i < listeners.length; i++) {
            try { listeners[i](msg); } catch (e) {}
        }
    };

    return {
        enabled: true,
        isLeader: function () { return leader; },
        onMessage: function (fn) { listeners.push(fn); },
        broadcast: function (msg) {
            try { channel.postMessage(msg); } catch (e) {}

            for (var i = 0; i < listeners.length; i++) {
                try { listeners[i](msg); } catch (e) {}
            }
        },
        // Returns the higher of `value` and whatever cursor is already
        // persisted on this device for `name`, and persists the result —
        // keeps a newly-opened tab (or a newly-promoted leader) from
        // re-announcing rows another tab already showed.
        syncCursor: function (name, value) {
            var key = ns + 'cursor_' + name;
            var stored = 0;

            try {
                stored = parseInt(localStorage.getItem(key) || '0', 10) || 0;
            } catch (e) {}

            var next = Math.max(stored, Number(value) || 0);

            try {
                localStorage.setItem(key, String(next));
            } catch (e) {}

            return next;
        }
    };
})();

last_id = RT_SYNC.syncCursor('notice', last_id);
lastId = RT_SYNC.syncCursor('lead', lastId);
</script>

<script src="https://www.gstatic.com/firebasejs/4.1.2/firebase-app.js" type="text/javascript" nonce="<?= rtH($rtNonce) ?>"></script>
<script src="https://www.gstatic.com/firebasejs/4.1.2/firebase-messaging.js" type="text/javascript" nonce="<?= rtH($rtNonce) ?>"></script>
<script src="<?= statH(statAssetUrl('/assets/js/push.js')) ?>" nonce="<?= rtH($rtNonce) ?>"></script>

<script type="text/javascript" nonce="<?= rtH($rtNonce) ?>">
$(document).ready(function () {
    'use strict';

    $('.rt-period-toggle').on('click', function (e) {
        var $dropdown = $(this).closest('.rt-period-dropdown');

        if ($dropdown.length < 1) {
            return;
        }

        e.preventDefault();
        e.stopPropagation();

        $('.rt-period-dropdown').not($dropdown).removeClass('open')
            .find('.rt-period-toggle').attr('aria-expanded', 'false');

        $dropdown.toggleClass('open');
        $(this).attr('aria-expanded', $dropdown.hasClass('open') ? 'true' : 'false');
    });

    $(document).on('click', function () {
        $('.rt-period-dropdown').removeClass('open')
            .find('.rt-period-toggle').attr('aria-expanded', 'false');
    });

    $('.rt-period-menu').on('click', function (e) {
        e.stopPropagation();
    });

    function asText(value) {
        if (value === null || typeof value === 'undefined') {
            return '';
        }

        return String(value);
    }

    function escapeHtml(value) {
        return $('<div>').text(asText(value)).html();
    }

    function safeAssetUrl(value) {
        var raw = asText(value);

        if (raw === '') {
            return '';
        }

        try {
            var parsed = new URL(raw, window.location.href);

            if (parsed.protocol !== 'https:' && parsed.origin !== window.location.origin) {
                return '';
            }

            return parsed.href;
        } catch (e) {
            return '';
        }
    }

    window.Notify = function (text, callback, closeCallback, style) {
        var time = 25000;
        var $container = $('#notifications');
        var safeStyle = typeof style === 'undefined' ? 'warning' : asText(style).replace(/[^a-z0-9_-]/gi, '');
        var $html = $('<div>', {'class': 'notice notice-' + safeStyle});
        var $icon = $('<img>', {
            src: <?= json_encode(statAssetUrl('/assets/img/ssid.svg'), JSON_UNESCAPED_SLASHES) ?>,
            alt: '',
            css: {
                width: '14px',
                height: '14px',
                verticalAlign: 'middle'
            }
        });

        $('<a>', {
            text: '',
            class: 'button close',
            style: 'padding-left:10px;',
            href: '#',
            click: function (e) {
                e.preventDefault();

                if (typeof closeCallback === 'function') {
                    closeCallback();
                }

                removeNotice();
            }
        }).prependTo($html);

        $html.append($icon);
        $html.append(document.createTextNode(' ' + asText(text)));

        $container.prepend($html);
        $html.removeClass('hide').hide().fadeIn('slow');

        function removeNotice() {
            $html.stop().fadeOut('slow', function () {
                $html.remove();
            });
        }

        var timer = setInterval(removeNotice, time);

        $html.hover(function () {
            clearInterval(timer);
        }, function () {
            timer = setInterval(removeNotice, time);
        });

        $html.on('click', function () {
            clearInterval(timer);

            if (typeof callback === 'function') {
                callback();
            }

            removeNotice();
        });
    };

    function safeIconUrl(value) {
        var raw = asText(value);

        if (raw === '') {
            return '';
        }

        try {
            var parsed = new URL(raw, window.location.href);

            if (parsed.origin !== window.location.origin) {
                return '';
            }

            // Network icons are PNG (json.parse.php), the remaining inline icons
            // are SVG — both extensions must pass or the icon silently drops to
            // a plain text label. Same-origin + /assets/img/ + a single filename
            // segment still bound this to the asset directory.
            if (!/^\/(?:[a-z0-9_.-]+\/)*assets\/img\/[a-z0-9_.-]+\.(?:svg|png)$/i.test(parsed.pathname)) {
                return '';
            }

            return parsed.pathname + parsed.search;
        } catch (e) {
            return '';
        }
    }

// Flags render as <img src="flag_placeholder.png" class="flag flag-xx">: the
// placeholder is a blank/transparent sprite-sized PNG, the actual flag comes
// from the .flag-xx background-position rule in assets/css/flags.css (loaded
// by header.php as /dist/flags.css). The sprite only positions codes it
// actually ships: anything else keeps `background-position: 0 0` and would
// render the wrong country, so an unlisted code falls back to the
// `.flag-doesnt-exist` placeholder box instead of a `.flag-xx` class.
var RT_FLAG_CODES = <?= json_encode(
    ' ' . statFlagSpriteCodeList() . ' ',
    JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
) ?>;

var RT_FLAG_PLACEHOLDER = <?= json_encode(
    statAssetUrl('/assets/img/flag_placeholder.png'),
    JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
) ?>;

function flagClassName(value) {
    var code = asText(value).toLowerCase().replace(/[^a-z]/g, '');

    if (!/^[a-z]{2}$/.test(code) || RT_FLAG_CODES.indexOf(' ' + code + ' ') === -1) {
        return 'rt-flag flag flag-doesnt-exist';
    }

    return 'rt-flag flag flag-' + code;
}

function renderRealtimeNotice(userRow) {
    var $wrap = $('<span>', {'class': 'rt-notice-line'});
    var networkIcon = safeIconUrl(userRow.network_icon);

    $('<span>', {'class': 'rt-click-id'})
        .text(asText(userRow.click_id))
        .appendTo($wrap);

    $wrap.append(document.createTextNode(' : '));

    $('<img>', {'class': flagClassName(userRow.country_code), src: RT_FLAG_PLACEHOLDER, alt: ''}).appendTo($wrap);

    $wrap.append(document.createTextNode(' '));

    $('<span>', {'class': 'rt-country-code'})
        .text(asText(userRow.country_code))
        .appendTo($wrap);

    $wrap.append(document.createTextNode(' : '));

    if (networkIcon !== '') {
        $('<img>', {
            src: networkIcon,
            alt: asText(userRow.network),
            title: asText(userRow.network),
            class: 'rt-inline-icon rt-network-icon'
        }).appendTo($wrap);
    } else {
        $('<span>').text(asText(userRow.network)).appendTo($wrap);
    }

    return $wrap;
}

window.NotifyNode = function ($node, callback, closeCallback, style) {
    var time = 25000;
    var $container = $('#notifications');
    var safeStyle = typeof style === 'undefined' ? 'warning' : asText(style).replace(/[^a-z0-9_-]/gi, '');
    var $html = $('<div>', {'class': 'notice notice-' + safeStyle});
    var $icon = $('<img>', {
        src: <?= json_encode(statAssetUrl('/assets/img/user.svg'), JSON_UNESCAPED_SLASHES) ?>,
        alt: '',
        class: 'rt-inline-icon'
    });

    $('<a>', {
        text: '',
        class: 'button close',
        href: '#',
        click: function (e) {
            e.preventDefault();

            if (typeof closeCallback === 'function') {
                closeCallback();
            }

            removeNotice();
        }
    }).prependTo($html);

    $html.append($icon);
    $html.append(document.createTextNode(' '));
    $html.append($node);

    $container.prepend($html);
    $html.removeClass('hide').hide().fadeIn('slow');

    function removeNotice() {
        $html.stop().fadeOut('slow', function () {
            $html.remove();
        });
    }

    var timer = setInterval(removeNotice, time);

    $html.hover(function () {
        clearInterval(timer);
    }, function () {
        timer = setInterval(removeNotice, time);
    });

    $html.on('click', function () {
        clearInterval(timer);

        if (typeof callback === 'function') {
            callback();
        }

        removeNotice();
    });
};

RT_SYNC.onMessage(function (msg) {
    if (!msg || msg.type !== 'rt-notice') {
        return;
    }

    var delay = 10000;
    var rows = Array.isArray(msg.rows) ? msg.rows : [];

    $.each(rows, function (keyId, userRow) {
        if (!userRow || typeof userRow !== 'object') {
            return;
        }

        if (
            asText(userRow.country_code) === '-' ||
            asText(userRow.country_code) === 'ID'
        ) {
            return;
        }

        setTimeout(function () {
            window.NotifyNode(renderRealtimeNotice(userRow));
        }, Number(keyId) * delay);
    });

    if (typeof msg.cursor === 'number' && msg.cursor > last_id) {
        last_id = msg.cursor;
    }
});

setInterval(function () {
    if (!RT_SYNC.isLeader()) {
        return;
    }

    $.ajax({
        url: 'json.parse.php?id=' + encodeURIComponent(String(last_id)),
        dataType: 'json',
        cache: false,
        success: function (json) {
            if (!Array.isArray(json) || json.length < 1) {
                return;
            }

            var cursor = last_id;

            $.each(json, function (keyId, userRow) {
                if (userRow && typeof userRow === 'object') {
                    var id = parseInt(userRow.id, 10) || 0;
                    if (id > cursor) {
                        cursor = id;
                    }
                }
            });

            cursor = RT_SYNC.syncCursor('notice', cursor);
            last_id = cursor;

            RT_SYNC.broadcast({type: 'rt-notice', rows: json, cursor: cursor});
        }
    });
}, 10000);

    $.fn.dataTable.ext.errMode = 'throw';

    var table = $('#userlead').DataTable({
        ajax: 'data.php?date=' + encodeURIComponent(String(rtConversion)),
        columns: [
            {data: 'id'},
            {data: 'click_id'},
            {data: 'network'},
            {data: 'country'},
            {data: 'traffic'},
            {data: 'payout'},
            {data: 'ip_address'}
        ],
        oLanguage: {
            sSearch: '',
            sSearchPlaceholder: 'Search...'
        },
        sPaginationType: 'bootstrap',
        paging: false,
        responsive: true,
        ordering: true,
        order: [],
        columnDefs: [{targets: [0, 5], type: 'num'}],
        info: false,
        bFilter: true,
        autoWidth: false,
        sDom: "<'top'>l<'searchbox' t>ip",
        footerCallback: function () {
            var api = this.api();

            var intVal = function (i) {
                if (typeof i === 'string') {
                    return i.replace(/[\$,]/g, '') * 1;
                }

                if (typeof i === 'number') {
                    return i;
                }

                return 0;
            };

            var pageTotal = api
                .column(5, {page: 'current'})
                .data()
                .reduce(function (a, b) {
                    return intVal(a) + intVal(b);
                }, 0);

            $('#sum').html('<i>Total Earning: $' + pageTotal.toFixed(2) + '</i>');
        }
    });

    function applyRealtimeTableData(json) {
        if (!json || !Array.isArray(json.data)) {
            return;
        }

        table.clear();
        table.rows.add(json.data);
        table.draw(false);
    }

    $('.dataTables_empty').text('There are currently no leads available for this.');

    if ($.fn.tableExport) {
        $('#userlead').tableExport({
            headers: true,
            footers: true,
            formats: ['xlsx'],
            fileName: 'realtime-' + new Date().toISOString().slice(0, 10),
            bootstrap: false,
            exportButtons: true,
            position: 'bottom',
            ignoreRows: null,
            ignoreCols: null,
            trimWhitespace: false,
            RTL: false,
            sheetname: 'id'
        });
        var $rtButtons = $('#userlead').find('caption').children().detach();
        $rtButtons.appendTo('#rt-export');
    }

    $('#search').on('keyup', function () {
        table.search($(this).val()).draw();
    });

    $('#refresh').on('click', function () {
        $('#userlead').fadeOut(100).fadeIn(100);
        table.ajax.reload(null, false);
        window.scrollTo(0, document.body.scrollHeight);
    });

    RT_SYNC.onMessage(function (msg) {
        if (!msg || msg.type !== 'rt-lead') {
            return;
        }

        var delay = 5000;
        var rows = Array.isArray(msg.rows) ? msg.rows : [];
        // Audio/push only fire on this device's leader tab — the tab doing
        // the actual polling. Follower tabs on the same device still get the
        // table update (via the broadcast table payload below) but stay
        // silent, so N tabs open on one machine don't alert N times for the
        // same lead. Cross-device dedup (user.silent) is decided server-side
        // in lead.php and is respected on top of that.
        var iAmLeader = RT_SYNC.isLeader();

        if (msg.table) {
            applyRealtimeTableData(msg.table);
        }

        $.each(rows, function (key, user) {
            if (!user || typeof user !== 'object') {
                return;
            }

            setTimeout(function () {
                var audioUrl = safeAssetUrl(user.audio);
                var iconUrl = safeAssetUrl(user.img);
                var silent = user.silent === true || !iAmLeader;

                if (!silent && audioUrl !== '') {
                    try {
                        var audio = new Audio(audioUrl);
                        var playResult = audio.play();

                        if (playResult && typeof playResult.catch === 'function') {
                            playResult.catch(function () {});
                        }
                    } catch (e) {}
                }

                if (!silent && typeof Push !== 'undefined' && Push && Push.Permission && Push.create) {
                    Push.Permission.request(function () {
                        Push.create(asText(user.click_id), {
                            body: '{' + asText(user.network) + '} ' +
                                asText(user.country) + ' -' +
                                asText(user.traffic) + ' -' +
                                asText(user.payout),
                            icon: iconUrl,
                            timeout: 4000,
                            onClick: function () {
                                window.focus();
                                this.close();
                            }
                        });
                    });
                }

                window.scrollTo(0, document.body.scrollHeight);
            }, Number(key) * delay);
        });

        if (typeof msg.cursor === 'number' && msg.cursor > lastId) {
            lastId = msg.cursor;
        }
    });

    setInterval(function () {
        if (!RT_SYNC.isLeader()) {
            return;
        }

        $.ajax({
            url: 'lead.php?id=' + encodeURIComponent(String(lastId)),
            dataType: 'json',
            cache: false,
            success: function (json) {
                if (!Array.isArray(json) || json.length < 1) {
                    return;
                }

                var cursor = lastId;

                $.each(json, function (key, user) {
                    if (user && typeof user === 'object') {
                        var id = parseInt(user.id, 10) || 0;
                        if (id > cursor) {
                            cursor = id;
                        }
                    }
                });

                cursor = RT_SYNC.syncCursor('lead', cursor);
                lastId = cursor;

                function broadcastLead(tableJson) {
                    // Table refresh is best-effort — if data.php fails, the
                    // lead rows (audio/push/toast) must still reach every
                    // tab, just without a table repaint this cycle.
                    RT_SYNC.broadcast({
                        type: 'rt-lead',
                        rows: json,
                        cursor: cursor,
                        table: (tableJson && Array.isArray(tableJson.data)) ? tableJson : null
                    });
                }

                $.ajax({
                    url: 'data.php?date=' + encodeURIComponent(String(rtConversion)),
                    dataType: 'json',
                    cache: false
                }).done(broadcastLead).fail(function () {
                    broadcastLead(null);
                });
            }
        });
    }, 10000);

    window.scrollTo(0, document.body.scrollHeight);

    $(document).on('submit', '#logout-form', function(e) {
    e.preventDefault();

    var form = this;
    var toast = document.getElementById('logout-toast');

    if (toast) {
        toast.classList.add('show');
    }

    window.setTimeout(function() {
        form.submit();
    }, 900);
});

    window.ip = function (ele) {
        var id = '';

        if (ele) {
            if (typeof ele.getAttribute === 'function') {
                id = ele.getAttribute('data-ip') || ele.id || '';
            } else if (ele.id) {
                id = ele.id;
            }
        }

        id = String(id);

        if (id === '') {
            return;
        }

        var ipAPI = 'checkIP.php?IP2Location=' + encodeURIComponent(id);

        if (typeof Swal === 'undefined' || !Swal || !Swal.queue) {
            return;
        }

        Swal.queue([{
            title: 'IP Address Lookup!',
            confirmButtonText: 'IP Checker',
            showCancelButton: true,
            allowOutsideClick: false,
            html: '<span class="rt-swal-text">Get IP Address location information:</span>',
            showLoaderOnConfirm: true,
            preConfirm: function () {
                return fetch(ipAPI, {
                    credentials: 'same-origin',
                    headers: {
                        Accept: 'application/json'
                    }
                })
                    .then(function (response) {
                        if (!response.ok) {
                            throw new Error('Invalid response.');
                        }

                        return response.json();
                    })
                    .then(function (data) {
                        var html = '<pre>' +
                            '<footer class="text-muted">IP Address Identify Geolocation:</footer>' +
                            'ip_address: ' + escapeHtml(data.ip_address) +
                            '\ncountry_code: <img class="' + flagClassName(data.code) + '" src="' + RT_FLAG_PLACEHOLDER + '" alt=""> ' + escapeHtml(data.code) +
                            '\ncountry_name: ' + escapeHtml(data.name) +
                            '\nregion: ' + escapeHtml(data.region) +
                            '\ncity: ' + escapeHtml(data.city) +
                            '</pre>';

                        Swal.insertQueueStep({
                            title: 'IP Address Result',
                            html: html,
                            confirmButtonText: 'Close'
                        });
                    })
                    .catch(function () {
                        Swal.insertQueueStep({
                            type: 'error',
                            title: 'Lookup Failed',
                            text: 'Unable to get IP address location information.',
                            confirmButtonText: 'Close'
                        });
                    });
            }
        }]);
    };

    $(document).on('click', '.js-ip', function (e) {
        e.preventDefault();

        if (typeof window.ip === 'function') {
            window.ip(this);
        }
    });
});
</script>

<div id="logout-toast">Logging out…</div>
<footer class="app-footer">
    <div class="app-sign">Ngix · xctd</div>
    <div class="rg-source"><span class="pre-colon">SOURCE</span>: <span class="post-colon">NGIX ⸺ XCTD</span></div>
</footer>
<link rel="stylesheet" href="<?= statH(statAssetUrl('/assets/css/stat-realtime-2.css')) ?>">
<script nonce="<?= rtH($rtNonce) ?>">
/* NGIX patch: statistics logout and loading state */
(function(){
    'use strict';

    function closest(node, selector) {
        return node && typeof node.closest === 'function' ? node.closest(selector) : null;
    }

    function ensureLogoutToast() {
        var toast = document.getElementById('logout-toast');

        if (!toast) {
            toast = document.createElement('div');
            toast.setAttribute('nonce', '<?= rtH($rtNonce) ?>');
            toast.id = 'logout-toast';
            toast.textContent = 'Logging out…';
            document.body.appendChild(toast);
        }

        toast.setAttribute('role', 'status');
        toast.setAttribute('aria-live', 'polite');
        return toast;
    }

    function setLoading(button) {
        if (!button) {
            return;
        }

        if (!button.dataset.ngixOriginalLabel) {
            button.dataset.ngixOriginalLabel = button.innerHTML;
        }

        button.classList.add('is-loading');
        button.setAttribute('aria-busy', 'true');
        button.disabled = true;
    }

    document.addEventListener('submit', function(event) {
        var form = closest(event.target, '#logout-form,.logout-form');

        if (!form) {
            return;
        }

        event.preventDefault();
        event.stopPropagation();

        if (typeof event.stopImmediatePropagation === 'function') {
            event.stopImmediatePropagation();
        }

        if (form.dataset.ngixSubmitting === '1') {
            return;
        }

        form.dataset.ngixSubmitting = '1';

        var button = form.querySelector('#btn-logout,.logout-btn,button[type="submit"],input[type="submit"]');
        setLoading(button);

        var toast = ensureLogoutToast();
        toast.classList.add('show');

        window.setTimeout(function() {
            HTMLFormElement.prototype.submit.call(form);
        }, 600);
    }, true);

    document.addEventListener('click', function(event) {
        var button = closest(event.target, '.pn-refresh-btn,#refresh,[data-spinner]');

        if (!button || button.classList.contains('is-loading')) {
            return;
        }

        button.classList.add('is-loading');
        button.setAttribute('aria-busy', 'true');
    }, true);
}());
</script>
<style nonce="<?= rtH($rtNonce) ?>">
/* NGIX patch: statistics bg/backdrop deglitch */
html{width:100%!important;min-width:0!important;max-width:100%!important;min-height:100%!important;margin:0!important;padding:0!important;overflow-x:hidden!important;background:var(--porcelain)!important;zoom:1!important}
body{position:relative!important;width:100%!important;min-width:0!important;max-width:100%!important;min-height:100vh!important;min-height:100svh!important;min-height:100dvh!important;margin:0!important;overflow-x:hidden!important;background:linear-gradient(rgba(252,251,248,.74),rgba(252,251,248,.88)),url('/assets/img/favicon.svg') right 14px bottom 12px/28px 28px no-repeat fixed,url('/assets/img/bg-intro.png') center center/cover no-repeat fixed,var(--porcelain)!important;color:var(--text,var(--graphite))!important}
body::after{content:none!important;display:none!important;background:none!important}
body::before{z-index:1!important}
body>.container,.container{position:relative!important;z-index:2!important;max-width:1180px!important;overflow:visible!important}
.navbar.navbar-fixed-top,.navbar-fixed-top{position:fixed!important;top:0!important;right:0!important;left:0!important;width:100%!important;max-width:100%!important;margin:0!important;border-radius:0!important;transform:none!important;z-index:1055!important}
.panel_m.panel{position:relative!important;overflow:hidden!important;isolation:isolate!important;background:rgba(252,251,248,.62)!important}
.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{position:absolute!important;inset:0!important;top:0!important;right:0!important;bottom:0!important;left:0!important;width:100%!important;min-width:0!important;max-width:100%!important;height:100%!important;min-height:100%!important;max-height:none!important;z-index:0!important;pointer-events:none!important;background-image:linear-gradient(rgba(252,251,248,.86),rgba(252,251,248,.86)),url('<?= statH(statAssetUrl('/assets/img/bg-intro.png')) ?>')!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,contain!important;filter:saturate(.62) contrast(.84) blur(.12px)!important;contain:paint!important;opacity:.22;transform:none}
@keyframes ngixFogDrift{0%,100%{transform:translate3d(0,0,0) scale(1.015);opacity:.22}50%{transform:translate3d(0.6%,-0.4%,0) scale(1.015);opacity:.26}}
@media (prefers-reduced-motion:no-preference){.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{animation:ngixFogDrift 28s ease-in-out infinite}}
.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body,.panel_m.panel>.table-responsive,.panel_m.panel>form{position:relative!important;z-index:2!important}
.table-responsive{max-width:100%!important;overflow-x:auto!important;overflow-y:visible!important}
@supports (height:100lvh){body{min-height:100lvh!important}}
@media (prefers-color-scheme:dark){html{background:var(--graphite)!important}body{background:linear-gradient(rgba(37,42,46,.78),rgba(37,42,46,.88)),url('/assets/img/favicon.svg') right 14px bottom 12px/28px 28px no-repeat fixed,url('/assets/img/bg-intro.png') center center/cover no-repeat fixed,var(--graphite)!important}.panel_m.panel{background:rgba(37,42,46,.72)!important}.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{background-image:linear-gradient(rgba(37,42,46,.84),rgba(37,42,46,.84)),url('<?= statH(statAssetUrl('/assets/img/bg-intro.png')) ?>')!important;filter:saturate(.58) contrast(.78) blur(.16px)!important;opacity:.20}}
@media screen and (max-width:768px){body{background-position:0 0,right 10px bottom 10px,center center!important;background-size:auto,24px 24px,cover!important}.navbar.navbar-fixed-top,.navbar-fixed-top{width:100%!important}.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{background-size:100% 100%,contain!important;background-position:center center,center center!important;opacity:.18}}
/* NGIX patch: enable right-click + remove dropdown blue highlight */
html,
body {
    -webkit-touch-callout: default !important;
    -webkit-tap-highlight-color: transparent !important;
}

button,
.btn,
a,
.navbar-nav > li > a,
.dropdown-toggle,
.dropdown-menu > li > a,
.rt-period-toggle,
.rt-period-menu > li > a,
.pc-nav-toggle,
.pc-nav-menu > li > a {
    -webkit-tap-highlight-color: transparent !important;
    outline: none !important;
    box-shadow: none !important;
}

.dropdown-menu,
.dropdown-menu *,
.rt-period-menu,
.rt-period-menu *,
.pc-nav-menu,
.pc-nav-menu * {
    -webkit-user-select: none !important;
    user-select: none !important;
}

input,
textarea,
select,
code,
pre,
table,
.table,
.td-url,
.td-tracker,
.td-subdomain,
.td-pass,
.pc-country {
    -webkit-user-select: text !important;
    user-select: text !important;
}

.dropdown-menu > li > a:hover,
.dropdown-menu > li > a:focus,
.dropdown-menu > li > a:active,
.dropdown-menu > .active > a,
.dropdown-menu > .active > a:hover,
.dropdown-menu > .active > a:focus,
.rt-period-menu > li > a:hover,
.rt-period-menu > li > a:focus,
.rt-period-menu > li > a:active,
.pc-nav-menu > li > a:hover,
.pc-nav-menu > li > a:focus,
.pc-nav-menu > li > a:active {
    background: var(--panel-soft) !important;
    color: var(--text-strong) !important;
    outline: none !important;
    box-shadow: none !important;
}

.btn:focus,
.btn:active,
button:focus,
button:active,
a:focus,
a:active,
.dropdown-toggle:focus,
.dropdown-toggle:active {
    outline: none !important;
    box-shadow: none !important;
}

::selection {
    background: rgba(37,42,46,.14);
    color: inherit;
}

::-moz-selection {
    background: rgba(37,42,46,.14);
    color: inherit;
}

/*
 * Mobile: reflow #userlead from a wide table into one compact card per row,
 * everything on a single line so the grid never needs left/right scrolling
 * on a phone:
 *   #1  userid  [network icon]  [country flag] US  [traffic icon]  $earning
 * ID is the only field allowed to shrink/ellipsis — everything else (icons,
 * the row number, the earning figure) keeps its natural width so the line
 * never needs to wrap or scroll.
 * IPADDRESS (column 7) is dropped from this view — not part of the scheme.
 */
@media screen and (max-width: 768px) {
    #userlead thead {
        display: none;
    }

    #userlead,
    #userlead tbody {
        display: block;
        width: 100%;
    }

    /* overflow-x:auto (not hidden) is a safety net, not an intended scroll:
       in the normal case content fits and nothing is scrollable/visible as a
       scrollbar. It only activates if a row genuinely can't fit at 14px —
       otherwise the trailing field (earning) would get silently clipped
       instead, which is worse than an occasional few px of scroll. */
    #userlead tr {
        display: flex;
        flex-wrap: nowrap;
        align-items: center;
        column-gap: 4px;
        margin-bottom: 6px;
        padding: 6px 4px 6px 6px;
        border: 1px solid var(--line);
        border-radius: var(--radius);
        background: var(--panel);
        overflow-x: auto;
        overflow-y: hidden;
        scrollbar-width: none;
    }

    #userlead tr::-webkit-scrollbar {
        display: none;
    }

    /* width/min-width/max-width forced back to auto: bootgrid sets an inline
       style="width:...px" per <td> for the desktop grid, and an inline width
       becomes a flex item's used flex-basis (spec: flex-basis:auto falls
       back to the width property when it isn't auto) — without this, icon
       cells inherit their wide desktop column width and leave a dead gap
       before the card's right edge instead of the group hugging it. */
    #userlead td {
        display: inline-flex !important;
        align-items: center;
        justify-content: flex-end;
        gap: 2px;
        padding: 0 !important;
        border: 0 !important;
        white-space: nowrap;
        font-family: "Roboto Mono", ui-monospace, monospace;
        font-size: 14px;
        flex: 0 0 auto;
        width: auto !important;
        min-width: 0 !important;
        max-width: none !important;
        text-align: right;
    }

    #userlead td:nth-child(1) {
        font-weight: var(--fw-semibold);
        color: var(--text-strong);
    }

    #userlead td:nth-child(1)::before {
        content: "#";
    }

    /* Reclaim a bit more width for this specific tight single-line layout —
       device/network icons only, scoped to #userlead so the 14px size kept
       elsewhere (desktop grid, live notification feed) is untouched. */
    #userlead .rt-device-ico,
    #userlead .rt-icon {
        width: 12px !important;
        height: 12px !important;
    }

    /* Separator only before ID and country — not before #1 (starts the
       line), IPADDRESS (hidden), the icon-only network/traffic cells, or
       earning (a $ figure already reads as its own field; dropping this
       last separator reclaims just enough width to stop it clipping). */
    #userlead td:nth-child(2)::before,
    #userlead td:nth-child(4)::before {
        content: "\B7";
        margin-right: 3px;
        color: var(--line);
        font-weight: var(--fw-regular);
    }

    /* Keep #1 pinned left. Push the visual group from the ID/star cell
       through the device/traffic cell to the right, immediately before
       EARNING. This is mobile-only and does not change table data/order. */
    #userlead tr {
        justify-content: flex-start;
    }

    #userlead td:nth-child(2) {
        margin-left: auto !important;
        flex: 0 0 auto !important;
    }

    #userlead td:nth-child(3),
    #userlead td:nth-child(4),
    #userlead td:nth-child(5) {
        flex: 0 0 auto !important;
    }

    #userlead td:nth-child(6) {
        flex: 0 0 auto !important;
        margin-left: 2px !important;
        font-weight: var(--fw-bold);
    }

    /* IPADDRESS isn't part of this scheme — hide it on the mobile card. */
    #userlead td:nth-child(7) {
        display: none !important;
    }

    #userlead tfoot,
    #userlead tfoot tr {
        display: block;
        width: 100%;
    }

    #userlead tfoot th {
        display: block !important;
        text-align: right;
        padding: 8px 10px !important;
    }
}
</style>
<script src="<?= statH(statAssetUrl('/assets/js/stat-realtime.js')) ?>" nonce="<?= rtH($rtNonce) ?>"></script>
</body>
</html>
