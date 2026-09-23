<?php

declare(strict_types=1);

include_once '../login.php';

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

$rtNonce = bin2hex(random_bytes(16));

function pnSendSecurityHeaders(string $nonce = ''): void
{
    if (headers_sent()) {
        return;
    }

    header_remove('Content-Security-Policy');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

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
        "script-src 'self' 'nonce-{$nonce}' https://cdn.datatables.net https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net",
        "script-src-elem 'self' 'nonce-{$nonce}' https://cdn.datatables.net https://cdnjs.cloudflare.com https://unpkg.com https://cdn.jsdelivr.net",
        "connect-src 'self' https:",
    ]);

    header('Content-Security-Policy: ' . $csp);
}

function pnEnsureSession(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function pnH(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function pnCsrfToken(): string
{
    pnEnsureSession();

    if (
        !isset($_SESSION['pn_csrf_token'])
        || !is_string($_SESSION['pn_csrf_token'])
        || $_SESSION['pn_csrf_token'] === ''
    ) {
        $_SESSION['pn_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['pn_csrf_token'];
}

function pnVerifyCsrf(?string $token): bool
{
    pnEnsureSession();

    if (!is_string($token) || $token === '') {
        return false;
    }

    if (!isset($_SESSION['pn_csrf_token']) || !is_string($_SESSION['pn_csrf_token'])) {
        return false;
    }

    return hash_equals($_SESSION['pn_csrf_token'], $token);
}

function pnHandleLogout(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
    if ($action !== 'logout') {
        return;
    }

    if (!pnVerifyCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        echo 'Invalid CSRF token.';
        exit;
    }

    pnEnsureSession();
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            (string) session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => isset($params['path']) ? (string) $params['path'] : '/',
                'domain' => isset($params['domain']) ? (string) $params['domain'] : '',
                    'secure' => statIsHttpsRequest(),
                'httponly' => true,
                'samesite' => 'Strict',
            ],
        );
    }

    session_destroy();
    header('Location: ' . statUrl('/performance/'));
    exit;
}

function normalizeDate(string $input): ?string
{
    $input = trim($input);

    if ($input === '') {
        return null;
    }

    $dateTime = DateTime::createFromFormat('Y-m-d', $input);
    if (!$dateTime instanceof DateTime) {
        return null;
    }

    $errors = DateTime::getLastErrors();
    if ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0)) {
        return null;
    }

    return $dateTime->format('Y-m-d');
}

function pnSafeFileNameDate(string $value): string
{
    return preg_replace('/[^0-9\-]/', '', $value) ?? '';
}

/**
 * Fetch aggregated conversion rows for a date range, honoring the report scope.
 * Shared by the AJAX loader and the no-JS server-render fallback so both resolve
 * the same rows by the same rule.
 *
 * @return list<array{id:int,click_id:string,clicks:int,leads:int,payout:string,cr:string}>
 */
function pnFetchConversions(PDO $pdo, string $start, string $end): array
{
    $scope    = stat_scope_sub_id();
    $scopeSql = $scope !== null ? ' AND click_id = :scope' : '';

    $sql = '
        SELECT
            click_id,
            SUM(clicks) AS clicks,
            SUM(leads) AS leads,
            SUM(payout) AS payout,
            MAX(click_date) AS last_click_date
        FROM clickrecord
        WHERE click_date BETWEEN :start AND :end' . $scopeSql . '
        GROUP BY click_id
        ORDER BY payout DESC, last_click_date DESC, click_id ASC
    ';

    $params = ['start' => $start, 'end' => $end];
    if ($scope !== null) {
        $params['scope'] = $scope;
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    $rows = [];
    $index = 1;
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $clicks = (int) ($row['clicks'] ?? 0);
        $leads = (int) ($row['leads'] ?? 0);
        $payout = (float) ($row['payout'] ?? 0.0);
        $cr = $clicks > 0 ? round(($leads / $clicks) * 100, 2) : 0.0;
        $clickId = strtoupper(preg_replace('/[^A-Za-z0-9_\-]/', '', (string) ($row['click_id'] ?? '')) ?? '');

        $rows[] = [
            'id' => $index,
            'click_id' => $clickId,
            'clicks' => $clicks,
            'leads' => $leads,
            'payout' => number_format($payout, 2, '.', ''),
            'cr' => number_format($cr, 2, '.', ''),
        ];

        $index++;
    }

    return $rows;
}

pnSendSecurityHeaders($rtNonce);
pnHandleLogout();

$today = gmdate('Y-m-d'); // UTC: match click_date stored in UTC (see INSTALL §F / click_date policy)
$start = $today;
$end = $today;
$data = ['data' => []];
$statusMessage = '';
$statusType = '';

// AJAX conversion load: return rows as JSON so the "Load Conversions" button and
// the first-open auto-load refresh the table without reloading the page. The no-JS
// <form> POST below still server-renders the same rows as a fallback.
if (($_POST['action'] ?? '') === 'load') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    if (!pnVerifyCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        echo json_encode(['ok' => false, 'error' => 'invalid-csrf']);
        exit;
    }

    $ajStart = normalizeDate((string) ($_POST['start'] ?? '')) ?? $today;
    $ajEnd   = normalizeDate((string) ($_POST['end'] ?? '')) ?? $today;
    if ($ajStart > $ajEnd) {
        http_response_code(422);
        echo json_encode(['ok' => false, 'error' => 'invalid-range']);
        exit;
    }

    try {
        $rows = pnFetchConversions($pdo, $ajStart, $ajEnd);
    } catch (Throwable $e) {
        error_log('[statistics/performance] ajax query failed: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'server-error']);
        exit;
    }

    echo json_encode(['ok' => true, 'start' => $ajStart, 'end' => $ajEnd, 'data' => $rows]);
    exit;
}

if (isset($_POST['click'], $_POST['start'], $_POST['end'])) {
    try {
        if (!pnVerifyCsrf($_POST['csrf_token'] ?? null)) {
            throw new RuntimeException('Invalid CSRF token.');
        }

        $start = normalizeDate((string) $_POST['start']) ?? $today;
        $end = normalizeDate((string) $_POST['end']) ?? $today;

        if ($start > $end) {
            throw new InvalidArgumentException('Invalid date range.');
        }

        $data['data'] = pnFetchConversions($pdo, $start, $end);
    } catch (Throwable $e) {
        error_log('[statistics/performance] query failed: ' . $e->getMessage());
        $statusType = 'error';
        if ($e instanceof RuntimeException && $e->getMessage() === 'Invalid CSRF token.') {
            $statusMessage = 'Invalid CSRF token.';
        } elseif ($e instanceof InvalidArgumentException && $e->getMessage() === 'Invalid date range.') {
            $statusMessage = 'Invalid date range.';
        } else {
            $statusMessage = 'Request failed.';
        }
    }
}

include_once '../header.php';
?>
<style nonce="<?= pnH($rtNonce) ?>">
:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--bg:var(--porcelain);--light:var(--porcelain);--surface:var(--porcelain);--panel2:var(--paper);--panel-soft:var(--paper);--panel-raised:var(--panel);--panel-fade:rgba(252, 251, 248, 0.7);--nav:var(--paper);--line:var(--soft-steel);--line2:var(--border);--line-soft:var(--border);--stroke:var(--soft-steel);--text:var(--graphite);--btn:var(--graphite);--primary:var(--graphite);--primary2:var(--ink);--text-strong:var(--ink);--strong:var(--ink);--dark:var(--ink);--muted:var(--steel-gray);--accent:var(--burnt-copper);--accent-h:#8f5236;--accent-hover:#8f5236;--accent-s:var(--burnt-copper-soft);--accent-soft:var(--burnt-copper-soft);--on:var(--paper);--on-accent:var(--paper);--good:var(--graphite);--ok:var(--graphite);--success:var(--graphite);--ok-soft:var(--burnt-copper-soft);--success-soft:var(--burnt-copper-soft);--bad:var(--burnt-copper);--danger:var(--burnt-copper);--danger-soft:var(--burnt-copper-soft);--warn:var(--steel-gray);--blue-soft:var(--burnt-copper-soft);--blue-line:rgba(168, 100, 66, 0.28);--shadow-modal:var(--shadow);--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}@media (prefers-color-scheme:dark){}*{box-sizing:border-box}html,body{width:100%;height:100dvh;margin:0;}html{background:var(--bg);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}body{font-family:var(--font);padding:58px 8px 18px!important;background:radial-gradient(circle at 50% 8%,rgba(168,100,66,.12),transparent 28rem),radial-gradient(circle at 10% 80%,rgba(22,25,28,.06),transparent 22rem),var(--porcelain)!important;color:var(--text)!important;font-family:var(--mono)!important;font-size:var(--fs-base);line-height:var(--lh-normal);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}a{color:inherit;text-decoration:none}.container{width:100%;max-width:1180px;margin:0 auto}code{font-family:var(--mono);font-size:var(--fs-sm);color:var(--text);background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:var(--paper)!important;box-shadow:var(--shadow)!important}.navbar .container{max-width:1180px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:var(--fs-base);line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;line-height:20px!important;color:var(--text)!important;font-size:var(--fs-sm)}.navbar-nav>li>a:hover,.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:focus,.navbar-default .navbar-nav>.active>a:hover{background:var(--accent)!important;color:var(--on-accent)!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.panel,.panel-default,.well,.modal-content{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading,.panel-footer,.modal-header,.modal-footer{padding:8px 10px!important;background:var(--porcelain)!important;border:0!important;color:var(--text-strong)!important}.panel-body,.modal-body{padding:10px!important;background:transparent!important;color:var(--text)!important}.pull-right{display:flex;align-items:center;gap:6px}.modal-content{box-shadow:var(--shadow-modal)!important}.modal-title{font-size:var(--fs-md);font-weight:var(--fw-bold);color:var(--text-strong)}.close{color:var(--text)!important;opacity:.78;text-shadow:none}.form-group{margin-bottom:8px}.control-label,label{margin-bottom:4px;color:var(--text-strong);font-size:var(--fs-sm)}.form-control,input[type=text],input[type=number],input[type=password],input[type=search],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;box-shadow:none!important; }.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;border-color:#444746!important;box-shadow:none!important}.form-control::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control[readonly],input[readonly],textarea[readonly]{background:var(--panel-soft)!important;color:var(--text)!important}textarea.form-control{height:auto;min-height:114px;resize:none}.input-group-addon{height:31px;padding:5px 8px;background:transparent!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:var(--fs-sm)}.btn,button,.btn-sm,.btn-xs{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm);font-weight:var(--fw-bold);line-height:var(--lh-tight);box-shadow:none!important;outline:none;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active,.btn.active{background:var(--btn-bg)!important;border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.btn-primary:hover{background:var(--btn-bg)!important;filter:brightness(1.18);border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(102,113,122,.16)!important;color:var(--danger)!important}.glyphicon{top:1px;color:currentColor}.action-ico{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.action-ico svg{display:block}.table-responsive{border:0!important}.table{width:100%;margin:4px 0 0;border-collapse:separate;border-spacing:0;border:0;border-radius:var(--radius);overflow:hidden;background:var(--panel)!important}.table>thead>tr>th{position:sticky;top:0;z-index:20;padding:7px 8px!important;border-bottom:1px solid var(--line)!important;background:var(--porcelain)!important;color:var(--text-strong)!important;font-size:var(--fs-xs)!important;line-height:var(--lh-tight);text-transform:uppercase;letter-spacing:.035em;white-space:nowrap}.table>tbody>tr>td{padding:6px 8px!important;border-top:1px solid var(--line-soft)!important;color:var(--text);font-size:var(--fs-sm);vertical-align:middle;word-break:break-word;background:var(--panel)!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.bootgrid-table th>.column-header-anchor{color:var(--text-strong)!important}.bootgrid-header,.bootgrid-footer{margin:6px 0!important;color:var(--text)!important}.bootgrid-header .search .form-control{height:31px}.bootgrid-header .actionBar{text-align:right}.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.dropdown-menu{border:0!important;border-radius:var(--radius)!important;background:var(--paper)!important;box-shadow:var(--shadow-modal)!important}.dropdown-menu>li>a{color:var(--text)!important;font-size:var(--fs-sm)}.dropdown-menu>li>a:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.alert{border-radius:var(--radius)!important}.alert-danger,.error{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.28)!important;color:var(--danger)!important}.alert-success,.success{background:var(--blue-soft)!important;border-color:var(--blue-line)!important;color:var(--text)!important}.label{border-radius:var(--radius)!important}.label-default{background:var(--panel-soft)!important;color:var(--text)!important;border:1px solid var(--line)}blockquote{margin:0 0 10px;padding:7px 10px;border-left:2px solid var(--line)!important;background:var(--panel-fade);border-radius:var(--radius);font-size:var(--fs-sm)}.text-warning{margin:0 0 2px;color:var(--text-strong)!important;font-weight:var(--fw-bold)}.text-muted{color:var(--text)!important}.flag{border-radius:var(--radius)}.admin-toast-root{position:fixed;right:12px;bottom:12px;z-index:10050;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.admin-toast{font-family:var(--mono);max-width:340px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm);line-height:var(--lh-snug)}.admin-toast strong{display:block;margin-bottom:2px;color:var(--text-strong)}.admin-toast--error{border-color:rgba(102,113,122,.34);background:var(--danger-soft);color:var(--danger)}.admin-toast--success{border-color:var(--blue-line);background:var(--blue-soft);color:var(--text)}.admin-fallback-backdrop{position:fixed;inset:0;z-index:10040;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(37,42,46,.36)}.admin-fallback-dialog{width:min(420px,100%);border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.admin-fallback-head{padding:10px;border-bottom:1px solid var(--line-soft);font-weight:var(--fw-bold);color:var(--text-strong);background:var(--porcelain)}.admin-fallback-body{padding:10px;font-size:var(--fs-sm)}.admin-fallback-actions{display:flex;gap:6px;justify-content:flex-end;padding:10px;border-top:1px solid var(--line-soft);background:var(--porcelain)}@media screen and (max-width:768px){body{padding:58px 6px 12px!important;font-size:var(--fs-base)}.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px!important;background:var(--porcelain)!important}.navbar .container{padding-left:8px!important;padding-right:8px!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}.pull-right{float:none!important;justify-content:flex-end}.input-group{display:block}.input-group>.form-control,.input-group>.input-group-addon,.input-group>.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.input-group-addon{border-bottom:0!important;border-radius:var(--radius) var(--radius) 0 0!important}.input-group>.form-control{border-radius:0 0 var(--radius) var(--radius)!important}.input-group-btn>.btn{margin-top:5px}.table{display:block;overflow-x:auto;white-space:nowrap}.modal-dialog{width:auto!important;margin:8px}}#tbl_trackers{table-layout:fixed;width:100%;min-width:800px}#tbl_trackers th:nth-child(1),#tbl_trackers td:nth-child(1){width:50px;text-align:center;padding-left:4px!important;padding-right:4px!important}#tbl_trackers th:nth-child(2),#tbl_trackers td:nth-child(2){width:120px}#tbl_trackers th:nth-child(3),#tbl_trackers td:nth-child(3){width:120px}#tbl_trackers th:nth-child(5),#tbl_trackers td:nth-child(5){width:120px}.td-num{display:block;font-size:var(--fs-sm);font-weight:var(--fw-semibold);font-family:var(--mono);color:color-mix(in srgb,var(--text) 44%,transparent);text-align:center}.td-tracker{display:inline-block;width:100%;padding:2px 8px;border-radius:.3rem;border:1px solid var(--line);background:var(--panel-soft);font-family:var(--mono);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.03em;white-space:nowrap}.td-subdomain{display:inline-block;padding:2px 8px;border-radius:.3rem!important;width:100%;border:1px solid var(--line);background:var(--panel-soft);font-family:var(--mono);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.03em;white-space:nowrap}.td-url{display:block;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono);font-size:var(--fs-sm)}.td-pass{font-family:var(--mono);font-size:var(--fs-sm);color:color-mix(in srgb,var(--text) 60%,transparent)}
/* bootgrid toolbar search/select fix */.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{background:color-mix(in srgb,var(--accent) 5%,transparent)!important;color:var(--text-strong)!important;box-shadow:none!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:none!important}.panel,.panel-default{overflow:visible!important}.panel-body{overflow:visible!important}.table-responsive{overflow-x:auto!important;overflow-y:visible!important}.bootgrid-header{position:relative!important;z-index:80!important;display:block!important;margin:8px 0 7px!important;color:var(--text)!important}.bootgrid-header .actionBar{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;float:none!important;width:100%!important;margin:0!important;text-align:right!important;white-space:nowrap!important}.bootgrid-header .search{position:relative!important;display:inline-flex!important;align-items:center!important;float:none!important;width:220px!important;min-width:220px!important;max-width:260px!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .search .input-group{display:flex!important;align-items:stretch!important;width:100%!important;border-collapse:separate!important}.bootgrid-header .search .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:32px!important;padding:0!important;border:1px solid var(--line)!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important}.bootgrid-header .search .input-group-addon .glyphicon{top:0!important;font-size:var(--fs-sm)!important}.bootgrid-header .search .search-field,.bootgrid-header .search .form-control{display:block!important;flex:1 1 auto!important;width:100%!important;height:32px!important;min-height:32px!important;padding:5px 9px!important;border:1px solid var(--line)!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{border-color:var(--accent)!important;border-left:0!important;box-shadow:none!important}.bootgrid-header .actions{position:relative!important;display:inline-flex!important;align-items:center!important;gap:6px!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions>.btn-group{position:relative!important;display:inline-flex!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions .btn,.bootgrid-header .actions .dropdown-toggle{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:6px!important;height:32px!important;min-width:38px!important;padding:5px 10px!important;line-height:var(--lh-tight)!important;border-radius:var(--radius)!important}.bootgrid-header .actions .dropdown-toggle{min-width:64px!important}.bootgrid-header .actions .dropdown-toggle .caret{margin-left:2px!important}.bootgrid-header .actions .dropdown-menu{position:absolute!important;top:calc(100% + 4px)!important;right:0!important;left:auto!important;z-index:3000!important;display:none;min-width:112px!important;width:112px!important;margin:0!important;padding:4px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--paper)!important;box-shadow:var(--shadow-modal)!important;list-style:none!important}.bootgrid-header .actions .open>.dropdown-menu{display:block!important}.bootgrid-header .actions .dropdown-menu>li{display:block!important;float:none!important;width:100%!important;margin:0!important;padding:0!important;text-align:left!important}.bootgrid-header .actions .dropdown-menu>li>a{display:block!important;width:100%!important;min-width:0!important;padding:6px 9px!important;border-radius:var(--radius)!important;background:transparent!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-tight)!important;text-align:left!important;white-space:nowrap!important}.bootgrid-header .actions .dropdown-menu>li>a:hover,.bootgrid-header .actions .dropdown-menu>li>a:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.bootgrid-header .actions .dropdown-menu>.active>a,.bootgrid-header .actions .dropdown-menu>.active>a:hover,.bootgrid-header .actions .dropdown-menu>.active>a:focus{background:var(--accent-soft)!important;color:var(--text-strong)!important;box-shadow:none!important}.bootgrid-footer{position:relative!important;z-index:20!important}.bootgrid-footer .pagination{margin:0!important}@media screen and (max-width:768px){.bootgrid-header .actionBar{align-items:stretch!important;justify-content:stretch!important;flex-wrap:wrap!important;gap:6px!important}.bootgrid-header .search{width:100%!important;min-width:0!important;max-width:none!important;flex:1 0 100%!important}.bootgrid-header .actions{margin-left:auto!important}.bootgrid-header .actions .dropdown-menu{right:0!important;left:auto!important}}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
/* final action icon render fix */#tbl_trackers th:last-child,#tbl_trackers td:last-child{text-align:center!important;white-space:nowrap!important;width:108px!important;min-width:108px!important;max-width:108px!important}.bootgrid-table td:last-child{overflow:visible!important}.action-btn,.bootgrid-table .command-edit,.bootgrid-table .command-delete{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:32px!important;height:26px!important;min-width:32px!important;min-height:26px!important;padding:0!important;margin:0 2px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:0!important;line-height:1!important;text-indent:0!important;vertical-align:middle!important;opacity:1!important;visibility:visible!important;box-shadow:none!important;overflow:visible!important}.action-btn:hover,.bootgrid-table .command-edit:hover{background:var(--accent-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.bootgrid-table .command-delete{color:var(--danger)!important}.bootgrid-table .command-delete:hover{background:var(--danger-soft)!important;border-color:color-mix(in srgb,var(--danger) 34%,var(--line))!important;color:var(--danger)!important}.bootgrid-table .command-edit[disabled],.bootgrid-table .command-delete[disabled]{opacity:.58!important;cursor:not-allowed!important}.action-btn .action-ico,.bootgrid-table .command-edit .action-ico,.bootgrid-table .command-delete .action-ico{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;color:currentColor!important;opacity:1!important;visibility:visible!important;overflow:visible!important;pointer-events:none!important}.action-btn svg,.bootgrid-table .command-edit svg,.bootgrid-table .command-delete svg{display:block!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;overflow:visible!important;color:currentColor!important;opacity:1!important;visibility:visible!important;pointer-events:none!important}.action-btn svg *,.bootgrid-table .command-edit svg *,.bootgrid-table .command-delete svg *{vector-effect:non-scaling-stroke!important;stroke:currentColor!important;stroke-width:2!important;stroke-linecap:round!important;stroke-linejoin:round!important;fill:none!important;opacity:1!important;visibility:visible!important}.btn-icon svg,.btn-primary svg{display:block!important;width:13px!important;height:13px!important;fill:currentColor!important;color:currentColor!important;opacity:1!important;visibility:visible!important}.pn-date-field .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;color:var(--text)!important;opacity:1!important;visibility:visible!important}.pn-date-field .input-group-addon svg{display:block!important;width:18px!important;height:18px!important;min-width:18px!important;min-height:18px!important;overflow:visible!important;color:currentColor!important;opacity:1!important;visibility:visible!important}.pn-date-field .input-group-addon svg *{stroke:currentColor!important;fill:none!important;opacity:1!important;visibility:visible!important}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
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
.panel_m{margin-top:4px}.panel-heading .panel-title{gap:10px}.panel-heading .searchbox{display:flex!important;align-items:stretch!important;flex:1 1 auto!important;max-width:520px!important;width:100%!important}.panel-heading .searchbox>.input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:31px!important;padding:0!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important}.panel-heading .searchbox>.form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;border-left:0!important;border-right:0!important;border-radius:0!important}.panel-heading .searchbox>.input-group-btn{display:flex!important;flex:0 0 auto!important;width:auto!important}.panel-heading .searchbox>.input-group-btn>.btn{height:31px!important;margin:0!important;border-radius:0 var(--radius) var(--radius) 0!important;white-space:nowrap!important}.pre-colon{font-weight:var(--fw-bold);color:var(--text-strong)}.post-colon{font-family:var(--mono);color:var(--text)}#notifications{position:fixed;right:12px;bottom:12px;z-index:10060;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.notice{max-width:420px;padding:8px 10px;border:1px solid var(--blue-line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm);line-height:var(--lh-snug)}.notice .close{float:right;margin-left:8px;width:14px;height:14px;border:0!important;border-radius:var(--radius)!important;background:var(--panel-soft)!important}#logout-toast{position:fixed;right:12px;bottom:12px;z-index:10070;display:none;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm)}#logout-toast.show{display:block}.navbar-btn.btn-link{margin:0!important;border:0!important;background:transparent!important;box-shadow:none!important}@media screen and (max-width:768px){.panel-heading .panel-title{display:block!important}.panel-heading .searchbox{max-width:none!important}.panel-heading .searchbox>.input-group-addon,.panel-heading .searchbox>.form-control,.panel-heading .searchbox>.input-group-btn,.panel-heading .searchbox>.input-group-btn>.btn{display:flex!important;width:auto!important}.panel-heading .searchbox>.form-control{flex:1 1 auto!important}.panel-heading .searchbox>.input-group-btn>.btn{margin-top:0!important}.navbar-btn.btn-link{padding:12px 10px!important}.table{width:100%!important}}
/* performance-network local alignment */.pn-filter-form{display:flex;align-items:stretch;gap:8px;margin:0 0 8px;flex-wrap:wrap}.pn-filter-form .pn-date-field{flex:1 1 220px;min-width:180px;padding:0}.pn-filter-form .input-group{width:100%;display:flex!important;align-items:stretch!important}.pn-filter-form .form-control{border-radius:var(--radius) 0 0 var(--radius)!important}.pn-filter-form .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important}.pn-filter-form .btn{height:31px;align-self:stretch}.pn-toolbar{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}.pn-toolbar .searchbox{flex:1 1 280px;margin:0!important}.pn-toolbar .input-group{display:flex!important;width:100%!important}.pn-toolbar .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important}.pn-toolbar .form-control{flex:1 1 auto!important;width:auto!important;border-left:0!important;border-right:0!important;border-radius:0!important}.pn-toolbar .input-group-btn{display:flex!important;flex:0 0 auto!important}.pn-toolbar .input-group-btn>.btn{height:31px!important;border-radius:0 var(--radius) var(--radius) 0!important;margin:0!important}.pn-export{display:flex;align-items:center;justify-content:flex-end;gap:6px;flex:0 0 auto}.pn-empty{padding:12px!important;text-align:center!important;color:var(--text)!important;background:var(--panel)!important}.rg-source .pre-colon{font-weight:var(--fw-bold);color:var(--text-strong)}.rg-source .post-colon{font-family:var(--mono);color:var(--text)}#logout-toast{position:fixed;right:12px;bottom:12px;z-index:10060;display:none;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm)}#logout-toast.show{display:block}.navbar-btn.btn-link{height:44px!important;margin:0!important;padding:12px 10px!important;border:0!important;background:transparent!important;color:var(--text)!important;text-decoration:none!important}.navbar-btn.btn-link:hover{background:transparent!important;color:var(--text-strong)!important}@media screen and (max-width:768px){.pn-filter-form{display:flex!important;gap:6px}.pn-filter-form .pn-date-field{flex:1 1 100%;width:100%;min-width:0}.pn-filter-form .input-group{display:flex!important}.pn-filter-form .input-group>.form-control{width:auto!important;border-radius:var(--radius) 0 0 var(--radius)!important}.pn-filter-form .input-group>.input-group-addon{width:34px!important;border-bottom:1px solid var(--line)!important;border-radius:0 var(--radius) var(--radius) 0!important}.pn-filter-form .btn{width:100%!important}.pn-toolbar{align-items:stretch}.pn-toolbar .searchbox{flex:1 1 100%}.pn-toolbar .input-group{display:flex!important}.pn-toolbar .input-group>.form-control{width:auto!important;border-radius:0!important}.pn-toolbar .input-group>.input-group-addon{width:34px!important;border-bottom:1px solid var(--line)!important;border-radius:var(--radius) 0 0 var(--radius)!important}.pn-toolbar .input-group-btn{width:auto!important}.pn-toolbar .input-group-btn>.btn{width:auto!important;margin-top:0!important;border-radius:0 var(--radius) var(--radius) 0!important}.pn-export{width:100%;justify-content:flex-end}.table{display:block;overflow-x:auto;white-space:nowrap}}
/* refresh/search input-group hard fix */.pn-toolbar{align-items:flex-start!important}.pn-toolbar .searchbox{display:block!important;flex:1 1 540px!important;max-width:540px!important;min-width:280px!important}.pn-toolbar .searchbox .input-group{display:flex!important;align-items:stretch!important;width:100%!important;border-collapse:separate!important}.pn-toolbar .searchbox .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;height:31px!important;padding:0!important;border:1px solid var(--line)!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel-soft)!important}.pn-toolbar .searchbox .form-control{display:block!important;flex:1 1 auto!important;width:auto!important;min-width:0!important;height:31px!important;border:1px solid var(--line)!important;border-left:0!important;border-right:0!important;border-radius:0!important}.pn-toolbar .searchbox .input-group-btn{display:flex!important;align-items:stretch!important;flex:0 0 auto!important;width:auto!important;min-width:0!important;white-space:nowrap!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:5px!important;width:auto!important;min-width:84px!important;height:31px!important;margin:0!important;padding:0 10px!important;border:1px solid var(--line)!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--panel)!important;color:var(--text)!important;white-space:nowrap!important;overflow:hidden!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn:hover{background: var(--panel-soft) !important;color: var(--text-strong) !important;}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn img{flex:0 0 auto!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn strong{display:inline!important;line-height:1!important}.pn-export{padding-top:0!important}@media screen and (max-width:768px){.pn-toolbar .searchbox{flex:1 1 100%!important;max-width:none!important;min-width:0!important}.pn-toolbar .searchbox .input-group{display:flex!important;flex-wrap:nowrap!important}.pn-toolbar .searchbox .input-group-addon{flex:0 0 32px!important;width:32px!important}.pn-toolbar .searchbox .input-group-btn{flex:0 0 auto!important;width:auto!important}.pn-toolbar .searchbox .input-group-btn>.pn-refresh-btn{width:auto!important;min-width:76px!important;margin:0!important}}
:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}.table>tbody>tr>td{font-family:var(--mono)!important;font-size:var(--fs-sm)!important}.form-control,input,select,textarea,.btn,button{font-family:var(--mono)!important;font-size:var(--fs-sm)!important}

/* performance network earning sort + numeric alignment */
#userlead th:nth-child(1),
#userlead td:nth-child(1){
  text-align:left!important;
  font-variant-numeric:tabular-nums;
}

#userlead th:nth-child(3),
#userlead td:nth-child(3),
#userlead th:nth-child(4),
#userlead td:nth-child(4),
#userlead th:nth-child(5),
#userlead td:nth-child(5),
#userlead th:nth-child(6),
#userlead td:nth-child(6){
  text-align:left!important;
  font-variant-numeric:tabular-nums;
  white-space:nowrap!important;
}

#userlead th:nth-child(6),
#userlead td:nth-child(6){
  min-width:110px!important;
}
.bottom {
    padding-top: 0px!important;
}
.app-sign{text-align:right;padding:3px 0 2px}.app-sign footer{font-family:var(--mono);text-decoration:none;letter-spacing:.09em;font-size:10px;font-weight:900;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;user-select:none;text-transform:uppercase;-webkit-user-select:none}select hr{border:none;border-top:1px solid rgba(37,42,46,.06)!important;color:rgba(37,42,46,.06)!important;opacity:.45;margin:1px 4px}input[type=url]{font-family:var(--mono)!important}
/* tighten empty DataTables toolbar gap (search ↔ table) */
#userlead_wrapper .top,#userlead_wrapper .dataTables_length,#userlead_wrapper .dataTables_filter{display:none!important;height:0!important;margin:0!important;padding:0!important}
#userlead_wrapper .searchbox{margin:0!important}
#userlead_wrapper{margin:0!important}
.panel_m .panel-body{padding:0 0 2px!important}
#userlead{margin-top:0!important}
/* footer + rg-source block */
.app-footer{width:100%;max-width:1180px;margin:12px auto 0;padding:7px 8px 3px;border-top:1px solid var(--line-soft);text-align:right;line-height:var(--lh-snug)}
.app-footer .app-sign{padding:0!important;font-family:var(--mono)!important;color:var(--graphite)!important;letter-spacing:.02em!important;line-height:1!important;text-decoration:none;font-size:10px!important;font-weight:900!important;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;text-transform:uppercase;user-select:none;-webkit-user-select:none}
.app-footer .rg-source{margin-top:3px;font-size:var(--fs-xs);color:var(--muted)}
.app-footer .rg-source .pre-colon{font-weight:var(--fw-bold);color:var(--text-strong)}
.app-footer .rg-source .post-colon{font-family:var(--mono);color:var(--text)}
/* ngix xctd image backdrop */
.panel_m.panel{position:relative!important;overflow:hidden!important;isolation:isolate!important;background:rgba(252,251,248,.74)!important}
.panel_m.panel>.ngix-image-backdrop{position:absolute!important;inset:0!important;z-index:0!important;pointer-events:none!important;background-image:linear-gradient(rgba(252,251,248,.82),rgba(252,251,248,.82)),url('<?= statH(statAssetUrl('/dist/bg-intro.png')) ?>')!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,cover!important;opacity:.42!important;filter:saturate(.72) contrast(.86) blur(.22px)!important;transform:translateZ(0)!important}
.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body{position:relative!important;z-index:2!important}
.panel_m.panel>.panel-heading{background:rgba(244,241,236,.82)!important;backdrop-filter:saturate(110%) blur(1px)!important}
.panel_m.panel>.panel-body{background:rgba(252,251,248,.46)!important}
#userlead{position:relative!important;z-index:3!important;background:rgba(252,251,248,.58)!important}
#userlead>thead>tr>th{background:rgba(244,241,236,.86)!important}
#userlead>tbody>tr>td{background:rgba(252,251,248,.34)!important}
#userlead.table-hover>tbody>tr:hover>td{background:rgba(244,241,236,.72)!important}
@media (prefers-color-scheme:dark){.panel_m.panel{background:rgba(37,42,46,.78)!important}.panel_m.panel>.ngix-image-backdrop{background-image:linear-gradient(rgba(37,42,46,.78),rgba(37,42,46,.78)),url('<?= statH(statAssetUrl('/dist/bg-intro.png')) ?>')!important;opacity:.46!important;filter:saturate(.70) contrast(.84) blur(.18px)!important}.panel_m.panel>.panel-heading{background:rgba(37,42,46,.84)!important}.panel_m.panel>.panel-body{background:rgba(37,42,46,.50)!important}#userlead{background:rgba(37,42,46,.50)!important}#userlead>thead>tr>th{background:rgba(37,42,46,.86)!important}#userlead>tbody>tr>td{background:rgba(37,42,46,.34)!important}#userlead.table-hover>tbody>tr:hover>td{background:rgba(37,42,46,.72)!important}}
@media screen and (max-width:768px){.panel_m.panel>.ngix-image-backdrop{background-size:100% 100%,cover!important;background-position:center center,center center!important;opacity:.34!important}}body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none}body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)}</style>
<!-- Fixed navbar -->
<link rel="stylesheet" href="<?= statH(statAssetUrl('/dist/stat-performance-1.css')) ?>">
<nav class="navbar navbar-default navbar-fixed-top">
    <div class="container">
        <div class="navbar-header">
            <button
                type="button"
                class="navbar-toggle collapsed"
                data-toggle="collapse"
                data-target="#navbar"
                aria-expanded="false"
                aria-controls="navbar"
            >
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="#">
                <strong>
                    <img src="<?= statH(statAssetUrl('/dist/ssid.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                    PERFORMANCE NETWORK
                </strong>
            </a>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
            <ul class="nav navbar-nav navbar-right">
                <li>
                    <a href="<?= statH(statUrl('/realtime/?date=rt_1')) ?>">
                        <strong>
                            REALTIME CONVERSION
                            <img src="<?= statH(statAssetUrl('/dist/chart.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                        </strong>
                    </a>
                </li>
                <li>
                    <a>
                        <strong>
                            
                        </strong>
                    </a>
                </li>
                <li class="active">
                    <a href="#">
                        <strong>PERFORMANCE NETWORK</strong>
                        
                    </a>
                </li>
                <li>
                    <form method="post" action="<?= statH(statUrl('/performance/')) ?>" id="logout-form" style="margin:0;">
                        <input type="hidden" name="csrf_token" value="<?= pnH(pnCsrfToken()) ?>">
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
    <?php if ($statusMessage !== '') : ?>
        <div class="alert <?= $statusType === 'error' ? 'alert-danger' : 'alert-success' ?>">
            <?= pnH($statusMessage) ?>
        </div>
    <?php endif; ?>

    <form method="post" id="pn-filter-form" class="pn-filter-form" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= pnH(pnCsrfToken()) ?>">
        <div class="pn-date-field">
            <div class="input-group date" data-date-format="yyyy-mm-dd">
                <input
                    type="text"
                    class="form-control input-sm"
                    name="start"
                    id="start"
                    placeholder="{start date}"
                    autocomplete="off"
                    value="<?= pnH($start) ?>"
                >
                <div class="input-group-addon input-sm">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
                </div>
            </div>
        </div>

        <div class="pn-date-field">
            <div class="input-group date" data-date-format="yyyy-mm-dd">
                <input
                    type="text"
                    class="form-control input-sm"
                    name="end"
                    id="end"
                    placeholder="{end date}"
                    autocomplete="off"
                    value="<?= pnH($end) ?>"
                >
                <div class="input-group-addon input-sm">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
                </div>
            </div>
        </div>

        <button name="click" class="btn btn-default btn-sm" value="1" type="submit">
            <strong>Load Conversions</strong>
        </button>
    </form>

    <div class="panel_m panel panel-default">
        <div class="ngix-image-backdrop" aria-hidden="true"></div>
        <div class="panel-heading">
            <div class="pn-toolbar">
                <div class="form-group search searchbox">
                    <div class="input-group">
                        <span class="input-group-addon">
                            <img src="<?= statH(statAssetUrl('/dist/search.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                        </span>
                        <input
                            type="text"
                            class="form-control input-sm"
                            id="search"
                            placeholder="Search..."
                        >
                        <span class="input-group-btn">
                            <button
                                class="btn btn-default btn-sm pn-refresh-btn"
                                id="refresh"
                                type="button"
                            >
                                <img src="<?= statH(statAssetUrl('/dist/refresh.svg')) ?>" alt="" style="width:13px;height:13px;vertical-align:middle;">
                                <strong>Refresh</strong>
                            </button>
                        </span>
                    </div>
                </div>
                <div id="export" class="pn-export"></div>
            </div>
        </div>
        <div class="panel-body">
            <div class="table-responsive">
            <table
                id="userlead"
                class="table table-condensed table-hover table-striped"
                cellspacing="0"
                data-toggle="bootgrid"
                style="table-layout:auto;">
                <thead>
                <tr>
                    <th data-column-id="id" data-type="numeric" data-identifier="true" data-resizable-column-id="id" data-noresize>#</th>
                    <th data-column-id="click_id">ID</th>
                    <th data-column-id="clicks">ALL CLICKS</th>
                    <th data-column-id="leads">LEADS</th>
                    <th data-column-id="cr">CR</th>
                    <th data-column-id="payout">EARNING</th>
                </tr>
                </thead>
                <tbody>
                <?php $rows = $data['data']; ?>
                <?php if (is_array($rows) && count($rows) > 0) : ?>
                    <?php foreach ($rows as $row) : ?>
                        <tr>
                            <td class="no"><?= pnH((string) $row['id']) ?></td>
                            <td><?= pnH((string) $row['click_id']) ?></td>
                            <td><?= pnH((string) $row['clicks']) ?></td>
                            <td><?= pnH((string) $row['leads']) ?></td>
                            <td><?= pnH((string) $row['cr']) ?></td>
                            <td><?= pnH((string) $row['payout']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
                <tfoot>
                <tr>
                    <th colspan="6" id="sum"></th>
                </tr>
                </tfoot>
            </table>
            </div>
        </div>
    </div>
</div>

<script type="text/javascript" nonce="<?= pnH($rtNonce) ?>" src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.4.1/js/bootstrap-datepicker.min.js"></script>
<script type="text/javascript" nonce="<?= pnH($rtNonce) ?>">
$(document).ready(function () {
    'use strict';

    $.fn.dataTable.ext.errMode = 'throw';

    $('.input-group.date').datepicker({
        format: 'yyyy-mm-dd'
    });

    var table = $('#userlead').DataTable({
        processing: true,
        language: {
            search: '',
            searchPlaceholder: 'Search...'
        },
        paging: false,
        ordering: true,
        order: [[5, 'desc'], [0, 'asc']],
        columnDefs: [
            {targets: [0, 2, 3, 4, 5], type: 'num'},
            {targets: 0, className: 'no'}
        ],
        info: false,
        searching: true,
        dom: "<'top'>l<'searchbox' t>ip",
        footerCallback: function () {
            var api = this.api();

            var intVal = function (i) {
                var parsed;

                if (typeof i === 'string') {
                    i = i.replace(/[^0-9.\-]/g, '');
                    parsed = parseFloat(i);
                    return isNaN(parsed) ? 0 : parsed;
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

    $('.dataTables_empty').text('No data available in table {select date range for load conversions}');

    $('#search').on('keyup', function () {
        table.search($(this).val()).draw();
    });

    // AJAX conversion loader — repopulates the DataTable in place so the
    // "Load Conversions" button, Refresh, and the first-open auto-load never
    // reload the page. The server-rendered <form> POST remains as the no-JS
    // fallback.
    var pnLoading = false;

    function pnRenderRows(rows) {
        table.clear();
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            // Column order matches <thead>: #, ID, ALL CLICKS, LEADS, CR, EARNING.
            table.row.add([r.id, r.click_id, r.clicks, r.leads, r.cr, r.payout]);
        }
        table.draw();
    }

    function pnLoadConversions() {
        if (pnLoading) {
            return;
        }
        pnLoading = true;
        $('#pn-loader').addClass('show').attr('aria-hidden', 'false');

        $.ajax({
            url: window.location.pathname,
            method: 'POST',
            dataType: 'json',
            data: {
                action: 'load',
                start: $('#start').val(),
                end: $('#end').val(),
                csrf_token: $('#pn-filter-form [name="csrf_token"]').val()
            }
        }).done(function (res) {
            if (res && res.ok) {
                pnRenderRows(res.data || []);
            } else {
                window.alert('Failed to load conversions: ' + ((res && res.error) || 'unknown'));
            }
        }).fail(function () {
            window.alert('Failed to load conversions.');
        }).always(function () {
            pnLoading = false;
            $('#pn-loader').removeClass('show').attr('aria-hidden', 'true');
        });
    }

    // "Load Conversions" submit → AJAX, no page reload.
    $('#pn-filter-form').on('submit', function (event) {
        event.preventDefault();
        pnLoadConversions();
    });

    $('#refresh').on('click', function () {
        pnLoadConversions();
    });

    // First open: auto-load today's data (date inputs default to today, UTC).
    pnLoadConversions();

    if ($.fn.tableExport) {
        var $myTable = $('#userlead');

        $myTable.tableExport({
            headers: true,
            footers: true,
            formats: ['xlsx'],
            fileName: <?= json_encode('conversion-' . pnSafeFileNameDate($start) . '-' . pnSafeFileNameDate($end), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>,
            bootstrap: false,
            exportButtons: true,
            position: 'bottom',
            ignoreRows: null,
            ignoreCols: null,
            trimWhitespace: false,
            RTL: false,
            sheetname: 'id'
        });

        var $buttons = $myTable.find('caption').children().detach();
        $buttons.appendTo('#export');
    }

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
});
</script>
<div id="logout-toast">Logging out…</div>
<style nonce="<?= pnH($rtNonce) ?>">
#pn-loader{position:fixed;inset:0;z-index:10080;display:none;align-items:center;justify-content:center;background:rgba(37,42,46,.42);backdrop-filter:blur(1.5px);-webkit-backdrop-filter:blur(1.5px)}
#pn-loader.show{display:flex}
#pn-loader .pn-loader-spinner{width:38px;height:38px;border:3px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;animation:pnspin .7s linear infinite}
@keyframes pnspin{to{transform:rotate(360deg)}}
</style>
<div id="pn-loader" role="status" aria-live="polite" aria-hidden="true"><div class="pn-loader-spinner"></div></div>
<footer class="app-footer">
    <div class="app-sign">Ngix · xctd</div>
    <div class="rg-source"><span class="pre-colon">SOURCE</span>: <span class="post-colon">NGIX ⸺ XCTD</span></div>
</footer>
<link rel="stylesheet" href="<?= statH(statAssetUrl('/dist/stat-performance-2.css')) ?>">
<script nonce="<?= pnH($rtNonce) ?>">
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
            toast.setAttribute('nonce', '<?= pnH($rtNonce) ?>');
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
<style nonce="<?= pnH($rtNonce) ?>">
/* NGIX patch: statistics bg/backdrop deglitch */
html{width:100%!important;min-width:0!important;max-width:100%!important;min-height:100%!important;margin:0!important;padding:0!important;overflow-x:hidden!important;background:var(--porcelain)!important;zoom:1!important}
body{position:relative!important;width:100%!important;min-width:0!important;max-width:100%!important;min-height:100vh!important;min-height:100svh!important;min-height:100dvh!important;margin:0!important;overflow-x:hidden!important;background:linear-gradient(rgba(252,251,248,.74),rgba(252,251,248,.88)),url('/assets/img/favicon.svg') right 14px bottom 12px/28px 28px no-repeat fixed,url('/assets/img/bg-intro.png') center center/cover no-repeat fixed,var(--porcelain)!important;color:var(--text,var(--graphite))!important}
body::after{content:none!important;display:none!important;background:none!important}
body::before{z-index:1!important}
body>.container,.container{position:relative!important;z-index:2!important;max-width:1180px!important;overflow:visible!important}
.navbar.navbar-fixed-top,.navbar-fixed-top{position:fixed!important;top:0!important;right:0!important;left:0!important;width:100%!important;max-width:100%!important;margin:0!important;border-radius:0!important;transform:none!important;z-index:1055!important}
.panel_m.panel{position:relative!important;overflow:hidden!important;isolation:isolate!important;background:rgba(252,251,248,.62)!important}
.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{position:absolute!important;inset:0!important;top:0!important;right:0!important;bottom:0!important;left:0!important;width:100%!important;min-width:0!important;max-width:100%!important;height:100%!important;min-height:100%!important;max-height:none!important;z-index:0!important;pointer-events:none!important;background-image:linear-gradient(rgba(252,251,248,.86),rgba(252,251,248,.86)),url('<?= statH(statAssetUrl('/dist/bg-intro.png')) ?>')!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,contain!important;filter:saturate(.62) contrast(.84) blur(.12px)!important;contain:paint!important;opacity:.22;transform:none}
@keyframes ngixFogDrift{0%,100%{transform:translate3d(0,0,0) scale(1.015);opacity:.22}50%{transform:translate3d(0.6%,-0.4%,0) scale(1.015);opacity:.26}}
@media (prefers-reduced-motion:no-preference){.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{animation:ngixFogDrift 28s ease-in-out infinite}}
.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body,.panel_m.panel>.table-responsive,.panel_m.panel>form{position:relative!important;z-index:2!important}
.table-responsive{max-width:100%!important;overflow-x:auto!important;overflow-y:visible!important}
@supports (height:100lvh){body{min-height:100lvh!important}}
@media (prefers-color-scheme:dark){html{background:var(--graphite)!important}body{background:linear-gradient(rgba(37,42,46,.78),rgba(37,42,46,.88)),url('/assets/img/favicon.svg') right 14px bottom 12px/28px 28px no-repeat fixed,url('/assets/img/bg-intro.png') center center/cover no-repeat fixed,var(--graphite)!important}.panel_m.panel{background:rgba(37,42,46,.72)!important}.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{background-image:linear-gradient(rgba(37,42,46,.84),rgba(37,42,46,.84)),url('<?= statH(statAssetUrl('/dist/bg-intro.png')) ?>')!important;filter:saturate(.58) contrast(.78) blur(.16px)!important;opacity:.20}}
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
 * Mobile: same single-line card scheme as statistics/realtime — row number
 * pinned left, the rest of the fields grouped and pushed flush right, no
 * left/right page scroll needed. ID is never truncated. Every other field
 * here (ALL CLICKS/LEADS/CR/EARNING) is plain numeric text, so unlike
 * realtime there are no icon-only columns to skip the separator for.
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
       style="width:...px" per <td> for the desktop grid — see the identical
       comment in statistics/realtime/index.php for why this matters. */
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

    /* No separator before EARNING (the last field): a $ figure already
       reads as its own field, and dropping this separator reclaims just
       enough width to avoid it clipping — see the identical fix in
       statistics/realtime/index.php. */
    #userlead td:nth-child(2)::before,
    #userlead td:nth-child(3)::before,
    #userlead td:nth-child(4)::before,
    #userlead td:nth-child(5)::before {
        content: "\B7";
        margin-right: 3px;
        color: var(--line);
        font-weight: var(--fw-regular);
    }

    /* #1 stays pinned left; the auto margin here pushes ID and everything
       after it into one group hugging the right edge. ID is never
       truncated — always renders at its full natural width. */
    #userlead td:nth-child(2) {
        margin-left: auto;
        flex: 0 0 auto;
    }

    #userlead td:nth-child(6) {
        font-weight: var(--fw-bold);
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
<script nonce="<?= pnH($rtNonce) ?>" src="<?= statH(statAssetUrl('/dist/stat-performance.js')) ?>"></script>
</body>
</html>
