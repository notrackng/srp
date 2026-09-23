<?php

declare(strict_types=1);

include_once('../login.php');

$rtNonce = bin2hex(random_bytes(16));

function pcSendSecurityHeaders(string $nonce): void
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
        // header.php still loads the existing DataTables, Font Awesome,
        // datepicker, Google Fonts, and SweetAlert assets from these CDNs.
        // Inline JavaScript remains nonce-only; only CSS inline compatibility
        // is retained because Bootstrap/DataTables generate style attributes.
        "style-src 'self' 'unsafe-inline' https://cdn.datatables.net https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "style-src-elem 'self' 'unsafe-inline' https://cdn.datatables.net https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "style-src-attr 'unsafe-inline'",
        "script-src 'self' 'nonce-{$nonce}' https://cdn.datatables.net https://unpkg.com https://cdn.jsdelivr.net",
        "script-src-elem 'self' 'nonce-{$nonce}' https://cdn.datatables.net https://unpkg.com https://cdn.jsdelivr.net",
        "connect-src 'self' https:",
    ]);

    header('Content-Security-Policy: ' . $csp);
}

function pcEnsureSession(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function pcH(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function pcCsrfToken(): string
{
    pcEnsureSession();

    if (
        !isset($_SESSION['pc_csrf_token'])
        || !is_string($_SESSION['pc_csrf_token'])
        || $_SESSION['pc_csrf_token'] === ''
    ) {
        $_SESSION['pc_csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['pc_csrf_token'];
}

function pcVerifyCsrf(?string $token): bool
{
    pcEnsureSession();

    if (!is_string($token) || $token === '') {
        return false;
    }

    if (!isset($_SESSION['pc_csrf_token']) || !is_string($_SESSION['pc_csrf_token'])) {
        return false;
    }

    return hash_equals($_SESSION['pc_csrf_token'], $token);
}

function pcSelfPath(): string
{
    $scriptName = isset($_SERVER['SCRIPT_NAME']) && is_string($_SERVER['SCRIPT_NAME'])
        ? $_SERVER['SCRIPT_NAME']
        : '/clicks/';

    if (
        $scriptName === '' || preg_match('/[
]/', $scriptName) === 1
    ) {
        return '/clicks/';
    }

    return $scriptName;
}

/**
 * @return array{total: int, rows: array<int, mixed>}
 */
function pcReadJsonPage(string $filename, int $offset, int $limit): array
{
    if (!is_file($filename) || !is_readable($filename)) {
        return ['total' => 0, 'rows' => []];
    }

    $handle = fopen($filename, 'rb');
    if (!is_resource($handle)) {
        return ['total' => 0, 'rows' => []];
    }

    $total = 0;
    $rows = [];
    $inArray = false;
    $started = false;
    $complexElement = false;
    $depth = 0;
    $inString = false;
    $escaped = false;
    $element = '';

    while (!feof($handle)) {
        $chunk = fread($handle, 8192);
        if (!is_string($chunk) || $chunk === '') {
            continue;
        }

        $length = strlen($chunk);
        for ($index = 0; $index < $length; $index++) {
            $char = $chunk[$index];

            if (!$inArray) {
                if ($char === '[') {
                    $inArray = true;
                }
                continue;
            }

            if (!$started) {
                if ($char === ']' || $char === ',' || trim($char) === '') {
                    continue;
                }

                $started = true;
                $complexElement = $char === '{' || $char === '[';
                $depth = $complexElement ? 1 : 0;
                $inString = $char === '"';
                $escaped = false;
                $element = $char;
                continue;
            }

            if (!$complexElement && !$inString && ($char === ',' || $char === ']')) {
                pcCollectJsonElement($element, $total, $rows, $offset, $limit);
                $started = false;
                $element = '';
                if ($char === ']') {
                    break 2;
                }
                continue;
            }

            $element .= $char;

            if ($inString) {
                if ($escaped) {
                    $escaped = false;
                } elseif ($char === '\\') {
                    $escaped = true;
                } elseif ($char === '"') {
                    $inString = false;
                }
                continue;
            }

            if ($char === '"') {
                $inString = true;
                continue;
            }

            if ($complexElement && ($char === '{' || $char === '[')) {
                $depth++;
                continue;
            }

            if ($complexElement && ($char === '}' || $char === ']')) {
                $depth--;
                if ($depth === 0) {
                    pcCollectJsonElement($element, $total, $rows, $offset, $limit);
                    $started = false;
                    $element = '';
                }
            }
        }
    }

    fclose($handle);

    if ($started && trim($element) !== '') {
        pcCollectJsonElement($element, $total, $rows, $offset, $limit);
    }

    return ['total' => $total, 'rows' => $rows];
}

/**
 * @param array<int, mixed> $rows
 */
function pcCollectJsonElement(string $element, int &$total, array &$rows, int $offset, int $limit): void
{
    try {
        $decoded = json_decode($element, true, 32, JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        return;
    }

    // Per-tracker partition. The click log is shared by every tracker, so a
    // scoped session must neither see nor count another tracker's rows —
    // filtering before $total is what keeps the pagination totals honest.
    // Admin (null scope) still sees everything. See stat_path.php.
    if (!stat_click_log_row_in_scope($decoded)) {
        return;
    }

    $position = $total;
    $total++;

    if ($position < $offset || count($rows) >= $limit) {
        return;
    }

    $rows[] = $decoded;
}

function pcCurrentPage(int $totalPages): int
{
    $rawPage = isset($_GET['page']) && is_scalar($_GET['page']) ? (string) $_GET['page'] : '1';

    if (preg_match('/\A\d{1,6}\z/', $rawPage) !== 1) {
        return 1;
    }

    return max(1, min($totalPages, (int) $rawPage));
}

function pcPageUrl(int $page): string
{
    return '?page=' . rawurlencode((string) max(1, $page));
}

function pcHandlePostLogout(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';
    if ($action !== 'logout') {
        return;
    }

    if (!pcVerifyCsrf($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        echo 'Invalid CSRF token.';
        exit;
    }

    pcEnsureSession();
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

    header('Location: ' . pcSelfPath());
    exit;
}

function pcSafeCountryCode(mixed $value): string
{
    $code = strtolower((string) $value);
    $code = preg_replace('/[^a-z]/', '', $code);

    if (!is_string($code) || $code === '') {
        return '--';
    }

    return substr($code, 0, 3);
}

function pcIconImg(string $src, string $label, int $size = 16): string
{
    $class = 'pc-icon';

    if ($size <= 12) {
        $class .= ' pc-icon-xs';
    } elseif ($size <= 13) {
        $class .= ' pc-icon-sm';
    }

    return '<img src="' . pcH(statAssetUrl($src)) . '" class="' . pcH($class) . '" alt="' . pcH($label) . '" title="' . pcH($label) . '" width="' . $size . '" height="' . $size . '">';
}

function pcRenderCountry(mixed $countryCode): string
{
    $code = pcSafeCountryCode($countryCode);
    $label = strtoupper($code === '--' ? '-' : $code);

    // CSS sprite flag (assets/css/flags.css), same as statistics/realtime: one
    // stylesheet instead of one SVG request per country, and no per-row glob of
    // the flags directory. statFlagSpriteCode() only returns a code the sprite
    // actually positions, so an unknown country renders a neutral box rather
    // than whichever flag happens to sit at `background-position: 0 0`.
    $spriteCode = statFlagSpriteCode($code);
    $flag = $spriteCode !== ''
        ? '<span class="pc-flag flag flag-' . $spriteCode . '"></span> '
        : '<span class="pc-flag pc-flag--unknown"></span> ';

    return $flag . '<strong class="pc-country">' . pcH($label) . '</strong>';
}

function pcRenderUserAgent(mixed $userAgent): string
{
    $raw = strtoupper(trim((string) $userAgent));
    $icon = statDeviceIconHtml($raw, 'pc-device-ico');

    if ($icon !== '') {
        return $icon;
    }

    return '<code>' . pcH($raw) . '</code>';
}

function pcRenderNetwork(mixed $info): string
{
    $raw = trim((string) $info);
    $key = strtolower($raw);

    $map = [
        'lospollos' => ['/dist/lp.png', 'LosPollos'],
        'imonetizeit' => ['/dist/imo.png', 'iMonetizeIt'],
        'imonetizeit-1' => ['/dist/imo.png', 'iMonetizeIt-1'],
        'imonetizeit-2' => ['/dist/imo.png', 'iMonetizeIt-2'],
        'trafee' => ['/dist/tf.png', 'Trafee'],
        'custom' => ['/dist/custom.svg', 'Custom'],
        'torazzo' => ['/dist/custom.svg', 'Torazzo'],
    ];

    if (isset($map[$key])) {
        return pcIconImg($map[$key][0], $map[$key][1], 12);
    }

    return '<code>' . pcH($raw) . '</code>';
}

pcSendSecurityHeaders($rtNonce);
pcHandlePostLogout();

$pageName = basename(__DIR__);
$isPerformanceClick = $pageName === 'click';
$title = $isPerformanceClick ? 'PERFORMANCE CLICKS' : 'PERFORMANCE CLICKS';

$time = gmdate('Y-m-d'); // UTC "today": matches the click-log writer (redirect/_meetups) and postback conversion_date

// Click log is always at {project_root}/statistics/temp/YYYY-MM-DD.json
$filename = dirname(__DIR__, 2) . '/statistics/temp/' . $time . '.json';

$perPage = 100;
$requestedPage = pcCurrentPage(1000000);
$offset = ($requestedPage - 1) * $perPage;
$pageData = pcReadJsonPage($filename, $offset, $perPage);
$total = $pageData['total'];
$totalPages = max(1, (int) ceil($total / $perPage));
$page = min($requestedPage, $totalPages);
$offset = ($page - 1) * $perPage;
$rows = $page === $requestedPage ? $pageData['rows'] : pcReadJsonPage($filename, $offset, $perPage)['rows'];
$self = pcSelfPath();

include_once('../header.php');
?>
<style nonce="<?= pcH($rtNonce) ?>">
:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--bg:var(--porcelain);--light:var(--porcelain);--surface:var(--porcelain);--panel2:var(--paper);--panel-soft:var(--paper);--panel-raised:var(--panel);--panel-fade:rgba(252, 251, 248, 0.7);--nav:var(--paper);--line:var(--soft-steel);--line2:var(--border);--line-soft:var(--border);--stroke:var(--soft-steel);--text:var(--graphite);--btn:var(--graphite);--primary:var(--graphite);--primary2:var(--ink);--text-strong:var(--ink);--strong:var(--ink);--dark:var(--ink);--muted:var(--steel-gray);--accent:var(--burnt-copper);--accent-h:#8f5236;--accent-hover:#8f5236;--accent-s:var(--burnt-copper-soft);--accent-soft:var(--burnt-copper-soft);--on:var(--paper);--on-accent:var(--paper);--good:var(--graphite);--ok:var(--graphite);--success:var(--graphite);--ok-soft:var(--burnt-copper-soft);--success-soft:var(--burnt-copper-soft);--bad:var(--burnt-copper);--danger:var(--burnt-copper);--danger-soft:var(--burnt-copper-soft);--warn:var(--steel-gray);--blue-soft:var(--burnt-copper-soft);--blue-line:rgba(168, 100, 66, 0.28);--shadow-modal:var(--shadow);--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}@media (prefers-color-scheme:dark){}*{box-sizing:border-box}html,body{width:100%;height:100dvh;margin:0;}html{background:var(--bg);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}body{font-family:var(--font);padding:58px 8px 18px!important;background:radial-gradient(circle at 50% 8%,rgba(168,100,66,.12),transparent 28rem),radial-gradient(circle at 10% 80%,rgba(22,25,28,.06),transparent 22rem),var(--porcelain)!important;color:var(--text)!important;font-family:var(--mono)!important;font-size:var(--fs-base);line-height:var(--lh-normal);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}a{color:inherit;text-decoration:none}.container{width:100%;max-width:1180px;margin:0 auto}code{font-family:var(--mono);font-size:var(--fs-sm);color:var(--text);background:var(--panel-soft);border:1px solid var(--line-soft);border-radius:var(--radius);padding:1px 4px}.navbar.navbar-default{min-height:44px;border:0!important;border-bottom:0!important;background:var(--paper)!important;box-shadow:var(--shadow)!important}.navbar .container{max-width:1180px}.navbar-brand{height:44px!important;padding:12px 10px!important;color:var(--text-strong)!important;font-size:var(--fs-base);line-height:20px}.navbar-nav>li>a{padding-top:12px!important;padding-bottom:12px!important;line-height:20px!important;color:var(--text)!important;font-size:var(--fs-sm)}.navbar-nav>li>a:hover,.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:focus,.navbar-default .navbar-nav>.active>a:hover{background:var(--accent)!important;color:var(--on-accent)!important}.navbar-toggle{margin-top:5px!important;margin-bottom:5px!important;border-color:var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important}.navbar-toggle .icon-bar{background:var(--text)!important}.panel,.panel-default,.well,.modal-content{border:0!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading,.panel-footer,.modal-header,.modal-footer{padding:8px 10px!important;background:var(--porcelain)!important;border:0!important;color:var(--text-strong)!important}.panel-body,.modal-body{padding:10px!important;background:transparent!important;color:var(--text)!important}.pull-right{display:flex;align-items:center;gap:6px}.modal-content{box-shadow:var(--shadow-modal)!important}.modal-title{font-size:var(--fs-md);font-weight:var(--fw-bold);color:var(--text-strong)}.close{color:var(--text)!important;opacity:.78;text-shadow:none}.form-group{margin-bottom:8px}.control-label,label{margin-bottom:4px;color:var(--text-strong);font-size:var(--fs-sm)}.form-control,input[type=text],input[type=number],input[type=password],input[type=search],select,textarea{height:31px;min-height:31px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-family:inhe!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;box-shadow:none!important; }.form-control:focus,input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)!important;box-shadow:none!important}.form-control::placeholder,textarea::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control[readonly],input[readonly],textarea[readonly]{background:var(--panel-soft)!important;color:var(--text)!important}textarea.form-control{height:auto;min-height:114px;resize:none}.input-group-addon{height:31px;padding:5px 8px;background:transparent!important;border-color:var(--line)!important;color:var(--text)!important;border-radius:var(--radius)!important;font-size:var(--fs-sm)}.btn,button,.btn-sm,.btn-xs{display:inline-flex;align-items:center;justify-content:center;gap:5px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm);font-weight:var(--fw-bold);line-height:var(--lh-tight);box-shadow:none!important;outline:none;transition:background .12s ease,border-color .12s ease,color .12s ease}.btn:hover,button:hover,.btn-sm:hover,.btn-xs:hover{background:var(--panel-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.btn-primary,.btn-primary:focus,.btn-primary:active,.btn.active{background:var(--btn-bg)!important;border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.btn-primary:hover{background:var(--btn-bg)!important;filter:brightness(1.18);border-color:var(--btn-border)!important;color:var(--btn-fg)!important}.btn-danger,.btn-danger:focus{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.34)!important;color:var(--danger)!important}.btn-danger:hover{background:rgba(102,113,122,.16)!important;color:var(--danger)!important}.glyphicon{top:1px;color:currentColor}.action-ico{display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}.action-ico svg{display:block}.table-responsive{border:0!important}.table{width:100%;margin:4px 0 0;border-collapse:separate;border-spacing:0;border:0;border-radius:var(--radius);overflow:hidden;background:var(--panel)!important}.table>thead>tr>th{position:sticky;top:0;z-index:20;padding:7px 8px!important;border-bottom:1px solid var(--line)!important;background:var(--porcelain)!important;color:var(--text-strong)!important;font-size:var(--fs-xs)!important;line-height:var(--lh-tight);text-transform:uppercase;letter-spacing:.035em;white-space:nowrap}.table>tbody>tr>td{padding:6px 8px!important;border-top:1px solid var(--line-soft)!important;color:var(--text);font-size:var(--fs-sm);vertical-align:middle;word-break:break-word;background:var(--panel)!important}.table-hover>tbody>tr:hover>td{background:var(--panel-soft)!important}.bootgrid-table th>.column-header-anchor{color:var(--text-strong)!important}.bootgrid-header,.bootgrid-footer{margin:6px 0!important;color:var(--text)!important}.bootgrid-header .search .form-control{height:31px}.bootgrid-header .actionBar{text-align:right}.pagination>li>a,.pagination>li>span{border-color:var(--line)!important;background:var(--panel)!important;color:var(--text)!important}.pagination>.active>a,.pagination>.active>span{background:var(--accent)!important;border-color:var(--accent)!important;color:var(--on-accent)!important}.dropdown-menu{border:0!important;border-radius:var(--radius)!important;background:var(--paper)!important;box-shadow:var(--shadow-modal)!important}.dropdown-menu>li>a{color:var(--text)!important;font-size:var(--fs-sm)}.dropdown-menu>li>a:hover{background:var(--panel-soft)!important;color:var(--text-strong)!important}.alert{border-radius:var(--radius)!important}.alert-danger,.error{background:var(--danger-soft)!important;border-color:rgba(102,113,122,.28)!important;color:var(--danger)!important}.alert-success,.success{background:var(--blue-soft)!important;border-color:var(--blue-line)!important;color:var(--text)!important}.label{border-radius:var(--radius)!important}.label-default{background:var(--panel-soft)!important;color:var(--text)!important;border:1px solid var(--line)}blockquote{margin:0 0 10px;padding:7px 10px;border-left:2px solid var(--line)!important;background:var(--panel-fade);border-radius:var(--radius);font-size:var(--fs-sm)}.text-warning{margin:0 0 2px;color:var(--text-strong)!important;font-weight:var(--fw-bold)}.text-muted{color:var(--text)!important}.flag{border-radius:var(--radius)}.admin-toast-root{position:fixed;right:12px;bottom:12px;z-index:10050;display:flex;flex-direction:column;gap:6px;align-items:flex-end}.admin-toast{font-family:var(--mono);max-width:340px;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm);line-height:var(--lh-snug)}.admin-toast strong{display:block;margin-bottom:2px;color:var(--text-strong)}.admin-toast--error{border-color:rgba(102,113,122,.34);background:var(--danger-soft);color:var(--danger)}.admin-toast--success{border-color:var(--blue-line);background:var(--blue-soft);color:var(--text)}.admin-fallback-backdrop{position:fixed;inset:0;z-index:10040;display:flex;align-items:center;justify-content:center;padding:12px;background:rgba(37,42,46,.36)}.admin-fallback-dialog{width:min(420px,100%);border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);overflow:hidden}.admin-fallback-head{padding:10px;border-bottom:1px solid var(--line-soft);font-weight:var(--fw-bold);color:var(--text-strong);background:var(--porcelain)}.admin-fallback-body{padding:10px;font-size:var(--fs-sm)}.admin-fallback-actions{display:flex;gap:6px;justify-content:flex-end;padding:10px;border-top:1px solid var(--line-soft);background:var(--porcelain)}@media screen and (max-width:768px){body{padding:58px 6px 12px!important;font-size:var(--fs-base)}.container{width:100%!important;max-width:100%!important;padding-left:6px!important;padding-right:6px!important}.panel-heading,.panel-body,.panel-footer{padding:7px!important;background:var(--porcelain)!important}.navbar .container{padding-left:8px!important;padding-right:8px!important}.navbar-collapse{border-color:var(--line)!important;background:var(--panel)!important}.pull-right{float:none!important;justify-content:flex-end}.input-group{display:block}.input-group>.form-control,.input-group>.input-group-addon,.input-group>.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.input-group-addon{border-bottom:0!important;border-radius:var(--radius) var(--radius) 0 0!important}.input-group>.form-control{border-radius:0 0 var(--radius) var(--radius)!important}.input-group-btn>.btn{margin-top:5px}.table{display:block;overflow-x:auto;white-space:nowrap}.modal-dialog{width:auto!important;margin:8px}}#tbl_trackers{table-layout:fixed;width:100%;min-width:800px}#tbl_trackers th:nth-child(1),#tbl_trackers td:nth-child(1){width:50px;text-align:center;padding-left:4px!important;padding-right:4px!important}#tbl_trackers th:nth-child(2),#tbl_trackers td:nth-child(2){width:120px}#tbl_trackers th:nth-child(3),#tbl_trackers td:nth-child(3){width:120px}#tbl_trackers th:nth-child(5),#tbl_trackers td:nth-child(5){width:120px}.td-num{display:block;font-size:var(--fs-sm);font-weight:var(--fw-semibold);font-family:var(--mono);color:color-mix(in srgb,var(--text) 44%,transparent);text-align:center}.td-tracker{display:inline-block;width:100%;padding:2px 8px;border-radius:.3rem;border:1px solid var(--line);background:var(--panel-soft);font-family:var(--mono);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.03em;white-space:nowrap}.td-subdomain{display:inline-block;padding:2px 8px;border-radius:.3rem!important;width:100%;border:1px solid var(--line);background:var(--panel-soft);font-family:var(--mono);font-size:var(--fs-sm);font-weight:var(--fw-bold);letter-spacing:.03em;white-space:nowrap}.td-url{display:block;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:var(--mono);font-size:var(--fs-sm)}.td-pass{font-family:var(--mono);font-size:var(--fs-sm);color:color-mix(in srgb,var(--text) 60%,transparent)}
/* bootgrid toolbar search/select fix */.navbar-default .navbar-nav>li>a:hover,.navbar-default .navbar-nav>li>a:focus{background:color-mix(in srgb,var(--accent) 5%,transparent)!important;color:var(--text-strong)!important;box-shadow:none!important}.navbar-default .navbar-nav>.active>a,.navbar-default .navbar-nav>.active>a:hover,.navbar-default .navbar-nav>.active>a:focus{background:transparent!important;color:var(--text-strong)!important;box-shadow:none!important}.panel,.panel-default{overflow:visible!important}.panel-body{overflow:visible!important}.table-responsive{overflow-x:auto!important;overflow-y:visible!important}.bootgrid-header{position:relative!important;z-index:80!important;display:block!important;margin:8px 0 7px!important;color:var(--text)!important}.bootgrid-header .actionBar{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;float:none!important;width:100%!important;margin:0!important;text-align:right!important;white-space:nowrap!important}.bootgrid-header .search{position:relative!important;display:inline-flex!important;align-items:center!important;float:none!important;width:220px!important;min-width:220px!important;max-width:260px!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .search .input-group{display:flex!important;align-items:stretch!important;width:100%!important;border-collapse:separate!important}.bootgrid-header .search .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:32px!important;padding:0!important;border:1px solid var(--line)!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel-soft)!important;color:var(--text)!important;line-height:1!important}.bootgrid-header .search .input-group-addon .glyphicon{top:0!important;font-size:var(--fs-sm)!important}.bootgrid-header .search .search-field,.bootgrid-header .search .form-control{display:block!important;flex:1 1 auto!important;width:100%!important;height:32px!important;min-height:32px!important;padding:5px 9px!important;border:1px solid var(--line)!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--panel)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-snug)!important;box-shadow:none!important}.bootgrid-header .search .search-field:focus,.bootgrid-header .search .form-control:focus{border-color:var(--accent)!important;border-left:0!important;box-shadow:none!important}.bootgrid-header .actions{position:relative!important;display:inline-flex!important;align-items:center!important;gap:6px!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions>.btn-group{position:relative!important;display:inline-flex!important;float:none!important;margin:0!important;vertical-align:middle!important}.bootgrid-header .actions .btn,.bootgrid-header .actions .dropdown-toggle{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:6px!important;height:32px!important;min-width:38px!important;padding:5px 10px!important;line-height:var(--lh-tight)!important;border-radius:var(--radius)!important}.bootgrid-header .actions .dropdown-toggle{min-width:64px!important}.bootgrid-header .actions .dropdown-toggle .caret{margin-left:2px!important}.bootgrid-header .actions .dropdown-menu{position:absolute!important;top:calc(100% + 4px)!important;right:0!important;left:auto!important;z-index:3000!important;display:none;min-width:112px!important;width:112px!important;margin:0!important;padding:4px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow-modal)!important;list-style:none!important}.bootgrid-header .actions .open>.dropdown-menu{display:block!important}.bootgrid-header .actions .dropdown-menu>li{display:block!important;float:none!important;width:100%!important;margin:0!important;padding:0!important;text-align:left!important}.bootgrid-header .actions .dropdown-menu>li>a{display:block!important;width:100%!important;min-width:0!important;padding:6px 9px!important;border-radius:var(--radius)!important;background:transparent!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-tight)!important;text-align:left!important;white-space:nowrap!important}.bootgrid-header .actions .dropdown-menu>li>a:hover,.bootgrid-header .actions .dropdown-menu>li>a:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.bootgrid-header .actions .dropdown-menu>.active>a,.bootgrid-header .actions .dropdown-menu>.active>a:hover,.bootgrid-header .actions .dropdown-menu>.active>a:focus{background:var(--accent-soft)!important;color:var(--text-strong)!important;box-shadow:none!important}.bootgrid-footer{position:relative!important;z-index:20!important}.bootgrid-footer .pagination{margin:0!important}@media screen and (max-width:768px){.bootgrid-header .actionBar{align-items:stretch!important;justify-content:stretch!important;flex-wrap:wrap!important;gap:6px!important}.bootgrid-header .search{width:100%!important;min-width:0!important;max-width:none!important;flex:1 0 100%!important}.bootgrid-header .actions{margin-left:auto!important}.bootgrid-header .actions .dropdown-menu{right:0!important;left:auto!important}}
input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
/* final action icon render fix */#tbl_trackers th:last-child,#tbl_trackers td:last-child{text-align:center!important;white-space:nowrap!important;width:108px!important;min-width:108px!important;max-width:108px!important}.bootgrid-table td:last-child{overflow:visible!important}.action-btn,.bootgrid-table .command-edit,.bootgrid-table .command-delete{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:32px!important;height:26px!important;min-width:32px!important;min-height:26px!important;padding:0!important;margin:0 2px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;font-size:0!important;line-height:1!important;text-indent:0!important;vertical-align:middle!important;opacity:1!important;visibility:visible!important;box-shadow:none!important;overflow:visible!important}.action-btn:hover,.bootgrid-table .command-edit:hover{background:var(--accent-soft)!important;border-color:var(--line)!important;color:var(--text-strong)!important}.bootgrid-table .command-delete{color:var(--danger)!important}.bootgrid-table .command-delete:hover{background:var(--danger-soft)!important;border-color:color-mix(in srgb,var(--danger) 34%,var(--line))!important;color:var(--danger)!important}.bootgrid-table .command-edit[disabled],.bootgrid-table .command-delete[disabled]{opacity:.58!important;cursor:not-allowed!important}.action-btn .action-ico,.bootgrid-table .command-edit .action-ico,.bootgrid-table .command-delete .action-ico{display:inline-flex!important;align-items:center!important;justify-content:center!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;color:currentColor!important;opacity:1!important;visibility:visible!important;overflow:visible!important;pointer-events:none!important}.action-btn svg,.bootgrid-table .command-edit svg,.bootgrid-table .command-delete svg{display:block!important;width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;overflow:visible!important;color:currentColor!important;opacity:1!important;visibility:visible!important;pointer-events:none!important}.action-btn svg *,.bootgrid-table .command-edit svg *,.bootgrid-table .command-delete svg *{vector-effect:non-scaling-stroke!important;stroke:currentColor!important;stroke-width:2!important;stroke-linecap:round!important;stroke-linejoin:round!important;fill:none!important;opacity:1!important;visibility:visible!important}.btn-icon svg,.btn-primary svg{display:block!important;width:13px!important;height:13px!important;fill:currentColor!important;color:currentColor!important;opacity:1!important;visibility:visible!important}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}
body,.table,input,select,textarea{font-family:var(--mono)!important}body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none}body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)}
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

/* ngix xctd backdrop */
.ngix-backdrop{position:relative;width:100%;max-width:1180px;min-height:168px;margin:0 auto 8px;border-radius:var(--radius);overflow:hidden;background:linear-gradient(180deg,var(--paper) 0%,var(--paper) 100%);border:1px solid var(--line-soft);isolation:isolate}
.ngix-backdrop:before{content:"";position:absolute;inset:-18px;background:linear-gradient(118deg,transparent 0 13%,rgba(168,100,66,.94) 13% 16%,rgba(37,42,46,.94) 16% 21%,transparent 21%),linear-gradient(298deg,transparent 0 12%,rgba(168,100,66,.94) 12% 15%,rgba(37,42,46,.94) 15% 20%,transparent 20%),radial-gradient(circle at 50% 38%,rgba(37,42,46,.035),transparent 44%);opacity:.96;z-index:0}
.ngix-backdrop:after{content:"";position:absolute;left:50%;top:51%;width:360px;height:360px;transform:translate(-50%,-50%);background:linear-gradient(45deg,transparent 42%,rgba(37,42,46,.055) 43% 57%,transparent 58%),linear-gradient(-45deg,transparent 42%,rgba(37,42,46,.045) 43% 57%,transparent 58%);clip-path:polygon(50% 8%,64% 29%,83% 10%,91% 56%,70% 84%,57% 92%,43% 92%,30% 84%,9% 56%,17% 10%,36% 29%);opacity:.75;z-index:0}
.ngix-backdrop-inner{position:relative;z-index:1;display:flex;align-items:center;justify-content:center;min-height:168px;padding:24px;text-align:center}
.ngix-backdrop-title{margin:0;color:var(--ink);font-family:var(--mono);font-size:34px;font-weight:var(--fw-bold);line-height:1;letter-spacing:.32em;text-transform:uppercase}
.ngix-backdrop-title span{color:var(--soft-steel);font-weight:var(--fw-regular)}.ngix-backdrop-title i{font-style:normal;color:var(--burnt-copper);letter-spacing:.08em}
.ngix-backdrop-sub{margin:12px 0 0;color:var(--steel-gray);font-family:var(--mono);font-size:var(--fs-xs);font-weight:var(--fw-regular);line-height:var(--lh-snug);letter-spacing:.32em;text-transform:uppercase}
.ngix-backdrop-sub i{font-style:normal;color:var(--burnt-copper);font-weight:var(--fw-bold);letter-spacing:.08em}
@media (prefers-color-scheme:dark){.ngix-backdrop{background:linear-gradient(180deg,var(--graphite) 0%,var(--graphite) 100%);border-color:rgba(252,251,248,.06)}.ngix-backdrop-title{color:var(--paper)}.ngix-backdrop-title span{color:var(--steel-gray)}.ngix-backdrop-sub{color:var(--soft-steel)}.ngix-backdrop:after{opacity:.30;filter:invert(1)}}
@media screen and (max-width:768px){.ngix-backdrop{min-height:132px;margin-bottom:6px}.ngix-backdrop-inner{min-height:132px;padding:18px}.ngix-backdrop-title{font-size:24px;letter-spacing:.22em}.ngix-backdrop-sub{font-size:var(--fs-xs);letter-spacing:.22em}.ngix-backdrop:after{width:260px;height:260px}}

/* performance click shared-layout patch */.pc-toolbar{margin-bottom:6px}.pc-search{display:flex!important;align-items:stretch!important;flex-wrap:nowrap!important;width:100%!important}.pc-search .input-group-addon{display:flex!important;align-items:center!important;justify-content:center!important;flex:0 0 34px!important;width:34px!important;min-width:34px!important;height:31px!important;border-right:0!important;border-radius:var(--radius) 0 0 var(--radius)!important}.pc-search .form-control{flex:1 1 auto!important;width:auto!important;min-width:0!important;border-left:0!important;border-radius:0 var(--radius) var(--radius) 0!important}.pc-table-wrap{display:none}.pc-icon{display:inline-block;width:16px;height:16px;vertical-align:middle}.pc-icon-sm{width:13px;height:13px}.pc-icon-xs{width:12px;height:12px}.pc-country{color:#252a2e!important}.pc-flag{display:inline-block;width:16px;height:11px;vertical-align:-1px;border-radius:.1rem;box-shadow:0 0 0 1px rgba(37,42,46,.10)}.pc-flag.flag{width:16px;height:11px;background-repeat:no-repeat;background-size:100%}.pc-flag--unknown{background:var(--panel-soft)}.pc-device-ico{display:inline-block;width:14px;height:14px;vertical-align:-3px;color: var(--graphite);fill: var(--porcelain)}.pc-click{font-family:var(--mono);font-weight:var(--fw-bold);color:var(--text-strong)}.pc-page-meta{color:var(--text);font-size:var(--fs-xs);margin-left:8px}.pc-pagination{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:10px 0 4px}.pc-pagination .pagination{margin:0!important;display:flex;flex-wrap:wrap}.logout-form{margin:0}.logout-btn{padding:12px 10px!important;color:var(--text)!important;text-decoration:none!important;background:transparent!important;border:0!important}.rg-source .pre-colon{font-weight:var(--fw-bold);color:var(--text-strong)}.rg-source .post-colon{font-family:var(--mono)}.is-hidden{display:none!important}#logout-toast{position:fixed;right:12px;bottom:12px;z-index:10050;display:none;padding:8px 10px;border:1px solid var(--line);border-radius:var(--radius);background:var(--panel);color:var(--text);box-shadow:var(--shadow-modal);font-size:var(--fs-sm)}#logout-toast.show{display:block}@media screen and (max-width:768px){.pc-search{display:flex!important}.pc-search .input-group-addon{width:34px!important}.pc-search .form-control{width:auto!important}#perf-click-table{width:100%!important}.pc-page-meta{display:block;width:100%;margin-left:0}.navbar-btn.logout-btn{padding:9px 10px!important}}
:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}.table>tbody>tr>td{font-family:var(--mono)!important;font-size:var(--fs-sm)!important}.form-control,input,select,textarea,.btn,button{font-family:var(--mono)!important;font-size:var(--fs-sm)!important}
/* click #perf-click-table column alignment */
#perf-click-table th:nth-child(1),#perf-click-table td:nth-child(1){width:44px!important;min-width:44px!important;max-width:44px!important;text-align:left!important;padding-left:12px!important;padding-right:8px!important;font-variant-numeric:tabular-nums}
.app-sign{text-align:right;padding:3px 0 2px}.app-sign footer{font-family:var(--mono);text-decoration:none;letter-spacing:.09em;font-size:10px;font-weight:900;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;user-select:none;text-transform:uppercase;-webkit-user-select:none}select hr{border:none;border-top:1px solid rgba(37,42,46,.06)!important;color:rgba(37,42,46,.06)!important;opacity:.45;margin:1px 4px}input[type=url]{font-family:var(--mono)!important}
/* tighten search ↔ table gap */
.panel_m .panel-body{padding:0 0 2px!important}
#perf-click-table{margin-top:0!important}
/* sortable headers */
#perf-click-table thead th{cursor:pointer;user-select:none;white-space:nowrap}
#perf-click-table thead th::after{content:'\2195';margin-left:6px;font-size:var(--fs-xs);opacity:.3}
#perf-click-table thead th.sort-asc::after{content:'\2191';opacity:.9}
#perf-click-table thead th.sort-desc::after{content:'\2193';opacity:.9}
/* footer + rg-source block */
.app-footer{width:100%;max-width:1180px;margin:12px auto 0;padding:7px 8px 3px;border-top:1px solid var(--line-soft);text-align:right;line-height:var(--lh-snug)}
.app-footer .app-sign{padding:0!important;font-family:var(--mono)!important;color:var(--graphite)!important;letter-spacing:.02em!important;line-height:1!important;text-decoration:none;font-size:10px!important;font-weight:900!important;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;text-transform:uppercase;user-select:none;-webkit-user-select:none}
.app-footer .rg-source{margin-top:3px;font-size:var(--fs-xs);color:var(--muted)}
.app-footer .rg-source .pre-colon{font-weight:var(--fw-bold);color:var(--text-strong)}
.app-footer .rg-source .post-colon{font-family:var(--mono);color:var(--text)}
/* centered content backdrop override */
.panel_m.panel{position:relative!important;overflow:hidden!important;isolation:isolate!important}
.panel_m.panel>.ngix-backdrop{position:absolute!important;inset:0!important;width:auto!important;max-width:none!important;min-height:0!important;margin:0!important;border:0!important;border-radius:var(--radius)!important;background:transparent!important;pointer-events:none!important;z-index:0!important;isolation:auto!important}
.panel_m.panel>.ngix-backdrop:before{content:""!important;position:absolute!important;inset:0!important;background:radial-gradient(circle at 50% 50%,rgba(37,42,46,.045),transparent 44%),linear-gradient(116deg,transparent 0 18%,rgba(168,100,66,.11) 18% 20%,rgba(37,42,46,.08) 20% 24%,transparent 24%),linear-gradient(296deg,transparent 0 18%,rgba(168,100,66,.11) 18% 20%,rgba(37,42,46,.08) 20% 24%,transparent 24%)!important;opacity:1!important;z-index:0!important}
.panel_m.panel>.ngix-backdrop:after{content:""!important;position:absolute!important;left:50%!important;top:53%!important;width:min(470px,76vw)!important;height:min(470px,76vw)!important;transform:translate(-50%,-50%)!important;background:linear-gradient(45deg,transparent 42%,rgba(37,42,46,.055) 43% 57%,transparent 58%),linear-gradient(-45deg,transparent 42%,rgba(37,42,46,.045) 43% 57%,transparent 58%)!important;clip-path:polygon(50% 8%,64% 29%,83% 10%,91% 56%,70% 84%,57% 92%,43% 92%,30% 84%,9% 56%,17% 10%,36% 29%)!important;opacity:.62!important;z-index:0!important}
.panel_m.panel>.ngix-backdrop>.ngix-backdrop-inner{position:absolute!important;inset:0!important;z-index:1!important;display:flex!important;align-items:center!important;justify-content:center!important;min-height:0!important;height:100%!important;padding:0!important;text-align:center!important}
.panel_m.panel .ngix-backdrop-title{margin:0!important;color:var(--ink)!important;font-family:var(--mono)!important;font-size:30px!important;font-weight:var(--fw-bold)!important;line-height:1!important;letter-spacing:.30em!important;text-transform:uppercase!important;opacity:.095!important}
.panel_m.panel .ngix-backdrop-title span{color:var(--ink)!important;font-weight:var(--fw-regular)!important}.panel_m.panel .ngix-backdrop-title i{font-style:normal!important;color:var(--burnt-copper)!important;letter-spacing:.08em!important}
.panel_m.panel .ngix-backdrop-sub{margin:11px 0 0!important;color:var(--ink)!important;font-family:var(--mono)!important;font-size:var(--fs-xs)!important;font-weight:var(--fw-regular)!important;line-height:var(--lh-snug)!important;letter-spacing:.28em!important;text-transform:uppercase!important;opacity:.10!important}
.panel_m.panel .ngix-backdrop-sub i{font-style:normal!important;color:var(--burnt-copper)!important;font-weight:var(--fw-bold)!important;letter-spacing:.08em!important}
.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body{position:relative!important;z-index:2!important}
@media (prefers-color-scheme:dark){.panel_m.panel>.ngix-backdrop:before{background:radial-gradient(circle at 50% 50%,rgba(252,251,248,.04),transparent 44%),linear-gradient(116deg,transparent 0 18%,rgba(168,100,66,.12) 18% 20%,rgba(252,251,248,.07) 20% 24%,transparent 24%),linear-gradient(296deg,transparent 0 18%,rgba(168,100,66,.12) 18% 20%,rgba(252,251,248,.07) 20% 24%,transparent 24%)!important}.panel_m.panel>.ngix-backdrop:after{filter:invert(1)!important;opacity:.26!important}.panel_m.panel .ngix-backdrop-title,.panel_m.panel .ngix-backdrop-sub{color:var(--paper)!important}}
@media screen and (max-width:768px){.panel_m.panel .ngix-backdrop-title{font-size:22px!important;letter-spacing:.20em!important}.panel_m.panel .ngix-backdrop-sub{font-size:8px!important;letter-spacing:.18em!important}.panel_m.panel>.ngix-backdrop:after{width:280px!important;height:280px!important}}

/* ngix xctd image backdrop final */
.panel_m.panel{position:relative!important;overflow:hidden!important;isolation:isolate!important;background:rgba(252,251,248,.74)!important}
.panel_m.panel>.ngix-image-backdrop{position:absolute!important;inset:0!important;z-index:0!important;pointer-events:none!important;background-image:linear-gradient(rgba(252,251,248,.82),rgba(252,251,248,.82)),url('<?= statH(statAssetUrl('/dist/bg-intro.png')) ?>')!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,cover!important;opacity:.42!important;filter:saturate(.72) contrast(.86) blur(.22px)!important;transform:translateZ(0)!important}
.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body{position:relative!important;z-index:2!important}
.panel_m.panel>.panel-heading{background:rgba(244,241,236,.82)!important;backdrop-filter:saturate(110%) blur(1px)!important}
.panel_m.panel>.panel-body{background:rgba(252,251,248,.46)!important}
#perf-click-table{position:relative!important;z-index:3!important;background:rgba(252,251,248,.58)!important}
#perf-click-table>thead>tr>th{background:rgba(244,241,236,.86)!important}
#perf-click-table>tbody>tr>td{background:rgba(252,251,248,.34)!important}
#perf-click-table.table-hover>tbody>tr:hover>td{background:rgba(244,241,236,.72)!important}
@media (prefers-color-scheme:dark){.panel_m.panel{background:rgba(37,42,46,.78)!important}.panel_m.panel>.ngix-image-backdrop{background-image:linear-gradient(rgba(37,42,46,.78),rgba(37,42,46,.78)),url('<?= statH(statAssetUrl('/dist/bg-intro.png')) ?>')!important;opacity:.46!important;filter:saturate(.70) contrast(.84) blur(.18px)!important}.panel_m.panel>.panel-heading{background:rgba(37,42,46,.84)!important}.panel_m.panel>.panel-body{background:rgba(37,42,46,.50)!important}#perf-click-table{background:rgba(37,42,46,.50)!important}#perf-click-table>thead>tr>th{background:rgba(37,42,46,.86)!important}#perf-click-table>tbody>tr>td{background:rgba(37,42,46,.34)!important}#perf-click-table.table-hover>tbody>tr:hover>td{background:rgba(37,42,46,.72)!important}}
@media screen and (max-width:768px){.panel_m.panel>.ngix-image-backdrop{background-size:100% 100%,cover!important;background-position:center center,center center!important;opacity:.34!important}}
.navbar-fixed-top{overflow:visible!important;z-index:1040!important}.navbar-collapse{overflow:visible!important}.pc-nav-dropdown{position:relative!important}.pc-nav-dropdown>.pc-nav-toggle{display:flex!important;align-items:center!important;gap:6px!important;min-height:44px!important}.pc-nav-dropdown>.pc-nav-toggle .caret{margin-left:2px!important}.pc-nav-dropdown.open>.pc-nav-toggle,.pc-nav-dropdown>.pc-nav-toggle:hover,.pc-nav-dropdown>.pc-nav-toggle:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.pc-nav-menu{position:absolute!important;top:100%!important;right:0!important;left:auto!important;z-index:5000!important;display:none;min-width:230px!important;width:230px!important;margin:2px 0 0!important;padding:6px!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel2)!important;box-shadow:0 10px 24px rgba(22,25,28,.10)!important;list-style:none!important}.pc-nav-dropdown.open>.pc-nav-menu{display:block!important}.pc-nav-menu>li{display:block!important;float:none!important;width:100%!important;margin:0!important;padding:0!important}.pc-nav-menu>li>a,.pc-nav-menu>.dropdown-header{display:flex!important;align-items:center!important;gap:6px!important;width:100%!important;min-height:30px!important;padding:7px 9px!important;border-radius:var(--radius)!important;color:var(--text)!important;font-size:var(--fs-sm)!important;line-height:var(--lh-tight)!important;white-space:nowrap!important}.pc-nav-menu>li>a:hover,.pc-nav-menu>li>a:focus{background:var(--panel-soft)!important;color:var(--text-strong)!important}.pc-nav-menu>li.active>a,.pc-nav-menu>li.active>a:hover,.pc-nav-menu>li.active>a:focus{background: rgba(37, 42, 46, 0.14) !important;color: var(--text-strong) !important;}.pc-nav-menu>.divider{height:1px!important;min-height:1px!important;margin:4px 2px!important;overflow:hidden!important;background:var(--line-soft)!important}.pc-nav-menu>.dropdown-header{color:var(--muted)!important;font-weight:var(--fw-bold)!important;text-transform:uppercase!important;letter-spacing:.04em!important}@media screen and (max-width:768px){.pc-nav-dropdown>.pc-nav-toggle{justify-content:space-between!important}.pc-nav-menu{position:static!important;width:100%!important;min-width:0!important;margin:0 0 8px!important;box-shadow:none!important}.pc-nav-dropdown.open>.pc-nav-menu{display:block!important}}
</style>
<link rel="stylesheet" href="<?= statH(statAssetUrl('/dist/stat-clicks-1.css')) ?>">
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
          <a class="navbar-brand" href="#"><strong><?= pcIconImg('/dist/chart.svg', '', 13) ?> <?= pcH($title) ?></strong></a>
        </div>
        <div id="navbar" class="navbar-collapse collapse">
          <ul class="nav navbar-nav navbar-right">
            <li class="dropdown active pc-nav-dropdown">
              <a href="#" class="dropdown-toggle pc-nav-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false"><strong><?= pcH($title) ?> <?= pcIconImg('/dist/chart.svg', '', 13) ?></strong> <span class="caret"></span></a>
              <ul class="dropdown-menu pc-nav-menu">
                <li class="dropdown-header">PERFORMANCE CLICKS</li>
                <li role="separator" class="divider"></li>
                <li><a href="<?= statH(statUrl('/realtime/?date=rt_1')) ?>"><strong>TODAY</strong></a></li>
                <li role="separator" class="divider"></li>
                <li><a href="<?= statH(statUrl('/realtime/?date=rt_2')) ?>"><strong>YESTERDAY</strong></a></li>
                <li role="separator" class="divider"></li>
                <li class="active"><a href="#"><strong>PERFORMANCE CLICKS <?= pcIconImg('/dist/chart.svg', '', 13) ?></strong></a></li>
              </ul>
            </li>
            <li><a></a></li>
            <li><a href="<?= statH(statUrl('/performance/')) ?>"><strong>PERFORMANCE NETWORK</strong> </a></li>
            <li>
              <form method="post" action="<?= pcH($self) ?>" id="logout-form" class="logout-form">
                <input type="hidden" name="csrf_token" value="<?= pcH(pcCsrfToken()) ?>">
                <input type="hidden" name="action" value="logout">
                <button type="submit" id="btn-logout" class="btn btn-link navbar-btn logout-btn"><strong>LOGOUT</strong></button>
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
                    <div class="input-group search searchbox pc-search">
                        <span class="input-group-addon"><?= pcIconImg('/dist/search.svg', '', 13) ?></span>
                        <input type="text" class="form-control input-sm filter" id="search" placeholder="Search for ID.." title="Type in a name" autocomplete="off">
                        <span class="input-group-btn">
                            <button type="button" id="refresh" class="btn btn-default btn-sm pn-refresh-btn">
                                <?= pcIconImg('/dist/refresh.svg', '', 13) ?> <strong>Refresh</strong>
                            </button>
                        </span>
                    </div>
                    <div id="pc-export" class="pn-export"></div>
                </div>
            </div>
            <div class="panel-body">
                <div class="table-responsive">
                <table class="table table-condensed table-hover table-striped" id="perf-click-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>CLICKID</th>
                            <th>COUNTRY</th>
                            <th>TRAFFIC</th>
                            <th>IP ADDRESS</th>
                            <th>NETWORK</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($rows as $row) : ?>
                        <?php
                        if (!is_array($row)) {
                            continue;
                        }

                        $id = isset($row['id']) ? (int) $row['id'] : 0;
                        $clickId = strtoupper(trim((string) ($row['click_id'] ?? '')));
                        $countryCode = pcRenderCountry($row['country_code'] ?? '');
                        $userAgent = pcRenderUserAgent($row['device_type'] ?? $row['user_agent'] ?? '');
                        $ipAddress = trim((string) ($row['ip_address'] ?? ''));
                        $network = pcRenderNetwork($row['info'] ?? '');
                        ?>
                        <tr class="pc-row" data-click-id="<?= pcH(strtolower($clickId)) ?>">
                            <td><?= (int) $id ?></td>
                            <td><span class="pc-click"><?= pcH($clickId) ?></span></td>
                            <td><?= $countryCode ?></td>
                            <td><?= $userAgent ?></td>
                            <td><code><?= pcH($ipAddress) ?></code></td>
                            <td><?= $network ?></td>
                        </tr>
                    <?php endforeach; ?>

                    <?php if (count($rows) === 0) : ?>
                        <tr>
                            <td colspan="6">There are currently no clicks available for this page.</td>
                        </tr>
                    <?php endif; ?>
                    </tbody>
                </table>
                </div>
            </div>
        </div>

        <?php if ($totalPages > 1) : ?>
            <nav class="pc-pagination">
                <ul class="pagination pagination-sm">
                    <li class="<?= $page <= 1 ? 'disabled' : '' ?>">
                        <a href="<?= pcH(pcPageUrl($page - 1)) ?>">&laquo;</a>
                    </li>
                    <?php
                    $startPage = max(1, $page - 4);
            $endPage = min($totalPages, $page + 4);
            ?>

                    <?php if ($startPage > 1) : ?>
                        <li class="disabled"><a href="#">…</a></li>
                    <?php endif; ?>

                    <?php for ($p = $startPage; $p <= $endPage; $p++) : ?>
                        <li class="<?= $p === $page ? 'active' : '' ?>">
                            <a href="<?= pcH(pcPageUrl($p)) ?>"><?= (int) $p ?></a>
                        </li>
                    <?php endfor; ?>

                    <?php if ($endPage < $totalPages) : ?>
                        <li class="disabled"><a href="#">…</a></li>
                    <?php endif; ?>

                    <li class="<?= $page >= $totalPages ? 'disabled' : '' ?>">
                        <a href="<?= pcH(pcPageUrl($page + 1)) ?>">&raquo;</a>
                    </li>
                </ul>
                <small class="pc-page-meta">
                    <?= number_format($total > 0 ? $offset + 1 : 0) ?>–<?= number_format(min($offset + $perPage, $total)) ?>
                    of <?= number_format($total) ?>
                </small>
            </nav>
        <?php endif; ?>
    </div>

<script src="<?= statH(statAssetUrl('/dist/stat-clicks-1.js')) ?>"></script>
<div id="logout-toast">Logging out…</div>
<footer class="app-footer">
    <div class="app-sign">Ngix · xctd</div>
    <div class="rg-source"><span class="pre-colon">SOURCE</span>: <span class="post-colon">NGIX ⸺ XCTD</span></div>
</footer>
<link rel="stylesheet" href="<?= statH(statAssetUrl('/dist/stat-clicks-2.css')) ?>">
<script nonce="<?= pcH($rtNonce) ?>">
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
            toast.setAttribute('nonce', '<?= pcH($rtNonce) ?>');
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
<style nonce="<?= pcH($rtNonce) ?>">
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
 * left/right page scroll needed. CLICKID is never truncated. IP ADDRESS
 * (column 5) is dropped from this view, same as realtime drops it.
 */
@media screen and (max-width: 768px) {
    #perf-click-table thead {
        display: none;
    }

    #perf-click-table,
    #perf-click-table tbody {
        display: block;
        width: 100%;
    }

    #perf-click-table tr {
        display: flex;
        flex-wrap: nowrap;
        align-items: center;
        column-gap: 4px;
        margin-bottom: 6px;
        padding: 6px 6px;
        border: 1px solid var(--line);
        border-radius: var(--radius);
        background: var(--panel);
        overflow-x: auto;
        overflow-y: hidden;
        scrollbar-width: none;
    }

    #perf-click-table tr::-webkit-scrollbar {
        display: none;
    }

    /* width/min-width/max-width forced back to auto in case DataTables (or
       any other grid helper on this page) ever stamps an inline column
       width — see the identical comment in statistics/realtime/index.php. */
    #perf-click-table td {
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

    #perf-click-table td:nth-child(1) {
        font-weight: var(--fw-semibold);
        color: var(--text-strong);
    }

    #perf-click-table td:nth-child(1)::before {
        content: "#";
    }

    #perf-click-table .pc-device-ico {
        width: 14px !important;
        height: 14px !important;
    }

    /* Separator only before text-bearing fields (CLICKID, COUNTRY) — not
       before #1, IP ADDRESS (hidden), or the icon-only TRAFFIC/NETWORK
       cells. */
    #perf-click-table td:nth-child(2)::before,
    #perf-click-table td:nth-child(3)::before {
        content: "\B7";
        margin-right: 3px;
        color: var(--line);
        font-weight: var(--fw-regular);
    }

    /* #1 stays pinned left; the auto margin here pushes CLICKID and
       everything after it into one group hugging the right edge. CLICKID
       is never truncated — always renders at its full natural width. */
    #perf-click-table td:nth-child(2) {
        margin-left: auto;
        flex: 0 0 auto;
    }

    #perf-click-table td:nth-child(6) {
        font-weight: var(--fw-bold);
    }

    /* IP ADDRESS isn't part of this scheme — hide it on the mobile card. */
    #perf-click-table td:nth-child(5) {
        display: none !important;
    }
}
</style>
<script src="<?= statH(statAssetUrl('/dist/stat-clicks-2.js')) ?>"></script>
</body></html>
