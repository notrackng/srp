<?php

declare(strict_types=1);
// env.php first: startAdminSession() runs further down and reaches
// srp_request_is_https() through adminIsHttpsRequest(). The later include_once
// of env.php comes after that call, so relying on it would be a fatal.
require_once dirname(__DIR__, 2) . '/env.php';
require_once dirname(__DIR__, 2) . '/asset_url.php';


error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

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
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => adminIsHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
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

function adminRequestCsrfToken(): ?string
{
    $headerToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
    if (is_string($headerToken) && $headerToken !== '') {
        return $headerToken;
    }

    $postedToken = $_POST['csrf_token'] ?? null;

    return is_string($postedToken) ? $postedToken : null;
}

function normalizeAddonDomain(string $value): string
{
    $domain = strtolower(trim($value));
    $domain = preg_replace('/^https?:\/\//i', '', $domain) ?? '';
    $domain = trim($domain, " \t\n\r\0\x0B./");

    if ($domain === '' || strlen($domain) > 253) {
        return '';
    }

    if (preg_match('/[\/\\\\:@?#\[\]]/', $domain) === 1) {
        return '';
    }

    if (preg_match('/^(localhost|localdomain)$/i', $domain) === 1) {
        return '';
    }

    if (filter_var($domain, FILTER_VALIDATE_IP) !== false) {
        return '';
    }

    if (preg_match('/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain) !== 1) {
        return '';
    }

    return $domain;
}

function showLoginPasswordProtect(string $errorMsg, string $nonce, string $csrfToken): never
{
    header('Location: /login.php');
    exit;
}

startAdminSession();

include_once __DIR__ . '/../password.login.php';
include_once __DIR__ . '/../xmlapi.php';
/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';
include_once dirname(__DIR__, 2) . '/env.php';
load_env_file(dirname(__DIR__, 2) . '/.env');

// Best-effort public IP of this server, offered as a one-click fill for the
// "Server IP" field (used for the addon domains' DNS A record).
$srpDetectedServerIp = '';
$srpServerAddrCandidate = (string) ($_SERVER['SERVER_ADDR'] ?? '');
if (
    $srpServerAddrCandidate !== ''
    && filter_var($srpServerAddrCandidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
) {
    $srpDetectedServerIp = $srpServerAddrCandidate;
}

$nonce = base64_encode(random_bytes(18));
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
    . "base-uri 'self'; "
    . "form-action 'self'; "
    . "frame-ancestors 'self'; "
    . "img-src 'self' data: https:; "
    . "font-src 'self' data: https:; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com; "
    . "script-src 'self' 'nonce-{$nonce}'; "
    . "connect-src 'self';",
);

if (isset($_GET['help'])) {
    $self = str_replace('\\', '\\\\', __FILE__);
    exit('Include following code into every page you would like to protect, at the very beginning (first line):<br>&lt;?php include("' . $self . '"); ?&gt;');
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    if (!adminHasValidCsrf(adminRequestCsrfToken())) {
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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'cpanel_delete') {
    header('Content-Type: application/json; charset=utf-8');

    if (!adminHasValidCsrf(adminRequestCsrfToken())) {
        http_response_code(419);
        echo json_encode(['ok' => false, 'err' => 'invalid-csrf']);
        exit;
    }

    $domain = normalizeAddonDomain((string) ($_POST['domain'] ?? ''));
    if ($domain === '') {
        http_response_code(422);
        echo json_encode(['ok' => false, 'err' => 'invalid-domain']);
        exit;
    }

    try {
        $cpanelUser        = app_required_env('CPANEL_USER');
        $cpanelPort        = (int) app_env('CPANEL_PORT', '2083');
        $cpanelHost        = app_detect_cpanel_host(app_env('CPANEL_HOST', 'localhost'), $cpanelPort);
        $token             = app_env('CPANEL_API_TOKEN', '');

        $xmlApi = new xmlapi($cpanelHost);
        $xmlApi->set_port($cpanelPort);
        $xmlApi->set_output('json');
        $xmlApi->set_debug(0);

        if ($token !== '') {
            $xmlApi->token_auth($cpanelUser, $token);
        } else {
            $xmlApi->password_auth($cpanelUser, app_required_env('CPANEL_PASSWORD'));
        }

        $delWildcard = $xmlApi->api2_query($cpanelUser, 'SubDomain', 'delsubdomain', [
            'domain' => '*.' . $domain,
        ]);
        $unpark = $xmlApi->api2_query($cpanelUser, 'Park', 'unpark', [
            'domain' => $domain,
        ]);

        echo json_encode(['ok' => true, 'domain' => $domain, 'del_wildcard' => $delWildcard, 'unpark' => $unpark]);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['ok' => false, 'err' => 'cpanel-request-failed']);
    }
    exit;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>ADMIN PANEL</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= adminEsc($csrfToken); ?>">
    <link href="/favicon.ico" rel="icon" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Caveat:wght@500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/bootstrap.min.css" type="text/css" media="all">
    <link href="/assets/css/flags-public.css" rel="stylesheet">
    <link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/addondomain-1.css') ?>">
</head>
<body>
<script nonce="<?= adminEsc($nonce); ?>" src="/assets/js/jquery-1.11.1.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>" src="/assets/js/bootstrap.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>">
(function ($) {
    'use strict';

    $.ajaxSetup({
        headers: {
            'X-CSRF-Token': <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>,
            'X-CSRF-Context': 'admin_panel'
        }
    });
}(jQuery));
</script>
<script src="<?= srpAssetUrl('/assets/js/addondomain-1.js') ?>"></script>

<div role="navigation" class="navbar navbar-default navbar-fixed-top">
        <div class="container">
            <div class="navbar-header">
                <button data-target=".navbar-collapse" data-toggle="collapse" class="navbar-toggle" type="button">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a href="#" class="navbar-brand"><strong>Admin Panel</strong></a>
            </div>
            <div class="navbar-collapse collapse navbar-right">
                <ul class="nav navbar-nav">
                    <li><a href="/dashboard/"><strong>Dashboard</strong></a></li>
                    <li><a href="/campaigns/"><strong>Campaigns</strong></a></li>
                    <li class="active"><a href="#"><strong>Addon Domain</strong></a></li>
                    <li>
                        <form method="post">
                            <input type="hidden" name="action" value="logout">
                            <input type="hidden" name="csrf_token" value="<?= adminEsc($csrfToken); ?>">
                            <button type="submit" class="navbar-btn btn-link"><strong>Logout</strong></button>
                        </form>
                    </li>
                </ul>
            </div>
            <!--/.nav-collapse -->
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
                            <span class="input-group-addon"><svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></span>
                            <input type="text" class="form-control" id="tbl-search" placeholder="Search...">
                        </div>
                        <div class="ddt" id="ddt-rowcount">
                            <button type="button" class="btn btn-sm ddt-btn" id="ddt-rowcount-btn"><span class="ddt-label">25</span><svg class="ddt-caret" viewBox="0 0 10 6" width="10" height="6" fill="currentColor" aria-hidden="true" focusable="false"><path d="M0 0l5 6 5-6z"/></svg></button>
                            <ul class="ddt-menu" id="ddt-rowcount-menu">
                                <li><a href="#" data-val="25" class="ddt-active">25</a></li>
                                <li><a href="#" data-val="50">50</a></li>
                                <li><a href="#" data-val="-1">All</a></li>
                            </ul>
                        </div>
                        <input type="hidden" id="tbl-rowcount" value="25">
                    </div>
                    <div style="display:inline-flex;gap:6px;align-items:center;">
                    <button type="button" class="btn btn-sm btn-default btn-icon" id="command-cf-config" title="Cloudflare Configuration">
                        <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07M8.46 8.46a5 5 0 0 0 0 7.07"/></svg> CF Config</button>
                    <button type="button" class="btn btn-sm btn-default btn-icon" id="command-sync-all" title="Sync all domains to Cloudflare">
                        <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg> Sync All CF</button>
                    <button type="button" class="btn btn-sm btn-primary btn-icon" id="command-add" data-row-id="0">
                        <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 5v14"/><path d="M5 12h14"/></svg> Addon Domain</button>
                    </div>
                </div>
                <div style="overflow-x:auto;">
                    <table id="tbl_domains" class="table table-hover">
                        <thead>
                            <tr>
                                <th>Empid</th>
                                <th>Domain Title</th>
                                <th>Domain Name</th>
                                <th>CF Status</th>
                                <th style="text-align:right;">Action</th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
                <div class="tbl-footer">
                    <span id="tbl-info"></span>
                    <ul class="pagination pagination-compact" id="tbl-pagination"></ul>
                </div>
            </div>
            <div class="app-sign"><footer>Ngix · xctd</footer></div>
        </div>
        <div id="add_model" class="modal fade" data-keyboard="false" data-backdrop="static">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <a class="close" data-dismiss="modal" aria-hidden="true">&times;</a>
                        <h4 class="modal-title">Addon Domain</h4>
                    </div>

                    <div class="modal-body">
                        <blockquote class="ns-card">
                            <p class="text-warning">Nameserver:</p>
                            <div class="text-muted" id="ns-info-list">
                                <span style="opacity:.6;">Memuat…</span>
                            </div>
                        </blockquote>
                        <form method="post" id="frm_add">
                            <input type="hidden" value="add" name="action" id="action">
                            <div class="form-group">
                                <label for="adddomain" class="control-label">Domain Title: use [GLOBAL DOMAIN] for submit into global domain</label>
                                <hr style="margin:1px;padding:1px;border:0;border-bottom:0px">
                                <div class="ddt ddt-full" id="ddt-adddomain">
                                    <button type="button" class="btn btn-sm ddt-btn" id="ddt-adddomain-btn" aria-haspopup="listbox"><span class="ddt-label">[GLOBAL DOMAIN]</span><svg class="ddt-caret" viewBox="0 0 10 6" width="10" height="6" fill="currentColor" aria-hidden="true" focusable="false"><path d="M0 0l5 6 5-6z"/></svg></button>
                                    <ul class="ddt-menu" id="ddt-adddomain-menu" role="listbox">
                                        <li><a href="#" data-val="global" class="ddt-active">[GLOBAL DOMAIN]</a></li>
                                        <?php
                                        $stmtGen = $pdo->query('SELECT sub_id FROM generate ORDER BY sub_id ASC');
if ($stmtGen !== false) {
    while ($rowGen = $stmtGen->fetch(PDO::FETCH_ASSOC)) {
        $subIdRaw = $rowGen['sub_id'] ?? '';
        $subId = is_string($subIdRaw) ? $subIdRaw : '';
        $sid = htmlspecialchars(
            $subId,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8',
        );
        echo '<li><a href="#" data-val="' . $sid . '">' . $sid . '</a></li>';
    }
}
?>
                                    </ul>
                                </div>
                                <input type="hidden" id="adddomain" value="global">
                                <input readonly="readonly" type="hidden" class="form-control" id="sub_domain" name="sub_domain" required="true" />
                            </div>
                            <div class="form-group">
                                <label for="domain" class="control-label">Domain Name: <span class="text-muted">(1 domain per submit)</span></label>
                                <input type="text" placeholder="example.com" class="form-control mono-input" id="domain" name="domain" required="true" autofocus>
                            </div>
                            <div class="cf-toggle-row">
                                <label for="cf-add-toggle" class="cf-toggle-label">
                                    <span class="cf-switch">
                                        <input type="checkbox" id="cf-add-toggle" checked>
                                        <span class="cf-switch-track"></span>
                                    </span>
                                    <span>Auto-integrasi: cPanel wildcard &rarr; <strong>Cloudflare</strong> (zone, security, settings, DNS)</span>
                                </label>
                            </div>
                        </form>
                    </div>
                    <div id="add-cf-panel" style="display:none;">
                        <div id="add-cf-loader" style="display:none;text-align:center;padding:22px 0 14px;">
                            <svg style="animation:cf-spin .8s linear infinite;color:var(--muted);" viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                            <div id="add-cf-status-text" style="margin-top:6px;font-size:var(--fs-sm);color:var(--muted);">CF Sync…</div>
                        </div>
                        <blockquote class="ns-card" id="add-cf-ns-block" style="display:none;">
                            <p class="text-warning">Nameserver Cloudflare:</p>
                            <div id="add-cf-ns-panel"></div>
                        </blockquote>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                        <button type="button" id="btn_add" class="btn btn-primary">Save</button>
                    </div>
                </div>
            </div>
        </div>
        <div id="edit_model" class="modal fade" data-keyboard="false" data-backdrop="static">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <a class="close" data-dismiss="modal" aria-hidden="true">&times;</a>
                        <h4 class="modal-title">Edit Domain</h4>
                    </div>
                    <div class="modal-body">
                        <form method="post" id="frm_edit">
                            <input type="hidden" value="edit" name="action" id="action">
                            <input type="hidden" value="0" name="edit_id" id="edit_id">

                            <div class="form-group">
                                <label for="edit_sub_domain" class="control-label">Domain Title:</label>
                                <input readonly="readonly" type="text" class="form-control" id="edit_sub_domain" name="edit_sub_domain" />
                            </div>
                            <div class="form-group">
                                <label for="edit_domain" class="control-label">Domain Name:</label>
                                <input type="text" class="form-control" id="edit_domain" name="edit_domain" required="true" autofocus/>
                            </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                        <button type="button" id="btn_edit" class="btn btn-primary">Save</button>
                    </div>
                    </form>
                </div>
            </div>
        </div>
        <div id="cf_config_modal" class="modal fade" data-keyboard="true" data-backdrop="static">
            <div class="modal-dialog" style="max-width:440px;">
                <div class="modal-content">
                    <div class="modal-header">
                        <a class="close" data-dismiss="modal" aria-hidden="true">&times;</a>
                        <h4 class="modal-title">
                            <svg viewBox="0 0 24 24" width="15" height="15" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;vertical-align:-2px;" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07M8.46 8.46a5 5 0 0 0 0 7.07"/></svg>
                            Cloudflare Configuration
                        </h4>
                    </div>
                    <div class="modal-body">
                        <p style="margin:0 0 12px;font-size:var(--fs-sm);color:var(--text);opacity:.8;">Perubahan langsung disimpan ke <code>.env</code>. Refresh halaman setelah simpan agar efektif.</p>
                        <div class="form-group">
                            <label class="control-label">CF API Token</label>
                            <div style="display:flex;gap:6px;align-items:center;">
                                <input type="password" class="form-control" id="cfg_cf_token" placeholder="Kosongkan = tidak diubah" autocomplete="new-password">
                                <button type="button" class="btn btn-sm btn-default" id="cfg_cf_token_toggle" title="Tampilkan/sembunyikan" style="flex-shrink:0;padding:4px;">
                                    <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                </button>
                            </div>
                            <small style="font-size:var(--fs-xs);color:var(--text);opacity:.68;">Untuk auto-create token, paste token dari template <strong>Create Additional Tokens</strong> lalu klik tombol Create Additional Tokens.</small>
                        </div>
                        <div class="cf-permission-panel">
                            <div class="cf-permission-head">
                                <div class="cf-permission-title">Permission yang dibutuhkan (Custom Token):</div>
                                <button type="button" class="btn btn-sm btn-default cf-permission-toggle" data-target="cf-permission-body-admin" aria-expanded="false">Show</button>
                            </div>
                            <div class="cf-permission-body" id="cf-permission-body-admin">
                            <div class="cf-permission-table">
                                <div class="cf-perm-row cf-perm-row--head"><span>Scope</span><span>Permission</span><span>Access</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Account</span><span>Account Settings</span><span class="cf-perm-access">Read</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Account</span><span>Zone</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone</span><span class="cf-perm-access">Read</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone Settings</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone Settings</span><span class="cf-perm-access">Read</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>SSL and Certificates</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>DNS</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>DNS</span><span class="cf-perm-access">Read</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Cache Rules</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Cache Rules</span><span class="cf-perm-access">Read</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Account</span><span>Rulesets</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Account</span><span>Filter Lists</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Cache Purge</span><span class="cf-perm-access">Purge</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Managed Headers</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Transform Rules</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone WAF</span><span class="cf-perm-access">Edit</span></div>
                            </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="control-label">CF Account ID</label>
                            <input type="text" class="form-control" id="cfg_cf_account" placeholder="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">
                        </div>
                        <div class="form-group">
                            <label class="control-label">TINYURL API Key</label>
                            <input type="password" class="form-control cf-secret-input" id="cfg_tinyurl_api_key" placeholder="Kosongkan = tidak diubah" autocomplete="new-password">
                        </div>
                        <div class="form-group">
                            <label class="control-label">MaxMind License Key</label>
                            <input type="password" class="form-control cf-secret-input" id="cfg_maxmind_license_key" placeholder="Kosongkan = tidak diubah" autocomplete="new-password">
                        </div>
                        <div class="form-group">
                            <label class="control-label">Server IP <small style="font-weight:var(--fw-regular);opacity:.7;">(untuk auto DNS A record)</small></label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="cfg_cf_ip" placeholder="1.2.3.4">
                                <span class="input-group-btn">
                                    <button type="button" class="btn btn-default" id="cfg_cf_ip_detect" title="Deteksi otomatis IP server" data-detected-ip="<?= adminEsc($srpDetectedServerIp); ?>">
                                        <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>
                                    </button>
                                </span>
                            </div>
                        </div>
                        <div class="form-group" style="margin-bottom:4px;">
                            <label class="control-label">Default Nameservers <small style="font-weight:var(--fw-regular);opacity:.7;">(default fallback jika domain belum sync)</small></label>
                            <input type="text" class="form-control mono-input" id="cfg_cf_ns1" placeholder="ns1.example.com" style="margin-bottom:5px;">
                            <input type="text" class="form-control mono-input" id="cfg_cf_ns2" placeholder="ns2.example.com" style="margin-bottom:5px;">
                            <input type="text" class="form-control mono-input" id="cfg_cf_ns3" placeholder="ns3.example.com (opsional)" style="margin-bottom:5px;">
                            <input type="text" class="form-control mono-input" id="cfg_cf_ns4" placeholder="ns4.example.com (opsional)">
                        </div>
                        <div id="cfg_status" style="display:none;margin-top:8px;padding:7px 10px;border-radius:var(--radius);font-size:var(--fs-sm);"></div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default btn-sm" data-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-default btn-sm" id="cfg_create_additional_token">Create Additional Tokens</button>
                        <button type="button" class="btn btn-primary btn-sm" id="cfg_save_btn">
                            <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                            Simpan
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <div id="cf_ns_modal" class="modal fade" data-keyboard="false" data-backdrop="static">
            <div class="modal-dialog" style="max-width:480px;">
                <div class="modal-content">
                    <div class="modal-header">
                        <a class="close" data-dismiss="modal" aria-hidden="true">&times;</a>
                        <h4 class="modal-title">Cloudflare Nameservers</h4>
                    </div>
                    <div class="modal-body">
                        <p style="margin:0 0 8px;font-size:var(--fs-sm);color:var(--text);">
                            Point your domain <strong class="cf-ns-domain"></strong> to these nameservers at your domain registrar:
                        </p>
                        <ul class="cf-ns-list" style="margin:0;padding-left:18px;list-style:disc;"></ul>
                        <p style="margin:10px 0 0;font-size:var(--fs-sm);color:var(--text);opacity:.72;">
                            DNS propagation may take up to 24 hours. Run <em>Sync</em> again after pointing NS to refresh status.
                        </p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    <script nonce="<?= adminEsc($nonce); ?>">
    $(document).ready(function() {
        var ngixButtonSpinner = '<svg class="btn-spin" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="8" cy="8" r="6" stroke-opacity=".3"></circle><path d="M8 2a6 6 0 0 1 6 6"></path><\/svg> ';
        // PermissionToggleFixedInit
        $(document).on('click', '.cf-permission-toggle', function(e) {
            e.preventDefault();
            e.stopPropagation();

            var targetId = $(this).attr('data-target');
            var panel = document.getElementById(targetId);
            if (!panel) {
                return;
            }

            var isOpen = panel.classList.toggle('is-open');
            this.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
            this.textContent = isOpen ? 'Hide' : 'Show';
        });

        function svgIcon(type) {
            var filledAttrs = ' width="16" height="16" viewBox="0 -960 960 960" fill="currentColor" focusable="false"';
            if (type === 'delete') {
                return '<span class="action-ico action-ico--filled" aria-hidden="true"><svg' + filledAttrs + '><path d="M259-104q-30.75 0-51.87-21.13Q186-146.25 186-177v-575h-41v-73h202v-34h267v34h202v73h-41v575q0 28.73-22.14 50.86Q730.72-104 702-104zm443-648H259v575h443zM357-264h73v-403h-73zm175 0h73v-403h-73zM259-752v575z"/></svg></span>';
            }
            return '<span class="action-ico action-ico--filled" aria-hidden="true"><svg' + filledAttrs + '><path d="M194-194h57l371-371-57-56-371 371zM88-88v-206l558-558q11-11 24.5-15.5T698-872t26.5 4 23.5 15l105 105q11 11 15 24t4 27-4.5 27-15.5 24L294-88zm666-609-57-56zM594-593l-29-28 57 56z"/></svg></span>';
        }
        function escHtml(v) {
            return String(v === null || v === undefined ? '' : v)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        var state = { current: 1, rowCount: 25, search: '' };

        $("#adddomain").on('change', function() { $("#sub_domain").val(this.value); });
        $("#sub_domain").val('global');
        (function(){var btn=document.getElementById('ddt-adddomain-btn'),menu=document.getElementById('ddt-adddomain-menu'),inp=document.getElementById('adddomain');if(!btn||!menu||!inp)return;btn.addEventListener('click',function(e){e.stopPropagation();menu.classList.toggle('open');});menu.addEventListener('click',function(e){var a=e.target.closest?e.target.closest('a'):(e.target.tagName==='A'?e.target:null);if(!a)return;e.preventDefault();var v=a.getAttribute('data-val');menu.querySelectorAll('a').forEach(function(el){el.classList.remove('ddt-active');});a.classList.add('ddt-active');btn.querySelector('.ddt-label').textContent=a.textContent.trim();inp.value=v;menu.classList.remove('open');$(inp).trigger('change');});document.addEventListener('click',function(){menu.classList.remove('open');});})();

        function cfStatusBadge(row) {
            var hasZone = row.cf_zone_id && row.cf_zone_id !== '';
            var status = hasZone ? (row.cf_status || 'unknown') : (row.domain_status || 'none');
            if (status === '' || status === 'none') {
                return '<span class="cf-badge cf-badge--none" title="Not synced">— none</span>';
            }
            var cls = 'cf-badge';
            var label = status;
            if (status === 'active') { cls += ' cf-badge--active'; label = '<svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg> aktif'; }
            else if (status === 'pending') { cls += ' cf-badge--pending'; label = '<svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> pending'; }
            else if (status === 'moved') { cls += ' cf-badge--moved'; label = '<svg viewBox="0 0 24 24" width="10" height="10" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px" aria-hidden="true"><line x1="7" y1="17" x2="17" y2="7"/><polyline points="7 7 17 7 17 17"/></svg> moved'; }
            var title = hasZone ? 'Zone: ' + escHtml(row.cf_zone_id || '') : 'cPanel DNS status';
            return '<span class="' + cls + '" title="' + title + '">' + label + '</span>';
        }

        function cfSvg(type) {
            var a = ' width="14" height="14" viewBox="0 0 24 24" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"';
            if (type === 'sync') return '<svg' + a + '><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg>';
            if (type === 'purge') return '<svg' + a + '><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>';
            if (type === 'speed') return '<svg' + a + '><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>';
            if (type === 'origin') return '<svg' + a + '><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14v3"/></svg>';
            if (type === 'unlink') return '<svg' + a + '><path d="M15 7h3a5 5 0 0 1 0 10h-3M9 17H6a5 5 0 0 1 0-10h3"/></svg>';
            if (type === 'cpanel-ssl') return '<svg' + a + '><path d="M12 2 4 6v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-4z"/><path d="m9 12 2 2 4-4"/></svg>';
            return '';
        }

        function renderRow(row, idx) {
            var hasZone = row.cf_zone_id && row.cf_zone_id !== '';
            var cfStatus = hasZone ? (row.cf_status || '') : '';
            return '<tr data-row-id="' + escHtml(row.id) + '" data-cf-status="' + escHtml(cfStatus) + '" data-cf-cert="' + (String(row.cf_cert_installed) === '1' ? '1' : '0') + '">' +
                '<td><span class="td-num">' + (idx + 1) + '</span></td>' +
                '<td><span class="td-subdomain">' + escHtml(row.sub_domain) + '</span></td>' +
                '<td><span class="td-domain" title="' + escHtml(row.domain) + '">' + escHtml(row.domain) + '</span></td>' +
                '<td>' + cfStatusBadge(row) + '</td>' +
                '<td style="text-align:right;white-space:nowrap;">' +
                    '<button type="button" class="btn-cf command-cf-sync" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" title="Sync to Cloudflare">' + cfSvg('sync') + '</button>' +
                    (hasZone ? '<button type="button" class="btn-cf command-cf-purge" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" title="Purge CF Cache">' + cfSvg('purge') + '</button>' : '<button type="button" class="btn-cf" disabled style="opacity:.3;cursor:default;" title="No zone yet">' + cfSvg('purge') + '</button>') +
                    (hasZone ? '<button type="button" class="btn-cf command-cf-speed" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" title="Apply CF Speed Optimizations">' + cfSvg('speed') + '</button>' : '<button type="button" class="btn-cf" disabled style="opacity:.3;cursor:default;" title="No zone yet">' + cfSvg('speed') + '</button>') +
                    (hasZone ? '<button type="button" class="btn-cf command-cf-origin-cert" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" title="Install CF Origin Certificate">' + cfSvg('origin') + '</button>' : '<button type="button" class="btn-cf" disabled style="opacity:.3;cursor:default;" title="No zone yet">' + cfSvg('origin') + '</button>') +
                    '<button type="button" class="btn-cf command-cf-origin-cert-to-cpanel" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" title="Remove CF Origin Certificate, switch to cPanel SSL (AutoSSL)">' + cfSvg('cpanel-ssl') + '</button>' +
                    (hasZone ? '<button type="button" class="btn-cf command-cf-unlink" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" title="Unlink from Cloudflare (keep domain)">' + cfSvg('unlink') + '</button>' : '') +
                    ' <button type="button" class="btn btn-sm btn-default action-btn command-delete" data-row-id="' + escHtml(row.id) + '" data-domain="' + escHtml(row.domain) + '" data-zone-id="' + escHtml(row.cf_zone_id || '') + '" title="Delete" aria-label="Delete">' + svgIcon('delete') + '</button>' +
                '</td></tr>';
        }

        function renderPagination(total, current, rowCount) {
            if (rowCount === -1 || total === 0) { $('#tbl-pagination').empty(); return; }
            var pages = Math.ceil(total / rowCount);
            if (pages <= 1) { $('#tbl-pagination').empty(); return; }
            var html = '';
            html += '<li class="' + (current <= 1 ? 'disabled' : '') + '"><a href="#" data-page="' + (current - 1) + '">&laquo;</a></li>';
            var start = Math.max(1, current - 2), end = Math.min(pages, current + 2);
            if (start > 1) { html += '<li><a href="#" data-page="1">1</a></li>' + (start > 2 ? '<li class="disabled"><span>…</span></li>' : ''); }
            for (var p = start; p <= end; p++) {
                html += '<li class="' + (p === current ? 'active' : '') + '"><a href="#" data-page="' + p + '">' + p + '</a></li>';
            }
            if (end < pages) { html += (end < pages - 1 ? '<li class="disabled"><span>…</span></li>' : '') + '<li><a href="#" data-page="' + pages + '">' + pages + '</a></li>'; }
            html += '<li class="' + (current >= pages ? 'disabled' : '') + '"><a href="#" data-page="' + (current + 1) + '">&raquo;</a></li>';
            $('#tbl-pagination').html(html);
            $('#tbl-pagination').off('click', 'a').on('click', 'a', function(e) {
                e.preventDefault();
                var pg = parseInt($(this).data('page'));
                if (!isNaN(pg) && pg >= 1 && pg <= pages && pg !== state.current) {
                    state.current = pg; loadData();
                }
            });
        }

        function cfRequest(action, rowId, extra, btn) {
            if (btn) { $(btn).prop('disabled', true).addClass('btn-cf--loading'); }
            var data = $.extend({ action: action, id: rowId }, extra || {});
            return $.ajax({ type: 'POST', url: 'cf.php', data: data, dataType: 'json' })
                .always(function() { if (btn) { $(btn).prop('disabled', false).removeClass('btn-cf--loading'); } });
        }

        function cfUpdateRowBadge(rowId, cfStatus, zoneId, cfNs) {
            var tr = $('#tbl_domains tbody tr[data-row-id="' + rowId + '"]');
            if (!tr.length) { return; }
            var fakeRow = { cf_zone_id: zoneId, cf_status: cfStatus, cf_ns: cfNs };
            tr.find('td:nth-child(4)').html(cfStatusBadge(fakeRow));
            tr.attr('data-cf-status', (zoneId && zoneId !== '') ? (cfStatus || '') : '');
        }

        function cfSync(rowId, domain, btn) {
            // Show NS modal immediately with spinner
            $('#cf_ns_modal .cf-ns-domain').text(domain);
            $('#cf_ns_modal .cf-ns-list').html(
                '<li style="text-align:center;padding:18px 0;list-style:none;">' +
                '<svg style="animation:cf-spin .8s linear infinite;color:var(--muted);" viewBox="0 0 24 24" width="28" height="28" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>' +
                '<div style="margin-top:10px;font-size:var(--fs-sm);color:var(--muted);">Syncing to Cloudflare…</div>' +
                '</li>'
            );
            $('#cf_ns_modal').modal('show');

            cfRequest('zone_add', rowId, {}, btn)
                .done(function(data) {
                    if (data && data.ok) {
                        var dnsInfo = '';
                        if (data.dns_log && data.dns_log.length) {
                            var errs = data.dns_log.filter(function(l){ return l.indexOf('error:') === 0; }).length;
                            dnsInfo = ' · DNS: ' + (data.dns_log.length - errs) + ' ok' + (errs ? ', ' + errs + ' err' : '');
                        }
                        showToast('success', 'CF Zone OK', (data.cf_status || '') + ' — ' + domain + dnsInfo);
                        if (data.cf_warnings) { showToast('error', 'CF: ' + data.cf_warnings + ' operasi gagal', (data.cf_warning_sample && data.cf_warning_sample[0]) || 'cek error_log — kemungkinan izin token'); }
                        cfUpdateRowBadge(rowId, data.cf_status, data.zone_id, JSON.stringify(data.cf_ns || []));
                        // Replace spinner with NS info in the already-open modal
                        cfShowNsInPlace(rowId, domain, JSON.stringify(data.cf_ns || []));
                        if (data.cf_status === 'active') { cfAutoInstallCertOnce(rowId, domain); }
                    } else {
                        showToast('error', 'CF Error', (data && data.err) || 'zone_add failed');
                        $('#cf_ns_modal').modal('hide');
                    }
                })
                .fail(function() {
                    showToast('error', 'CF Sync Failed', domain);
                    $('#cf_ns_modal').modal('hide');
                });
        }

        function cfPurge(rowId, domain, btn) {
            cfRequest('purge_cache', rowId, {}, btn)
                .done(function(data) {
                    if (data && data.ok) { showToast('success', 'Cache Purged', domain); }
                    else { showToast('error', 'Purge Failed', (data && data.err) || ''); }
                })
                .fail(function() { showToast('error', 'Purge Failed', domain); });
        }

        function cfSpeed(rowId, domain, btn) {
            cfRequest('speed', rowId, {}, btn)
                .done(function(data) {
                    if (data && data.ok) {
                        if (data.warnings) {
                            showToast('error', 'Speed: ' + data.warnings + ' skipped', (data.sample && data.sample[0]) || 'cek error_log — kemungkinan izin/plan token');
                        } else {
                            showToast('success', 'Speed Optimized', domain + ' — brotli, minify, HTTP/3, cache, Argo');
                        }
                    } else {
                        showToast('error', 'Speed Failed', (data && data.err) || '');
                    }
                })
                .fail(function() { showToast('error', 'Speed Failed', domain); });
        }

        function cfUnlink(rowId, domain, btn) {
            Swal.fire({
                title: 'Unlink from Cloudflare?',
                text: 'Deletes the Cloudflare zone for ' + domain + ' and clears its CF settings. The domain row itself is kept — you can Sync it again later to re-provision a fresh zone.',
                type: 'warning',
                showCancelButton: true,
                allowOutsideClick: false,
                confirmButtonColor: '#6c757d',
                cancelButtonColor: '#6c757d',
                confirmButtonText: 'Yes, unlink it!'
            }).then(function(result) {
                if (!result.value) { return; }
                cfRequest('zone_unlink', rowId, {}, btn)
                    .done(function(data) {
                        if (data && data.ok) {
                            showToast('success', 'Unlinked', domain + ' — no longer managed by Cloudflare');
                            cfUpdateRowBadge(rowId, '', '', '[]');
                            var $tr = $('#tbl_domains tbody tr[data-row-id="' + rowId + '"]');
                            $tr.attr('data-cf-cert', '0');
                            cfCertDoneSet(domain, false);
                            loadData();
                            cfShowUnlinkNsNotice(domain);
                        } else {
                            showToast('error', 'Unlink Failed', (data && data.err) || domain);
                        }
                    })
                    .fail(function() { showToast('error', 'Unlink Failed', domain); });
            });
        }

        // After unlink, the domain's old Cloudflare nameservers are dead (the
        // zone is gone) — warn the admin so a "parked but unreachable" domain
        // doesn't go unnoticed, and give them the server IP so they can point
        // an A record straight at it if they want to keep the site up without
        // Cloudflare in front of it.
        function cfShowUnlinkNsNotice(domain) {
            $.ajax({ type: 'POST', url: 'cf.php', data: { action: 'config_get' }, dataType: 'json' })
                .done(function(res) {
                    var ip = (res && res.config && res.config.CF_SERVER_IP) || '';
                    var ipLine = ip
                        ? '<p style="margin:8px 0 0;font-family:var(--mono);font-size:var(--fs-sm);">A @ &rarr; ' + escHtml(ip) + '</p>'
                        : '';
                    Swal.fire({
                        title: 'Update DNS for ' + domain,
                        type: 'info',
                        html:
                            '<p style="margin:0;text-align:left;font-size:var(--fs-sm);">' +
                            'The Cloudflare zone is gone, so this domain’s old Cloudflare nameservers no longer resolve it. ' +
                            'Update its NS at the registrar (point it elsewhere, or back to your host’s default NS) — ' +
                            'or, to keep it working without Cloudflare in front, point an A record straight at this server:' +
                            '</p>' + ipLine,
                        confirmButtonText: 'Got it'
                    });
                });
        }

        function cfOriginCertInstall(rowId, domain, btn) {
            showToast('info', 'Installing Origin Certificate…', domain);
            cfRequest('origin_cert_install', rowId, {}, btn)
                .done(function(data) {
                    if (data && data.ok) {
                        var cert = data.origin_cert || {};
                        showToast('success', 'Origin Certificate Installed', (cert.ssl_mode || 'strict') + ' — ' + domain);
                    } else {
                        showToast('error', 'Origin Cert Failed', (data && data.err) || domain);
                    }
                })
                .fail(function(xhr) {
                    var msg = domain;
                    if (xhr && xhr.responseJSON && xhr.responseJSON.err) { msg = xhr.responseJSON.err; }
                    showToast('error', 'Origin Cert Failed', msg);
                });
        }

        function cfOriginCertToCpanel(rowId, domain, btn) {
            Swal.fire({
                title: 'Switch to cPanel SSL?',
                text: 'Removes the installed Cloudflare Origin Certificate for ' + domain + ' and triggers cPanel AutoSSL (Let\'s Encrypt) to issue a replacement. These are two separate steps — there is a real window, from seconds to a few minutes, where the domain has no valid SSL certificate at all until AutoSSL finishes. AutoSSL also checks every domain on the account, not just this one, so it may take a while.',
                type: 'warning',
                showCancelButton: true,
                allowOutsideClick: false,
                confirmButtonColor: '#6c757d',
                cancelButtonColor: '#6c757d',
                confirmButtonText: 'Yes, switch it!'
            }).then(function(result) {
                if (!result.value) { return; }
                showToast('info', 'Switching to cPanel SSL…', domain);
                cfRequest('origin_cert_to_cpanel', rowId, {}, btn)
                    .done(function(data) {
                        if (data && data.ok) {
                            var r = data.result || {};
                            var msg = (r.removed ? 'Origin cert removed' : 'No origin cert to remove')
                                + ', AutoSSL ' + (r.autossl_triggered ? 'triggered' : 'trigger failed') + '.';
                            showToast(r.autossl_triggered ? 'success' : 'error', 'cPanel SSL', domain + ' — ' + msg);
                            var $tr = $('#tbl_domains tbody tr[data-row-id="' + rowId + '"]');
                            $tr.attr('data-cf-cert', '0');
                            cfCertDoneSet(domain, false);
                        } else {
                            showToast('error', 'Switch Failed', (data && data.err) || domain);
                        }
                    })
                    .fail(function(xhr) {
                        var msg = domain;
                        if (xhr && xhr.responseJSON && xhr.responseJSON.err) { msg = xhr.responseJSON.err; }
                        showToast('error', 'Switch Failed', msg);
                    });
            });
        }

        // ── Auto CF status poll + one-time origin cert on first 'active' ──────
        var CF_POLL_INTERVAL_MS = 45000; // re-check pending zones every 45s
        var cfPollBusy = false;

        // Durable per-browser guard so auto-cert runs at most once per domain.
        // (DB has no cert column; this is client-side state — see CLAUDE.md.)
        function cfCertDoneMap() {
            try { return JSON.parse(localStorage.getItem('srp_addon_cf_cert_done') || '{}') || {}; }
            catch (e) { return {}; }
        }
        function cfCertDoneHas(domain) {
            return !!cfCertDoneMap()[String(domain).toLowerCase()];
        }
        function cfCertDoneSet(domain, done) {
            try {
                var m = cfCertDoneMap(), key = String(domain).toLowerCase();
                if (done) { m[key] = 1; } else { delete m[key]; }
                localStorage.setItem('srp_addon_cf_cert_done', JSON.stringify(m));
            } catch (e) {}
        }

        // Mark domains already 'active' at render time as handled WITHOUT
        // installing, so auto-cert only fires for domains that reach 'active'
        // afterwards (genuinely "first time" from the panel). Prevents
        // retroactively re-issuing certs for the existing active fleet.
        function cfSeedActiveAsHandled() {
            $('#tbl_domains tbody tr[data-row-id]').each(function() {
                var $tr = $(this);
                var domain = $tr.find('.command-cf-sync').data('domain') || '';
                if (!domain) { return; }
                // Server truth wins: cert recorded installed → durable guard.
                if (($tr.attr('data-cf-cert') || '') === '1') { cfCertDoneSet(domain, true); return; }
                // Anti-retroactive: suppress domains already 'active' at load so
                // auto-cert only fires for ones that reach active afterwards.
                if (($tr.attr('data-cf-status') || '') === 'active' && !cfCertDoneHas(domain)) {
                    cfCertDoneSet(domain, true);
                }
            });
        }

        // Install the CF origin certificate exactly once for a domain that has
        // just become active. Guard is set before the call to block re-entry;
        // rolled back on failure so a later poll/sync can retry.
        function cfAutoInstallCertOnce(rowId, domain) {
            if (!domain || cfCertDoneHas(domain)) { return; }
            cfCertDoneSet(domain, true);
            showToast('info', 'Auto SSL…', 'Origin cert untuk ' + domain);
            cfRequest('origin_cert_install', rowId, { auto: '1' })
                .done(function(data) {
                    if (data && data.ok) {
                        $('#tbl_domains tbody tr[data-row-id="' + rowId + '"]').attr('data-cf-cert', '1');
                        if (data.already_installed) { return; }
                        var cert = data.origin_cert || {};
                        showToast('success', 'Auto SSL OK', (cert.ssl_mode || 'strict') + ' — ' + domain);
                    } else {
                        cfCertDoneSet(domain, false);
                        showToast('error', 'Auto SSL Gagal', (data && data.err) || domain);
                    }
                })
                .fail(function(xhr) {
                    cfCertDoneSet(domain, false);
                    showToast('error', 'Auto SSL Gagal', (xhr && xhr.responseJSON && xhr.responseJSON.err) || domain);
                });
        }

        // Refresh every 'pending' zone once; flip badges; auto-cert on active.
        function cfRefreshPendingOnce() {
            if (cfPollBusy) { return; }
            var pending = [];
            $('#tbl_domains tbody tr[data-row-id]').each(function() {
                if (($(this).attr('data-cf-status') || '') === 'pending') {
                    var id = $(this).data('row-id');
                    var domain = $(this).find('.command-cf-sync').data('domain') || '';
                    if (id) { pending.push({ id: id, domain: domain }); }
                }
            });
            if (!pending.length) { return; }
            cfPollBusy = true;
            var i = 0;
            function nextPoll() {
                if (i >= pending.length) { cfPollBusy = false; return; }
                var p = pending[i]; i++;
                cfRequest('refresh_status', p.id, {})
                    .done(function(data) {
                        if (data && data.ok) {
                            cfUpdateRowBadge(p.id, data.cf_status, data.zone_id, JSON.stringify(data.cf_ns || []));
                            if (data.cf_cert_installed) {
                                $('#tbl_domains tbody tr[data-row-id="' + p.id + '"]').attr('data-cf-cert', '1');
                                cfCertDoneSet(p.domain, true);
                            }
                            if (data.cf_status === 'active') { cfAutoInstallCertOnce(p.id, p.domain); }
                        }
                    })
                    .always(function() { nextPoll(); });
            }
            nextPoll();
        }

        setInterval(cfRefreshPendingOnce, CF_POLL_INTERVAL_MS);

        function normalizeNsList(nsList) {
            if (!Array.isArray(nsList)) {
                return [];
            }
            return nsList.map(function(ns) {
                return String(ns || '').trim();
            }).filter(function(ns) {
                return ns !== '';
            });
        }

        // Update the already-open NS modal in place (no re-show flicker).
        function cfShowNsInPlace(rowId, domain, nsJson) {
            var ns = [];
            try { ns = normalizeNsList(JSON.parse(nsJson || '[]')); } catch(e) {}
            var isFallback = false;
            if (!ns.length && cfDefaultNs.length) {
                ns = normalizeNsList(cfDefaultNs);
                isFallback = true;
            }
            var nsHtml = ns.length
                ? ns.map(function(n) { return '<li style="font-family:var(--mono);font-size:var(--fs-sm);padding:2px 0;">' + escHtml(n) + '</li>'; }).join('')
                : '<li style="color:var(--text);opacity:.6;">No NS records stored — run sync to retrieve them.</li>';
            if (isFallback) {
                nsHtml += '<li style="margin-top:6px;font-size:var(--fs-xs);color:var(--text);opacity:.6;list-style:none;">⚠ Fallback dari env — jalankan Sync lagi nanti untuk NS spesifik domain ini.</li>';
            }
            // Fade transition: spinner out → NS info in
            var $list = $('#cf_ns_modal .cf-ns-list');
            $list.css({ opacity: '0', transition: 'opacity .15s ease' });
            setTimeout(function() {
                $list.html(nsHtml);
                $list.css({ opacity: '1' });
            }, 160);
        }

        function bindRowActions() {
            $('#tbl_domains').find('.command-delete').off('click').on('click', function() {
                var $btn = $(this);
                var rowId = $btn.data('row-id');
                var domain = $btn.data('domain') || '';
                var zoneId = $btn.data('zone-id') || '';
                var $tr = $btn.closest('tr');
                Swal.fire({
                    title: 'Are you sure?',
                    text: "You won't be able to revert this!",
                    type: 'warning',
                    showCancelButton: true,
                    allowOutsideClick: false,
                    confirmButtonColor: '#6c757d',
                    cancelButtonColor: '#6c757d',
                    confirmButtonText: 'Yes, delete it!'
                }).then(function(result) {
                    if (!result.value) { return; }
                    $tr.find('button').prop('disabled', true);
                    $tr.find('td:last-child').html(
                        '<span style="display:inline-flex;align-items:center;gap:5px;padding:0 6px;color:var(--muted);font-size:var(--fs-xs);">' +
                        '<svg style="animation:cf-spin .7s linear infinite" viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>' +
                        'Deleting…</span>'
                    );
                    $tr.css('opacity', '0.5');
                    $.ajax({
                        type: 'POST', url: 'response.php',
                        data: { id: rowId, action: 'delete' },
                        dataType: 'json'
                    }).done(function() {
                        var pending = [];
                        if (domain !== '') {
                            pending.push($.ajax({
                                type: 'POST', url: '',
                                data: { action: 'cpanel_delete', domain: domain },
                                dataType: 'json'
                            }));
                        }
                        if (domain !== '' && zoneId !== '') {
                            pending.push($.ajax({
                                type: 'POST', url: 'cf.php',
                                data: { action: 'zone_delete', zone_id: zoneId },
                                dataType: 'json'
                            }));
                        }
                        (pending.length ? $.when.apply($, pending) : $.when()).always(function() {
                            $tr.fadeOut(180, function() {
                                $(this).remove();
                                showToast('success', 'Deleted', domain || 'Domain removed.');
                                loadData();
                            });
                        });
                    }).fail(function() {
                        $tr.css('opacity', '');
                        loadData();
                        showToast('error', 'Delete Failed', domain);
                    });
                });
            });

            $('#tbl_domains').find('.command-cpanel-sync').off('click').on('click', function() {
                var btn = this;
                var domain = $(btn).data('domain');
                if (!domain) { return; }
                showToast('info', 'cPanel Sync…', domain);
                cpanelSync(domain, btn)
                    .done(function(res) {
                        if (res && res.ok) {
                            showToast('success', 'cPanel Synced', domain);
                        } else {
                            showToast('error', 'cPanel Sync Failed', (res && res.err) || domain);
                        }
                    })
                    .fail(function() { showToast('error', 'cPanel Sync Error', domain); });
            });

            $('#tbl_domains').find('.command-cf-sync').off('click').on('click', function() {
                var btn = this;
                var rowId = $(btn).data('row-id');
                var domain = $(btn).data('domain');
                if (($(btn).closest('tr').attr('data-cf-status') || '') === 'active') {
                    showToast('info', 'Sudah aktif', domain + ' — sync dilewati');
                    return;
                }
                cfSync(rowId, domain, btn);
            });

            $('#tbl_domains').find('.command-cf-purge').off('click').on('click', function() {
                var btn = this;
                var rowId = $(btn).data('row-id');
                var domain = $(btn).data('domain');
                cfPurge(rowId, domain, btn);
            });

            $('#tbl_domains').find('.command-cf-speed').off('click').on('click', function() {
                var btn = this;
                var rowId = $(btn).data('row-id');
                var domain = $(btn).data('domain');
                cfSpeed(rowId, domain, btn);
            });

            $('#tbl_domains').find('.command-cf-origin-cert').off('click').on('click', function() {
                var btn = this;
                var rowId = $(btn).data('row-id');
                var domain = $(btn).data('domain');
                cfOriginCertInstall(rowId, domain, btn);
            });

            $('#tbl_domains').find('.command-cf-origin-cert-to-cpanel').off('click').on('click', function() {
                var btn = this;
                var rowId = $(btn).data('row-id');
                var domain = $(btn).data('domain');
                cfOriginCertToCpanel(rowId, domain, btn);
            });

            $('#tbl_domains').find('.command-cf-unlink').off('click').on('click', function() {
                var btn = this;
                var rowId = $(btn).data('row-id');
                var domain = $(btn).data('domain');
                cfUnlink(rowId, domain, btn);
            });
        }

        function loadData() {
            $.ajax({
                type: 'POST', url: 'response.php',
                data: { current: state.current, rowCount: state.rowCount, searchPhrase: state.search },
                dataType: 'json',
                success: function(data) {
                    var rows = data.rows || [], total = data.total || 0;
                    var html = '';
                    for (var i = 0; i < rows.length; i++) { html += renderRow(rows[i], i); }
                    $('#tbl_domains tbody').html(html || '<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--text);">No data</td></tr>');
                    var from = total === 0 ? 0 : ((state.current - 1) * (state.rowCount === -1 ? total : state.rowCount)) + 1;
                    var to = state.rowCount === -1 ? total : Math.min(state.current * state.rowCount, total);
                    $('#tbl-info').text('Showing ' + from + ' to ' + to + ' of ' + total + ' entries');
                    renderPagination(total, state.current, state.rowCount);
                    bindRowActions();
                    cfSeedActiveAsHandled();
                    cfRefreshPendingOnce();
                }
            });
        }

        var searchTimer;
        $('#tbl-search').on('input', function() {
            clearTimeout(searchTimer);
            var val = $(this).val();
            searchTimer = setTimeout(function() { state.search = val; state.current = 1; loadData(); }, 300);
        });
        $('#tbl-rowcount').on('change', function() {
            state.rowCount = parseInt(this.value); state.current = 1; loadData();
        });
        (function(){var btn=document.getElementById('ddt-rowcount-btn'),menu=document.getElementById('ddt-rowcount-menu'),inp=document.getElementById('tbl-rowcount');if(!btn||!menu||!inp)return;btn.addEventListener('click',function(e){e.stopPropagation();menu.classList.toggle('open');});menu.addEventListener('click',function(e){var a=e.target.closest?e.target.closest('a'):(e.target.tagName==='A'?e.target:null);if(!a)return;e.preventDefault();var v=a.getAttribute('data-val');menu.querySelectorAll('a').forEach(function(el){el.classList.remove('ddt-active');});a.classList.add('ddt-active');btn.querySelector('.ddt-label').textContent=a.textContent;inp.value=v;menu.classList.remove('open');$(inp).trigger('change');});document.addEventListener('click',function(){menu.classList.remove('open');});})();

        function cpanelSync(domain, btn) {
            if (btn) { $(btn).prop('disabled', true).addClass('btn-cf--loading'); }
            return $.ajax({
                type: 'POST',
                url: 'cpanel-add.php',
                dataType: 'json',
                data: {
                    action: 'cpanel_add',
                    domain: domain,
                    url: domain,
                    csrf_token: $('meta[name="csrf-token"]').attr('content') || ''
                }
            })
                .always(function() { if (btn) { $(btn).prop('disabled', false).removeClass('btn-cf--loading'); } });
        }

        function ajaxAction(action) {
            var addon = $('#domain').val().trim();
            // Auto-integration: on add, run cPanel wildcard → Cloudflare zone
            // (security + settings + DNS) when the CF toggle is checked.
            // Toggle defaults to on; user may uncheck to skip CF for this add.
            var withCf = action === 'add' && $('#cf-add-toggle').is(':checked');
            var data = $('#frm_' + action).serializeArray();
            var btn = action === 'add' ? $('#btn_add') : $('#btn_edit');

            if (action === 'add') {
                data.push({ name: 'sync_cf', value: withCf ? '1' : '0' });
                showToast('info', 'Adding Domain…', addon);
            }

            btn.prop('disabled', true);
            $.ajax({
                type: 'POST', url: 'response.php',
                data: data, dataType: 'json'
            }).done(function(res) {
                if (!(res && res.ok)) {
                    showToast('error', 'Save Failed', (res && res.err) || addon || 'Request failed');
                    return;
                }

                var newId = (res.id) ? parseInt(res.id, 10) : 0;

                if (action !== 'add' || addon === '') {
                    $('#' + action + '_model').modal('hide');
                    loadData();
                    showToast('success', 'Saved', 'Domain updated.');
                    return;
                }

                if (newId < 1) {
                    $('#' + action + '_model').modal('hide');
                    showToast('error', 'Add Failed', 'missing-domain-id');
                    return;
                }

                // Keep modal open during cPanel + CF sync so user sees progress.
                // Show CF loader immediately if CF is enabled.
                if (withCf) {
                    $('#add-cf-panel').show();
                    $('#add-cf-loader').show();
                    $('#add-cf-ns-block').hide();
                    $('#add-cf-status-text').text('Memulai cPanel + Cloudflare…');
                }

                cpanelSync(res.domain || addon)
                    .done(function(cpData) {
                        if (!(cpData && cpData.ok)) {
                            showToast('error', 'cPanel Sync Failed', (cpData && cpData.err) || (res.domain || addon));
                            if (!withCf) { $('#' + action + '_model').modal('hide'); }
                            return;
                        }

                        if (!withCf) {
                            $('#' + action + '_model').modal('hide');
                            loadData();
                            showToast('success', 'cPanel OK', 'Wildcard enabled — ' + (res.domain || addon));
                            return;
                        }

                        // CF panel should already be visible — update status
                        $('#add-cf-status-text').text('Syncing to Cloudflare…');

                        cfRequest('zone_add', newId, {})
                            .done(function(cfData) {
                                if (cfData && cfData.ok) {
                                    var dnsInfo = '';
                                    if (cfData.dns_log && cfData.dns_log.length) {
                                        var errs = cfData.dns_log.filter(function(l) {
                                            return String(l).indexOf('error:') === 0;
                                        }).length;
                                        dnsInfo = ' · DNS: ' + (cfData.dns_log.length - errs) + ' ok' + (errs ? ', ' + errs + ' err' : '');
                                    }
                                    $('#add-cf-status-text').text('CF Zone: ' + (cfData.cf_status || '') + dnsInfo);
                                    showToast('success', 'CF Zone OK', (cfData.cf_status || '') + ' — ' + (res.domain || addon) + dnsInfo);
                                    if (cfData.cf_warnings) { showToast('error', 'CF: ' + cfData.cf_warnings + ' operasi gagal', (cfData.cf_warning_sample && cfData.cf_warning_sample[0]) || 'cek error_log — kemungkinan izin token'); }
                                    cfUpdateRowBadge(newId, cfData.cf_status, cfData.zone_id, JSON.stringify(cfData.cf_ns || []));

                                    // Replace loader with NS info
                                    $('#add-cf-loader').hide();
                                    $('#add-cf-ns-block').show();
                                    var nsList = [];
                                    try { nsList = normalizeNsList(JSON.parse(cfData.cf_ns || '[]')); } catch(e) {}
                                    var nsHtml = nsList.length
                                        ? nsList.map(function(n) { return '<code style="display:block;font-size:var(--fs-sm);padding:1px 0;">' + escHtml(n) + '</code>'; }).join('')
                                        : '<span style="opacity:.6;font-size:var(--fs-sm);">Menunggu NS dari Cloudflare — cek lagi nanti.</span>';
                                    $('#add-cf-ns-panel').html(nsHtml);

                                    loadData();
                                    // Auto-close modal after 2.5s so user can read NS info
                                    setTimeout(function() { $('#add_model').modal('hide'); }, 2500);
                                } else {
                                    $('#add-cf-loader').hide();
                                    $('#add-cf-ns-block').hide();
                                    $('#add-cf-status-text').text('CF Sync Failed: ' + ((cfData && cfData.err) || 'unknown'));
                                    showToast('error', 'CF Error', (cfData && cfData.err) || 'cf-sync-failed');
                                    // Keep modal open so user sees the error
                                }
                            })
                            .fail(function(xhr) {
                                var msg = 'cf-sync-failed';
                                if (xhr && xhr.responseJSON && xhr.responseJSON.err) {
                                    msg = xhr.responseJSON.err;
                                }
                                $('#add-cf-loader').hide();
                                $('#add-cf-ns-block').hide();
                                $('#add-cf-status-text').text('CF Sync Error: ' + msg);
                                showToast('error', 'CF Sync Error', msg);
                            });
                    })
                    .fail(function(xhr) {
                        var msg = res.domain || addon;
                        if (xhr && xhr.responseJSON && xhr.responseJSON.err) {
                            msg = xhr.responseJSON.err;
                        } else {
                            msg = 'cpanel-request-failed';
                        }
                        $('#add-cf-loader').hide();
                        $('#add-cf-status-text').text('cPanel Error: ' + msg);
                        showToast('error', 'cPanel Sync Error', msg);
                    });
            }).fail(function(xhr) {
                var msg = 'Request failed';
                if (xhr && xhr.responseJSON && xhr.responseJSON.err) {
                    msg = xhr.responseJSON.err;
                }
                showToast('error', action === 'add' ? 'Add Failed' : 'Save Failed', msg);
            }).always(function() {
                btn.prop('disabled', false);
            });
        }

        $('#command-sync-all').on('click', function() {
            var btn = this;
            var syncSvg = '<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg>';
            $(btn).prop('disabled', true).addClass('btn-syncall--loading').html(syncSvg + ' Syncing…');
            var rows = [], skipped = 0;
            $('#tbl_domains tbody tr[data-row-id]').each(function() {
                var rowId = $(this).data('row-id');
                var domain = $(this).find('.command-cf-sync').data('domain') || '';
                if (($(this).attr('data-cf-status') || '') === 'active') { skipped++; return; }
                if (rowId && domain) { rows.push({ id: rowId, domain: domain }); }
            });
            if (rows.length === 0) {
                showToast('info', skipped ? 'Semua aktif' : 'No rows', skipped ? skipped + ' domain sudah aktif — dilewati.' : 'Load data first.');
                $(btn).prop('disabled', false).removeClass('btn-syncall--loading').html('<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg> Sync All CF');
                return;
            }
            var done = 0;
            function syncNext() {
                if (done >= rows.length) {
                    showToast('success', 'Sync All Done', done + ' domain diproses' + (skipped ? ', ' + skipped + ' aktif dilewati' : '') + '.');
                    $(btn).prop('disabled', false).removeClass('btn-syncall--loading').html('<svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6"/><path d="M2.5 12A10 10 0 0 1 20 6.3"/><path d="M2.5 22v-6h6"/><path d="M21.5 12A10 10 0 0 1 4 17.7"/></svg> Sync All CF');
                    loadData();
                    return;
                }
                var r = rows[done];
                done++;
                $(btn).html(syncSvg + ' Syncing ' + done + '/' + rows.length + '…');
                cfRequest('zone_add', r.id, {})
                    .done(function(data) {
                        if (data && data.ok) {
                            cfUpdateRowBadge(r.id, data.cf_status, data.zone_id, JSON.stringify(data.cf_ns || []));
                            if (data.cf_status === 'active') { cfAutoInstallCertOnce(r.id, r.domain); }
                        }
                    })
                    .always(function() { syncNext(); });
            }
            syncNext();
        });

        var cpanelNsCache = null;
        var cpanelNsLoading = false;

        function loadCpanelNs() {
            if (cpanelNsCache !== null) {
                renderCpanelNs(cpanelNsCache);
                return;
            }
            $('#ns-info-list').html('<span style="opacity:.6;">Memuat…</span>');
            $.ajax({ type: 'GET', url: 'cpanel-ns.php', dataType: 'json' })
                .done(function(data) {
                    cpanelNsCache = (data && data.ok && data.ns && data.ns.length) ? data.ns : [];
                    renderCpanelNs(cpanelNsCache);
                })
                .fail(function() {
                    $('#ns-info-list').html('<span style="opacity:.6;">Gagal memuat nameserver.</span>');
                });
        }

        function renderCpanelNs(nsList) {
            nsList = normalizeNsList(nsList);
            if (!nsList || !nsList.length) {
                $('#ns-info-list').html('<span style="opacity:.6;">Nameserver tidak ditemukan.</span>');
                return;
            }
            var mid = Math.ceil(nsList.length / 2);
            function col(items, offset) {
                return items.map(function(ns, i) {
                    return 'NS' + (offset + i + 1) + ': <code>' + escHtml(ns) + '</code>';
                }).join('<hr style="margin:1px;padding:0;border:0;">');
            }
            var left  = col(nsList.slice(0, mid), 0);
            var right = col(nsList.slice(mid), mid);
            var html = '<div style="display:flex;gap:24px;flex-wrap:wrap;">'
                + '<div style="flex:1;min-width:200px;">' + left + '</div>'
                + '<div style="flex:1;min-width:200px;">' + right + '</div>'
                + '</div>';
            $('#ns-info-list').html(html);
        }

        $("#command-add").on('click', function() {
            $("#domain").val('');
            var cfOn = $('#cf-add-toggle').is(':checked');
            // Show/hide CF panel based on toggle state
            $('#add-cf-panel').css('display', cfOn ? 'block' : 'none');
            $('#add-cf-loader').css('display', 'none');
            $('#add-cf-ns-block').css('display', 'none');
            $('#add-cf-ns-panel').empty();
            loadCpanelNs();
            $('#add_model').modal('show');
        });

        // Toggle CF panel visibility when checkbox changes
        $('#cf-add-toggle').on('change', function() {
            $('#add-cf-panel').css('display', this.checked ? 'block' : 'none');
            if (!this.checked) {
                $('#add-cf-loader').css('display', 'none');
                $('#add-cf-ns-block').css('display', 'none');
            }
        });
        $('#add_model').on('hidden.bs.modal', function() {
            $('#domain').val('');
            resetAddModal();
        });
        // Single domain per submit only — batching multiple cPanel wildcard +
        // Cloudflare zone provisioning calls in one modal session was the
        // source of instability (partial failures mid-batch, long-running
        // sequential AJAX chains). One submit = one domain = one clear
        // success/failure outcome.
        var ADD_MAX_DOMAINS = 1;

        // Parse the domain input: split on whitespace/comma, strip
        // protocol/path, lowercase, drop empties, dedupe (server remains the
        // authority on per-domain validity — ADD_MAX_DOMAINS is what actually
        // enforces "one domain" below).
        function parseDomainList(raw) {
            var seen = {}, out = [];
            String(raw || '').split(/[\s,]+/).forEach(function(d) {
                d = d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[\/\\].*$/, '');
                if (d === '' || seen[d]) { return; }
                seen[d] = true;
                out.push(d);
            });
            return out;
        }

        // Run one domain through insert → cpanel wildcard → optional CF zone.
        // Always resolves (never rejects) so a batch continues past failures.
        function addDomainPipeline(domain, withCf) {
            var dfd = $.Deferred();
            showToast('info', 'Adding Domain…', domain);
            $.ajax({
                type: 'POST', url: 'response.php', dataType: 'json',
                data: { action: 'add', sub_domain: $('#sub_domain').val(), domain: domain, sync_cf: withCf ? '1' : '0' }
            }).done(function(res) {
                if (!(res && res.ok)) {
                    showToast('error', 'Save Failed', (res && res.err) || domain || 'Request failed');
                    dfd.resolve({ domain: domain, ok: false });
                    return;
                }
                var newId = res.id ? parseInt(res.id, 10) : 0;
                var realDomain = res.domain || domain;
                if (newId < 1) {
                    showToast('error', 'Add Failed', 'missing-domain-id');
                    dfd.resolve({ domain: realDomain, ok: false });
                    return;
                }
                showToast('info', 'cPanel Sync…', realDomain);
                cpanelSync(realDomain).done(function(cpData) {
                    if (!(cpData && cpData.ok)) {
                        showToast('error', 'cPanel Sync Failed', (cpData && cpData.err) || realDomain);
                        dfd.resolve({ domain: realDomain, ok: false });
                        return;
                    }
                    showToast('success', 'cPanel OK', 'Wildcard enabled — ' + realDomain);
                    if (!withCf) { dfd.resolve({ domain: realDomain, ok: true }); return; }

                    // Show CF loader in the add modal
                    $('#ns-info-list').closest('blockquote').hide();
                    $('#frm_add').hide();
                    $('#add-cf-panel').css('display', 'block');
                    $('#add-cf-ns-block').hide();
                    $('#add-cf-status-text').text('CF Sync: ' + realDomain + '…');
                    $('#add-cf-loader').css('display', 'block');
                    cfRequest('zone_add', newId, {}).done(function(cfData) {
                        $('#add-cf-loader').hide();
                        if (cfData && cfData.ok) {
                            var dnsInfo = '';
                            if (cfData.dns_log && cfData.dns_log.length) {
                                var errs = cfData.dns_log.filter(function(l) { return String(l).indexOf('error:') === 0; }).length;
                                dnsInfo = ' · DNS: ' + (cfData.dns_log.length - errs) + ' ok' + (errs ? ', ' + errs + ' err' : '');
                            }
                            showToast('success', 'CF Zone OK', (cfData.cf_status || '') + ' — ' + realDomain + dnsInfo);
                            if (cfData.cf_warnings) { showToast('error', 'CF: ' + cfData.cf_warnings + ' operasi gagal', (cfData.cf_warning_sample && cfData.cf_warning_sample[0]) || 'cek error_log — kemungkinan izin token'); }
                            cfUpdateRowBadge(newId, cfData.cf_status, cfData.zone_id, JSON.stringify(cfData.cf_ns || []));
                            var cfNsList = normalizeNsList(cfData.cf_ns || []);
                            var isFallback = false;
                            if (!cfNsList.length && cfDefaultNs.length) { cfNsList = normalizeNsList(cfDefaultNs); isFallback = true; }
                            var nsItems = cfNsList.length
                                ? cfNsList.map(function(n) {
                                    return '<li style="font-family:var(--mono);font-size:var(--fs-sm);padding:2px 0;">' + escHtml(n) + '</li>';
                                }).join('')
                                : '<li style="color:var(--muted);opacity:.6;">No NS records stored — run sync first.</li>';
                            if (isFallback) { nsItems += '<li style="margin-top:6px;font-size:var(--fs-xs);color:var(--muted);opacity:.6;list-style:none;">⚠ Fallback dari env — jalankan Sync untuk NS spesifik domain ini.</li>'; }
                            $('#add-cf-ns-panel').append(
                                '<div style="margin:0 0 4px;font-size:var(--fs-xs);font-weight:var(--fw-semibold);">' + escHtml(realDomain) + '</div>'
                                + '<ul style="margin:0 0 8px;padding-left:16px;">' + nsItems + '</ul>'
                            );
                            $('#add-cf-ns-block').show();
                            if (cfData.cf_status === 'active') { cfAutoInstallCertOnce(newId, realDomain); }
                            dfd.resolve({ domain: realDomain, ok: true, nsShown: true });
                        } else {
                            showToast('error', 'CF Error', (cfData && cfData.err) || 'cf-sync-failed');
                            dfd.resolve({ domain: realDomain, ok: false });
                        }
                    }).fail(function(xhr) {
                        $('#add-cf-loader').hide();
                        showToast('error', 'CF Sync Error', (xhr && xhr.responseJSON && xhr.responseJSON.err) || 'cf-sync-failed');
                        dfd.resolve({ domain: realDomain, ok: false });
                    });
                }).fail(function(xhr) {
                    showToast('error', 'cPanel Sync Error', (xhr && xhr.responseJSON && xhr.responseJSON.err) || 'cpanel-request-failed');
                    dfd.resolve({ domain: realDomain, ok: false });
                });
            }).fail(function(xhr) {
                showToast('error', 'Add Failed', (xhr && xhr.responseJSON && xhr.responseJSON.err) || 'Request failed');
                dfd.resolve({ domain: domain, ok: false });
            });
            return dfd.promise();
        }

        function resetAddModal() {
            $('#frm_add').show();
            $('#ns-info-list').closest('blockquote').show();
            $('#add-cf-panel').css('display', 'none');
            $('#add-cf-loader').css('display', 'none');
            $('#add-cf-ns-block').css('display', 'none');
            $('#add-cf-ns-panel').html('');
        }

        // Process the validated list one domain at a time (sequential, like
        // Sync All) to avoid hammering cPanel/Cloudflare.
        function runAddBatch(domains, withCf) {
            var btn = $('#btn_add'), i = 0, ok = 0, fail = 0, nsShown = false;
            btn.prop('disabled', true);
            function next() {
                if (i >= domains.length) {
                    btn.prop('disabled', false).text('Save');
                    loadData();
                    showToast(fail ? 'error' : 'success', 'Add Selesai', ok + ' sukses' + (fail ? ', ' + fail + ' gagal' : '') + ' dari ' + domains.length + ' domain.');
                    if (!nsShown) { $('#add_model').modal('hide'); }
                    return;
                }
                var d = domains[i]; i++;
                btn.text('Saving ' + i + '/' + domains.length + '…');
                addDomainPipeline(d, withCf).always(function(r) {
                    if (r && r.ok) { ok++; if (r.nsShown) { nsShown = true; } } else { fail++; }
                    next();
                });
            }
            next();
        }

        $("#btn_add").on('click', function() {
            var domains = parseDomainList($("#domain").val());
            if (domains.length < 1) {
                Swal.fire({ allowOutsideClick: false, type: 'error', title: 'Oops...', text: 'Masukkan minimal 1 domain.' });
                return false;
            }
            if (domains.length > ADD_MAX_DOMAINS) {
                Swal.fire({ allowOutsideClick: false, type: 'error', title: 'Terlalu banyak', text: 'Maksimal ' + ADD_MAX_DOMAINS + ' domain per submit (Anda memasukkan ' + domains.length + ').' });
                return false;
            }
            runAddBatch(domains, $('#cf-add-toggle').is(':checked'));
        });
        $("#btn_edit").on('click', function() { ajaxAction('edit'); });

        loadData();

        // ── CF Config modal ──────────────────────────────────────────────
        var cfDefaultNs = [];

        $('#command-cf-config').on('click', function() {
            $('#cfg_status').hide().text('');
            $('#cfg_cf_token').val('').attr('type', 'password').attr('placeholder', 'Token baru…').removeAttr('data-masked');
            $('#cfg_cf_account').val('');
            $('#cfg_tinyurl_api_key').val('').attr('type', 'password').attr('placeholder', 'Kosongkan = tidak diubah').removeAttr('data-masked');
            $('#cfg_maxmind_license_key').val('').attr('type', 'password').attr('placeholder', 'Kosongkan = tidak diubah').removeAttr('data-masked');
            $('#cfg_cf_ip').val('');
            $('#cfg_cf_ns1').val('');
            $('#cfg_cf_ns2').val('');
            $('#cfg_cf_ns3').val('');
            $('#cfg_cf_ns4').val('');
            $.ajax({ type: 'GET', url: 'cf.php', data: { action: 'config_get' }, dataType: 'json' })
                .done(function(data) {
                    if (data && data.ok && data.config) {
                        var masked = data.config.CF_API_TOKEN || '';
                        if (masked !== '') {
                            $('#cfg_cf_token').val(masked).attr('data-masked', '1').attr('placeholder', '');
                        } else {
                            $('#cfg_cf_token').attr('placeholder', 'Belum diset');
                        }
                        $('#cfg_cf_account').val(data.config.CF_ACCOUNT_ID || '');
                        $('#cfg_tinyurl_api_key').val(data.config.TINYURL_API_KEY || '').attr('data-masked', data.config.TINYURL_API_KEY ? '1' : null).attr('placeholder', data.config.TINYURL_API_KEY ? '' : 'Belum diset');
                        $('#cfg_maxmind_license_key').val(data.config.MAXMIND_LICENSE_KEY || '').attr('data-masked', data.config.MAXMIND_LICENSE_KEY ? '1' : null).attr('placeholder', data.config.MAXMIND_LICENSE_KEY ? '' : 'Belum diset');
                        $('#cfg_cf_ip').val(data.config.CF_SERVER_IP || '');
                        $('#cfg_cf_ns1').val(data.config.CF_NS1 || '');
                        $('#cfg_cf_ns2').val(data.config.CF_NS2 || '');
                        $('#cfg_cf_ns3').val(data.config.CF_NS3 || '');
                        $('#cfg_cf_ns4').val(data.config.CF_NS4 || '');
                        cfDefaultNs = normalizeNsList([data.config.CF_NS1, data.config.CF_NS2, data.config.CF_NS3, data.config.CF_NS4]);
                    }
                });
            $('#cf_config_modal').modal('show');
        });

        $('#cfg_cf_token_toggle').on('click', function() {
            var inp = $('#cfg_cf_token');
            inp.attr('type', inp.attr('type') === 'password' ? 'text' : 'password');
        });

        $('#cfg_cf_token').on('input', function() {
            $(this).removeAttr('data-masked');
        });
        $('.cf-secret-input').on('input', function() {
            $(this).removeAttr('data-masked');
        });

        $('#cfg_cf_ip_detect').on('click', function() {
            var detected = ($(this).attr('data-detected-ip') || '').trim();
            if (detected === '') {
                showToast('error', 'IP Tidak Terdeteksi', 'Server tidak bisa mendeteksi IP publiknya secara otomatis. Isi manual.');
                return;
            }
            $('#cfg_cf_ip').val(detected);
            showToast('success', 'IP Terdeteksi', 'Server IP diisi otomatis: ' + detected);
        });

        // CreateAdditionalTokensInit
        $('#cfg_create_additional_token').on('click', function() {
            var btn = $(this);
            var btnOriginalHtml = btn.html();
            btn.prop('disabled', true).html(ngixButtonSpinner + 'Generating…');
            var creatorToken = $('#cfg_cf_token').val().trim();
            var accountId = $('#cfg_cf_account').val().trim();
            var st = $('#cfg_status').show();

            if (creatorToken === '' || $('#cfg_cf_token').attr('data-masked') === '1' || creatorToken.indexOf('•') !== -1 || creatorToken.indexOf('*') !== -1) {
                st.removeClass().text('Paste token asli dari template Create Additional Tokens dulu.');
                btn.prop('disabled', false).html(btnOriginalHtml || 'Create Additional Tokens');
                return;
            }

            st.text('Creating additional token…');

            $.ajax({
                type: 'POST',
                url: '/api/cf_create_token.php',
                data: {
                    creator_token: creatorToken,
                    cf_account_id: accountId,
                    csrf_context: 'admin_panel',
                    csrf_token: <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>
                },
                dataType: 'json'
            }).done(function(data) {
                if (typeof data === 'string') {
                    try { data = JSON.parse(data); } catch (e) {}
                }

                if (!data || data.ok !== true || !data.token) {
                    var err = (data && (data.err || data.error)) ? (data.err || data.error) : 'Gagal membuat token';
                    var missingList = (data && data.missing && data.missing.length) ? data.missing
                        : (data && data.missing_rows && data.missing_rows.length)
                            ? data.missing_rows.map(function(r) { return r.scope + ' — ' + r.permission + ':' + r.access; })
                            : [];
                    if (missingList.length) {
                        err += ': ' + missingList.join(', ');
                    }
                    st.text(err);
                    showToast('error', 'CF Token Failed', err);
                    return;
                }

                var optionalMissingList = (data.optional_missing_rows && data.optional_missing_rows.length)
                    ? data.optional_missing_rows.map(function(r) { return r.scope + ' — ' + r.permission + ':' + r.access; })
                    : [];

                $('#cfg_cf_token').val(data.token).attr('type', 'password').removeAttr('data-masked');
                if (data.account_id) {
                    $('#cfg_cf_account').val(data.account_id);
                }

                var payload = {
                    action: 'config_save',
                    CF_API_TOKEN: data.token,
                    CF_ACCOUNT_ID: data.account_id || accountId,
                    TINYURL_API_KEY: $('#cfg_tinyurl_api_key').val().trim(),
                    MAXMIND_LICENSE_KEY: $('#cfg_maxmind_license_key').val().trim(),
                    CF_SERVER_IP: $('#cfg_cf_ip').val().trim(),
                    CF_NS1: $('#cfg_cf_ns1').val().trim(),
                    CF_NS2: $('#cfg_cf_ns2').val().trim(),
                    CF_NS3: $('#cfg_cf_ns3').val().trim(),
                    CF_NS4: $('#cfg_cf_ns4').val().trim()
                };

                $.ajax({ type: 'POST', url: 'cf.php', data: payload, dataType: 'json' })
                    .done(function(saveData) {
                        if (saveData && saveData.ok) {
                            st.html('<strong>Additional token created & saved.</strong>' + (optionalMissingList.length ? '<div style="margin-top:5px;font-size:var(--fs-xs);opacity:.75;">Optional unavailable: ' + escHtml(optionalMissingList.join(', ')) + '</div>' : '') + '<div class="cfg-token-copy-box"><strong>Copy now if needed:</strong>' + escHtml(data.token) + '</div>');
                            showToast('success', 'CF Token Created', optionalMissingList.length ? 'Saved with optional permission warnings.' : 'Additional token saved.');
                        } else {
                            st.html('<strong>Token created, save failed. Copy now:</strong>' + (optionalMissingList.length ? '<div style="margin-top:5px;font-size:var(--fs-xs);opacity:.75;">Optional unavailable: ' + escHtml(optionalMissingList.join(', ')) + '</div>' : '') + '<div class="cfg-token-copy-box">' + escHtml(data.token) + '</div>');
                            showToast('error', 'CF Token Save Failed', 'Copy token manually.');
                        }
                    })
                    .fail(function() {
                        st.html('<strong>Token created, save request failed. Copy now:</strong>' + (optionalMissingList.length ? '<div style="margin-top:5px;font-size:var(--fs-xs);opacity:.75;">Optional unavailable: ' + escHtml(optionalMissingList.join(', ')) + '</div>' : '') + '<div class="cfg-token-copy-box">' + escHtml(data.token) + '</div>');
                        showToast('error', 'CF Token Save Error', 'Copy token manually.');
                    });
            }).fail(function(xhr) {
                var response = xhr && xhr.responseJSON ? xhr.responseJSON : null;
                if (!response && xhr && typeof xhr.responseText === 'string' && xhr.responseText !== '') {
                    try { response = JSON.parse(xhr.responseText); } catch (e) {}
                }

                if (response && response.ok === true && response.token) {
                    $('#cfg_cf_token').val(response.token).attr('type', 'password').removeAttr('data-masked');
                    if (response.account_id) { $('#cfg_cf_account').val(response.account_id); }
                    st.html('<strong>Additional token created.</strong><div class="cfg-token-copy-box"><strong>Copy now if needed:</strong>' + escHtml(response.token) + '</div>');
                    showToast('success', 'CF Token Created', 'Token created; HTTP status was inconsistent.');
                    return;
                }

                var msg = 'Request gagal';
                if (response && (response.err || response.error)) {
                    msg = response.err || response.error;
                }
                st.text(msg);
                showToast('error', 'CF Token Error', msg);
            }).always(function() {
                btn.prop('disabled', false).html(btnOriginalHtml || 'Create Additional Tokens');
            });
        });

        $('#cfg_save_btn').on('click', function() {
            var btn = $(this);
            var btnOriginalHtml = btn.html();
            btn.prop('disabled', true).html(ngixButtonSpinner + 'Simpan');
            var payload = {
                action:                'config_save',
                CF_API_TOKEN:          $('#cfg_cf_token').val().trim(),
                CF_ACCOUNT_ID:         $('#cfg_cf_account').val().trim(),
                TINYURL_API_KEY:       $('#cfg_tinyurl_api_key').val().trim(),
                MAXMIND_LICENSE_KEY:   $('#cfg_maxmind_license_key').val().trim(),
                CF_SERVER_IP:          $('#cfg_cf_ip').val().trim(),
                CF_NS1:                $('#cfg_cf_ns1').val().trim(),
                CF_NS2:                $('#cfg_cf_ns2').val().trim(),
                CF_NS3:                $('#cfg_cf_ns3').val().trim(),
                CF_NS4:                $('#cfg_cf_ns4').val().trim()
            };
            $.ajax({ type: 'POST', url: 'cf.php', data: payload, dataType: 'json' })
                .done(function(data) {
                    var st = $('#cfg_status').show();
                    if (data && data.ok) {
                        var saved = data.saved && data.saved.length ? data.saved.join(', ') : 'Tidak ada perubahan';
                        st.css({ background: 'var(--blue-soft)', border: '1px solid var(--blue-line)', color: 'var(--text)' }).html('<strong>Tersimpan:</strong> ' + escHtml(saved));
                        if (data.saved && data.saved.length) {
                            showToast('success', 'CF Config Saved', saved);
                        }
                    } else {
                        st.css({ background: 'var(--danger-soft)', border: '1px solid rgba(108,117,125,.28)', color: 'var(--danger)' }).text((data && data.err) || 'Gagal menyimpan');
                    }
                })
                .fail(function() {
                    $('#cfg_status').show().css({ background: 'var(--danger-soft)', color: 'var(--danger)' }).text('Request gagal');
                })
                .always(function() { btn.prop('disabled', false).html(btnOriginalHtml); });
        });
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
    </script>
<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/addondomain-2.css') ?>">
<script src="<?= srpAssetUrl('/assets/js/addondomain-2.js') ?>"></script>

<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/addondomain-3.css') ?>">

<script src="<?= srpAssetUrl('/assets/js/addondomain-3.js') ?>"></script>

<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/addondomain-4.css') ?>">
<script src="<?= srpAssetUrl('/assets/js/addondomain-4.js') ?>"></script>
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
</body></html>
