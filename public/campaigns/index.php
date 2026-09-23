<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/env.php';
require_once dirname(__DIR__, 2) . '/asset_url.php';


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

function showLoginPasswordProtect(string $errorMsg, string $nonce, string $csrfToken): never
{
    header('Location: /login.php');
    exit;
}

startAdminSession();

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
    <link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/campaigns-1.css') ?>">
</head>
<body>
<script nonce="<?= adminEsc($nonce); ?>" src="/assets/js/jquery-1.11.1.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>" src="/assets/js/bootstrap.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>">
(function ($) {
    'use strict';

    $.ajaxSetup({
        headers: {
            'X-CSRF-Token': <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>
        }
    });
}(jQuery));
</script>
<script src="<?= srpAssetUrl('/assets/js/campaigns-1.js') ?>"></script>


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
                    <li class="active"><a href="#"><strong>Campaigns</strong></a></li>
                    <li><a href="/addondomain/"><strong>Addon Domain</strong></a></li>
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
                    <span class="input-group-addon"><span class="glyphicon glyphicon-search"></span></span>
                    <input type="text" class="form-control" id="tbl-search" placeholder="Search...">
                </div>
                <div class="ddt" id="ddt-rowcount">
                    <button type="button" class="btn btn-xs ddt-btn" id="ddt-rowcount-btn"><span class="ddt-label">25</span><svg class="ddt-caret" viewBox="0 0 10 6" width="10" height="6" fill="currentColor" aria-hidden="true" focusable="false"><path d="M0 0l5 6 5-6z"/></svg></button>
                    <ul class="ddt-menu" id="ddt-rowcount-menu">
                        <li><a href="#" data-val="25" class="ddt-active">25</a></li>
                        <li><a href="#" data-val="50">50</a></li>
                        <li><a href="#" data-val="-1">All</a></li>
                    </ul>
                </div>
                <input type="hidden" id="tbl-rowcount" value="25">
            </div>
            <button type="button" class="btn btn-sm btn-primary btn-icon" id="command-add" data-row-id="0">
                <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 5v14"/><path d="M5 12h14"/></svg>
                <span>Create Campaigns</span>
            </button>
        </div>
        <div style="overflow-x:auto;">
            <table id="tbl_campaigns" class="table table-hover">
                <thead>
                    <tr>
                        <th>Empid</th>
                        <th><span class="th-ico"><span>Country Code</span></span></th>
                        <th><span class="th-ico"><span>Device</span></span></th>
                        <th class="offer-cell">Smartlink</th>
                        <th>Network</th>
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
    <div class="modal-dialog modal-wide">
        <div class="modal-content">
            <div class="modal-header">
                <a class="close" data-dismiss="modal" aria-hidden="true">&times;</a>
                <h4 class="modal-title">Create Campaigns</h4>
            </div>
            <div class="modal-body">
                <?php
                $reportHost = adminEsc((string) app_env('REPORT_HOST', ''));
$postbackSecret = (string) app_env('POSTBACK_SECRET', '');
// Auto-fill the postback token so the example URL is copy-paste ready.
// Falls back to a placeholder when POSTBACK_SECRET is not configured.
// HTML-escaped because it is rendered via jQuery .html() into #hint-pb-line.
$pbTokenDisplay = $postbackSecret !== ''
? adminEsc($postbackSecret)
: '&lt;postback_secret&gt;';
?>
                <div id="hint-smartlink" style="display:none;">
                    <blockquote>
                        <p class="hint-title">Contoh Smartlink:</p>
                        <span class="hint-line" id="hint-sl-line"></span>
                    </blockquote>
                    <blockquote>
                        <p class="hint-title">Contoh Postback URL:</p>
                        <span class="hint-line" id="hint-pb-line"></span>
                    </blockquote>
                    <blockquote>
                        <p class="hint-title">Parameter tersedia:</p>
                        <span class="param-note"><code>{sub_id}</code> &mdash; Tracker ID (sub_id user)</span>
                        <span class="param-note"><code>{click_id}</code> &mdash; Click ID unik yang di-generate sistem</span>
                        <span class="param-note"><code>token</code> &mdash; <b>Wajib</b>, sudah otomatis terisi dari <code>POSTBACK_SECRET</code> (.env). Tanpa token yang benar &rarr; 403 FORBIDDEN.</span>
                        <span class="param-note">Bagian bertanda <code>[MAKRO_...]</code> harus diganti dengan makro milik network itu sendiri &mdash; ambil dari panel network. Makro yang salah dikirim apa adanya sebagai teks dan konversinya ditolak.</span>
                    </blockquote>
                </div>
                <form method="post" id="frm_add">
                    <input type="hidden" value="add" name="action" id="action">
                    <input readonly="readonly" type="hidden" class="form-control" id="country_code" name="country_code" required="true">
                    <input readonly="readonly" type="hidden" class="form-control" id="ua" name="ua" required="true">
                    <div class="form-group">
                        <label for="offer" class="control-label">Smartlink:</label>
                        <input type="text" class="form-control" id="offer" name="offer" placeholder="https://domain.com/..." required>
                    </div>
                    <div class="form-group">
                        <label for="c_net" class="control-label">Select Network:</label>
                        <div class="ddt ddt-full" id="ddt-c-net">
                            <button type="button" class="btn btn-xs ddt-btn" id="ddt-c-net-btn" aria-haspopup="listbox"><span class="ddt-label">* Select Network</span><svg class="ddt-caret" viewBox="0 0 10 6" width="10" height="6" fill="currentColor" aria-hidden="true" focusable="false"><path d="M0 0l5 6 5-6z"/></svg></button>
                            <ul class="ddt-menu" id="ddt-c-net-menu" role="listbox">
                                <li><a href="#" data-val="IMONETIZEIT">iMonetizeit</a></li>
                                <li><a href="#" data-val="LOSPOLLOS">LosPollos</a></li>
                                <li><a href="#" data-val="TRAFEE">Trafee</a></li>
                                <li><a href="#" data-val="CUSTOM">Custom</a></li>
                            </ul>
                        </div>
                        <input type="hidden" id="c_net">
                        <input type="text" class="form-control" id="custom_network" placeholder="Nama network..." style="display:none;margin-top:6px;" autocomplete="off">
                        <input readonly type="hidden" class="form-control" id="network" name="network" required>
                    </div>
                </form>
                <script nonce="<?= adminEsc($nonce); ?>">
                var _reportHost = <?= json_encode($reportHost, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>;
                var _pbToken = <?= json_encode($pbTokenDisplay, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>;
                var _networkHints = {
                    IMONETIZEIT: {
                        sl: 'https://domain.com/c/xx?s1=xx&amp;s2=xx&amp;s3=<b>{sub_id}</b>&amp;click_id=<b>{click_id}</b>',
                        // iMonetizeit's own postback macro names are not documented here.
                        // Left as explicit placeholders rather than guessed: a wrong macro
                        // arrives as a literal string and the conversion is rejected with
                        // no obvious cause. Replace both from the iMonetizeit panel.
                        pb: 'https://' + _reportHost + '/postback/?click_id=<b>&lt;click_id&gt;</b>&amp;payout=<b>&lt;payout&gt;</b>&amp;token=<b>' + _pbToken + '</b>'
                    },
                    LOSPOLLOS: {
                        sl: 'https://domain.com/go?s1=<b>{sub_id}</b>&amp;s2=<b>{click_id}</b>',
                        pb: 'https://' + _reportHost + '/postback/?click_id=<b>{cid}</b>&amp;payout=<b>{sum}</b>&amp;token=<b>' + _pbToken + '</b>'
                    },
                    TRAFEE: {
                        sl: 'https://domain.com/s/xxx?track=<b>{sub_id}</b>&amp;subsource=<b>{sub_id}</b>&amp;ext_click_id=<b>{click_id}</b>',
                        pb: 'https://' + _reportHost + '/postback/?click_id=<b>{ext_click_id}</b>&amp;payout=<b>{sum}</b>&amp;token=<b>' + _pbToken + '</b>'
                    },
                    CUSTOM: {
                        sl: 'Sesuaikan parameter tracking network Anda.',
                        pb: 'https://' + _reportHost + '/postback/?click_id=<b>{click_id}</b>&amp;payout=<b>{payout}</b>&amp;token=<b>' + _pbToken + '</b>'
                    }
                };

                </script>
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
                <h4 class="modal-title">Edit Campaign</h4>
            </div>
            <div class="modal-body">
                <form method="post" id="frm_edit">
                    <input type="hidden" value="edit" name="action" id="action">
                    <input type="hidden" value="0" name="edit_id" id="edit_id">
                    <div class="form-group">
                        <input type="hidden" class="form-control" id="edit_country_code" name="edit_country_code" required="true" readonly="readonly">
                    </div>
                    <div class="form-group">
                        <input type="hidden" class="form-control" id="edit_ua" name="edit_ua" required="true" readonly="readonly">
                    </div>
                    <div class="form-group">
                        <label for="edit_offer" class="control-label">Smartlink:</label>
                        <input type="text" class="form-control" id="edit_offer" name="edit_offer" required>
                    </div>
                    <div class="form-group">
                        <label for="edit_network" class="control-label">Network:</label>
                        <div class="ddt ddt-full" id="ddt-edit-network">
                            <button type="button" class="btn btn-xs ddt-btn" id="ddt-edit-network-btn" aria-haspopup="listbox"><span class="ddt-label">iMonetizeit</span><svg class="ddt-caret" viewBox="0 0 10 6" width="10" height="6" fill="currentColor" aria-hidden="true" focusable="false"><path d="M0 0l5 6 5-6z"/></svg></button>
                            <ul class="ddt-menu" id="ddt-edit-network-menu" role="listbox">
                                <li><a href="#" data-val="IMONETIZEIT" class="ddt-active">iMonetizeit</a></li>
                                <li><a href="#" data-val="LOSPOLLOS">LosPollos</a></li>
                                <li><a href="#" data-val="TRAFEE">Trafee</a></li>
                                <li><a href="#" data-val="CUSTOM">Custom</a></li>
                            </ul>
                        </div>
                        <input type="hidden" id="edit_network_sel" value="IMONETIZEIT">
                        <input type="text" class="form-control" id="edit_custom_network" placeholder="Nama network..." style="display:none;margin-top:6px;" autocomplete="off">
                        <input type="hidden" class="form-control" id="edit_network" name="edit_network" required>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                <button type="button" id="btn_edit" class="btn btn-primary">Save</button>
            </div>
        </div>
    </div>
</div>

<script src="<?= srpAssetUrl('/assets/js/campaigns-2.js') ?>"></script>
<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/campaigns-2.css') ?>">
<script src="<?= srpAssetUrl('/assets/js/campaigns-3.js') ?>"></script>

<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/campaigns-3.css') ?>">

<script src="<?= srpAssetUrl('/assets/js/campaigns-4.js') ?>"></script>

<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/campaigns-4.css') ?>">
<script src="<?= srpAssetUrl('/assets/js/campaigns-5.js') ?>"></script>
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
</body>
</html>
