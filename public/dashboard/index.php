<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/env.php';

require_once dirname(__DIR__, 2) . '/asset_url.php';


error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

include_once __DIR__ . '/../password.login.php';

const ADMIN_CSRF_NAMESPACE = 'admin_panel';

function adminServerString(string $key): string
{
    $value = $_SERVER[$key] ?? null;

    return is_string($value) ? $value : '';
}

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
    . "style-src 'self' 'nonce-{$nonce}' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com; "
    . "script-src 'self' 'nonce-{$nonce}'; "
    . "connect-src 'self';",
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

    <link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/dashboard-1.css') ?>">
</head>
<body>
<script nonce="<?= adminEsc($nonce); ?>" src="/assets/js/jquery-1.11.1.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>" src="/assets/js/bootstrap.min.js"></script>
<script nonce="<?= adminEsc($nonce); ?>">
(function ($) {
    'use strict';

    window.adminPanelCsrfToken = <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;

    $.ajaxSetup({
        headers: {
            'X-CSRF-Token': window.adminPanelCsrfToken
        }
    });
}(jQuery));
</script>
<script src="<?= srpAssetUrl('/assets/js/dashboard-1.js') ?>"></script>

<?php
$page_name = dirname(__FILE__);
$each_page_name = explode('/', $page_name);
$data = explode('.', end($each_page_name));
$team = strtoupper($data[0]);
$requestBaseUrl = (adminIsHttpsRequest() ? 'https' : 'http') . '://' . adminServerString('HTTP_HOST') . '/';
$requestBaseUrlAttr = adminEsc($requestBaseUrl);
$requestBaseUrlJs = json_encode($requestBaseUrl, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT);
$teamJs = json_encode($team, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT);
?>
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
                    <li class="active"><a href="#"><strong>Dashboard</strong></a></li>
                    <li><a href="/campaigns/"><strong>Campaigns</strong></a></li>
                    <li><a href="/addondomain/"><strong>Addon Domain</strong></a></li>
                    <!--<li><a href="/shortlinks/"><strong>Shortlinks</strong></a></li>-->
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
                    <div class="input-group tbl-search-group">
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
                    <svg viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 5v14"/><path d="M5 12h14"/></svg> Create Generate</button>
            </div>
            <div class="table-scroll">
                <table id="tbl_trackers" class="table table-hover">
                    <thead>
                        <tr>
                            <th>Empid</th>
                            <th>Tracker</th>
                            <th>Password</th>
                            <th>Generate URL</th>
                            <th>TEAM</th>
                            <th class="th-action">Action</th>
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
                    <h4 class="modal-title">Create Generate</h4>
                </div>
                <div class="modal-body">
                    <blockquote>
                    <p class="text-warning">ADD UserID:</p>
                    </blockquote> 
                    <form method="post" id="frm_add">
                        <input type="hidden" value="add" name="action" id="action">
                        <div class="form-group">
                            <label for="salary" class="control-label">Tracker:</label>
                            <input type="text" placeholder="{tracker}" class="form-control" id="sub_id" name="sub_id" required="true" autofocus="" autocomplete="off"/>
                        </div>
                        <div class="form-group">
                            <label for="salary" class="control-label">Password:</label>
                            <input type="text" placeholder="{password}" class="form-control" id="password" name="password" required="true"/>
                        </div>
                        <div class="form-group">
                            <label for="salary" class="control-label">Generate URL:</label>
                            <input readonly="readonly" type="text" class="form-control" id="gen_url" name="gen_url" placeholder="<?= $requestBaseUrlAttr; ?>"/>
                        </div>
                        <div class="form-group">
                            <label for="salary" class="control-label">TEAM:</label>
                            <input type="text" placeholder="{smartlink}" class="form-control" id="sm_url" name="sm_url" required="true" autocomplete="off" readonly/>
                        </div>
                        </div>
                        <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                    <button type="button" id="btn_add" class="btn btn-primary">Save</button>
                </div>
                </form>
            </div>
        </div>
    </div>
    <div id="edit_model" class="modal fade" data-keyboard="false" data-backdrop="static">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <a class="close" data-dismiss="modal" aria-hidden="true">&times;</a>
                    <h4 class="modal-title">Edit Generate</h4>
                </div>
                <div class="modal-body">
                    <form method="post" id="frm_edit">
                        <input type="hidden" value="edit" name="action" id="action">
                        <input type="hidden" value="0" name="edit_id" id="edit_id">
                        <div class="form-group">
                            <label for="salary" class="control-label">Tracker:</label>
                            <input type="text" class="form-control" id="edit_sub_id" name="edit_sub_id" required="true" autofocus autocomplete="off"/>
                        </div>
                        <div class="form-group">
                            <label for="salary" class="control-label">Password:</label>
                            <input type="text" class="form-control" id="edit_password" name="edit_password" placeholder="Leave blank to keep current password" autocomplete="off" />
                        </div>
                        <div class="form-group">
                            <label for="salary" class="control-label">Generate URL:</label>
                            <input type="text" class="form-control" id="edit_gen_url" name="edit_gen_url" readonly="readonly"/>
                        </div>
                        <div class="form-group">
                            <label for="salary" class="control-label">TEAM:</label>
                            <input type="text" class="form-control" id="edit_sm_url" name="edit_sm_url" autocomplete="off" readonly/>
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
    <script nonce="<?= adminEsc($nonce); ?>">
    $(document).ready(function() {
        function svgIcon(type) {
            var a = ' width="14" height="14" viewBox="0 0 24 24" stroke="currentColor" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"';
            var filledAttrs = ' width="16" height="16" viewBox="0 -960 960 960" fill="currentColor" focusable="false"';
            if (type === 'delete') {
                return '<span class="action-ico action-ico--filled" aria-hidden="true"><svg' + filledAttrs + '><path d="M259-104q-30.75 0-51.87-21.13Q186-146.25 186-177v-575h-41v-73h202v-34h267v34h202v73h-41v575q0 28.73-22.14 50.86Q730.72-104 702-104zm443-648H259v575h443zM357-264h73v-403h-73zm175 0h73v-403h-73zM259-752v575z"/></svg></span>';
            }
            if (type === 'eye') {
                return '<span class="action-ico" aria-hidden="true"><svg' + a + '><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg></span>';
            }
            if (type === 'eye-off') {
                return '<span class="action-ico" aria-hidden="true"><svg' + a + '><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg></span>';
            }
            return '<span class="action-ico action-ico--filled" aria-hidden="true"><svg' + filledAttrs + '><path d="M194-194h57l371-371-57-56-371 371zM88-88v-206l558-558q11-11 24.5-15.5T698-872t26.5 4 23.5 15l105 105q11 11 15 24t4 27-4.5 27-15.5 24L294-88zm666-609-57-56zM594-593l-29-28 57 56z"/></svg></span>';
        }
        function escHtml(v) {
            return String(v === null || v === undefined ? '' : v)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function ajaxErrorText(xhr) {
            var response = xhr && xhr.responseJSON ? xhr.responseJSON : null;
            var code = response && response.error ? String(response.error) : 'request-failed';
            if (xhr && xhr.status === 403) { return 'Unauthorized session. Please login again.'; }
            if (xhr && xhr.status === 419) { return 'Session expired. Reload the page and try again.'; }
            if (xhr && xhr.status === 422) { return 'Invalid or incomplete input.'; }
            if (xhr && xhr.status === 405) { return 'Invalid request method.'; }
            if (xhr && xhr.status >= 500) { return 'Server error: ' + code + '. Check PHP error_log.'; }
            return 'Request failed: ' + code;
        }

        function handleAjaxFailure(xhr) {
            Swal.fire({ allowOutsideClick: false, type: 'error', title: 'Request failed', text: ajaxErrorText(xhr) });
        }

        var serv = <?= $requestBaseUrlJs; ?>;
        var adminPanelCsrfToken = window.adminPanelCsrfToken || '';
        var state = { current: 1, rowCount: 25, search: '', rows: [] };

        document.getElementById('sub_id').onkeyup = function() {
            document.getElementById('gen_url').value = serv + this.value.toUpperCase();
        };
        document.getElementById('edit_sub_id').onkeyup = function() {
            document.getElementById('edit_gen_url').value = serv + this.value.toUpperCase();
        };

        function renderRow(row, idx) {
            var url = row.gen_url === null || row.gen_url === undefined ? '' : String(row.gen_url);
            var smUrl = row.sm_url === null || row.sm_url === undefined ? '' : String(row.sm_url);
            var pass = row.password_plain === null || row.password_plain === undefined ? '' : String(row.password_plain);
            return '<tr>' +
                '<td><span class="td-num">' + (idx + 1) + '</span></td>' +
                '<td><span class="td-tracker">' + escHtml(row.sub_id) + '</span></td>' +
                '<td><span class="td-pass" data-pass="' + escHtml(pass) + '" data-shown="0" title="Click the eye to show/hide">••••••</span> ' +
                    '<button type="button" class="btn btn-xs btn-default command-toggle-pass" title="Show/Hide" aria-label="Show or hide password hash">' + svgIcon('eye') + '</button></td>' +
                '<td><span class="td-url" title="' + escHtml(url) + '">' + escHtml(url) + '</span></td>' +
                '<td><span class="td-url" title="' + escHtml(smUrl) + '">' + escHtml(smUrl) + '</span></td>' +
                '<td class="td-action">' +
                    '<button type="button" class="btn btn-xs btn-default action-btn command-edit" data-row-id="' + escHtml(row.id) + '" title="Edit" aria-label="Edit">' + svgIcon('edit') + '</button> ' +
                    '<button type="button" class="btn btn-xs btn-default action-btn command-delete" data-row-id="' + escHtml(row.id) + '" title="Delete" aria-label="Delete">' + svgIcon('delete') + '</button>' +
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

        function bindRowActions() {
            $('#tbl_trackers').find('.command-toggle-pass').off('click').on('click', function() {
                var span = $(this).siblings('.td-pass');
                if (span.attr('data-shown') === '1') {
                    span.text('••••••').attr('data-shown', '0');
                    $(this).html(svgIcon('eye'));
                } else {
                    var v = span.attr('data-pass') || '';
                    span.text(v === '' ? '—' : v).attr('data-shown', '1');
                    $(this).html(svgIcon('eye-off'));
                }
            });
            $('#tbl_trackers').find('.command-edit').off('click').on('click', function() {
                var rowId = $(this).data('row-id');
                var row = null;
                for (var i = 0; i < state.rows.length; i++) {
                    if (String(state.rows[i].id) === String(rowId)) { row = state.rows[i]; break; }
                }
                if (!row) { Swal.fire({ allowOutsideClick: false, type: 'error', title: 'Oops...', text: 'No row selected.' }); return; }
                $('#edit_id').val(row.id);
                $('#edit_sub_id').val(row.sub_id);
                $('#edit_password').val('');
                $('#edit_gen_url').val(row.gen_url);
                $('#edit_sm_url').val(row.sm_url);
                $('#edit_model').modal('show');
            });
            $('#tbl_trackers').find('.command-delete').off('click').on('click', function() {
                var rowId = $(this).data('row-id');
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
                    if (result.value) {
                        $.ajax({
                            type: 'POST', url: 'response.php',
                            data: { id: rowId, action: 'delete', csrf_token: adminPanelCsrfToken },
                            dataType: 'json',
                            success: function() {
                                Swal.fire('Deleted!', 'Your file has been deleted.', 'success');
                                loadData();
                            },
                            error: handleAjaxFailure
                        });
                    }
                });
            });
        }

        function loadData() {
            $.ajax({
                type: 'POST', url: 'response.php',
                data: { current: state.current, rowCount: state.rowCount, searchPhrase: state.search },
                dataType: 'json',
                success: function(data) {
                    state.rows = data.rows || [];
                    var total = data.total || 0;
                    var html = '';
                    for (var i = 0; i < state.rows.length; i++) { html += renderRow(state.rows[i], i); }
                    $('#tbl_trackers tbody').html(html || '<tr><td colspan="6" class="td-empty">No data</td></tr>');
                    var from = total === 0 ? 0 : ((state.current - 1) * (state.rowCount === -1 ? total : state.rowCount)) + 1;
                    var to = state.rowCount === -1 ? total : Math.min(state.current * state.rowCount, total);
                    $('#tbl-info').text('Showing ' + from + ' to ' + to + ' of ' + total + ' entries');
                    renderPagination(total, state.current, state.rowCount);
                    bindRowActions();
                },
                error: handleAjaxFailure
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

        function ajaxAction(action) {
            var data = $("#frm_" + action).serializeArray();
            data.push({ name: 'csrf_token', value: adminPanelCsrfToken });
            $.ajax({
                type: 'POST', url: 'response.php',
                data: data, dataType: 'json',
                success: function() {
                    $('#' + action + '_model').modal('hide');
                    loadData();
                },
                error: handleAjaxFailure
            });
        }

        $("#command-add").on('click', function() {
            $("#sub_id").val('');
            $("#password").val(btoa(+new Date).substr(-7, 5));
            $("#gen_url").val('');
            $("#sm_url").val(<?= $teamJs; ?>);
            $('#add_model').modal('show');
        });
        $("#btn_add").on('click', function() {
            if ($.trim($("#sub_id").val()) === "" || $.trim($("#gen_url").val()) === "") {
                Swal.fire({ allowOutsideClick: false, type: 'error', title: 'Oops...', text: 'Something went wrong! {Required all fields}' });
                return false;
            }
            ajaxAction('add');
        });
        $("#btn_edit").on('click', function() { ajaxAction('edit'); });

        $('#sub_id, #edit_sub_id').on('keypress', function(event) {
            var regex = new RegExp("^[a-zA-Z0-9]+$");
            var key = String.fromCharCode(!event.charCode ? event.which : event.charCode);
            if (!regex.test(key)) { event.preventDefault(); return false; }
        });

        loadData();
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
<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/dashboard-2.css') ?>">
<script src="<?= srpAssetUrl('/assets/js/dashboard-2.js') ?>"></script>

<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/dashboard-3.css') ?>">

<script src="<?= srpAssetUrl('/assets/js/dashboard-3.js') ?>"></script>

<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/dashboard-4.css') ?>">
<script src="<?= srpAssetUrl('/assets/js/dashboard-4.js') ?>"></script>
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
