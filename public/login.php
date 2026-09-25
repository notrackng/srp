<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';

require_once dirname(__DIR__) . '/asset_url.php';

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

include_once __DIR__ . '/password.login.php';
require_once dirname(__DIR__) . '/login_throttle.php';

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

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('sslmgr_admin');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => adminIsHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    if (!session_start()) {
        http_response_code(503);
        exit('Service temporarily unavailable.');
    }
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
    $ipAddress = adminEsc((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>ADMIN PANEL</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="/favicon.ico" rel="icon" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Caveat:wght@500;600;700&amp;display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/bootstrap.min.css" type="text/css" media="all">
    <link rel="stylesheet" href="<?= adminEsc(srpAssetUrl('/assets/css/portal-login-1.css')); ?>">
    <style nonce="<?= adminEsc($nonce); ?>">
        .login-wrap,
        .app-sign {
            position: relative;
            z-index: 1;
        }
    </style>
</head>
<body>
<div class="container login-wrap">
    <div class="noise" aria-hidden="true"></div>
    <div class="scanline" aria-hidden="true"></div>
    <div class="panel panel-default">
        <div class="panel-heading"><strong class="usr">Login: Admin Panel</strong></div>
        <div class="panel-body">
            <?php if ($errorMsg !== '') : ?>
                <div class="msg">
                    <?= $errorMsg === 'csrf'
                        ? 'Session expired. Reload the page and try again.'
                        : 'Access denied. Your IP address: ' . $ipAddress; ?>
                </div>
            <?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="access_login" value="">
                <input type="hidden" name="csrf_token" value="<?= adminEsc($csrfToken); ?>">
                <div class="input-group">
                    <input
                        type="password"
                        class="form-control input-sm"
                        name="access_password"
                        maxlength="4096"
                        autofocus
                        required
                        placeholder="{password}"
                    >
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm" type="submit"><strong>Login</strong></button>
                    </span>
                </div>
            </form>
        </div>
    </div>
</div>
<div class="container"><div class="app-sign"><footer>Ngix · xctd</footer></div></div>
<script src="<?= adminEsc(srpAssetUrl('/assets/js/portal-login-1.js')); ?>"></script>
<link rel="stylesheet" href="<?= adminEsc(srpAssetUrl('/assets/css/portal-login-2.css')); ?>">
<script src="<?= adminEsc(srpAssetUrl('/assets/js/portal-login-2.js')); ?>"></script>
<link rel="stylesheet" href="<?= adminEsc(srpAssetUrl('/assets/css/portal-login-3.css')); ?>">
<script src="<?= adminEsc(srpAssetUrl('/assets/js/portal-login-3.js')); ?>"></script>
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
    <?php
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

if (adminIsHttpsRequest()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

header(
    "Content-Security-Policy: default-src 'self'; "
    . "base-uri 'self'; "
    . "form-action 'self'; "
    . "frame-ancestors 'self'; "
    . "object-src 'none'; "
    . "img-src 'self' data: https:; "
    . "font-src 'self' data: https:; "
    . "style-src 'self' 'unsafe-inline' 'nonce-{$nonce}' https://fonts.googleapis.com "
    . "https://use.fontawesome.com https://cdnjs.cloudflare.com; "
    . "script-src 'self' 'nonce-{$nonce}'; "
    . "connect-src 'self';",
);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    $logoutToken = $_POST['csrf_token'] ?? null;
    if (!adminHasValidCsrf(is_string($logoutToken) ? $logoutToken : null)) {
        http_response_code(419);
        exit('Session expired. Reload the page and try again.');
    }

    unset($_SESSION['admin_authenticated']);
    session_regenerate_id(true);
    header('Location: /login.php');
    exit;
}

// Rate limiting: 5 attempts -> 15 min lockout, 10 attempts -> 30 min.
// Tracked per-session and per-IP; the strongest signal wins.
$_SESSION['admin_login_attempts'] ??= 0;
$_SESSION['admin_login_last'] ??= 0;
$adminIpState = srp_login_throttle_state('admin_login');
$adminAttempts = max((int) $_SESSION['admin_login_attempts'], $adminIpState['fails']);
$adminLastFail = max((int) $_SESSION['admin_login_last'], $adminIpState['last']);
$adminLockout = srp_login_lockout_seconds($adminAttempts);

if ($adminLockout > 0 && (time() - $adminLastFail) < $adminLockout) {
    showLoginPasswordProtect('lockout', $nonce, $csrfToken);
}

if (isset($_POST['access_password'])) {
    $postedCsrfRaw = $_POST['csrf_token'] ?? '';
    $postedCsrfToken = is_string($postedCsrfRaw) ? $postedCsrfRaw : '';
    $passRaw = $_POST['access_password'] ?? '';
    $pass = is_string($passRaw) ? $passRaw : '';

    if (!adminHasValidCsrf($postedCsrfToken)) {
        showLoginPasswordProtect('csrf', $nonce, $csrfToken);
    }

    // srp_env_secret_matches() checks ADMIN_PASSWORD_HASH (preferred, bcrypt/
    // argon2) before falling back to the plaintext ADMIN_PASSWORD var — public/
    // install.php only ever writes the *_HASH variant, so reading the plain var
    // alone (the previous behaviour here) left the admin panel unreachable
    // after a fresh install.
    $isValid = srp_env_secret_matches('ADMIN_PASSWORD', $pass);

    if (!$isValid && srp_env_secret_matches('A2ROOT_PASSWORD', $pass)) {
        $isValid = true;
    }

    if (!$isValid) {
        $_SESSION['admin_login_attempts'] = (int) $_SESSION['admin_login_attempts'] + 1;
        $_SESSION['admin_login_last'] = time();
        srp_login_throttle_register_fail('admin_login');
        showLoginPasswordProtect('err', $nonce, $csrfToken);
    }

    $_SESSION['admin_login_attempts'] = 0;
    $_SESSION['admin_login_last'] = 0;
    srp_login_throttle_reset('admin_login');
    session_regenerate_id(true);
    $_SESSION['admin_authenticated'] = true;
}

if (empty($_SESSION['admin_authenticated'])) {
    showLoginPasswordProtect('', $nonce, $csrfToken);
}

header('Location: /dashboard/');
exit;
