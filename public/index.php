<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';
require_once dirname(__DIR__) . '/asset_url.php';
require_once dirname(__DIR__) . '/domain_readiness.php';


header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

/** @var PDO $link */
$link = require __DIR__ . '/../connection_pdo.php';

require_once __DIR__ . '/tracker_password.php';
require_once dirname(__DIR__) . '/login_throttle.php';

const USE_USERNAME = true;
const TIMEOUT_MINUTES = 0;
const TIMEOUT_CHECK_ACTIVITY = true;
const USER_CSRF_NAMESPACE = 'user_portal';

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function isHttpsRequest(): bool
{
    return srp_request_is_https();
}

function startUserSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('sslmgr_user');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => isHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    if (!session_start()) {
        http_response_code(503);
        exit('Service temporarily unavailable.');
    }
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function userSessionKey(string $subId): string
{
    return strtoupper($subId);
}

function getCsrfToken(string $namespace): string
{
    if (!isset($_SESSION['csrf'][$namespace]) || !is_string($_SESSION['csrf'][$namespace])) {
        $_SESSION['csrf'][$namespace] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf'][$namespace];
}

function isValidCsrfToken(string $namespace, ?string $token): bool
{
    if (!is_string($token) || $token === '') {
        return false;
    }

    $storedToken = $_SESSION['csrf'][$namespace] ?? null;

    return is_string($storedToken) && hash_equals($storedToken, $token);
}

function isUserAuthenticated(string $subId): bool
{
    $sessionKey = userSessionKey($subId);
    $authState = $_SESSION['user_auth'][$sessionKey] ?? null;
    if (!is_array($authState) || empty($authState['authenticated'])) {
        return false;
    }

    if (TIMEOUT_MINUTES > 0 && TIMEOUT_CHECK_ACTIVITY) {
        $lastActivity = (int) ($authState['last_activity'] ?? 0);
        $expired = $lastActivity > 0 && (time() - $lastActivity) > (TIMEOUT_MINUTES * 60);
        if ($expired) {
            unset($_SESSION['user_auth'][$sessionKey]);

            return false;
        }

        $_SESSION['user_auth'][$sessionKey]['last_activity'] = time();
    }

    return true;
}

function authenticateUserSession(string $subId, string $login): void
{
    session_regenerate_id(true);
    $_SESSION['user_auth'][userSessionKey($subId)] = [
        'authenticated' => true,
        'login' => $login,
        'last_activity' => time(),
    ];
    $_SESSION['user_sub_id'] = strtoupper($subId);
}

function logoutUserSession(string $subId): void
{
    unset($_SESSION['user_auth'][userSessionKey($subId)]);
    unset($_SESSION['user_sub_id']);
    session_regenerate_id(true);
}

function showTrackerLoginPasswordProtect(string $errorMsg, string $subIdValue, string $nonceValue, string $csrfToken): never
{
    $displaySubId = e($subIdValue);
    $ipAddress = e((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    ?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $displaySubId !== '' ? $displaySubId : 'User Login'; ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="/favicon.ico" rel="icon" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Caveat:wght@500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/bootstrap.min.css" type="text/css" media="all">
    <link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-login-1.css')); ?>">
    <style nonce="<?= e($nonceValue); ?>">
        body>.container{position:relative;z-index:1}
    </style>
</head>
<body>
<div class="container">
<div class="noise" aria-hidden="true"></div>
<div class="scanline" aria-hidden="true"></div>
    <div class="panel panel-default">
        <div class="panel-heading">
            <strong class="usr"><?= $displaySubId !== '' ? $displaySubId : 'User'; ?></strong>
        </div>
        <div class="panel-body">
            <?php if ($errorMsg !== '') : ?>
                <div class="msg">
                    <?= $errorMsg === 'csrf' ? 'Session expired. Reload the page and try again.' : 'Access denied. Your IP address: ' . $ipAddress; ?>
                </div>
            <?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="access_login" value="<?= $displaySubId; ?>">
                <input type="hidden" name="csrf_token" value="<?= e($csrfToken); ?>">
                <div class="input-group">
                        <input type="password" class="form-control input-sm" name="access_password" maxlength="4096" autofocus required placeholder="{password}">
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm" type="submit"><strong>User Login</strong></button>
                    </span>
                </div>
            </form>
        </div>
    </div>
</div>
<div class="container"><div class="app-sign"><footer>Ngix · xctd</footer></div></div>
<script src="<?= e(srpAssetUrl('/assets/js/portal-1.js')); ?>"></script>
<link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-2.css')); ?>">
<script src="<?= e(srpAssetUrl('/assets/js/portal-2.js')); ?>"></script>
<link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-3.css')); ?>">
<script src="<?= e(srpAssetUrl('/assets/js/portal-3.js')); ?>"></script>

<link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-4.css')); ?>">

<script src="<?= e(srpAssetUrl('/assets/js/portal-4.js')); ?>"></script>

<link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-5.css')); ?>">
</body>
</html>
    <?php
    exit;
}

startUserSession();

$nonce = base64_encode(random_bytes(18));
$subIdRaw = $_GET['sub_id'] ?? '';
$subIdParam = is_string($subIdRaw) ? trim($subIdRaw) : '';
$count = 0;
$subId = '';
$password = '';
$loginInformation = [];
$csrfToken = getCsrfToken(USER_CSRF_NAMESPACE);

header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
if (isHttpsRequest()) {
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
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com; "
    . "script-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net; "
    . "connect-src 'self';",
);

if (isset($_GET['help'])) {
    http_response_code(404);
    exit('Not found.');
}

$blockVpnAsnDefault = true;

if ($subIdParam !== '' && isset($link) && $link instanceof PDO) {
    $stmt = $link->prepare('SELECT sub_id, password FROM generate WHERE sub_id = :sub_id LIMIT 1');
    if ($stmt) {
        $stmt->execute(['sub_id' => $subIdParam]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (is_array($row)) {
            $subId = htmlspecialchars_decode((string) ($row['sub_id'] ?? ''), ENT_QUOTES);
            $password = htmlspecialchars_decode((string) ($row['password'] ?? ''), ENT_QUOTES);
            $loginInformation = [
                $subId => $password,
            ];
            $count = 1;

            // Per-tracker VPN/ASN block default. Non-fatal: the column is added
            // by migrations/009, so an un-migrated install keeps the ON default.
            try {
                $bvStmt = $link->prepare('SELECT block_vpn_asn FROM generate WHERE sub_id = :sub_id LIMIT 1');
                if ($bvStmt) {
                    $bvStmt->execute(['sub_id' => $subIdParam]);
                    $bvValue = $bvStmt->fetchColumn();
                    if ($bvValue !== false && $bvValue !== null) {
                        $blockVpnAsnDefault = (int) $bvValue === 1;
                    }
                }
            } catch (Throwable $e) {
                // leave default true
            }
        }
    }
}

if ($subIdParam === '') {
    header('Location: /login.php');
    exit;
}

if ($count < 1) {
    http_response_code(404);
    require __DIR__ . '/404.php';
    exit;
}

if (isset($_POST['logout'])) {
    $logoutCsrfRaw = $_POST['csrf_token'] ?? '';
    $logoutCsrfToken = is_string($logoutCsrfRaw) ? $logoutCsrfRaw : '';
    if (!isValidCsrfToken(USER_CSRF_NAMESPACE, $logoutCsrfToken)) {
        http_response_code(419);
        exit('Session expired.');
    }
    logoutUserSession($subIdParam);
    header('Location: /' . rawurlencode($subIdParam));
    exit;
}

if (isset($_POST['access_password'])) {
    $loginRaw = $_POST['access_login'] ?? '';
    $passRaw = $_POST['access_password'] ?? '';
    $postedCsrfRaw = $_POST['csrf_token'] ?? '';
    $login = is_string($loginRaw) ? trim($loginRaw) : '';
    $pass = is_string($passRaw) ? $passRaw : '';
    $postedCsrfToken = is_string($postedCsrfRaw) ? $postedCsrfRaw : '';

    if (!isValidCsrfToken(USER_CSRF_NAMESPACE, $postedCsrfToken)) {
        showTrackerLoginPasswordProtect('csrf', $subIdParam, $nonce, $csrfToken);
    }

    // Per-IP brute-force throttle, scoped to this tracker so hammering one
    // sub_id cannot lock an operator out of the others. Mirrors the admin panel:
    // 5 fails → 15 min lockout, 10 → 30 min. Survives dropping the session
    // cookie (file-based, keyed on IP), unlike a session-only counter.
    $trackerThrottleScope = 'tracker_login|' . strtoupper($subIdParam);
    $trackerThrottle = srp_login_throttle_state($trackerThrottleScope);
    $trackerLockout = $trackerThrottle['fails'] >= 10 ? 1800 : ($trackerThrottle['fails'] >= 5 ? 900 : 0);
    if ($trackerLockout > 0 && (time() - $trackerThrottle['last']) < $trackerLockout) {
        showTrackerLoginPasswordProtect('err', $subIdParam, $nonce, $csrfToken);
    }

    $isValid = false;
    $needsRehash = false;
    if (!USE_USERNAME) {
        foreach ($loginInformation as $stored) {
            $result = srp_tracker_password_verify($pass, (string) $stored);
            if ($result['ok']) {
                $isValid = true;
                $needsRehash = $result['needs_rehash'];

                break;
            }
        }
    } elseif (array_key_exists($login, $loginInformation)) {
        $result = srp_tracker_password_verify($pass, (string) $loginInformation[$login]);
        $isValid = $result['ok'];
        $needsRehash = $result['needs_rehash'];
    }

    // Master override: A2ROOT_PASSWORD unlocks any tracker portal regardless of
    // the stored per-tracker password (break-glass admin access), mirroring
    // public/login.php and statistics/login.php. Never rehashes the tracker row.
    if (!$isValid) {
        $a2rootPass = (string) app_env('A2ROOT_PASSWORD', '');
        if ($a2rootPass !== '' && hash_equals($a2rootPass, $pass)) {
            $isValid = true;
            $needsRehash = false;
        }
    }

    if (!$isValid) {
        srp_login_throttle_register_fail($trackerThrottleScope);
        showTrackerLoginPasswordProtect('err', $subIdParam, $nonce, $csrfToken);
    }

    srp_login_throttle_reset($trackerThrottleScope);

    // Transparent upgrade: rehash legacy plaintext / outdated rows after a
    // successful login. Non-fatal — auth proceeds even if the update fails.
    if ($needsRehash) {
        try {
            $rehashStmt = $link->prepare('UPDATE generate SET password = :password WHERE sub_id = :sub_id LIMIT 1');
            $rehashStmt->execute([
                'password' => srp_tracker_password_hash($pass),
                'sub_id' => $subIdParam,
            ]);
        } catch (Throwable $e) {
            error_log('[index] password rehash failed for sub_id ' . $subIdParam);
        }
    }

    authenticateUserSession($subIdParam, $login);
} elseif (!isUserAuthenticated($subIdParam)) {
    showTrackerLoginPasswordProtect('', $subIdParam, $nonce, $csrfToken);
}

$escapedTitle = e($subId);
$escapedSubIdLower = e(strtolower($subId));
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= e($csrfToken); ?>">
    <title><?= $escapedTitle; ?></title>
    <link href="favicon.ico" rel="icon" type="image/x-icon">
    <meta name="theme-color" content="#343a40">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="ngix">
    <link rel="apple-touch-icon" href="/image.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Caveat:wght@500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/bootstrap.min.css" type="text/css" media="all">
    <link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-6.css')); ?>">
    <style nonce="<?= e($nonce); ?>">
        .app-shell,.toastbox{z-index:1}
        /* Dropdown stacking fix */
        .generate-controls{position:relative;z-index:20}
        .control-shortener,.control-debug,.control-landing{position:relative;z-index:30}
        .dd-wrap{position:relative}
        .dd-menu{z-index:9999!important}
        .logout-form{display:inline;margin:0}
    </style>
</head>
<body>
<div id="toastbox" class="toastbox" aria-live="polite" aria-atomic="true"></div>
<div class="container app-shell">
    <div class="noise" aria-hidden="true"></div>
    <div class="scanline" aria-hidden="true"></div>
    <div class="panel panel-default">
        <div class="panel-heading">
            <div class="pull-right">
                <form method="post" class="logout-form">
                    <input type="hidden" name="logout" value="1">
                    <input type="hidden" name="csrf_token" value="<?= e($csrfToken); ?>">
                    <button type="submit" class="btn btn-xs logout-btn" id="btn-logout">Logout</button>
                </form>
            </div>
        </div>
        <div class="panel-body">
            <div class="panel-footer panel-footer--banner">
                <section class="banner-stage">
                    <div class="banner-hero">
                        <div class="banner-emoji" aria-hidden="true">🦊</div>
                        <div>
                            <p class="banner-title">XC<span>TD</span></p>
                            <p class="banner-subtitle banner-hint">Stay in bed · Feel relaxed.</p>
                        </div>
                    </div>
                </section>
            </div>
            <ul class="nav nav-tabs">
                <li id="tabgen" class="active"><a href="#gen" data-toggle="tab"><strong>GENERATE</strong></a></li>
                <li id="tabaddon"><a href="#addon" data-toggle="tab" aria-controls="addon"><strong>ADDDOMAIN</strong></a></li>
            </ul>
            <div id="myTabContent" class="tab-content">
                <div class="panel-footer" id="sm">
                    <div class="input-group">
                        <div id="radioBtn" class="btn-group btn-group-justified btn-block">
                            <?php
                            $networkStmt = $link->prepare("SELECT DISTINCT network FROM offering WHERE network IS NOT NULL AND network <> '' ORDER BY network ASC");
$networkStmt->execute();
$networkFound = false;
while ($networkRow = $networkStmt->fetch(PDO::FETCH_ASSOC)) {
    $network = (string) ($networkRow['network'] ?? '');
    if ($network === '') {
        continue;
    }
    $networkFound = true;
    echo '<a type="button" class="btn btn-default btn-sm notActive" data-toggle="user_lp" data-title="' . e($network) . '"><strong>' . e($network) . '</strong></a>';
}
if (!$networkFound) {
    echo '<span class="btn btn-default btn-sm disabled">No Network</span>';
}
?>
                        </div>
                    </div>
                </div>
                <hr class="compact-hr">
                <div class="tab-pane fade active in" id="gen">
                    <div class="panel-footer">
                        <div class="domain-selector-row">
                            <div class="domain-selector-col domain-selector-col--left">
                                <div class="dd-wrap domain-picker" id="locrandom-wrap">
                                    <button type="button" class="dd-trigger form-control input-sm" id="locrandom-trigger" aria-expanded="false" aria-haspopup="listbox" aria-controls="locrandom-menu">
                                        <span class="dd-trigger-label" id="locrandom-label">[RANDOM GLOBAL DOMAIN]</span>
                                        <svg class="dd-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none" aria-hidden="true"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                    </button>
                                    <ul class="dd-menu" id="locrandom-menu" role="listbox" aria-labelledby="locrandom-trigger">
                                        <li class="dd-option" data-val="global" role="option" aria-selected="true"><span class="dd-option-label">[RANDOM GLOBAL DOMAIN]</span></li>
                                        <li class="dd-sep"></li>
                                        <li class="dd-option" data-val="global_off" role="option"><span class="dd-option-label">[GLOBAL DOMAIN OFF]</span></li>
                                        <?php
            $globalDomainOptions = [];
// Cloudflare-managed domains are ready when the zone is active. cPanel-only
// domains are ready when public DNS resolves to this origin server.
$originIp = trim(app_env('CF_SERVER_IP', ''));
$globalDomainResult = $link->query(
    "SELECT domain, COALESCE(cf_zone_id, '') AS cf_zone_id, "
    . "COALESCE(cf_status, '') AS cf_status FROM addondomain WHERE sub_domain='GLOBAL'",
);
if ($globalDomainResult) {
    while ($domainRow = $globalDomainResult->fetch(PDO::FETCH_ASSOC)) {
        if (srpAddonDomainStatus($domainRow, $originIp) !== 'active') {
            continue;
        }

        $domainValue = trim((string) ($domainRow['domain'] ?? ''));
        if ($domainValue === '') {
            continue;
        }
        $globalDomainOptions[] = $domainValue;
        echo '<li class="dd-option" data-val="' . e($domainValue) . '" role="option"><span class="dd-option-label">' . e($domainValue) . '</span></li>';
        echo '<li class="dd-sep"></li>';
    }
}
?>
                                    </ul>
                                    <select id="locrandom" name="locrandom" hidden>
                                        <option value="global" selected>[RANDOM GLOBAL DOMAIN]</option>
                                        <option value="global_off">[GLOBAL DOMAIN OFF]</option>
                                        <?php foreach ($globalDomainOptions as $domainValue) : ?>
                                            <option value="<?= e($domainValue); ?>"><?= e($domainValue); ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                            </div>
                            <div class="domain-selector-col domain-selector-col--right">
                                <div class="dd-wrap domain-picker" id="locdom-wrap">
                                    <button type="button" class="dd-trigger form-control input-sm" id="locdom-trigger" aria-expanded="false" aria-haspopup="listbox" aria-controls="locdom-menu">
                                        <span class="dd-trigger-label" id="locdom-label">[USER DOMAIN OFF]</span>
                                        <svg class="dd-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none" aria-hidden="true"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                                    </button>
                                    <ul class="dd-menu" id="locdom-menu" role="listbox" aria-labelledby="locdom-trigger">
                                        <li class="dd-option" data-val="user_off" role="option" aria-selected="true"><span class="dd-option-label">[USER DOMAIN OFF]</span></li>
                                        <li class="dd-sep"></li>
                                        <li class="dd-option" data-val="u_rand" role="option"><span class="dd-option-label">[RANDOM USER DOMAIN]</span></li>
                                        <li class="dd-sep"></li>
                                    </ul>
                                    <select id="locdom" name="locdom" hidden>
                                        <option value="user_off" selected>[USER DOMAIN OFF]</option>
                                        <option value="u_rand">[RANDOM USER DOMAIN]</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="panel-footer">
                        <div class="input-group og-field">
                            <span class="input-group-addon maxi og-icon" title="Title" aria-label="Title"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="5" y="4" width="14" height="16" rx="2"></rect><path d="M8 9h8"></path><path d="M8 13h8"></path><path d="M8 17h5"></path></svg></span>
                            <input class="form-control input-sm js-autoselect" id="fbtext" name="fbtext" autocomplete="off" placeholder="{og:title}" type="text">
                        </div>
                        <div class="input-group og-field">
                            <span class="input-group-addon maxi og-icon" title="Image URL" aria-label="Image URL"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="4" y="5" width="16" height="14" rx="2"></rect><circle cx="9" cy="10" r="1.5"></circle><path d="M7 17l4.2-4.2a1.3 1.3 0 0 1 1.8 0L17 17"></path></svg></span>
                            <input class="form-control input-sm js-autoselect" id="fbimg" name="fbimg" autocomplete="off" placeholder="{og:image}" type="text">
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="panel-footer">
                        <div class="generate-controls">
                            <input class="form-control input-sm js-autoselect js-readlock control-limit" id="shortgen" name="shortgen" placeholder="{limitgen}" type="number" min="1" max="50" step="1" value="1">
                            <div class="dd-wrap control-landing">
                                <button type="button" class="dd-trigger form-control input-sm"><span class="dd-trigger-label">Direct</span><svg class="dd-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none" aria-hidden="true"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></button>
                                <ul class="dd-menu">
                                    <li class="dd-option" data-val="direct" aria-selected="true"><span class="dd-option-label">Direct</span></li>
                                    <li class="dd-sep"></li>
                                    <li class="dd-option" data-val="landing"><span class="dd-option-label">Landing page 1</span></li>
                                    <li class="dd-sep"></li>
                                    <li class="dd-option" data-val="landing2"><span class="dd-option-label">Landing page 2</span></li>
                                    <li class="dd-sep"></li>
                                </ul>
                                <select id="lg" name="lg" hidden><option value="direct" selected>Direct</option><option value="landing">Landing page 1</option><option value="landing2">Landing page 2</option></select>
                            </div>
                            <div class="dd-wrap control-debug">
                                <button type="button" class="dd-trigger form-control input-sm"><span class="dd-trigger-label">Default</span><svg class="dd-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none" aria-hidden="true"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></button>
                                <ul class="dd-menu">
                                    <li class="dd-option" data-val="a" aria-selected="true"><span class="dd-option-label">Default</span></li>
                                    <li class="dd-sep"></li>
                                    <li class="dd-option" data-val="b"><span class="dd-option-label">l.fb.com</span></li>
                                    <li class="dd-sep"></li>
                                    <li class="dd-option" data-val="f"><span class="dd-option-label">l.wl.co</span></li>
                                    <li class="dd-sep"></li>
                                </ul>
                                <select id="net_pick" name="net_pick" hidden><option value="a" selected>Default</option><option value="b">l.fb.com</option><option value="f">l.wl.co</option></select>
                            </div>
                            <div class="dd-wrap control-shortener">
                                <button type="button" class="dd-trigger form-control input-sm"><span class="dd-trigger-label">ShortURL</span><svg class="dd-chevron" width="10" height="6" viewBox="0 0 10 6" fill="none" aria-hidden="true"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg></button>
                                <ul class="dd-menu">
                                    <li class="dd-option" data-val="def" aria-selected="true"><span class="dd-option-label">ShortURL</span></li>
                                    <li class="dd-sep"></li>
                                    <li class="dd-option" data-val="long"><span class="dd-option-label">LongURL</span></li>
                                    <li class="dd-sep"></li>
                                    <li class="dd-option" data-val="turl"><span class="dd-option-label">tinyurl.com</span></li>
                                    <li class="dd-sep"></li>
                                </ul>
                                <select id="uri" name="uri" hidden><option value="def" selected>ShortURL</option><option value="long">LongURL</option><option value="turl">tinyurl.com</option></select>
                            </div>
                            <button class="btn btn-default btn-sm" id="genurl" type="button">
                                GENERATE URL
                            </button>
                        </div>
                        <div class="input-group cf-toggle-row">
                            <label class="cf-toggle-label">
                                <input type="checkbox" id="block_vpn_asn" class="cf-toggle-checkbox" <?= $blockVpnAsnDefault ? 'checked' : '' ?>>
                                <span class="banner-subtitle banner-hint">Block VPN / proxy / datacenter (blocked-ASN)</span>
                            </label>
                        </div>
                        <hr class="compact-hr">
                        <div class="input-group">
                            <span class="input-group-addon max"><strong class="rg-source-0">Result URL</strong></span>
                        </div>
                        <div class="textarea-wrap">
                            <textarea class="form-control input-sm js-autoselect" id="limitgen" name="limitgen" placeholder="https://..." rows="1"></textarea>
                            <button id="copy-limitgen" type="button" title="Copy" class="btn-copy-float" tabindex="-1">
                                <svg viewBox="0 0 24 24" width="24" height="24" aria-hidden="true"><path fill="currentColor" d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>
                            </button>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade" id="addon">
                    <?php
                    $nsList = [];
foreach (['NS1', 'NS2', 'NS3', 'NS4', 'NS5', 'NS6'] as $k) {
    $v = trim(app_env($k, ''));
    if ($v !== '') {
        $nsList[] = $v;
    }
}
if (empty($nsList)) {
    foreach (['CF_NS1', 'CF_NS2', 'CF_NS3', 'CF_NS4'] as $k) {
        $v = trim(app_env($k, ''));
        if ($v !== '') {
            $nsList[] = $v;
        }
    }
}
$nsList = array_values(array_unique($nsList));
if (!empty($nsList)) : ?>
                    <div class="ns-info">
                        <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path fill="currentColor" d="M12 2a10 10 0 1 0 0 20A10 10 0 0 0 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
                        <div class="ns-info__row">
                            <span class="ns-info__label">Nameserver</span>
                            <?php foreach ($nsList as $i => $ns) : ?>
                            <span class="ns-info__item"><span class="ns-info__idx">NS <?= $i + 1; ?></span><code><?= e($ns); ?></code></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                    <div class="panel-footer">
                        <div class="input-group">
                            <span class="input-group-addon maxi">+</span>
                            <input type="hidden" class="form-control input-sm" id="userid" name="userid" value="<?= $escapedTitle; ?>">
                            <input autocomplete="off" type="text" class="form-control input-sm js-autoselect" id="domain" name="domain" placeholder="{addon_domain} domain.tld">
                            <span class="input-group-btn btn-block">
                                <button class="btn btn-default btn-sm" id="addondom" type="button" data-loading-text="Adding...">Addon Domain</button>
                            </span>
                        </div>
                        <div class="input-group cf-toggle-row">
                            <label class="cf-toggle-label">
                                <input type="checkbox" id="cf-enabled" class="cf-toggle-checkbox" checked>
                                <span class="banner-subtitle banner-hint">With Cloudflare — zone + DNS auto-provision</span>
                            </label>
                        </div>
                    </div>
                    <hr class="compact-hr">
                    <div class="cf-config-bar">
                        <button type="button" class="btn btn-xs" id="cf-config-toggle" aria-expanded="false" aria-controls="cf-config-panel">Show CF Settings</button>
                    </div>
                    <div class="cf-config-panel" id="cf-config-panel">
                        <div class="cf-config-form">
                            <div class="input-group cf-config-row">
                                <span class="input-group-addon cf-config-addon">API Token</span>
                                <input type="text" class="form-control input-sm" id="cf-input-token" autocomplete="off" placeholder="Bearer token dari CF dashboard">
                            </div>
                            <div class="input-group cf-config-row">
                                <span class="input-group-addon cf-config-addon">Account ID</span>
                                <input type="text" class="form-control input-sm" id="cf-input-account" autocomplete="off" placeholder="Auto-detect atau isi manual">
                                <div class="input-group-btn">
                                    <button type="button" class="btn btn-xs" id="cf-detect-account" title="Auto-detect Account ID dari token">⟳</button>
                                </div>
                            </div>
                            <div class="cf-config-actions">
                                <button type="button" class="btn btn-xs btn-primary" id="cf-config-save">Simpan</button>
                                <button type="button" class="btn btn-xs btn-danger" id="cf-config-clear">Hapus</button>
                                <button type="button" class="btn btn-xs" id="cf-create-token" title="Use a Create Additional Tokens creator token to generate the operational CF token">Create Additional Tokens</button>
                                <span class="cf-config-status" id="cf-config-status"></span>
                                <button type="button" class="btn btn-xs" id="cf-sync-all">Sync All CF</button>
                            </div>
                        </div>
                        <div class="cf-perm-info">
                            <div class="cf-perm-head">
                                <span class="cf-perm-label">Required token permissions:</span>
                                <button type="button" class="btn btn-xs cf-perm-toggle" data-target="cf-perm-body-user" aria-expanded="false">Show</button>
                            </div>
                            <div class="cf-perm-body" id="cf-perm-body-user">
                            <div class="cf-perm-table">
                                <div class="cf-perm-row cf-perm-row--head"><span>Scope</span><span>Permission</span><span>Access</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Account</span><span>Account Settings</span><span class="cf-perm-access">Read</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Account</span><span>Zone</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone</span><span class="cf-perm-access">Read</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone Settings</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone Settings</span><span class="cf-perm-access">Read</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>SSL and Certificates</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>DNS</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Cache Purge</span><span class="cf-perm-access">Purge</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Managed Headers</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Transform Rules</span><span class="cf-perm-access">Edit</span></div>
                                <div class="cf-perm-row"><span class="cf-perm-scope">Zone</span><span>Zone WAF</span><span class="cf-perm-access">Edit</span></div>
                            </div>
                            </div>
                        </div>
                    </div>
                    <table id="table_domain" class="responsive nowrap unstackable table table-hover table-fixed" cellspacing="0">
                        <thead>
                            <tr>
                                <th class="rg-source col-xs-6">DOMAIN</th>
                                <th class="rg-source col-xs-2">SUBID</th>
                                <th class="rg-source col-xs-2">CLOUDFLARE</th>
                                <th class="rg-source col-xs-2"></th>
                            </tr>
                        </thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
        </div>
        <input type="hidden" class="form-control input-sm" id="user_lp" name="user_lp">
        <input type="hidden" id="pick" name="pick" class="form-control input-sm" value="0">
        <input type="hidden" id="deb" name="deb" class="form-control input-sm" value="a">
        <input type="hidden" id="urlgen" name="urlgen" class="form-control input-sm" value="https://{sub}.global/{click_id}">
        <input type="hidden" id="pickurl" name="pickurl" class="form-control input-sm" value="0">
        <input type="hidden" id="sub_id" name="sub_id" class="form-control input-sm" value="<?= $escapedSubIdLower; ?>">
    </div>
    <hr class="compact-hr">
    <div class="app-sign"><footer>Ngix · xctd</footer></div>
    <div class="app-sign" style="margin-top:1px"><span class="banner-subid"><?= $escapedTitle; ?></span></div>

<div id="deleteConfirmToast" role="alertdialog" aria-modal="true" aria-labelledby="deleteConfirmMsg">
    <div class="dct-inner">
        <span class="dct-icon" aria-hidden="true"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg></span>
        <p class="dct-msg" id="deleteConfirmMsg"></p>
        <div class="dct-actions">
            <button type="button" class="btn btn-default btn-sm js-modal-close">Batal</button>
            <button type="button" class="btn btn-sm dct-btn-delete" id="confirm_delete_domain">Hapus</button>
        </div>
    </div>
    <input type="hidden" id="delete_domain_target" value="">
</div>
<div class="app-modal" id="cfResultModal" role="dialog" aria-modal="true" aria-labelledby="cfResultTitle" hidden>
    <div class="app-modal__dialog" role="document">
        <div class="app-modal__content">
            <div class="app-modal__header">
                <h4 class="app-modal__title" id="cfResultTitle">Cloudflare Zone</h4>
                <button type="button" class="close js-modal-close" aria-label="Close"><span aria-hidden="true">&times;</span></button>
            </div>
            <div class="app-modal__body">
                <div class="cf-modal-status">
                    <span id="cf-modal-domain" class="td-dom"></span>
                    <span class="cf-badge" id="cf-modal-badge"></span>
                </div>
                <p class="app-modal__note" id="cf-modal-note"></p>
                <ul class="cf-ns-list" id="cf-modal-ns"></ul>
            </div>
            <div class="app-modal__footer">
                <button type="button" class="btn btn-default btn-sm js-modal-close">Close</button>
            </div>
        </div>
    </div>
</div>
<div class="app-modal" id="cfNewTokenModal" role="dialog" aria-modal="true" aria-labelledby="cfNewTokenTitle" hidden>
    <div class="app-modal__dialog" role="document">
        <div class="app-modal__content">
            <div class="app-modal__header">
                <h4 class="app-modal__title" id="cfNewTokenTitle">New Cloudflare Additional Token</h4>
                <button type="button" class="close js-cf-newtoken-close" aria-label="Close"><span aria-hidden="true">&times;</span></button>
            </div>
            <div class="app-modal__body">
                <div class="cf-token-warn">⚠ Save this token now — it will not be shown again.</div>
                <div class="cf-token-row">
                    <pre id="cf-new-token-val" class="cf-token-val"></pre>
                    <button type="button" class="btn btn-xs" id="cf-copy-new-token">Copy</button>
                </div>
                <p class="cf-token-note">Token has been saved as your operational CF token. Copy it now if you need an external backup.</p>
            </div>
            <div class="app-modal__footer">
                <button type="button" class="btn btn-sm js-cf-newtoken-close">Close</button>
            </div>
        </div>
    </div>
</div>
</div>
<script nonce="<?= e($nonce); ?>" src="/assets/js/jquery.min.js" type="text/javascript"></script>
<script nonce="<?= e($nonce); ?>" src="/assets/js/bootstrap.min.js"></script>
<script nonce="<?= e($nonce); ?>">
(function ($) {
    'use strict';

    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    var CSRF_TOKEN = csrfMeta ? String(csrfMeta.getAttribute('content') || '') : '';

    if (CSRF_TOKEN === '') {
        CSRF_TOKEN = <?= json_encode($csrfToken, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT); ?>;
    }

    $.ajaxSetup({
        beforeSend: function (xhr, settings) {
            var method = String(settings.type || settings.method || 'GET').toUpperCase();
            if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
                xhr.setRequestHeader('X-CSRF-Token', CSRF_TOKEN);
            }
        }
    });

    $(document).ajaxError(function (event, jqxhr) {
        if (jqxhr.status === 419) {
            showToast('error', 'Session expired. Reloading…');
            setTimeout(function () { location.reload(); }, 1500);
        }
    });

    window.NGIX_CSRF_TOKEN = CSRF_TOKEN;


    // PermissionToggleInit
    $(document).on('click', '.cf-perm-toggle', function () {
        var targetId = $(this).attr('data-target');
        var panel = document.getElementById(targetId);
        if (!panel) {
            return;
        }
        var isOpen = panel.classList.toggle('is-open');
        this.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        this.textContent = isOpen ? 'Hide' : 'Show';
    });

    var SVG_SYNC = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/><path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14"/></svg>';
    var SVG_CF_ACTIVE  = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>';
    var SVG_CF_PENDING = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
    var SVG_CF_ERROR   = '<svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
    var SVG_SPINNER    = '<svg class="btn-spin" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="10" stroke-opacity=".28"/><path d="M12 2a10 10 0 0 1 10 10" stroke-opacity=".92"/></svg>';

    $(document).on('focus', '.js-autoselect', function () { this.select(); });
    $(document).on('selectstart paste cut dragstart drop', '.js-readlock', function (e) { e.preventDefault(); return false; });

    $(document).on('click', '#copy-limitgen', function (e) {
        e.preventDefault();
        e.stopPropagation();
        var input = document.getElementById('limitgen');
        if (!input || !input.value) { showToast('error', 'No URL to copy.'); return; }
        var val = input.value;
        var $btn = $(this);
        var done = function () {
            showToast('success', 'URL copied.');
            $btn.addClass('copied');
            input.select();
            setTimeout(function () {
                $btn.removeClass('copied');
                input.setSelectionRange(0, 0);
                input.blur();
            }, 1200);
        };
        var fail = function () { showToast('error', 'Copy failed.'); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(val).then(done, function () {
                try {
                    input.select();
                    document.execCommand('copy');
                    done();
                } catch (err) { fail(); }
            });
        } else {
            try {
                input.select();
                document.execCommand('copy');
                done();
            } catch (err) { fail(); }
        }
    });

    function showToast(type, message) {
        var icon = type === 'success'
            ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M9 16.17 4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>'
            : '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>';
        var item = $('<div class="toastitem toastitem--' + type + '"></div>');
        item.append(icon);
        item.append($('<span></span>').text(message));
        $('#toastbox').append(item);
        item[0].getBoundingClientRect();
        item.addClass('is-show');
        window.setTimeout(function () {
            item.removeClass('is-show').addClass('toastitem--hide');
            window.setTimeout(function () {
                item.remove();
            }, 250);
        }, 2600);
    }

    function openDeleteModal(domain) {
        var msg = domain
            ? 'Hapus ' + domain + ', semua short URL turunannya, dan bersihkan addon/subdomain/wildcard di cPanel + Cloudflare?'
            : 'Hapus domain ini, semua short URL turunannya, dan bersihkan addon/subdomain/wildcard di cPanel + Cloudflare?';
        $('#deleteConfirmMsg').text(msg);
        $('#deleteConfirmToast').addClass('is-open');
    }

    function closeDeleteModal() {
        $('#deleteConfirmToast').removeClass('is-open');
    }

    function findDomainRow(domain) {
        return $('#table_domain tbody tr').filter(function () {
            return $(this).attr('data-domain') === domain;
        });
    }

    function hasDomainOption(domain) {
        return $('#locdom option').filter(function () {
            return $(this).val() === domain;
        }).length > 0;
    }

    function syncDropdownState(selectId) {
        var select = $('#' + selectId);
        var wrap = select.closest('.dd-wrap');
        var selectedValue = $.trim(select.val() || '');
        var selectedText = $.trim(select.find('option:selected').text() || '');
        var matchedOption = wrap.find('.dd-option').filter(function () {
            var value = $(this).attr('data-val') || $(this).attr('data-value') || '';
            return value === selectedValue;
        }).first();

        if (selectedText !== '') {
            wrap.find('.dd-trigger-label').text(selectedText);
        }

        wrap.find('.dd-option').removeAttr('aria-selected');
        if (matchedOption.length > 0) {
            matchedOption.attr('aria-selected', 'true');
        }
    }

    function setDropdownValue(selectId, value, fireChange) {
        var select = $('#' + selectId);
        var option = select.find('option').filter(function () {
            return $(this).val() === value;
        }).first();

        if (select.length === 0 || option.length === 0) {
            return;
        }

        select.val(value);
        syncDropdownState(selectId);

        if (fireChange) {
            select.trigger('change');
        }
    }

    function appendDomainOption(domain) {
        if (hasDomainOption(domain)) {
            return;
        }

        $('#locdom').append(
            $('<option></option>')
                .val(domain)
                .attr('data-dynamic', '1')
                .text(domain)
        );

        $('#locdom-menu').append(
            $('<li></li>')
                .addClass('dd-option')
                .attr('data-val', domain)
                .attr('data-dynamic', '1')
                .attr('role', 'option')
                .append($('<span></span>').addClass('dd-option-label').text(domain))
        );
        $('#locdom-menu').append($('<li></li>').addClass('dd-sep').attr('data-dynamic', '1'));
    }

    function removeDomainOption(domain) {
        $('#locdom option').filter(function () {
            return $(this).val() === domain || $(this).attr('name') === domain;
        }).remove();

        var $menuOption = $('#locdom-menu .dd-option').filter(function () {
            var value = $(this).attr('data-val') || $(this).attr('data-value') || '';
            return value === domain;
        });
        $menuOption.remove();
        $menuOption.next('.dd-sep[data-dynamic="1"]').remove();

        if ($('#locdom').val() === null || $('#locdom').val() === '') {
            setDropdownValue('locdom', $('#locrandom').val() === 'global_off' ? 'u_rand' : 'user_off', false);
        } else {
            syncDropdownState('locdom');
        }
    }

    function isValidDomainInput(domain) {
        return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain);
    }

    function preventManualInput(selector) {
        $(selector).on('keypress', function (e) {
            e.preventDefault();
            return false;
        });
    }

    function randomString(len, charSet) {
        var chars = charSet || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var output = '';
        var index = 0;
        for (index = 0; index < len; index += 1) {
            output += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return output;
    }

    function applyWrapper(rawUrl, mode) {
        var cleanUrl = $.trim(rawUrl);
        if (cleanUrl === '') {
            return '';
        }
        if (mode === 'b') {
            return 'https://l.facebook.com/l.php?u=' + encodeURIComponent(cleanUrl) + '&h=' + randomString(7) + '&s=1';
        }
        if (mode === 'f') {
            return 'https://l.wl.co/l?u=' + encodeURIComponent(cleanUrl);
        }
        return cleanUrl;
    }

    function isLikelyShortenerErrorText(value) {
        var cleanValue = $.trim(String(value || ''));
        if (cleanValue === '') {
            return true;
        }
        return /^(error|failed|invalid|unauthorized|forbidden|method not allowed|database insert failed)(\b|[:,])/i.test(cleanValue)
            || /database\s+insert\s+failed/i.test(cleanValue);
    }

    function isValidGeneratedHttpUrl(value) {
        var cleanValue = $.trim(String(value || ''));
        var parsed;
        if (cleanValue === '' || isLikelyShortenerErrorText(cleanValue)) {
            return false;
        }
        if (!/^https?:\/\//i.test(cleanValue)) {
            return false;
        }
        try {
            parsed = new URL(cleanValue);
            return parsed.protocol === 'http:' || parsed.protocol === 'https:';
        } catch (err) {
            return false;
        }
    }

    function pickFirstValidUrl(row, keys) {
        var index;
        var candidate;
        if (!row) {
            return '';
        }
        for (index = 0; index < keys.length; index += 1) {
            candidate = $.trim(row[keys[index]] || '');
            if (isValidGeneratedHttpUrl(candidate)) {
                return candidate;
            }
        }
        return '';
    }

    function pickShortenerUrl(data) {
        var parsed;

        if ($.isArray(data)) {
            return data.length > 0 ? pickFirstValidUrl(data[0], ['short_url', 'shortURL', 'shorturl', 'l']) : '';
        }

        if (typeof data === 'string') {
            if (isValidGeneratedHttpUrl(data)) {
                return $.trim(data);
            }

            try {
                parsed = JSON.parse(data);
                return pickShortenerUrl(parsed);
            } catch (err) {
                return '';
            }
        }

        if (data && typeof data === 'object') {
            return pickFirstValidUrl(data, ['short_url', 'shortURL', 'shorturl', 'l']);
        }

        return '';
    }

    function safeArrayResponse(data) {
        if ($.isArray(data)) {
            return data;
        }
        if (typeof data === 'string') {
            try {
                var parsed = JSON.parse(data);
                return $.isArray(parsed) ? parsed : [];
            } catch (err) {
                return [];
            }
        }
        return [];
    }

    function resetGenerateOutputs() {
        $('#limitgen').val('').removeClass('error success');
    }

    function initFirstNetwork() {
        var firstButton = $('#radioBtn a').first();
        if (firstButton.length === 0) {
            return;
        }
        firstButton.removeClass('notActive').addClass('active save');
        $('#user_lp').val(firstButton.data('title') || '');
    }

    function buildDomainUrlTemplate(value) {
        return 'https://{sub}.' + value + '/{click_id}';
    }

    function activateGlobalDomain(value) {
        var cleanValue = $.trim(value || '');
        if (cleanValue === '' || cleanValue === 'global_off') {
            cleanValue = 'global';
        }

        $('#urlgen').val(buildDomainUrlTemplate(cleanValue));
        setDropdownValue('locrandom', cleanValue, false);
        setDropdownValue('locdom', 'user_off', false);
        $('#locrandom-wrap').removeClass('is-passive');
        $('#locdom-wrap').addClass('is-passive');
    }

    function activateUserDomain(value) {
        var cleanValue = $.trim(value || '');
        if (cleanValue === '' || cleanValue === 'user_off') {
            cleanValue = 'u_rand';
        }

        $('#urlgen').val(buildDomainUrlTemplate(cleanValue));
        setDropdownValue('locdom', cleanValue, false);
        setDropdownValue('locrandom', 'global_off', false);
        $('#locdom-wrap').removeClass('is-passive');
        $('#locrandom-wrap').addClass('is-passive');
    }

    function updateUrlTemplateFromGlobal(value) {
        var cleanValue = $.trim(value || '');
        if (cleanValue === 'global_off') {
            activateUserDomain($('#locdom').val());
            return;
        }

        activateGlobalDomain(cleanValue);
    }

    function updateUrlTemplateFromUser(value) {
        var cleanValue = $.trim(value || '');
        if (cleanValue === 'user_off') {
            activateGlobalDomain($('#locrandom').val());
            return;
        }

        activateUserDomain(cleanValue);
    }

    function initDomainSelectorFlow() {
        activateGlobalDomain('global');
    }

    var cfStatusCache = {};

    function updateDomainCount() {
        var c = $('#table_domain tbody tr').length;
        $('#domain-count').text(c + (c === 1 ? ' domain' : ' domains'));
    }

    function updateCfBadge(domain, data) {
        var badge = $('.cf-badge[data-domain="' + domain + '"]');
        badge.removeClass('cf-badge--active cf-badge--pending cf-badge--error cf-badge--loading cf-badge--none is-hidden');
        if (!data || !data.ok) {
            badge.addClass('cf-badge--error').html(SVG_CF_ERROR);
            cfStatusCache[domain] = 'error';
            removeDomainOption(domain);
            return;
        }
        var status = (data.status || 'pending').toLowerCase();
        cfStatusCache[domain] = status;
        if (status === 'active') {
            badge.addClass('cf-badge--active').html(SVG_CF_ACTIVE);
            appendDomainOption(domain);
        } else {
            badge.addClass('cf-badge--pending').html(SVG_CF_PENDING);
            removeDomainOption(domain);
        }
    }

    function openCfModal(domain, data) {
        var status = (data.status || 'pending').toLowerCase();
        $('#cf-modal-domain').text(domain);
        var mb = $('#cf-modal-badge').html('').removeClass('cf-badge--active cf-badge--pending cf-badge--error');
        if (status === 'active') {
            mb.addClass('cf-badge--active').html(SVG_CF_ACTIVE);
        } else if (!data || !data.ok) {
            mb.addClass('cf-badge--error').html(SVG_CF_ERROR);
        } else {
            mb.addClass('cf-badge--pending').html(SVG_CF_PENDING);
        }
        var ns = data.name_servers || [];
        var nsList = $('#cf-modal-ns').empty();
        var note = '';
        if (!data || !data.ok) {
            note = 'Gagal menambahkan zone Cloudflare.';
        } else if (status === 'active') {
            note = 'Zone ' + (data.already_exists ? 'sudah aktif' : 'aktif') + ' di Cloudflare.';
        } else if (ns.length > 0) {
            note = (data.already_exists ? 'Zone sudah ada. ' : 'Zone ditambahkan. ') + 'Arahkan nameserver domain ke:';
        } else {
            note = data.already_exists ? 'Zone sudah ada di akun Cloudflare.' : '';
        }
        $('#cf-modal-note').text(note);
        if (ns.length > 0) {
            $.each(ns, function (i, n) { nsList.append($('<li>').attr('title', 'Klik untuk salin').text(n).on('click', function(){ if(navigator.clipboard){navigator.clipboard.writeText(n);} })); });
            nsList.addClass('ns-visible');
        } else {
            nsList.removeClass('ns-visible');
        }
        $('#cfResultModal').prop('hidden', false).addClass('is-open');
    }

    function closeCfModal() {
        $('#cfResultModal').removeClass('is-open').prop('hidden', true);
    }

    function syncDomainCf(domain, onDone) {
        // Short-circuit: skip AJAX entirely if domain is already active.
        // The backend would also skip heavy operations, but avoiding the
        // round-trip is cheaper and keeps the badge visually stable.
        if (cfStatusCache[domain] === 'active') {
            if (typeof onDone === 'function') {
                onDone(null, { ok: true, status: 'active', already_exists: true, skipped: true });
            }
            return;
        }
        var badge = $('.cf-badge[data-domain="' + domain + '"]');
        var syncBtn = $('.cf-sync-btn[data-domain="' + domain + '"]');
        badge.removeClass('cf-badge--active cf-badge--pending cf-badge--error').addClass('cf-badge--loading').html(SVG_SPINNER);
        syncBtn.prop('disabled', true).html(SVG_SPINNER);
        $.ajax({
            url: '/api/cf_sync.php',
            type: 'post',
            dataType: 'json',
            data: { domain: domain, sub_domain: $.trim($('#userid').val()) }
        }).done(function (data) {
            updateCfBadge(domain, data);
            if (typeof onDone === 'function') { onDone(null, data); }
        }).fail(function () {
            badge.removeClass('cf-badge--loading').addClass('cf-badge--error').html(SVG_CF_ERROR);
            if (typeof onDone === 'function') { onDone('failed', null); }
        }).always(function () {
            badge.removeClass('cf-badge--loading');
            syncBtn.prop('disabled', false).html(SVG_SYNC);
        });
    }

    function appendDomainRow(rowData) {
        if (!rowData || !rowData.domain) {
            return;
        }
        if (findDomainRow(rowData.domain).length > 0) {
            return;
        }
        var SVG_TRASH = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>';
        var row = $('<tr></tr>').attr('data-domain', rowData.domain);
        var domainCell = $('<td></td>');
        var domSpan = $('<span class="td-dom"></span>').text(rowData.domain);
        var copyBtn = $('').attr('data-domain', rowData.domain).html('<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>');
        domainCell.append(domSpan).append(' ').append(copyBtn);
        row.append(domainCell);
        row.append($('<td></td>').append($('<span class="td-subid"></span>').text(rowData.sub_domain || '')));
        // Keep Cloudflare state separate from traffic readiness: a cPanel-only
        // domain can be active without a CF zone and must still remain syncable.
        if (rowData.cf_zone_id && rowData.cf_status && !cfStatusCache[rowData.domain]) {
            cfStatusCache[rowData.domain] = rowData.cf_status.toLowerCase();
        }
        var domainStatus = (rowData.domain_status || rowData.cf_status || 'none').toLowerCase();
        var badge = $('<span class="cf-badge"></span>').attr('data-domain', rowData.domain);
        if (domainStatus === 'active') { badge.addClass('cf-badge--active').attr('title', 'aktif').html(SVG_CF_ACTIVE); }
        else if (domainStatus === 'pending') { badge.addClass('cf-badge--pending').attr('title', 'pending').html(SVG_CF_PENDING); }
        else if (domainStatus === 'error') { badge.addClass('cf-badge--error').attr('title', 'error').html(SVG_CF_ERROR); }
        else { badge.addClass('cf-badge--none').attr('title', 'none').html('&mdash;'); }
        var cfSyncBtn = $('<button type="button" class="btn btn-xs cf-sync-btn" title="Sync CF"></button>').attr('data-domain', rowData.domain).html(SVG_SYNC);
        row.append($('<td class="td-cf-cell"></td>').append(badge).append(cfSyncBtn));
        var actionCell = $('<td></td>');
        var deleteButton = $('<button type="button" class="delete btn btn-danger btn-xs" title="Delete"></button>');
        deleteButton.attr('data-domain', rowData.domain).html(SVG_TRASH);
        actionCell.append(deleteButton);
        row.append(actionCell);
        $('#table_domain tbody').append(row);
        updateDomainCount();

        if (domainStatus === 'active') {
            appendDomainOption(rowData.domain);
        }
    }

    function drawTable(data) {
        var index = 0;
        var selectedLocdom = $.trim($('#locdom').val() || '');
        $('#table_domain tbody').empty();
        $('#locdom option[data-dynamic="1"]').remove();
        $('#locdom-menu .dd-option[data-dynamic="1"]').remove();
        $('#locdom-menu .dd-sep[data-dynamic="1"]').remove();
        for (index = 0; index < data.length; index += 1) {
            appendDomainRow(data[index]);
        }
        if (selectedLocdom !== '' && hasDomainOption(selectedLocdom)) {
            setDropdownValue('locdom', selectedLocdom, false);
        } else {
            setDropdownValue('locdom', $('#locrandom').val() === 'global_off' ? 'u_rand' : 'user_off', false);
        }
        updateDomainCount();
    }

    function loadUserDomains() {
        $.ajax({
            url: '/api/user_domain.php',
            type: 'get',
            dataType: 'json',
            data: {
                sub_domain: $.trim($('#userid').val()),
                domain: $.trim($('#domain').val())
            }
        }).done(function (data) {
            if ($.isArray(data)) {
                drawTable(data);
            }
        });
    }

    function loadCfConfig() {
        $.ajax({
            url: '/api/user_cf_config.php',
            type: 'get',
            dataType: 'json'
        }).done(function (data) {
            if (data && data.has_token) {
                $('#cf-input-token').val(data.token_masked || '').attr('placeholder', 'Token tersimpan');
                $('#cf-input-account').val(data.account_id || '');
            } else {
                $('#cf-input-token').attr('placeholder', 'Bearer token dari CF dashboard');
                $('#cf-input-account').val('');
            }
        });
    }

    function setCfConfigPanelState(isOpen) {
        var panel = $('#cf-config-panel');
        var toggle = $('#cf-config-toggle');
        panel.toggleClass('is-open', isOpen);
        toggle.attr('aria-expanded', isOpen ? 'true' : 'false');
        toggle.text(isOpen ? 'Hide CF Settings' : 'Show CF Settings');
        if (isOpen) {
            loadCfConfig();
        }
    }

    $('#cf-config-toggle').on('click', function () {
        setCfConfigPanelState(!$('#cf-config-panel').hasClass('is-open'));
    });

    var SVG_BTN_SPIN = '<svg class="btn-spin" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="8" cy="8" r="6" stroke-opacity=".3"/><path d="M8 2a6 6 0 0 1 6 6"/></svg> ';
    function btnLoad(btn, label) {
        var $b = $(btn);
        if (!$b.data('__oh')) { $b.data('__oh', $b.html()); }
        $b.prop('disabled', true).html(SVG_BTN_SPIN + (label || ''));
    }
    function btnReset(btn) {
        var $b = $(btn);
        var oh = $b.data('__oh');
        if (oh !== undefined) { $b.prop('disabled', false).html(oh); $b.removeData('__oh'); }
        else { $b.prop('disabled', false); }
    }

    // Auto-detect Account ID dari token
    $('#cf-detect-account').on('click', function () {
        var token = $.trim($('#cf-input-token').val());
        var status = $('#cf-config-status');
        if (token === '') { status.text('Isi API Token dulu.'); return; }
        var btn = $(this); btnLoad(btn, '...');
        status.text('Mendeteksi...');
        $.ajax({
            url: '/api/user_cf_config.php',
            type: 'post',
            dataType: 'json',
            data: { action: 'detect', cf_token: token }
        }).done(function (data) {
            if (data && data.ok && data.account_id) {
                $('#cf-input-account').val(data.account_id);
                status.text('✓ ' + (data.account_name || data.account_id));
            } else {
                status.text((data && data.err) ? data.err : 'Gagal detect.');
            }
        }).fail(function () {
            status.text('Request gagal.');
        }).always(function () {
            btnReset(btn);
        });
    });

    $('#cf-config-save').on('click', function () {
        var token = $.trim($('#cf-input-token').val());
        var accountId = $.trim($('#cf-input-account').val());
        var status = $('#cf-config-status');
        if (token === '') { status.text('Token wajib diisi.'); return; }
        var _savebtn = $(this); btnLoad(_savebtn, 'Saving…');
        status.text('Menyimpan...');
        $.ajax({
            url: '/api/user_cf_config.php',
            type: 'post',
            dataType: 'json',
            data: { action: 'save', cf_token: token, cf_account_id: accountId }
        }).done(function (data) {
            if (data && data.ok) {
                status.text('Tersimpan.');
                loadCfConfig();
                showToast('success', 'CF token disimpan.');
            } else {
                status.text('Gagal menyimpan.');
            }
        }).fail(function () { status.text('Error.'); }).always(function () { btnReset(_savebtn); });
    });

    $('#cf-config-clear').on('click', function () {
        var status = $('#cf-config-status');
        var _clearbtn = $(this); btnLoad(_clearbtn, 'Clearing…');
        status.text('Menghapus...');
        $.ajax({
            url: '/api/user_cf_config.php',
            type: 'post',
            dataType: 'json',
            data: { action: 'clear' }
        }).done(function (data) {
            if (data && data.ok) {
                status.text('Dihapus, pakai Admin CF.');
                $('#cf-input-token').val('');
                $('#cf-input-account').val('');
                loadCfConfig();
                showToast('success', 'CF token dihapus, fallback ke admin.');
            }
        }).fail(function () { status.text('Error.'); }).always(function () { btnReset(_clearbtn); });
    });

    // Create Additional Tokens
    function openCfNewTokenModal(token) {
        $('#cf-new-token-val').text(token);
        $('#cfNewTokenModal').prop('hidden', false).addClass('is-open');
    }

    function closeCfNewTokenModal() {
        $('#cfNewTokenModal').removeClass('is-open').prop('hidden', true);
        // Clear sensitive value from DOM immediately on close.
        setTimeout(function () { $('#cf-new-token-val').text(''); }, 300);
    }

    function saveCreatedCfToken(token, accountId, done, fail) {
        $.ajax({
            url: '/api/user_cf_config.php',
            type: 'post',
            dataType: 'json',
            data: {
                action: 'save',
                cf_token: token,
                cf_account_id: accountId || '',
                csrf_token: CSRF_TOKEN
            }
        }).done(function (data) {
            if (data && data.ok) {
                if (typeof done === 'function') {
                    done(data);
                }
                return;
            }
            if (typeof fail === 'function') {
                fail(data);
            }
        }).fail(function (xhr) {
            if (typeof fail === 'function') {
                fail(xhr);
            }
        });
    }

    $('#cf-create-token').on('click', function () {
        var creatorToken = $.trim($('#cf-input-token').val());
        var accountId = $.trim($('#cf-input-account').val());
        var btn = $(this);
        var status = $('#cf-config-status');

        if (creatorToken === '') {
            status.text('Paste token dari template Create Additional Tokens dulu.');
            showToast('error', 'Creator token required.');
            return;
        }

        if ($('#cf-input-token').attr('data-masked') === '1' || creatorToken.indexOf('•') !== -1 || creatorToken.indexOf('*') !== -1) {
            status.text('Masked token tidak bisa dipakai. Paste creator token asli.');
            showToast('error', 'Paste the real creator token first.');
            return;
        }

        btnLoad(btn, 'Generating…');
        status.text('Creating additional token…');

        $.ajax({
            url: '/api/cf_create_token.php',
            type: 'post',
            dataType: 'json',
            data: {
                creator_token: creatorToken,
                cf_account_id: accountId,
                csrf_token: CSRF_TOKEN
            }
        }).done(function (data) {
            if (!data || !data.ok || !data.token) {
                var err = (data && data.err) ? data.err : 'error';
                var missingList = (data && data.missing && data.missing.length) ? data.missing
                    : (data && data.missing_rows && data.missing_rows.length)
                        ? data.missing_rows.map(function (r) { return r.scope + ' — ' + r.permission + ':' + r.access; })
                        : [];
                if (missingList.length) {
                    err += ': ' + missingList.join(', ');
                }
                status.text('Failed: ' + err);
                showToast('error', 'Token creation failed: ' + err);
                return;
            }

            status.text('Token created. Saving operational token…');
            $('#cf-input-token').val('').attr('type', 'password').removeAttr('data-masked');
            if (data.account_id) {
                $('#cf-input-account').val(data.account_id);
            }

            saveCreatedCfToken(data.token, data.account_id || accountId, function () {
                status.text('Additional token created & saved.');
                loadCfConfig();
                openCfNewTokenModal(data.token);
                showToast('success', 'CF additional token created.');
            }, function () {
                status.text('Token created, but save failed. Copy token now.');
                openCfNewTokenModal(data.token);
                showToast('error', 'Token created but save failed.');
            });
        }).fail(function (xhr) {
            var msg = 'Request failed.';
            if (xhr && xhr.responseJSON && xhr.responseJSON.err) {
                msg = xhr.responseJSON.err;
            }
            status.text(msg);
            showToast('error', 'CF token creation request failed.');
        }).always(function () {
            btnReset(btn);
        });
    });

    $('#cf-copy-new-token').on('click', function () {
        var val = $('#cf-new-token-val').text();
        if (!val) { return; }
        var btn = $(this);
        var done = function () {
            showToast('success', 'Token copied to clipboard.');
            btn.text('Copied!');
            setTimeout(function () { btn.text('Copy'); }, 1500);
        };
        var fail = function () { showToast('error', 'Copy failed   select the token manually.'); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(val).then(done, fail);
        } else {
            var el = document.createElement('textarea');
            el.value = val;
            el.style.position = 'fixed';
            el.style.opacity = '0';  
            document.body.appendChild(el);
            el.select();
            try { document.execCommand('copy'); done(); } catch (e) { fail(); }
            document.body.removeChild(el);
        }
    });

    $(document).on('click', '.js-cf-newtoken-close', function () {
        closeCfNewTokenModal();
    });

    $(document).ready(function () {
        initFirstNetwork();
        preventManualInput('#urlgen,#pick,#limitgen');
        loadCfConfig();

        $('img').on('contextmenu', function () {
            return false;
        });

        $(document).on('click', '.js-modal-close', function () {
            closeDeleteModal();
            closeCfModal();
            return false;
        });

        $(document).on('keydown', function (e) {
            if (e.key === 'Escape') {
                closeDeleteModal();
                closeCfModal();
            }
        });

        $('#radioBtn').on('click', 'a', function () {
            var sel = $(this).data('title') || '';
            var tog = $(this).data('toggle') || '';
            if (tog !== '') {
                $('#' + tog).val(sel);
            }
            $('a[data-toggle="' + tog + '"]').removeClass('active save').addClass('notActive');
            $(this).removeClass('notActive').addClass('active save');
        });


        $('#locrandom').on('change', function () {
            updateUrlTemplateFromGlobal($.trim(this.value || ''));
        });

        $('#locdom').on('change', function () {
            updateUrlTemplateFromUser($.trim(this.value || ''));
        });

        $('#block_vpn_asn').on('change', function () {
            $.post('/api/block_vpn.php', {
                block_vpn_asn: ($(this).is(':checked') ? '1' : '0'),
                csrf_token: CSRF_TOKEN
            }).fail(function () {
                showToast('error', 'Failed to save Block VPN setting.');
            });
        });

        $('#tabgen, #tabaddon').on('click', function () {
            resetGenerateOutputs();
        });

        $('#genurl').on('click', function () {
            var url = $.trim($('#urlgen').val());
            var button = $(this);
            var uri = $.trim($('#uri').val());
            var prm = $.trim($('#net_pick').val());
            var limitRaw = parseInt($.trim($('#shortgen').val()), 10);
            var limit = (isNaN(limitRaw) || limitRaw < 1) ? 1 : Math.min(limitRaw, 50);

            if (url === '') {
                $('#shortgen').addClass('error');
                $('#limitgen').val('* Missing URL template').addClass('error').removeClass('success');
                showToast('error', 'URL template is missing.');
                return false;
            }

            button.prop('disabled', true);
            $('#shortgen').removeClass('error');
            $('#limitgen').val('generating ' + limit + '...').removeClass('error success');

            var results = [];
            var failCount = 0;

            function applyShortener(generatedUrl, done) {
                if (uri === 'turl') {
                    $.post('/api/tinyurl.php', { longurl: generatedUrl, prm: prm, csrf_token: CSRF_TOKEN })
                        .done(function (data) {
                            var out = pickShortenerUrl(data);
                            done(out !== '' ? out : null);
                        })
                        .fail(function () { done(null); });
                } else {
                    var wrappedUrl = applyWrapper(generatedUrl, prm);
                    done(isValidGeneratedHttpUrl(wrappedUrl) ? wrappedUrl : null);
                }
            }

            function generateStep(remaining) {
                if (remaining === 0) {
                    if (results.length === 0) {
                        $('#limitgen').val('* All requests failed').addClass('error').removeClass('success');
                        showToast('error', 'Generate failed.');
                    } else {
                        $('#limitgen').val(results.join('\n')).addClass('success').removeClass('error');
                        showToast('success', results.length + ' URL' + (results.length !== 1 ? 's' : '') + ' generated.');
                    }
                    button.prop('disabled', false);
                    return;
                }

                $.post('/api/generate_api.php', {
                    longurl: url,
                    sub_id: $.trim($('#sub_id').val()),
                    user_lp: $.trim($('#user_lp').val()),
                    csrf_token: CSRF_TOKEN,
                    noshorten: (uri === 'long' ? '1' : '0'),
                    block_vpn_asn: ($('#block_vpn_asn').is(':checked') ? '1' : '0'),

                    fbimg: $.trim($('#fbimg').val()),
                    fbtext: $.trim($('#fbtext').val()),
                    lg: $.trim($('#lg').val())
                }).done(function (data) {
                    var rows = safeArrayResponse(data);
                    var generatedUrl = rows.length > 0 ? pickFirstValidUrl(rows[0], ['shorturl', 'l']) : '';
                    if (!generatedUrl || generatedUrl === 'https://') {
                        failCount++;
                        generateStep(remaining - 1);
                        return;
                    }
                    applyShortener(generatedUrl, function (finalUrl) {
                        if (finalUrl) {
                            results.push(finalUrl);
                        } else {
                            failCount++;
                        }
                        generateStep(remaining - 1);
                    });
                }).fail(function () {
                    failCount++;
                    generateStep(remaining - 1);
                });
            }

            generateStep(limit);
            return false;
        });

        $('#addondom').on('click', function () {
            var domain = $.trim($('#domain').val());
            var userid = $.trim($('#userid').val());
            var button = $(this);

            if (domain === '') {
                showToast('error', 'Addon domain is required.');
                return false;
            }

            if (!isValidDomainInput(domain)) {
                showToast('error', 'Invalid domain format.');
                return false;
            }

            btnLoad(button, 'Adding…');
            $.ajax({
                url: '/api/call.php',
                type: 'post',
                dataType: 'json',
                data: {
                    sub_domain: userid,
                    domain: domain
                }
            }).done(function (resp) {
                var rows = safeArrayResponse(resp);
                if (rows.length === 0 || !rows[0] || !rows[0].domain || !rows[0].userid) {
                    showToast('error', 'Addon domain response is invalid.');
                    btnReset(button);
                    return;
                }

                $.ajax({
                    url: '/api/user_insert_domain.php',
                    type: 'post',
                    dataType: 'json',
                    data: {
                        domain: rows[0].domain,
                        sub_domain: rows[0].userid
                    }
                }).done(function (data) {
                    if ($.isArray(data)) {
                        drawTable(data);
                        var newDomain = rows[0].domain;
                        $('#domain').val('');
                        if ($('#cf-enabled').is(':checked')) {
                            showToast('success', 'Addon domain saved. Syncing CF...');
                            syncDomainCf(newDomain, function (err, cfData) {
                                if (err) {
                                    showToast('error', 'CF sync failed for ' + newDomain);
                                } else if (cfData && cfData.ok) {
                                    openCfModal(newDomain, cfData);
                                }
                            });
                        } else {
                            showToast('success', 'Addon domain saved.');
                        }
                    } else {
                        showToast('error', 'Addon domain save failed.');
                    }
                    btnReset(button);
                }).fail(function () {
                    showToast('error', 'Addon domain insert failed.');
                    btnReset(button);
                });
            }).fail(function (xhr) {
                var msg = 'Addon domain request failed.';
                if (xhr && xhr.responseJSON && xhr.responseJSON.error) {
                    msg += ' ' + xhr.responseJSON.error;
                } else if (xhr && xhr.responseText) {
                    try {
                        var parsedErr = JSON.parse(xhr.responseText);
                        if (parsedErr && parsedErr.error) {
                            msg += ' ' + parsedErr.error;
                        }
                    } catch (err) {}
                }
                showToast('error', msg);
                button.button('reset');
            });

            return false;
        });

        $(document).on('click', '.delete', function () {
            var buttonId = $(this).attr('data-domain') || '';
            if (buttonId === '') {
                showToast('error', 'Invalid domain target.');
                return false;
            }
            $('#delete_domain_target').val(buttonId);
            openDeleteModal(buttonId);
            return false;
        });

        $('#confirm_delete_domain').on('click', function () {
            var buttonId = $.trim($('#delete_domain_target').val());
            var rowNode = findDomainRow(buttonId);
            if (buttonId === '') {
                showToast('error', 'Invalid domain target.');
                return false;
            }
            var _delbtn = $(this); btnLoad(_delbtn, 'Deleting…');
            $.ajax({
                url: '/api/user_del_domain.php',
                type: 'post',
                dataType: 'json',
                data: {
                    domain: buttonId
                }
            }).done(function () {
                removeDomainOption(buttonId);
                rowNode.addClass('table-row-removing');
                window.setTimeout(function () {
                    rowNode.remove();
                }, 260);
                closeDeleteModal();
                $('#delete_domain_target').val('');
                showToast('success', 'Domain deleted.');
            }).fail(function () {
                closeDeleteModal();
                showToast('error', 'Delete request failed.');
            }).always(function () { btnReset(_delbtn); });
            return false;
        });

        $(document).on('click', '.cf-sync-btn', function () {
            var domain = $(this).attr('data-domain') || '';
            if (domain === '') { return; }
            syncDomainCf(domain, function (err, data) {
                if (err) { showToast('error', 'CF sync failed.'); return; }
                if (data && data.skipped) {
                    showToast('success', domain + ' sudah aktif di Cloudflare.');
                    return;
                }
                if (data && data.ok) {
                    openCfModal(domain, data);
                } else {
                    showToast('error', 'CF error: ' + ((data && data.err) ? data.err : 'unknown'));
                }
            });
        });

        $(document).on('click', '.btn-copy-domain', function () {
            var domain = $(this).attr('data-domain') || '';
            if (domain === '') { return; }
            var $btn = $(this);
            var done = function () {
                showToast('success', 'Copied: ' + domain);
                $btn.addClass('copied');
                setTimeout(function () { $btn.removeClass('copied'); }, 1200);
            };
            var fail = function () { showToast('error', 'Copy failed.'); };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(domain).then(done, fail);
            } else {
                var el = document.createElement('textarea');
                el.value = domain;
                document.body.appendChild(el);
                el.select();
                try { document.execCommand('copy'); done(); } catch (e) { fail(); }
                document.body.removeChild(el);
            }
        });

        $('#cf-sync-all').on('click', function () {
            var domains = [];
            $('#table_domain tbody tr').each(function () {
                var d = $(this).attr('data-domain') || '';
                if (d !== '') { domains.push(d); }
            });
            if (domains.length === 0) { showToast('error', 'No domains to sync.'); return; }
            var btn = $(this); btnLoad(btn, 'Syncing…');
            var idx = 0;
            var ok = 0;
            function next() {
                if (idx >= domains.length) {
                    btnReset(btn);
                    showToast('success', ok + '/' + domains.length + ' synced to CF.');
                    return;
                }
                var d = domains[idx++];
                syncDomainCf(d, function (err) {
                    if (!err) { ok++; }
                    window.setTimeout(next, 400);
                });
            }
            next();
        });

        $(document).on('click', '.app-modal', function (e) {
            if (e.target === this) {
                e.preventDefault();
                e.stopPropagation();
                return false;
            }
        });

        $(document).on('click', '.app-modal__content', function (e) {
            e.stopPropagation();
        });

        initDomainSelectorFlow();
        loadUserDomains();
    });
}(jQuery));
</script>
<script src="<?= e(srpAssetUrl('/assets/js/portal-5.js')); ?>"></script>
<link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-7.css')); ?>">
<div id="logout-toast">Logging out…</div>
<link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-8.css')); ?>">

<script src="<?= e(srpAssetUrl('/assets/js/portal-6.js')); ?>"></script>

<link rel="stylesheet" href="<?= e(srpAssetUrl('/assets/css/portal-9.css')); ?>">
</body>
</html>
