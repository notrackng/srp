<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

require_once __DIR__ . '/stat_path.php';
require_once dirname(__DIR__) . '/public/tracker_password.php';
require_once dirname(__DIR__) . '/login_throttle.php';

// repass.php is generated at runtime by report-password.php on first setup.
// Guard against the file being absent (fresh install) to prevent a fatal error.
if (is_file(__DIR__ . '/repass.php')) {
    include_once __DIR__ . '/repass.php';
}

// env.php (repo root) is the single source of load_env_file() and app_env().
// It is mandatory here, exactly as for every other statistics/ entry point
// (statistics/postback aborts when it is missing). A local fallback used to
// re-declare both with semantics that diverged from the canonical versions
// (app_env default '' vs null / ?string; load_env_file without the
// skip-if-already-set guard); it was removed so this page can never resolve
// env vars by a different rule than the rest of the codebase.
$envBootstrap = dirname(__DIR__) . '/env.php';
if (!is_file($envBootstrap) || !is_readable($envBootstrap)) {
    http_response_code(500);
    exit('Environment loader is unavailable.');
}
require_once $envBootstrap;

load_env_file(dirname(__DIR__) . '/.env');

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => statIsHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

$_loginDirect = (realpath(__FILE__) === realpath($_SERVER['SCRIPT_FILENAME']));

if (!$_loginDirect) {
    if (!empty($_SESSION['loggedIn'])) {
        return;
    }

    header('Location: ' . statUrl('/login.php'));
    exit;
}

$nonce = base64_encode(random_bytes(18));

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

function e(string $v): string
{
    return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

if (!isset($_SESSION['csrf_login']) || !is_string($_SESSION['csrf_login'])) {
    $_SESSION['csrf_login'] = bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['csrf_login'];
$a2rootPw = (string) app_env('A2ROOT_PASSWORD', '');
$error = '';

// Submitted tracker id (empty = admin login). is_string guard keeps it a real
// string for both the auth branch and the form repopulation below.
$rawSubIdInput = $_POST['sub_id'] ?? '';
$subIdInput = is_string($rawSubIdInput) ? strtoupper(trim($rawSubIdInput)) : '';

// If no password is configured at all, redirect to the setup page.
// This prevents a permanently broken login form on fresh installs.
if (!defined('REPASS') && $a2rootPw === '') {
    header('Location: ' . statUrl('/report-password.php'));
    exit;
}

// Rate limiting: 5 attempts → 15 min lockout, 10 attempts → 30 min.
// Combines the per-session counter with a per-IP file throttle so dropping the
// session cookie no longer resets the count. Scoped to the submitted sub_id
// (empty = admin) so one tracker's failures do not lock out the others.
$statThrottleScope = $subIdInput !== '' ? 'stat_login|' . $subIdInput : 'stat_login';
$_SESSION['stat_login_attempts'] ??= 0;
$_SESSION['stat_login_last'] ??= 0;
$statIpState = srp_login_throttle_state($statThrottleScope);
$statAttempts = max((int) $_SESSION['stat_login_attempts'], $statIpState['fails']);
$statLastFail = max((int) $_SESSION['stat_login_last'], $statIpState['last']);
$statLockout = srp_login_lockout_seconds($statAttempts);

if ($statLockout > 0 && (time() - $statLastFail) < $statLockout) {
    $error = 'lockout';
}

if (isset($_POST['password'])) {
    $postedCsrf = (string) ($_POST['csrf_token'] ?? '');
    $inputPw = (string) ($_POST['password'] ?? '');
    // Per-tracker login when a sub_id is supplied; empty sub_id = admin (global).
    $inputSubId = $subIdInput;

    $loginOk = false;
    $loginSubId = null; // non-null → scoped tracker session

    if (!hash_equals($csrfToken, $postedCsrf)) {
        $error = 'csrf';
    } elseif ($inputSubId !== '') {
        // Tracker: authenticate against the dashboard-managed generate.password
        // (bcrypt). The stats data is then scoped to this sub_id.
        if ($statLockout === 0 && preg_match('/^[A-Z0-9_-]{1,64}$/', $inputSubId) === 1) {
            try {
                /** @var PDO $statLoginPdo */
                $statLoginPdo = require dirname(__DIR__) . '/connection_pdo.php';
                $stmt = $statLoginPdo->prepare('SELECT password FROM generate WHERE sub_id = :sub_id LIMIT 1');
                $stmt->execute(['sub_id' => $inputSubId]);
                $hash = $stmt->fetchColumn();

                if (is_string($hash) && $hash !== '') {
                    // Same verifier as the tracker portal: accepts legacy plaintext
                    // rows and transparently upgrades them to bcrypt on success.
                    $verifyResult = srp_tracker_password_verify($inputPw, $hash);

                    if ($verifyResult['ok']) {
                        $loginOk = true;
                        $loginSubId = $inputSubId;

                        if ($verifyResult['needs_rehash']) {
                            try {
                                $rehashStmt = $statLoginPdo->prepare(
                                    'UPDATE generate SET password = :password WHERE sub_id = :sub_id LIMIT 1',
                                );
                                $rehashStmt->execute([
                                    'password' => srp_tracker_password_hash($inputPw),
                                    'sub_id' => $inputSubId,
                                ]);
                            } catch (Throwable $e) {
                                error_log('[stat-login] password rehash failed for sub_id ' . $inputSubId);
                            }
                        }
                    }
                }
            } catch (Throwable $e) {
                error_log('[stat-login] tracker auth error: ' . $e->getMessage());
            }
        }
    } elseif (
        $statLockout === 0
        && (
            (defined('REPASS') && password_verify($inputPw, REPASS))
            || ($a2rootPw !== '' && hash_equals($a2rootPw, $inputPw))
        )
    ) {
        // Admin (global view) — unchanged credentials.
        $loginOk = true;
        $loginSubId = null;
    }

    if ($error !== 'csrf') {
        if ($loginOk) {
            $_SESSION['stat_login_attempts'] = 0;
            $_SESSION['stat_login_last'] = 0;
            srp_login_throttle_reset($statThrottleScope);
            session_regenerate_id(true);
            $_SESSION['loggedIn'] = true;
            $_SESSION['stat_is_admin'] = ($loginSubId === null);

            if ($loginSubId === null) {
                unset($_SESSION['stat_sub_id']);
            } else {
                $_SESSION['stat_sub_id'] = $loginSubId;
            }

            $_SESSION['csrf_login'] = bin2hex(random_bytes(32));
            header('Location: ' . statUrl('/realtime/?date=rt_1'));
            exit;
        }

        $_SESSION['stat_login_attempts'] = $statAttempts + 1;
        $_SESSION['stat_login_last'] = time();
        srp_login_throttle_register_fail($statThrottleScope);
        $error = 'invalid';
    }
}

if (!empty($_SESSION['loggedIn'])) {
    header('Location: ' . statUrl('/realtime/?date=rt_1'));
    exit;
}

$remoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;
$ipAddress = e(is_string($remoteAddr) && $remoteAddr !== '' ? $remoteAddr : 'unknown');
$errorMessage = '';

if ($error === 'csrf') {
    $errorMessage = 'Session expired. Reload the page and try again.';
} elseif ($error === 'lockout') {
    $errorMessage = 'Too many failed attempts. Try again later. Your IP address: ' . $ipAddress;
} elseif ($error !== '') {
    $errorMessage = 'Access denied. Your IP address: ' . $ipAddress;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Lead Report</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="<?= statH(statAssetUrl('/favicon.ico')) ?>" rel="icon" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Caveat:wght@500;600;700&display=swap" rel="stylesheet">
    <style nonce="<?= e($nonce); ?>">:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--bg:var(--porcelain);--light:var(--porcelain);--surface:var(--porcelain);--panel2:var(--paper);--panel-soft:var(--paper);--panel-raised:var(--panel);--panel-fade:rgba(252, 251, 248, 0.7);--nav:var(--paper);--line:var(--soft-steel);--line2:var(--border);--line-soft:var(--border);--stroke:var(--soft-steel);--text:var(--graphite);--btn:var(--graphite);--primary:var(--graphite);--primary2:var(--ink);--text-strong:var(--ink);--strong:var(--ink);--dark:var(--ink);--muted:var(--steel-gray);--accent:var(--burnt-copper);--accent-h:#8f5236;--accent-hover:#8f5236;--accent-s:var(--burnt-copper-soft);--accent-soft:var(--burnt-copper-soft);--on:var(--paper);--on-accent:var(--paper);--good:var(--graphite);--ok:var(--graphite);--success:var(--graphite);--ok-soft:var(--burnt-copper-soft);--success-soft:var(--burnt-copper-soft);--bad:var(--burnt-copper);--danger:var(--burnt-copper);--danger-soft:var(--burnt-copper-soft);--warn:var(--steel-gray);--blue-soft:var(--burnt-copper-soft);--blue-line:rgba(168, 100, 66, 0.28);--shadow-modal:var(--shadow);--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}@media (prefers-color-scheme:dark){}*{box-sizing:border-box}html,body{width:100%;height:100dvh;margin:0;}body{padding:42px 8px 18px;font-family:var(--font);font-size:var(--fs-base);line-height:var(--lh-normal);background:radial-gradient(circle at 50% 8%,rgba(168,100,66,.12),transparent 28rem),radial-gradient(circle at 10% 80%,rgba(22,25,28,.06),transparent 22rem),var(--porcelain);color:var(--text);-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}.container{width:100%;max-width:600px!important;margin:0 auto!important}.panel,.panel-default{margin:0 auto;max-width:600px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow)!important;overflow:hidden}.panel-heading{padding:8px 10px;background:var(--porcelain)!important;border-bottom:1px solid var(--line-soft)!important;color:var(--text-strong);font-size:var(--fs-base)}.panel-body{padding:10px;background:transparent!important}.msg{margin-bottom:8px;padding:8px 10px;border:1px solid var(--line-soft);background:var(--panel-soft);color:var(--muted);border-radius:var(--radius);font-size:var(--fs-sm);font-family:var(--mono)}.input-group{display:flex;align-items:stretch;width:100%}.input-group>.form-control{position:relative;z-index:2;flex:1 1 auto;min-width:0}.input-group-btn{display:flex;flex:0 0 auto}.btn{display:inline-flex;align-items:center;justify-content:center;margin:0;padding:6px 12px;border:1px solid transparent;border-radius:var(--radius);line-height:1.42857143;text-align:center;white-space:nowrap;vertical-align:middle;cursor:pointer;user-select:none;-webkit-user-select:none;text-decoration:none}.form-control{display:block;width:100%;padding:5px 10px;line-height:1.42857143;appearance:none;-webkit-appearance:none;transition:border-color .15s ease-in-out;height:31px!important;border:1px solid var(--line)!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:none!important;font-family:var(--font);font-size:var(--fs-sm);caret-color:var(--text)!important}.form-control:-webkit-autofill,.form-control:-webkit-autofill:focus{-webkit-box-shadow:0 0 0 1000px var(--panel2) inset!important;-webkit-text-fill-color:var(--text)!important;caret-color:var(--text)!important}.form-control::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control:focus{outline:none;border-color:#66717a!important}.input-group-btn>.btn{min-width:148px;height:31px;border:1px solid var(--btn-border)!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--btn-bg)!important;color:var(--btn-fg)!important;font-size:var(--fs-sm);box-shadow:none!important; }.input-group-btn>.btn:hover{background:var(--btn-bg)!important;filter:brightness(1.18);border-color:var(--btn-border)!important}@media screen and (max-width:560px){body{padding:12px 8px;font-size:var(--fs-base)}.panel-heading,.panel-body{padding:8px}.input-group{display:block}.form-control,.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.form-control{border-radius:var(--radius)!important}.input-group-btn>.btn{margin-top:6px;border-radius:var(--radius)!important}}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}input[type=password]::-ms-reveal,input[type=password]::-ms-clear,input[type=password]::-webkit-textfield-decoration-container{display:none!important}.login-wrap{max-width:600px;margin-top:-10px}select hr{border:none;border-top:1px solid rgba(37,42,46,.06)!important;color:rgba(37,42,46,.06)!important;opacity:.45;margin:1px 4px}.app-sign{text-align:right;padding:3px 0 2px}.app-sign footer{font-family:var(--mono);text-decoration:none;letter-spacing:.09em;font-size:10px;font-weight:900;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;user-select:none;text-transform:uppercase;-webkit-user-select:none}input[type=url]{font-family:var(--mono)!important}.usr{font-family:var(--mono)}@keyframes btn-spin{to{transform:rotate(360deg)}}.btn-spin{display:inline-block;vertical-align:-2px;animation:btn-spin .7s linear infinite;opacity:.8}body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none}body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)}
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
<div class="container login-wrap">
<div class="noise" aria-hidden="true"></div>
<div class="scanline" aria-hidden="true"></div>
    <div class="panel panel-default">
        <div class="panel-heading"><strong class="usr">Login: Lead Report</strong></div>
        <div class="panel-body">
            <?php if ($errorMessage !== '') : ?>
                <div class="msg">
                    <?= $errorMessage; ?>
                </div>
            <?php endif; ?>
            <form method="post" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= e($csrfToken); ?>">
                <div class="input-group" style="margin-bottom:6px">
                    <input type="hidden" class="form-control input-sm" name="sub_id" autofocus
                           autocapitalize="characters" autocomplete="username" spellcheck="false"
                           placeholder="{sub_id — leave empty for admin}"
                           value="<?= e($subIdInput); ?>">
                </div>
                <div class="input-group">
                    <input type="password" class="form-control input-sm" name="password" placeholder="{password}">
                    <span class="input-group-btn">
                        <button class="btn btn-default btn-sm" type="submit"><strong>Login</strong></button>
                    </span>
                </div>
            </form>
        </div>
    </div>
</div>
<div class="container"><div class="app-sign"><footer>Ngix · xctd</footer></div></div>
<script nonce="<?= e($nonce); ?>">(function(){document.addEventListener('contextmenu',function(e){if(e.target&&e.target.tagName==='IMG'){e.preventDefault();}});var f=document.querySelector('form[method=post]');if(!f)return;var SP='<svg class="btn-spin" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="8" cy="8" r="6" stroke-opacity=".3"/><path d="M8 2a6 6 0 0 1 6 6"/><\/svg> ';f.addEventListener('submit',function(){var b=f.querySelector('button[type=submit]');if(!b||b.disabled)return;b.disabled=true;b.innerHTML=SP+'Logging in…';});}())</script>
<style nonce="<?= e($nonce); ?>">
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
<style nonce="<?= e($nonce); ?>">
/* NGIX patch: .msg toast auto-hide */
.msg{position:fixed!important;right:14px!important;bottom:14px!important;z-index:10080!important;display:block!important;width:min(360px,calc(100vw - 28px))!important;max-width:calc(100vw - 28px)!important;margin:0!important;padding:9px 11px!important;border:1px solid var(--line,rgba(37,42,46,.18))!important;border-left:3px solid var(--danger,var(--accent,var(--graphite)))!important;border-radius:var(--radius,.3rem)!important;background:var(--panel2,var(--panel,var(--paper)))!important;color:var(--text,var(--graphite))!important;box-shadow:0 4px 18px rgba(22,25,28,.12)!important;font:12px/1.4 var(--mono,Consolas,Monaco,'Courier New',monospace)!important;word-break:break-word!important;opacity:0!important;transform:translateY(10px)!important;pointer-events:none!important;transition:opacity .18s ease,transform .18s ease!important}.msg.show{opacity:1!important;transform:translateY(0)!important;pointer-events:auto!important}.msg.is-hiding{opacity:0!important;transform:translateY(10px)!important;pointer-events:none!important}.msg-ok{border-left-color:var(--success,var(--ok,var(--graphite)))!important;color:var(--text,var(--graphite))!important}
@media screen and (max-width:560px){.msg{right:8px!important;left:8px!important;bottom:8px!important;width:auto!important;max-width:none!important}}
</style>
<script nonce="<?= e($nonce); ?>">
/* NGIX patch: auto-hide .msg toast */
(function(){
    'use strict';

    function initMsgToasts() {
        var nodes = document.querySelectorAll('.msg');

        if (!nodes.length) {
            return;
        }

        Array.prototype.forEach.call(nodes, function(node, index) {
            var isOk = node.classList.contains('msg-ok');
            var visibleDelay = 40 + (index * 80);
            var hideDelay = 4200 + (index * 350);
            var bottom = 14 + (index * 58);

            node.setAttribute('role', isOk ? 'status' : 'alert');
            node.setAttribute('aria-live', isOk ? 'polite' : 'assertive');
            node.style.bottom = String(bottom) + 'px';

            window.setTimeout(function() {
                node.classList.add('show');
            }, visibleDelay);

            window.setTimeout(function() {
                node.classList.remove('show');
                node.classList.add('is-hiding');

                window.setTimeout(function() {
                    node.hidden = true;
                }, 240);
            }, hideDelay);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initMsgToasts, {once: true});
        return;
    }

    initMsgToasts();
}());
</script>
<style nonce="<?= e($nonce); ?>">
/* NGIX patch: disable image/background right-click */
img,picture,svg,canvas,.ngix-image-backdrop,.image-protect,.app-banner,.brand-logo,.logo{
  -webkit-user-drag:none!important;
  -webkit-touch-callout:none!important;
  -webkit-user-select:none!important;
  user-select:none!important;
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
<script nonce="<?= e($nonce); ?>">
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
