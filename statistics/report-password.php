<?php

declare(strict_types=1);

// statIsHttpsRequest() lives here. Without this require the file fatals in
// configureSession() before rendering anything — the page was returning 500.
require_once __DIR__ . '/stat_path.php';
// Per-IP backstop for the session-based lockout below — without it, dropping
// the session cookie resets the failure count and the lockout never engages.
require_once dirname(__DIR__) . '/login_throttle.php';

const REPASS_FILE = __DIR__ . '/repass.php';
const AUTH_FILE = __DIR__ . '/report_auth.php';
const SESSION_NAME = 'report_password_admin';
const CSRF_KEY = 'report_password_csrf';
const AUTH_SESSION_KEY = 'report_password_auth';
const LOGIN_MAX_ATTEMPTS = 5;
const MIN_PASSWORD_LENGTH = 5;

function configureSecurityHeaders(string $nonce): void
{
    header('Content-Type: text/html; charset=UTF-8');
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
        "img-src 'self' data:",
        "font-src 'self' data: https://fonts.gstatic.com https://use.fontawesome.com https://cdnjs.cloudflare.com",
        "style-src 'self' 'nonce-" . $nonce . "' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com",
        "style-src-elem 'self' 'nonce-" . $nonce . "' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com",
        "style-src-attr 'none'",
        "script-src 'self' 'nonce-" . $nonce . "'",
        "connect-src 'self'",
        'upgrade-insecure-requests',
    ]);
    header('Content-Security-Policy: ' . $csp);
}

function configureSession(): void
{
    session_name(SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => statIsHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Show/hide toggle for a password field.
 *
 * Lives inside `.pw-wrap`, which reserves the 32px gutter this button fills
 * (`.pw-wrap .form-control { padding-right: 32px }`). The two icons are both
 * rendered; `.ico-eye-off` starts hidden via CSS and the script at the bottom
 * of the page swaps their `display` on click.
 *
 * The three forms on this page are mutually exclusive (if / elseif / else), so
 * only ever one `#pw-toggle` + `#pw-field` pair exists in the document.
 */
function pwToggleButton(): string
{
    return '<button type="button" class="pw-toggle" id="pw-toggle" aria-label="Show password" tabindex="-1">'
        . '<svg class="ico-eye" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
        . ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
        . '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>'
        . '<svg class="ico-eye-off" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor"'
        . ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
        . '<path d="M10.7 5.1A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a18.4 18.4 0 0 1-2.4 3.4M6.5 6.6A18.2 18.2 0 0 0 2 12'
        . 's3.6 7 10 7a10.3 10.3 0 0 0 4.4-.95"/><path d="m3 3 18 18"/>'
        . '<path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>'
        . '</button>';
}

function csrfToken(): string
{
    if (
        !isset($_SESSION[CSRF_KEY])
        || !is_string($_SESSION[CSRF_KEY])
        || $_SESSION[CSRF_KEY] === ''
    ) {
        $_SESSION[CSRF_KEY] = bin2hex(random_bytes(32));
    }

    return $_SESSION[CSRF_KEY];
}

function rotateCsrfToken(): void
{
    $_SESSION[CSRF_KEY] = bin2hex(random_bytes(32));
}

function verifyCsrf(?string $token): bool
{
    if (!is_string($token) || $token === '') {
        return false;
    }

    if (!isset($_SESSION[CSRF_KEY]) || !is_string($_SESSION[CSRF_KEY])) {
        return false;
    }

    return hash_equals($_SESSION[CSRF_KEY], $token);
}

function isAuthenticated(): bool
{
    return isset($_SESSION[AUTH_SESSION_KEY]) && $_SESSION[AUTH_SESSION_KEY] === true;
}

function selfPath(): string
{
    $scriptName = isset($_SERVER['SCRIPT_NAME']) && is_string($_SERVER['SCRIPT_NAME'])
        ? $_SERVER['SCRIPT_NAME']
        : '';

    if ($scriptName === '' || preg_match('/[\r\n]/', $scriptName) === 1) {
        return '';
    }

    return $scriptName;
}

function loadAuthConfig(): array
{
    if (!is_file(AUTH_FILE)) {
        return [];
    }

    $config = require AUTH_FILE;

    if (!is_array($config)) {
        return [];
    }

    return $config;
}

function validatePassword(string $value, string $label): array
{
    $value = trim($value);

    if ($value === '') {
        return [false, $label . ' cannot be empty.', ''];
    }

    if (strlen($value) < MIN_PASSWORD_LENGTH) {
        return [false, $label . ' must be at least ' . MIN_PASSWORD_LENGTH . ' characters.', ''];
    }

    if (strlen($value) > 128) {
        return [false, $label . ' must not exceed 128 characters.', ''];
    }

    if (preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
        return [false, $label . ' contains blocked control characters.', ''];
    }

    if (
        stripos($value, '<?') !== false
        || stripos($value, '?>') !== false
        || stripos($value, '<script') !== false
    ) {
        return [false, 'Suspicious payload blocked.', ''];
    }

    return [true, '', $value];
}

function setupAuth(#[\SensitiveParameter] string $password): void
{
    if (is_file(AUTH_FILE)) {
        throw new RuntimeException('Auth file already exists.');
    }

    $dir = dirname(AUTH_FILE);

    if (!is_dir($dir)) {
        throw new RuntimeException('Target directory does not exist.');
    }

    if (!is_writable($dir)) {
        throw new RuntimeException('Target directory is not writable.');
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);

    if (!is_string($hash) || $hash === '') {
        throw new RuntimeException('Failed creating password hash.');
    }

    $php = "<?php\n\ndeclare(strict_types=1);\n\nreturn [\n"
        . "    'password_hash' => " . var_export($hash, true) . ",\n"
        . "];\n";

    $tmp = AUTH_FILE . '.tmp.' . bin2hex(random_bytes(8));

    $bytes = file_put_contents($tmp, $php, LOCK_EX);
    if ($bytes === false) {
        throw new RuntimeException('Failed writing temporary auth file.');
    }

    @chmod($tmp, 0640);

    if (!rename($tmp, AUTH_FILE)) {
        @unlink($tmp);

        throw new RuntimeException('Failed creating auth file.');
    }
}

/**
 * Per-IP failure state from the shared file throttle, expressed as remaining
 * lockout seconds (0 = not locked). Backstops the per-session counters below
 * so dropping the session cookie no longer resets the failure count.
 */
function ipThrottleRemainingLockSeconds(): int
{
    // Default (1 hour) decay window: failures must stay remembered well past
    // the 60s lockout itself, or an attacker could pace guesses exactly at the
    // lockout boundary and never accumulate past LOGIN_MAX_ATTEMPTS.
    $state = srp_login_throttle_state(SESSION_NAME);

    if ($state['fails'] < LOGIN_MAX_ATTEMPTS) {
        return 0;
    }

    return max(0, srp_login_lockout_seconds($state['fails']) - (time() - $state['last']));
}

function registerFailedLogin(): void
{
    if (!isset($_SESSION['login_attempts']) || !is_int($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
    }

    $_SESSION['login_attempts']++;

    if ($_SESSION['login_attempts'] >= LOGIN_MAX_ATTEMPTS) {
        $_SESSION['login_locked_until'] = time() + srp_login_lockout_seconds($_SESSION['login_attempts']);
    }

    srp_login_throttle_register_fail(SESSION_NAME);
}

function clearFailedLogin(): void
{
    unset($_SESSION['login_attempts'], $_SESSION['login_locked_until']);
    srp_login_throttle_reset(SESSION_NAME);
}

function isLoginLocked(): bool
{
    $sessionLocked = (
        isset($_SESSION['login_locked_until'])
        && is_int($_SESSION['login_locked_until'])
        && $_SESSION['login_locked_until'] > time()
    );

    return $sessionLocked || ipThrottleRemainingLockSeconds() > 0;
}

function loginRemainingLockSeconds(): int
{
    $sessionRemaining = isset($_SESSION['login_locked_until']) && is_int($_SESSION['login_locked_until'])
        ? max(0, $_SESSION['login_locked_until'] - time())
        : 0;

    return max($sessionRemaining, ipThrottleRemainingLockSeconds());
}

function attemptLogin(#[\SensitiveParameter] string $password): bool
{
    if (isLoginLocked()) {
        return false;
    }

    $config = loadAuthConfig();

    $storedHash = isset($config['password_hash']) && is_string($config['password_hash'])
        ? $config['password_hash']
        : '';

    if ($storedHash === '') {
        return false;
    }

    if (!password_verify(trim($password), $storedHash)) {
        registerFailedLogin();

        return false;
    }

    session_regenerate_id(true);
    $_SESSION[AUTH_SESSION_KEY] = true;
    clearFailedLogin();
    rotateCsrfToken();

    return true;
}

function logout(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            (string) session_name(),
            '',
            [
                'expires' => time() - 42000,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => statIsHttpsRequest(),
                'httponly' => true,
                'samesite' => 'Strict',
            ],
        );
    }

    session_destroy();
}

function loadCurrentPassword(): string
{
    if (!is_file(REPASS_FILE)) {
        return '';
    }

    $content = file_get_contents(REPASS_FILE);
    if (!is_string($content) || $content === '') {
        return '';
    }

    if (preg_match('/define\s*\(\s*[\'"]REPASS[\'"]\s*,\s*([\'"])(.*?)\1\s*\)\s*;/s', $content, $matches) !== 1) {
        return '';
    }

    // Return a placeholder — never expose the raw hash or plaintext to the UI.
    return '••••••••';
}

function saveReportPassword(#[\SensitiveParameter] string $password): void
{
    $dir = dirname(REPASS_FILE);

    if (!is_dir($dir)) {
        throw new RuntimeException('Target directory does not exist.');
    }

    if (!is_writable($dir)) {
        throw new RuntimeException('Target directory is not writable.');
    }

    if (is_file(REPASS_FILE) && !is_writable(REPASS_FILE)) {
        throw new RuntimeException('repass.php exists but is not writable.');
    }

    $hash = password_hash($password, PASSWORD_BCRYPT);
    $php  = "<?php\n\ndeclare(strict_types=1);\n\ndefine('REPASS', " . var_export($hash, true) . ");\n";
    $tmp = REPASS_FILE . '.tmp.' . bin2hex(random_bytes(8));

    $bytes = file_put_contents($tmp, $php, LOCK_EX);
    if ($bytes === false) {
        throw new RuntimeException('Failed writing temporary password file.');
    }

    @chmod($tmp, 0640);

    if (!rename($tmp, REPASS_FILE)) {
        @unlink($tmp);

        throw new RuntimeException('Failed replacing repass.php.');
    }
}

$nonce = bin2hex(random_bytes(16));

configureSession();
configureSecurityHeaders($nonce);

$statusType = '';
$statusMessage = '';
$self = selfPath();
$redirectSelf = $self !== '' ? $self : './';
$authExists = is_file(AUTH_FILE);
$currentPassword = isAuthenticated() ? loadCurrentPassword() : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!verifyCsrf($_POST['csrf_token'] ?? null)) {
            throw new RuntimeException('Invalid CSRF token.');
        }

        $action = isset($_POST['action']) && is_string($_POST['action']) ? $_POST['action'] : '';

        if ($action === 'setup') {
            if ($authExists) {
                throw new RuntimeException('Setup is already locked.');
            }

            $postedPassword = isset($_POST['password']) && is_string($_POST['password'])
                ? $_POST['password']
                : '';

            [$isPasswordValid, $passwordError, $cleanPassword] = validatePassword($postedPassword, 'Admin password');

            if (!$isPasswordValid) {
                throw new InvalidArgumentException($passwordError);
            }

            setupAuth($cleanPassword);
            rotateCsrfToken();

            $authExists = true;
            $statusType = 'ok';
            $statusMessage = 'Admin password created. Please login.';
        } elseif ($action === 'login') {
            if (!$authExists) {
                throw new RuntimeException('Admin password is not configured.');
            }

            if (isLoginLocked()) {
                throw new RuntimeException('Too many failed attempts. Try again in ' . loginRemainingLockSeconds() . ' seconds.');
            }

            $postedPassword = isset($_POST['password']) && is_string($_POST['password'])
                ? $_POST['password']
                : '';

            if (!attemptLogin($postedPassword)) {
                throw new RuntimeException('Invalid password.');
            }

            $currentPassword = loadCurrentPassword();
            $statusType = 'ok';
            $statusMessage = 'Login successful.';
        } elseif ($action === 'logout') {
            logout();
            header('Location: ' . $redirectSelf);
            exit;
        } elseif ($action === 'update') {
            if (!isAuthenticated()) {
                throw new RuntimeException('Unauthorized request.');
            }

            $postedPassword = isset($_POST['update']) && is_string($_POST['update'])
                ? $_POST['update']
                : '';

            [$isValid, $validationError, $cleanPassword] = validatePassword($postedPassword, 'Report password');

            if (!$isValid) {
                throw new InvalidArgumentException($validationError);
            }

            saveReportPassword($cleanPassword);
            rotateCsrfToken();

            $currentPassword = '••••••••';
            $statusType = 'ok';
            $statusMessage = 'Report password updated.';
        } else {
            throw new RuntimeException('Invalid action.');
        }
    } catch (Throwable $e) {
        error_log('[statistics/report-password] request failed: ' . $e->getMessage());
        $statusType = 'error';
        $safeMessage = '';

        if ($e instanceof InvalidArgumentException) {
            $message = $e->getMessage();
            if (
                $message === 'Suspicious payload blocked.'
                || preg_match('/^(Admin password|Report password) cannot be empty\.$/', $message) === 1
                || preg_match('/^(Admin password|Report password) must be at least [0-9]+ characters\.$/', $message) === 1
                || preg_match('/^(Admin password|Report password) must not exceed 128 characters\.$/', $message) === 1
                || preg_match('/^(Admin password|Report password) contains blocked control characters\.$/', $message) === 1
            ) {
                $safeMessage = $message;
            }
        } elseif ($e instanceof RuntimeException) {
            $message = $e->getMessage();
            if (
                $message === 'Invalid CSRF token.'
                || $message === 'Setup is already locked.'
                || $message === 'Admin password is not configured.'
                || $message === 'Invalid password.'
                || $message === 'Unauthorized request.'
                || $message === 'Invalid action.'
                || str_starts_with($message, 'Too many failed attempts. Try again in ')
            ) {
                $safeMessage = $message;
            }
        }

        $statusMessage = $safeMessage !== '' ? $safeMessage : 'Request failed.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Report Password</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Caveat:wght@500;600;700&display=swap" rel="stylesheet">
<link href="favicon.ico" rel="icon" type="image/x-icon">
<style nonce="<?= h($nonce) ?>">:root{color-scheme:light;--porcelain:#f4f1ec;--paper:#fcfbf8;--soft-steel:#d9dee2;--graphite:#252a2e;--steel-gray:#66717a;--ink:#16191c;--burnt-copper:#a86442;--burnt-copper-soft:rgba(168, 100, 66, 0.16);--panel:rgba(252, 251, 248, 0.82);--border:rgba(37, 42, 46, 0.14);--shadow:rgba(0, 0, 0, 0.12) 0px 1px 3px, rgba(0, 0, 0, 0.24) 0px 1px 2px;--radius:0.3rem;--pointer-x:50vw;--pointer-y:50vh;--font: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;--mono: "Geist Mono", "Roboto Mono", Consolas, monospace !important;--bg:var(--porcelain);--light:var(--porcelain);--surface:var(--porcelain);--panel2:var(--paper);--panel-soft:var(--paper);--panel-raised:var(--panel);--panel-fade:rgba(252, 251, 248, 0.7);--nav:var(--paper);--line:var(--soft-steel);--line2:var(--border);--line-soft:var(--border);--stroke:var(--soft-steel);--text:var(--graphite);--btn:var(--graphite);--primary:var(--graphite);--primary2:var(--ink);--text-strong:var(--ink);--strong:var(--ink);--dark:var(--ink);--muted:var(--steel-gray);--accent:var(--burnt-copper);--accent-h:#8f5236;--accent-hover:#8f5236;--accent-s:var(--burnt-copper-soft);--accent-soft:var(--burnt-copper-soft);--on:var(--paper);--on-accent:var(--paper);--good:var(--graphite);--ok:var(--graphite);--success:var(--graphite);--ok-soft:var(--burnt-copper-soft);--success-soft:var(--burnt-copper-soft);--bad:var(--burnt-copper);--danger:var(--burnt-copper);--danger-soft:var(--burnt-copper-soft);--warn:var(--steel-gray);--blue-soft:var(--burnt-copper-soft);--blue-line:rgba(168, 100, 66, 0.28);--shadow-modal:var(--shadow);--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px;--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7}@media (prefers-color-scheme:dark){}*{box-sizing:border-box}html,body{width:100%;height:100dvh;margin:0;}body{padding:42px 8px 18px;font-family:var(--font);font-size:var(--fs-base);line-height:var(--lh-normal);background:linear-gradient(180deg,var(--paper) 0%,var(--porcelain) 100%);color:var(--text);-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}.container{width:100%;max-width:600px!important;margin:-10px auto 0!important}.panel,.panel-default{margin:0 auto;max-width:600px;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--panel)!important;box-shadow:var(--shadow)!important;backdrop-filter:blur(16px) saturate(180%);-webkit-backdrop-filter:blur(16px) saturate(180%);overflow:hidden}.panel-heading{padding:8px 10px;background:var(--porcelain)!important;border-bottom:1px solid var(--line-soft)!important;color:var(--text-strong);font-size:var(--fs-base)}.panel-heading-auth{display:flex;align-items:center;justify-content:space-between;gap:8px}.logout-form{margin:0}.panel-body{padding:10px;background:transparent!important}.msg{margin-bottom:8px;padding:8px 10px;border:1px solid rgba(102,113,122,.28);background:var(--danger-soft);color:var(--danger);border-radius:var(--radius);font-size:var(--fs-sm);word-break:break-word;font-family:var(--mono)}.msg-ok{border-color:rgba(102,113,122,.28);background:var(--ok-soft);color:var(--ok)}.current-box{margin-bottom:10px;padding:8px 10px;border:1px solid var(--line-soft);background:rgba(252,251,248,.38);color:var(--text);border-radius:var(--radius);font-size:var(--fs-sm);word-break:break-word}.current-box strong{display:block;margin-bottom:2px;color:color-mix(in srgb,var(--text) 62%,transparent);font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:.05em}.input-group{width:100%;display:flex!important;align-items:center}.input-group>.form-control{flex:1 1 auto;width:auto!important;min-width:0}.form-control{height:31px;border:1px solid var(--line)!important;border-radius:var(--radius) 0 0 var(--radius)!important;background:var(--panel)!important;color:var(--text)!important;box-shadow:none!important;font-family:inhe!important;font-size:var(--fs-sm);padding:6px 10px;min-width:0}.form-control::placeholder{color:color-mix(in srgb,var(--text) 54%,transparent)}.form-control:focus,.form-control:focus-visible{outline:none!important;border-color:var(--accent)!important}.input-group-btn{display:flex!important;flex:0 0 auto;width:auto!important}.input-group-btn>.btn{min-width:148px;height:31px;border:1px solid var(--btn-border)!important;border-radius:0 var(--radius) var(--radius) 0!important;background:var(--btn-bg)!important;color:var(--btn-fg)!important;font-size:var(--fs-sm);font-weight:var(--fw-bold);box-shadow:none!important;padding:0 14px;white-space:nowrap;cursor:pointer}.input-group-btn>.btn:hover{background:var(--btn-bg)!important;filter:brightness(1.18);border-color:var(--btn-border)!important}.hint{margin:10px 0 0;color:color-mix(in srgb,var(--text) 72%,transparent);font-size:var(--fs-sm);font-family:var(--mono);}.btn-link{border:0!important;background:transparent!important;color:var(--text)!important;padding:0;font-size:var(--fs-sm);text-decoration:underline;box-shadow:none!important;cursor:pointer}.btn-link:hover{opacity:.82}@media screen and (max-width:560px){body{padding:12px 8px;font-size:var(--fs-base)}.panel-heading,.panel-body{padding:8px}.input-group{display:flex!important}.form-control,.input-group-btn,.input-group-btn>.btn{display:block;width:100%!important}.form-control{border-radius:var(--radius)!important}.input-group-btn>.btn{margin-top:6px;border-radius:var(--radius)!important}.pw-wrap{display:block;width:100%}}input:focus,textarea:focus,select:focus,button:focus,.form-control:focus,.btn:focus,a:focus{outline:none!important}body::before{content:'NGIX\2022 XCTD';position:fixed;top:12px;left:14px;z-index:0;font:600 11px/1 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;letter-spacing:.24em;text-transform:uppercase;color:rgba(37,42,46,.06);pointer-events:none}body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background-image:url('/assets/img/favicon.svg'),url('/assets/img/bg-intro.png');background-repeat:no-repeat,no-repeat;background-position:right 14px bottom 12px,center center;background-size:28px 28px,cover;opacity:.28;filter:saturate(.68) contrast(.84) brightness(1.03) blur(.32px);transform:translateZ(0)}.pw-wrap{position:relative;flex:1 1 auto;min-width:0}.pw-wrap .form-control{display:block;width:100%;padding-right:32px!important}.pw-toggle{position:absolute;right:0;top:0;bottom:0;width:32px;display:flex;align-items:center;justify-content:center;background:transparent;border:0;cursor:pointer;color:color-mix(in srgb,var(--text) 46%,transparent);padding:0;line-height:0;border-radius:0}.pw-toggle:hover{color:var(--text)}.pw-toggle svg{display:block;pointer-events:none}.pw-toggle .ico-eye-off{display:none}select hr{border:none;border-top:1px solid rgba(37,42,46,.06)!important;color:rgba(37,42,46,.06)!important;opacity:.45;margin:1px 4px}.app-sign{text-align:right;padding:3px 0 2px}.app-sign footer{font-family:var(--mono);text-decoration:none;letter-spacing:.09em;font-size:10px;font-weight:900;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;user-select:none;text-transform:uppercase;-webkit-user-select:none}input[type=url]{font-family:var(--mono)!important}
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
<div class="container">
<div class="noise" aria-hidden="true"></div>
<div class="scanline" aria-hidden="true"></div>
    <div class="panel panel-default">
        <div class="panel-heading<?= isAuthenticated() ? ' panel-heading-auth' : '' ?>">
            <strong>Report Password</strong>
            <?php if (isAuthenticated()) : ?>
                <form action="<?= h($self) ?>" method="post" class="logout-form">
                    <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                    <input type="hidden" name="action" value="logout">
                    <button class="btn-link" type="submit">Logout</button>
                </form>
            <?php endif; ?>
        </div>
        <div class="panel-body">
            <?php if ($statusMessage !== '') : ?>
                <div class="msg <?= $statusType === 'ok' ? 'msg-ok' : '' ?>">
                    <?= h($statusMessage) ?>
                </div>
            <?php endif; ?>

            <?php if (!$authExists) : ?>
                <form action="<?= h($self) ?>" method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                    <input type="hidden" name="action" value="setup">
                    <div class="input-group">
                        <div class="pw-wrap">
                            <input type="password" class="form-control input-sm" id="pw-field" name="password" autocomplete="new-password" required minlength="<?= MIN_PASSWORD_LENGTH ?>" maxlength="128" autofocus placeholder="Create admin password">
                            <?= pwToggleButton() ?>
                        </div>
                        <span class="input-group-btn">
                            <button class="btn btn-default btn-sm" type="submit"><strong>Create</strong></button>
                        </span>
                    </div>
                </form>
                <p class="hint">First-run setup. Minimum password length: <?= MIN_PASSWORD_LENGTH ?> characters.</p>

            <?php elseif (!isAuthenticated()) : ?>
                <form action="<?= h($self) ?>" method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                    <input type="hidden" name="action" value="login">
                    <div class="input-group">
                        <div class="pw-wrap">
                            <input type="password" class="form-control input-sm" id="pw-field" name="password" autocomplete="current-password" required minlength="<?= MIN_PASSWORD_LENGTH ?>" maxlength="128" autofocus placeholder="Password">
                            <?= pwToggleButton() ?>
                        </div>
                        <span class="input-group-btn">
                            <button class="btn btn-default btn-sm" type="submit"><strong>Login</strong></button>
                        </span>
                    </div>
                </form>
                <p class="hint">Password-only login enabled. Failed attempts are rate-limited per session.</p>

            <?php else : ?>
                <div class="current-box">
                    <strong>Current Report Password</strong>
                    <?= $currentPassword !== '' ? h($currentPassword) : 'Not set' ?>
                </div>
                <form action="<?= h($self) ?>" method="post" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="<?= h(csrfToken()) ?>">
                    <input type="hidden" name="action" value="update">
                    <div class="input-group">
                        <div class="pw-wrap">
                            <input type="password" class="form-control input-sm" id="pw-field" name="update" autocomplete="new-password" required minlength="<?= MIN_PASSWORD_LENGTH ?>" maxlength="128" autofocus placeholder="New report password">
                            <?= pwToggleButton() ?>
                        </div>
                        <span class="input-group-btn">
                            <button class="btn btn-default btn-sm" name="Submit" type="submit" value="Update"><strong>Update</strong></button>
                        </span>
                    </div>
                </form>
                <p class="hint">Minimum report password length: <?= MIN_PASSWORD_LENGTH ?> characters. Suspicious payloads are blocked.</p>
            <?php endif; ?>
        </div>
    </div>
</div>
<script nonce="<?= h($nonce) ?>">(function(){var b=document.getElementById('pw-toggle'),i=document.getElementById('pw-field');if(!b||!i)return;b.addEventListener('click',function(){var s=i.type==='password';i.type=s?'text':'password';b.setAttribute('aria-label',s?'Hide password':'Show password');b.querySelector('.ico-eye').style.display=s?'none':'block';b.querySelector('.ico-eye-off').style.display=s?'block':'none';});})();</script>
<style nonce="<?= h($nonce) ?>">
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
<style nonce="<?= h($nonce) ?>">
/* NGIX patch: .msg toast auto-hide */
.msg{position:fixed!important;right:14px!important;bottom:14px!important;z-index:10080!important;display:block!important;width:min(360px,calc(100vw - 28px))!important;max-width:calc(100vw - 28px)!important;margin:0!important;padding:9px 11px!important;border:1px solid var(--line,rgba(37,42,46,.18))!important;border-left:3px solid var(--danger,var(--accent,var(--graphite)))!important;border-radius:var(--radius,.3rem)!important;background:var(--panel2,var(--panel,var(--paper)))!important;color:var(--text,var(--graphite))!important;box-shadow:0 4px 18px rgba(22,25,28,.12)!important;font:12px/1.4 var(--mono,Consolas,Monaco,'Courier New',monospace)!important;word-break:break-word!important;opacity:0!important;transform:translateY(10px)!important;pointer-events:none!important;transition:opacity .18s ease,transform .18s ease!important}.msg.show{opacity:1!important;transform:translateY(0)!important;pointer-events:auto!important}.msg.is-hiding{opacity:0!important;transform:translateY(10px)!important;pointer-events:none!important}.msg-ok{border-left-color:var(--success,var(--ok,var(--graphite)))!important;color:var(--text,var(--graphite))!important}
@media screen and (max-width:560px){.msg{right:8px!important;left:8px!important;bottom:8px!important;width:auto!important;max-width:none!important}}
</style>
<script nonce="<?= h($nonce) ?>">
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
<style nonce="<?= h($nonce) ?>">
/* NGIX patch: disable image/background right-click */
img,picture,svg,canvas,.ngix-image-backdrop,.image-protect,.app-banner,.brand-logo,.logo{
  -webkit-user-drag:none!important;
  -webkit-touch-callout:none!important;
  -webkit-user-select:none!important;
  user-select:none!important;
}
</style>
<script nonce="<?= h($nonce) ?>">
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
<style nonce="<?= h($nonce) ?>">
/* NGIX patch: statistics modal/logout/spinner correction */
@keyframes ngixStatSpin{to{transform:rotate(360deg)}}
.modal{z-index:1090!important;padding:0!important;text-align:center!important}
.modal:before{content:"";display:inline-block;height:100%;vertical-align:middle}
.modal-dialog{display:inline-block!important;width:min(560px,calc(100vw - 24px))!important;max-width:calc(100vw - 24px)!important;margin:0 auto!important;text-align:left!important;vertical-align:middle!important;transform:none!important}
.modal.in .modal-dialog,.modal.show .modal-dialog{transform:none!important}
.modal-content{max-height:calc(100vh - 24px)!important;max-height:calc(100dvh - 24px)!important;display:flex!important;flex-direction:column!important;overflow:hidden!important}
.modal-header,.modal-footer{flex:0 0 auto!important}.modal-body{flex:1 1 auto!important;overflow:auto!important;-webkit-overflow-scrolling:touch!important}.modal-backdrop{z-index:1080!important}
.swal-overlay,.swal2-container{z-index:11000!important;display:flex!important;align-items:center!important;justify-content:center!important;padding:12px!important;overflow:auto!important}.swal-modal,.swal2-modal,.swal2-popup{position:relative!important;top:auto!important;right:auto!important;bottom:auto!important;left:auto!important;width:min(360px,calc(100vw - 24px))!important;max-width:calc(100vw - 24px)!important;max-height:calc(100vh - 24px)!important;max-height:calc(100dvh - 24px)!important;margin:0!important;transform:none!important;overflow:auto!important}.swal2-actions,.swal2-buttonswrapper{display:flex!important;align-items:center!important;justify-content:center!important;gap:8px!important;min-height:32px!important}.swal2-loader{display:inline-block!important;width:22px!important;height:22px!important;min-width:22px!important;min-height:22px!important;margin:0 8px!important;border:3px solid currentColor!important;border-right-color:transparent!important;border-bottom-color:transparent!important;border-radius:50%!important;animation:ngixStatSpin .72s linear infinite!important;box-shadow:none!important}.swal2-loading .swal2-confirm{display:none!important}
#logout-form,.logout-form{display:flex!important;align-items:center!important;justify-content:center!important;margin:0!important}.navbar-nav>li>#logout-form,.navbar-nav>li>.logout-form{height:44px!important}.navbar-btn.btn-link,#btn-logout,.logout-btn{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:7px!important;height:44px!important;min-height:44px!important;margin:0!important;padding:12px 10px!important;border:0!important;border-radius:0!important;background:transparent!important;color:var(--text,var(--graphite))!important;text-decoration:none!important;box-shadow:none!important;line-height:20px!important;white-space:nowrap!important}.navbar-btn.btn-link:hover,#btn-logout:hover,.logout-btn:hover{background:var(--panel-soft,rgba(37,42,46,.06))!important;color:var(--text-strong,var(--ink))!important}.navbar-btn.btn-link:disabled,#btn-logout:disabled,.logout-btn:disabled{opacity:.76!important;cursor:wait!important}.btn.is-loading,.navbar-btn.is-loading,#btn-logout.is-loading,.logout-btn.is-loading{cursor:wait!important;pointer-events:none!important}.btn.is-loading:before,.navbar-btn.is-loading:before,#btn-logout.is-loading:before,.logout-btn.is-loading:before{content:""!important;display:inline-block!important;width:12px!important;height:12px!important;min-width:12px!important;margin-right:2px!important;border:2px solid currentColor!important;border-right-color:transparent!important;border-bottom-color:transparent!important;border-radius:50%!important;animation:ngixStatSpin .72s linear infinite!important}.pn-refresh-btn.is-loading img,#refresh.is-loading img{display:none!important}#logout-toast{position:fixed!important;right:12px!important;bottom:12px!important;z-index:11020!important;display:block!important;width:min(320px,calc(100vw - 24px))!important;padding:9px 11px!important;border:1px solid var(--line,rgba(37,42,46,.18))!important;border-left:3px solid var(--accent,var(--graphite))!important;border-radius:var(--radius,.3rem)!important;background:var(--panel2,var(--paper))!important;color:var(--text,var(--graphite))!important;box-shadow:0 8px 28px rgba(22,25,28,.14)!important;font:12px/1.35 var(--mono,Consolas,Monaco,'Courier New',monospace)!important;opacity:0!important;transform:translateY(8px)!important;pointer-events:none!important;transition:opacity .16s ease,transform .16s ease!important}#logout-toast.show{opacity:1!important;transform:translateY(0)!important;pointer-events:auto!important}
@media screen and (max-width:768px){.modal:before{display:none!important}.modal-dialog{display:block!important;width:auto!important;max-width:none!important;margin:10px!important}.modal-content{max-height:calc(100vh - 20px)!important;max-height:calc(100dvh - 20px)!important}.navbar-collapse #logout-form,.navbar-collapse .logout-form{justify-content:flex-start!important}.navbar-collapse #btn-logout,.navbar-collapse .logout-btn{width:100%!important;justify-content:flex-start!important;border-radius:var(--radius,.3rem)!important}#logout-toast{right:8px!important;left:8px!important;bottom:8px!important;width:auto!important}}
</style>
<script nonce="<?= h($nonce) ?>">
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
<style nonce="<?= h($nonce) ?>">
/* NGIX patch: statistics bg/backdrop deglitch */
html{width:100%!important;min-width:0!important;max-width:100%!important;min-height:100%!important;margin:0!important;padding:0!important;overflow-x:hidden!important;background:var(--porcelain)!important;zoom:1!important}
body{position:relative!important;width:100%!important;min-width:0!important;max-width:100%!important;min-height:100vh!important;min-height:100svh!important;min-height:100dvh!important;margin:0!important;overflow-x:hidden!important;background:linear-gradient(rgba(252,251,248,.74),rgba(252,251,248,.88)),url('/assets/img/favicon.svg') right 14px bottom 12px/28px 28px no-repeat fixed,url('/assets/img/bg-intro.png') center center/cover no-repeat fixed,var(--porcelain)!important;color:var(--text,var(--graphite))!important}
body::after{content:none!important;display:none!important;background:none!important}
body::before{z-index:1!important}
body>.container,.container{position:relative!important;z-index:2!important;max-width:1180px!important;overflow:visible!important}
.navbar.navbar-fixed-top,.navbar-fixed-top{position:fixed!important;top:0!important;right:0!important;left:0!important;width:100%!important;max-width:100%!important;margin:0!important;border-radius:0!important;transform:none!important;z-index:1055!important}
.panel_m.panel{position:relative!important;overflow:hidden!important;isolation:isolate!important;background:rgba(252,251,248,.62)!important}
.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{position:absolute!important;inset:0!important;top:0!important;right:0!important;bottom:0!important;left:0!important;width:100%!important;min-width:0!important;max-width:100%!important;height:100%!important;min-height:100%!important;max-height:none!important;z-index:0!important;pointer-events:none!important;background-image:linear-gradient(rgba(252,251,248,.86),rgba(252,251,248,.86)),url('/assets/img/bg-intro.png')!important;background-repeat:no-repeat,no-repeat!important;background-position:center center,center center!important;background-size:100% 100%,contain!important;filter:saturate(.62) contrast(.84) blur(.12px)!important;contain:paint!important;opacity:.22;transform:none}
@keyframes ngixFogDrift{0%,100%{transform:translate3d(0,0,0) scale(1.015);opacity:.22}50%{transform:translate3d(0.6%,-0.4%,0) scale(1.015);opacity:.26}}
@media (prefers-reduced-motion:no-preference){.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{animation:ngixFogDrift 28s ease-in-out infinite}}
.panel_m.panel>.panel-heading,.panel_m.panel>.panel-body,.panel_m.panel>.table-responsive,.panel_m.panel>form{position:relative!important;z-index:2!important}
.table-responsive{max-width:100%!important;overflow-x:auto!important;overflow-y:visible!important}
@supports (height:100lvh){body{min-height:100lvh!important}}
@media (prefers-color-scheme:dark){html{background:var(--graphite)!important}body{background:linear-gradient(rgba(37,42,46,.78),rgba(37,42,46,.88)),url('/assets/img/favicon.svg') right 14px bottom 12px/28px 28px no-repeat fixed,url('/assets/img/bg-intro.png') center center/cover no-repeat fixed,var(--graphite)!important}.panel_m.panel{background:rgba(37,42,46,.72)!important}.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{background-image:linear-gradient(rgba(37,42,46,.84),rgba(37,42,46,.84)),url('/assets/img/bg-intro.png')!important;filter:saturate(.58) contrast(.78) blur(.16px)!important;opacity:.20}}
@media screen and (max-width:768px){body{background-position:0 0,right 10px bottom 10px,center center!important;background-size:auto,24px 24px,cover!important}.navbar.navbar-fixed-top,.navbar-fixed-top{width:100%!important}.panel_m.panel>.ngix-image-backdrop,.ngix-image-backdrop{background-size:100% 100%,contain!important;background-position:center center,center center!important;opacity:.18}}

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
</body>
</html>