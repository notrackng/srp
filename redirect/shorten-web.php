<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';
require_once dirname(__DIR__) . '/login_throttle.php';

load_env_file(dirname(__DIR__) . '/.env');

// ── Security headers ──────────────────────────────────────────────────────────
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$isHttps = (
    (isset($_SERVER['HTTPS']) && is_string($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off')
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && is_string($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https')
    || (isset($_SERVER['SERVER_PORT']) && is_string($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443)
);

if ($isHttps) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// ── Session ───────────────────────────────────────────────────────────────────
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Strict');
if ($isHttps) {
    ini_set('session.cookie_secure', '1');
}
session_start();

// ── API key dari env ──────────────────────────────────────────────────────────
$apiKey = app_env('SRP_API_KEY', '') ?? '';

if ($apiKey === '') {
    http_response_code(500);
    exit('SRP_API_KEY tidak dikonfigurasi.');
}

// ── Resolve URL endpoint (self) ───────────────────────────────────────────────
$scheme   = $isHttps ? 'https' : 'http';
$host     = isset($_SERVER['HTTP_HOST']) && is_string($_SERVER['HTTP_HOST'])
    ? preg_replace('/[^a-zA-Z0-9.\-:]/', '', $_SERVER['HTTP_HOST'])
    : 'localhost';
$selfBase = $scheme . '://' . $host;
$apiUrl   = $selfBase . '/api/shorten';

// ── Auth sederhana: password = API key ───────────────────────────────────────
$isAuthed = isset($_SESSION['srp_web_authed']) && $_SESSION['srp_web_authed'] === true;

if (!$isAuthed) {
    // Per-IP throttle, same rationale/threshold as redirect/api/shorten.php's
    // Bearer-auth check: this password IS the SRP_API_KEY, so this login form
    // needs the same protection every other credential surface in the app has.
    $shortenWebAuthScope = 'shorten_web';

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['web_password'])) {
        $shortenWebAuthState = srp_login_throttle_state($shortenWebAuthScope);
        $shortenWebLocked = $shortenWebAuthState['fails'] >= 20
            && (time() - $shortenWebAuthState['last']) < 900;

        $entered = is_string($_POST['web_password']) ? $_POST['web_password'] : '';
        if (!$shortenWebLocked && hash_equals($apiKey, $entered)) {
            srp_login_throttle_reset($shortenWebAuthScope);
            session_regenerate_id(true);
            $_SESSION['srp_web_authed'] = true;
            $_SESSION['srp_csrf']       = bin2hex(random_bytes(32));
            header('Location: ' . $selfBase . '/shorten-web.php');
            exit;
        }

        if (!$shortenWebLocked) {
            srp_login_throttle_register_fail($shortenWebAuthScope);
        }

        srp_web_render_login($shortenWebLocked ? 'Terlalu banyak percobaan. Coba lagi nanti.' : 'Password salah.');
        exit;
    }

    srp_web_render_login('');
    exit;
}

// ── Init CSRF ─────────────────────────────────────────────────────────────────
if (empty($_SESSION['srp_csrf']) || !is_string($_SESSION['srp_csrf'])) {
    $_SESSION['srp_csrf'] = bin2hex(random_bytes(32));
}
$csrfToken = (string) $_SESSION['srp_csrf'];

// ── Handle form submission ────────────────────────────────────────────────────
$result  = null;
$errors  = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrf = isset($_POST['csrf_token']) && is_string($_POST['csrf_token'])
        ? $_POST['csrf_token'] : '';

    if (!hash_equals($csrfToken, $postedCsrf)) {
        $errors[] = 'Token CSRF tidak valid. Muat ulang halaman.';
    } else {
        $modeRaw = isset($_POST['mode']) && is_string($_POST['mode']) ? $_POST['mode'] : 'sub_id';
        $mode    = in_array($modeRaw, ['fields', 'url_mode'], true) ? $modeRaw : 'sub_id';

        if ($mode === 'url_mode') {
            $targetUrl = srp_web_str($_POST['target_url'] ?? null);
            if ($targetUrl === null) {
                $errors[] = 'URL tidak boleh kosong.';
            } elseif (filter_var($targetUrl, FILTER_VALIDATE_URL) === false) {
                $errors[] = 'URL tidak valid.';
            } else {
                $subId = srp_web_extract_sub_id_from_url($targetUrl);
                if ($subId === null) {
                    $errors[] = 'URL harus berisi sub_id valid pada path terakhir.';
                } else {
                    $result = srp_web_call_api($apiUrl, $apiKey, ['sub_id' => $subId]);
                }
            }
        } elseif ($mode === 'sub_id') {
            $subId = srp_web_str($_POST['sub_id'] ?? null);
            if ($subId === null) {
                $errors[] = 'sub_id tidak boleh kosong.';
            } elseif (preg_match('/^[A-Za-z0-9_-]{1,2048}$/', $subId) !== 1) {
                $errors[] = 'sub_id mengandung karakter tidak valid (harus base64url: A-Z a-z 0-9 _ -).';
            } else {
                $body = ['sub_id' => $subId];
            }
        } else {
            $clickId = srp_web_str($_POST['click_id'] ?? null);
            $userLp  = srp_web_str($_POST['user_lp'] ?? null);

            if ($clickId === null) {
                $errors[] = 'click_id tidak boleh kosong.';
            }

            if ($userLp === null) {
                $errors[] = 'user_lp tidak boleh kosong.';
            }

            if ($errors === []) {
                $body = [
                    'click_id' => $clickId,
                    'user_lp'  => $userLp,
                ];

                $canonicalUrl = srp_web_str($_POST['canonical_url'] ?? null);
                if ($canonicalUrl !== null) {
                    $body['canonical_url'] = $canonicalUrl;
                }

                $title = srp_web_str($_POST['title'] ?? null);
                if ($title !== null) {
                    $body['title'] = $title;
                }

                $imageUrl = srp_web_str($_POST['image_url'] ?? null);
                if ($imageUrl !== null) {
                    $body['image_url'] = $imageUrl;
                }

                $lg = srp_web_str($_POST['lg'] ?? null);
                if ($lg !== null) {
                    $body['lg'] = $lg;
                }
            }
        }

        if ($mode !== 'url_mode' && $errors === []) {
            $code = srp_web_str($_POST['code'] ?? null);
            if ($code !== null) {
                /** @var array<string, mixed> $body */
                $body['code'] = $code;
            }

            $baseUrl = srp_web_str($_POST['base_url'] ?? null);
            if ($baseUrl !== null) {
                /** @var array<string, mixed> $body */
                $body['base_url'] = $baseUrl;
            }

            /** @var array<string, mixed> $body */
            $result = srp_web_call_api($apiUrl, $apiKey, $body);
        }
    }
}

// ── Render ────────────────────────────────────────────────────────────────────
// Pre-extract result strings untuk template
$resultOk    = $result !== null && ($result['ok'] ?? false) === true;
$resultUrl   = $result !== null && is_string($result['url'] ?? null) ? (string) $result['url'] : '';
$resultCode  = $result !== null && is_string($result['code'] ?? null) ? (string) $result['code'] : '-';
$resultToken = $result !== null && is_string($result['token'] ?? null) ? (string) $result['token'] : '-';
$resultError = $result !== null && is_string($result['error'] ?? null) ? (string) $result['error'] : 'Unknown error';
/** @var array<string, string> $_POST */
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-{$nonce}'; script-src 'nonce-{$nonce}'; form-action 'self'; frame-ancestors 'none';");

?><!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shorten Link</title>
<style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
*, *::before, *::after {
    box-sizing: border-box;
}

:root{color-scheme: light;
    --bg: #f8fafd;
    --surface: #f0f3f8;
    --panel: rgba(255, 255, 255, .82);
    --panel-strong: #ffffff;
    --line: #e2e8f0;
    --line-soft: rgba(68, 71, 70, .08);
    --text: #444746;
    --muted: #6e7370;
    --strong: #1f2221;
    --accent: #444746;
    --accent-hover: #1f2221;
    --accent-soft: rgba(68, 71, 70, .10);
    --danger-bg: #fff7f7;
    --danger-line: #fecaca;
    --success-bg: #f8fbf8;
    --success-line: #cbd5cf;
    --radius: .3rem;
    --focus: 0 0 0 .18rem rgba(68, 71, 70, .14);--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px}

html {
    min-height: 100%;
    background: var(--bg);
}

body {
    min-height: 100vh;
    margin: 0;
    padding: 2rem 1rem;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    overflow-x: hidden;
    font-family:var(--font);
    color: var(--text);
    background:
        radial-gradient(circle at 50% 8%, rgba(255, 255, 255, .72), transparent 26rem),
        radial-gradient(circle at 12% 80%, rgba(68, 71, 70, .055), transparent 22rem),
        linear-gradient(180deg, rgba(248, 250, 253, .98), rgba(240, 243, 248, .96));
}

.card {
    width: 100%;
    max-width: 620px;
    padding: 1.35rem;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: none;
    backdrop-filter: blur(18px) saturate(1.08);
    -webkit-backdrop-filter: blur(18px) saturate(1.08);
}

h1 {
    margin: 0 0 1.25rem;
    color: var(--strong);
    font-size: 1.15rem;
    font-weight:var(--fw-bold);
    letter-spacing: -.02em;
}

label {
    display: block;
    margin-bottom: .35rem;
    color: var(--muted);
    font-size: .78rem;
    font-weight:var(--fw-semibold);
    letter-spacing: .01em;
}

input,
select,
textarea {
    width: 100%;
    min-height: 2.45rem;
    padding: .58rem .72rem;
    color: var(--text);
    background: rgba(255, 255, 255, .78);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    outline: none;
    transition: border-color .16s ease, box-shadow .16s ease, background-color .16s ease;
}

textarea {
    min-height: 4.5rem;
    resize: vertical;
}

input::placeholder,
textarea::placeholder {
    color: rgba(110, 115, 112, .72);
}

input:focus,
select:focus,
textarea:focus {
    background: var(--panel-strong);
    border-color: rgba(68, 71, 70, .44);
    box-shadow: var(--focus);
}

.field {
    margin-bottom: 1rem;
}

.row {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: .75rem;
}

.tabs {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: .45rem;
    margin-bottom: 1.15rem;
    padding: .28rem;
    background: rgba(240, 243, 248, .78);
    border: 1px solid var(--line-soft);
    border-radius: var(--radius);
}

.tab-btn {
    min-height: 2.25rem;
    padding: .48rem .58rem;
    color: var(--muted);
    background: transparent;
    border: 1px solid transparent;
    border-radius: var(--radius);
    font-size: .82rem;
    font-weight:var(--fw-bold);
    cursor: pointer;
    transition: color .16s ease, background-color .16s ease, border-color .16s ease;
}

.tab-btn:hover,
.tab-btn.active {
    color: var(--strong);
    background: var(--panel-strong);
    border-color: var(--line);
}

.section {
    display: none;
}

.section.show {
    display: block;
}

.btn {
    width: 100%;
    min-height: 2.55rem;
    margin-top: .45rem;
    padding: .68rem 1rem;
    color: #ffffff;
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: var(--radius);
    font-size: .92rem;
    font-weight:var(--fw-bold);
    cursor: pointer;
    transition: background-color .16s ease, border-color .16s ease, transform .16s ease;
}

.btn:hover {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
}

.btn:active {
    transform: translateY(1px);
}

.alert-err,
.alert-ok {
    margin-bottom: 1rem;
    padding: .78rem .9rem;
    border-radius: var(--radius);
    font-size: .86rem;
    line-height:var(--lh-normal);
}

.alert-err {
    color: #7f1d1d;
    background: var(--danger-bg);
    border: 1px solid var(--danger-line);
}

.alert-ok {
    color: var(--text);
    background: var(--success-bg);
    border: 1px solid var(--success-line);
}

.result-url {
    margin-top: .38rem;
    color: var(--strong);
    font-size: 1rem;
    font-weight:var(--fw-bold);
    word-break: break-all;
}

.result-link {
    color: inherit;
    text-decoration: none;
}

.result-link:hover {
    text-decoration: underline;
}

.meta {
    margin-top: .35rem;
    color: var(--muted);
    font-size: .78rem;
}

code {
    padding: .08rem .22rem;
    color: var(--strong);
    background: rgba(68, 71, 70, .08);
    border-radius: .22rem;
}

hr {
    margin: 1.15rem 0;
    border: 0;
    border-top: 1px solid var(--line);
}

@media (max-width: 640px) {
    body {
        padding: 1rem .75rem;
    }

    .card {
        padding: 1rem;
    }

    .row,
    .tabs {
        grid-template-columns: 1fr;
    }
}
</style>
</head>
<body>
<div class="card">
  <h1>Shorten Link</h1>

<?php if ($errors !== []) : ?>
  <div class="alert-err">
    <?php foreach ($errors as $e) : ?>
      <div><?= htmlspecialchars($e, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></div>
    <?php endforeach; ?>
  </div>
<?php endif; ?>

<?php if ($result !== null) : ?>
    <?php if ($resultOk) : ?>
    <div class="alert-ok">
      <div>Short link berhasil dibuat!</div>
      <div class="result-url">
        <a href="<?= htmlspecialchars($resultUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>"
           target="_blank" rel="noopener noreferrer" class="result-link">
          <?= htmlspecialchars($resultUrl !== '' ? $resultUrl : '-', ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>
        </a>
      </div>
      <div class="meta">Code: <strong><?= htmlspecialchars($resultCode, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></strong>
        &nbsp;|&nbsp; Token: <code><?= htmlspecialchars($resultToken, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></code>
      </div>
    </div>
    <?php else : ?>
    <div class="alert-err">
      Gagal: <?= htmlspecialchars($resultError, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>
    </div>
    <?php endif; ?>
<?php endif; ?>

  <form method="POST" action="">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">

    <div class="tabs">
      <button type="button" class="tab-btn active" data-tab="sub_id">Legacy sub_id</button>
      <button type="button" class="tab-btn" data-tab="fields">Fields manual</button>
      <button type="button" class="tab-btn" data-tab="url_mode">URL Langsung</button>
      <input type="hidden" name="mode" id="mode-input" value="sub_id">
    </div>

    <div class="section show" id="tab-sub_id">
      <div class="field">
        <label for="sub_id">sub_id (base64url token)</label>
        <textarea id="sub_id" name="sub_id" rows="3" maxlength="2048"
          placeholder="QXRzajgsU0lFTE9XLDE3NzU4OTc2MyxJTU9ORVRJWUVJVA"><?= htmlspecialchars((string) ($_POST['sub_id'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></textarea>
      </div>
    </div>

    <div class="section" id="tab-fields">
      <div class="row">
        <div class="field">
          <label for="click_id">click_id *</label>
          <input type="text" id="click_id" name="click_id" maxlength="256"
            value="<?= htmlspecialchars((string) ($_POST['click_id'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
        </div>
        <div class="field">
          <label for="user_lp">user_lp *</label>
          <input type="text" id="user_lp" name="user_lp" maxlength="64"
            value="<?= htmlspecialchars((string) ($_POST['user_lp'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
        </div>
      </div>
      <div class="field">
        <label for="canonical_url">canonical_url</label>
        <input type="url" id="canonical_url" name="canonical_url" maxlength="2048"
          value="<?= htmlspecialchars((string) ($_POST['canonical_url'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
      <div class="row">
        <div class="field">
          <label for="title">title</label>
          <input type="text" id="title" name="title" maxlength="512"
            value="<?= htmlspecialchars((string) ($_POST['title'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
        </div>
        <div class="field">
          <label for="lg">lg</label>
          <select id="lg" name="lg">
            <option value="">— pilih —</option>
            <option value="landing" <?= (($_POST['lg'] ?? '') === 'landing') ? 'selected' : '' ?>>landing</option>
            <option value="direct" <?= (($_POST['lg'] ?? '') === 'direct') ? 'selected' : '' ?>>direct</option>
          </select>
        </div>
      </div>
      <div class="field">
        <label for="image_url">image_url</label>
        <input type="url" id="image_url" name="image_url" maxlength="2048"
          value="<?= htmlspecialchars((string) ($_POST['image_url'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
    </div>

    <div class="section" id="tab-url_mode">
      <div class="field">
        <label for="target_url">URL target (sub_id di path)</label>
        <input type="url" id="target_url" name="target_url" maxlength="2048"
          placeholder="https://example.com/s-QXRzajgs..."
          value="<?= htmlspecialchars((string) ($_POST['target_url'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
    </div>

    <div id="optional-fields">
    <hr>

    <div class="row">
      <div class="field">
        <label for="code">code kustom (opsional)</label>
        <input type="text" id="code" name="code" maxlength="32" pattern="[A-Za-z0-9_\-]+"
          placeholder="slug-kustom"
          value="<?= htmlspecialchars((string) ($_POST['code'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
      <div class="field">
        <label for="base_url">base_url (opsional)</label>
        <input type="url" id="base_url" name="base_url" maxlength="256"
          placeholder="https://domain.tld"
          value="<?= htmlspecialchars((string) ($_POST['base_url'] ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
      </div>
    </div>
    </div><!-- /#optional-fields -->

    <button type="submit" class="btn">Buat Short Link</button>
  </form>
</div>

<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
(function () {
    var tabs = document.querySelectorAll('.tab-btn');
    var modeInput = document.getElementById('mode-input');
    var optFields = document.getElementById('optional-fields');

    function setOptional(tab) {
        if (optFields) { optFields.style.display = tab === 'url_mode' ? 'none' : ''; }
    }

    tabs.forEach(function (btn) {
        btn.addEventListener('click', function () {
            var tab = btn.getAttribute('data-tab');
            tabs.forEach(function (b) { b.classList.remove('active'); });
            btn.classList.add('active');
            document.querySelectorAll('.section').forEach(function (s) { s.classList.remove('show'); });
            var section = document.getElementById('tab-' + tab);
            if (section) { section.classList.add('show'); }
            if (modeInput) { modeInput.value = tab; }
            setOptional(tab);
        });
    });

    <?php if (($_POST['mode'] ?? 'sub_id') === 'fields') : ?>
    document.querySelector('[data-tab="fields"]').click();
    <?php elseif (($_POST['mode'] ?? 'sub_id') === 'url_mode') : ?>
    document.querySelector('[data-tab="url_mode"]').click();
    <?php endif; ?>
}());
</script>
</body>
</html>
<?php

// ── Fungsi helper ─────────────────────────────────────────────────────────────

/**
 * @param array<string, mixed> $body
 * @return array<string, mixed>
 */
function srp_web_call_api(string $apiUrl, string $apiKey, array $body): array
{
    $jsonBody = json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    if ($apiUrl === '') {
        return ['ok' => false, 'error' => 'API URL tidak dikonfigurasi.'];
    }

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => $apiUrl,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $jsonBody,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'Accept: application/json',
            'Authorization: Bearer ' . $apiKey,
        ],
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $raw      = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);

    if ($raw === false || $curlErr !== '') {
        return ['ok' => false, 'error' => 'cURL error: ' . $curlErr];
    }

    try {
        $decoded = json_decode((string) $raw, true, 8, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        return ['ok' => false, 'error' => 'Response bukan JSON valid (HTTP ' . $httpCode . ')'];
    }

    if (!is_array($decoded)) {
        return ['ok' => false, 'error' => 'Response tidak terduga (HTTP ' . $httpCode . ')'];
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
}

function srp_web_str(mixed $value): ?string
{
    if (!is_scalar($value)) {
        return null;
    }
    $value = trim((string) $value);

    return $value !== '' ? $value : null;
}

function srp_web_extract_sub_id_from_url(string $targetUrl): ?string
{
    $path = parse_url($targetUrl, PHP_URL_PATH);
    if (!is_string($path) || $path === '') {
        return null;
    }

    $segments = explode('/', trim($path, '/'));
    $lastSegment = end($segments);
    if (!is_string($lastSegment) || $lastSegment === '') {
        return null;
    }

    $subId = rawurldecode($lastSegment);

    return preg_match('/^[A-Za-z0-9_-]{1,2048}$/', $subId) === 1 ? $subId : null;
}

function srp_web_render_login(string $error): void
{
    $nonce = base64_encode(random_bytes(16));
    header("Content-Security-Policy: default-src 'none'; style-src 'nonce-{$nonce}'; form-action 'self'; frame-ancestors 'none';");
    ?><!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shorten Link — Login</title>
<style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?>">
*, *::before, *::after {
    box-sizing: border-box;
}

:root{color-scheme: light;
    --bg: #f8fafd;
    --surface: #f0f3f8;
    --panel: rgba(255, 255, 255, .84);
    --panel-strong: #ffffff;
    --line: #e2e8f0;
    --text: #444746;
    --muted: #6e7370;
    --strong: #1f2221;
    --accent: #444746;
    --accent-hover: #1f2221;
    --danger-bg: #fff7f7;
    --danger-line: #fecaca;
    --radius: .3rem;
    --focus: 0 0 0 .18rem rgba(68, 71, 70, .14);--btn-bg:#444746;--btn-fg:#fff;--btn-border:#444746;--fw-regular:400;--fw-medium:500;--fw-semibold:600;--fw-bold:700;--lh-tight:1.2;--lh-snug:1.35;--lh-normal:1.5;--lh-relaxed:1.7;--fs-xs:11px;--fs-sm:12px;--fs-base:13px;--fs-md:14px;--fs-lg:17px;--fs-xl:20px}

html {
    min-height: 100%;
    background: var(--bg);
}

body {
    min-height: 100vh;
    margin: 0;
    padding: 1rem;
    display: flex;
    align-items: center;
    justify-content: center;
    overflow-x: hidden;
    font-family:var(--font);
    color: var(--text);
    background:
        radial-gradient(circle at 50% 10%, rgba(255, 255, 255, .72), transparent 24rem),
        radial-gradient(circle at 12% 82%, rgba(68, 71, 70, .055), transparent 20rem),
        linear-gradient(180deg, rgba(248, 250, 253, .98), rgba(240, 243, 248, .96));
}

.card {
    width: 100%;
    max-width: 360px;
    padding: 1.25rem;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: none;
    backdrop-filter: blur(18px) saturate(1.08);
    -webkit-backdrop-filter: blur(18px) saturate(1.08);
}

h1 {
    margin: 0 0 1.15rem;
    color: var(--strong);
    font-size: 1.08rem;
    font-weight:var(--fw-bold);
    letter-spacing: -.02em;
}

label {
    display: block;
    margin-bottom: .35rem;
    color: var(--muted);
    font-size: .78rem;
    font-weight:var(--fw-semibold);
}

input[type=password] {
    width: 100%;
    min-height: 2.45rem;
    padding: .58rem .72rem;
    color: var(--text);
    background: rgba(255, 255, 255, .78);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    outline: none;
    transition: border-color .16s ease, box-shadow .16s ease, background-color .16s ease;
}

input[type=password]:focus {
    background: var(--panel-strong);
    border-color: rgba(68, 71, 70, .44);
    box-shadow: var(--focus);
}

.btn {
    width: 100%;
    min-height: 2.55rem;
    margin-top: 1rem;
    padding: .68rem 1rem;
    color: #ffffff;
    background: var(--accent);
    border: 1px solid var(--accent);
    border-radius: var(--radius);
    font-size: .92rem;
    font-weight:var(--fw-bold);
    cursor: pointer;
    transition: background-color .16s ease, border-color .16s ease, transform .16s ease;
}

.btn:hover {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
}

.btn:active {
    transform: translateY(1px);
}

.alert-err {
    margin-bottom: 1rem;
    padding: .72rem .85rem;
    color: #7f1d1d;
    background: var(--danger-bg);
    border: 1px solid var(--danger-line);
    border-radius: var(--radius);
    font-size: .86rem;
    line-height:var(--lh-normal);
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
</head>
<body>
<div class="card">
  <h1>Shorten Link</h1>
    <?php if ($error !== '') : ?>
    <div class="alert-err"><?= htmlspecialchars($error, ENT_QUOTES | ENT_HTML5, 'UTF-8') ?></div>
    <?php endif; ?>
  <form method="POST" action="">
    <div>
      <label for="web_password">Password (API Key)</label>
      <input type="password" id="web_password" name="web_password" autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn">Masuk</button>
  </form>
</div>
</body>
</html>
    <?php
}
