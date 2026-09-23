<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/env.php';

function statBasePath(): string
{
    static $basePath = null;

    if (is_string($basePath)) {
        return $basePath;
    }

    $scriptName = $_SERVER['SCRIPT_NAME'] ?? '';

    if (!is_string($scriptName)) {
        $basePath = '';
        return $basePath;
    }

    $scriptName = str_replace('\\', '/', $scriptName);

    if (
        $scriptName === ''
        || $scriptName[0] !== '/'
        || preg_match('/[\x00-\x1F\x7F]/', $scriptName) === 1
    ) {
        $basePath = '';
        return $basePath;
    }

    $dir = rtrim(str_replace('\\', '/', dirname($scriptName)), '/');

    if ($dir === '' || $dir === '.' || $dir === '/') {
        $basePath = '';
        return $basePath;
    }

    $sections = ['realtime', 'performance', 'clicks', 'postback'];

    foreach ($sections as $section) {
        $legacySuffix = '/statistics/' . $section;
        $directSuffix = '/' . $section;

        if (substr($dir, -strlen($legacySuffix)) === $legacySuffix) {
            $dir = substr($dir, 0, -strlen($legacySuffix));
            break;
        }

        if (substr($dir, -strlen($directSuffix)) === $directSuffix) {
            $dir = substr($dir, 0, -strlen($directSuffix));
            break;
        }
    }

    $dir = rtrim($dir, '/');

    if ($dir === '' || $dir === '.' || $dir === '/') {
        $basePath = '';
        return $basePath;
    }

    $basePath = $dir;

    return $basePath;
}

function statUrl(string $path): string
{
    $path = trim($path);

    if ($path === '') {
        return statBasePath() . '/';
    }

    if (!statIsSafeAppPath($path, true)) {
        return statBasePath() . '/';
    }

    if ($path[0] !== '/') {
        $path = '/' . $path;
    }

    return statBasePath() . $path;
}

function statAssetUrl(string $path): string
{
    $path = trim($path);

    if ($path === '') {
        return '';
    }

    if ($path[0] !== '/') {
        $path = '/' . $path;
    }

    if (!statIsSafeAppPath($path, false)) {
        return '';
    }

    if (preg_match('#\A/fonts/#', $path) === 1) {
        $path = '/assets/css/' . ltrim(substr($path, strlen('/fonts/')), '/');
    } elseif (preg_match('#\A/dist/#', $path) === 1) {
        $relative = ltrim(substr($path, strlen('/dist/')), '/');
        $lower = strtolower($relative);

        if (preg_match('/\.(css|eot|ttf|woff2?|otf)\z/', $lower) === 1) {
            $path = '/assets/css/' . $relative;
        } elseif (preg_match('/\.(js|mjs)\z/', $lower) === 1) {
            $path = '/assets/js/' . $relative;
        } else {
            $path = '/assets/img/' . $relative;
        }
    }

    if (
        !preg_match('#\A/assets/(css|js|img)/[A-Za-z0-9._/-]+\z#', $path)
        && !in_array($path, ['/favicon.ico', '/robots.txt'], true)
    ) {
        return '';
    }

    $url = statUrl($path);

    // Cache-bust after validation, never before: the check above rejects a '?',
    // so the stamp cannot be part of the validated path. .htaccess caches
    // /assets/* for 30 days, so without this an edited file would stay stale.
    // Stamp the file the web server actually serves. statistics/ now carries its
    // own assets/ tree, so on the s. host `/assets/...` resolves under this
    // module while dirname(__DIR__) is the project root; stamping the root copy
    // would hide edits to the served one behind the 30-day cache. Falls back to
    // the shared tree for single-docroot mode and CLI.
    $relative = str_replace('/', DIRECTORY_SEPARATOR, $path);
    $docRoot = (string) ($_SERVER['DOCUMENT_ROOT'] ?? '');

    $file = $docRoot !== '' ? rtrim($docRoot, '/\\') . $relative : __DIR__ . $relative;

    if (!is_file($file)) {
        $file = __DIR__ . $relative;
    }

    if (!is_file($file)) {
        $file = dirname(__DIR__) . $relative;
    }

    $mtime = is_file($file) ? filemtime($file) : false;

    return $mtime !== false ? $url . '?v=' . $mtime : $url;
}

function statH(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Country codes that have a `.flag-xx` rule in assets/css/flags.css (the
 * responsive sprite backed by assets/img/flags/flags_responsive.png).
 *
 * The sprite positions every flag with a background-position percentage, so a
 * code that has no rule of its own keeps `background-position: 0 0` and renders
 * the WRONG country instead of nothing. Callers must therefore check the code
 * against this list and fall back to a neutral placeholder when it is missing.
 */
function statFlagSpriteCodeList(): string
{
    return 'ad ae af ag ai al am an ao aq ar as at au aw az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bv bw by bz'
        . ' ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm'
        . ' fo fr ga gb gd ge gf gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il in io iq ir is it'
        . ' jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn'
        . ' mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr'
        . ' pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sy sz tc td tf tg th tj'
        . ' tk tl tm tn to tp tr tt tv tw ty tz ua ug uk um us uy uz va vc ve vg vi vn vu wf ws ye za zm zr zw';
}

/**
 * Normalise a country code to the `.flag-xx` sprite class suffix.
 *
 * Returns '' when the value is not a two-letter code or has no sprite entry, so
 * the caller can render a neutral box instead of a misleading flag.
 */
function statFlagSpriteCode(string $value): string
{
    $code = strtolower(trim($value));

    if (preg_match('/\A[a-z]{2}\z/', $code) !== 1) {
        return '';
    }

    return str_contains(' ' . statFlagSpriteCodeList() . ' ', ' ' . $code . ' ') ? $code : '';
}

/**
 * Device icon for a traffic/user-agent label (WAP, WEB, TABLET and aliases).
 *
 * Inlined rather than served from /assets/img: the clicks and realtime grids
 * draw one per row, and `stroke="currentColor"` lets the glyph follow the
 * table's text colour instead of being baked to a fixed grey.
 *
 * Returns '' for an unmapped label so the caller can fall back to plain text.
 */
function statDeviceIconHtml(string $label, string $class): string
{
    // All three share one viewBox/stroke language, so no per-glyph transform
    // is needed to equalise their box size (unlike the old filled-path set).
    $icons = [
        'WAP'     => [
            'name' => 'mobile',
            'body' => '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M10 5h4"/>'
                . '<circle cx="12" cy="19" r=".75" fill="currentColor" stroke="none"/>',
        ],
        'MOBILE'  => [
            'name' => 'mobile',
            'body' => '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M10 5h4"/>'
                . '<circle cx="12" cy="19" r=".75" fill="currentColor" stroke="none"/>',
        ],
        'WEB'     => [
            'name' => 'desktop',
            'body' => '<rect x="2" y="2" width="20" height="16" rx="2"/><path d="M1 22h22"/>',
        ],
        'DESKTOP' => [
            'name' => 'desktop',
            'body' => '<rect x="2" y="2" width="20" height="16" rx="2"/><path d="M1 22h22"/>',
        ],
        'TABLET'  => [
            'name' => 'tablet',
            'body' => '<rect x="4" y="2" width="16" height="20" rx="2"/>'
                . '<circle cx="12" cy="19" r=".75" fill="currentColor" stroke="none"/>',
        ],
    ];

    $key = strtoupper(trim($label));

    if (!isset($icons[$key])) {
        return '';
    }

    $icon = $icons[$key];

    // The grid renders this icon as the ONLY representation of the device
    // (no text label next to it), so role/aria-label/title are kept — do not
    // switch to aria-hidden here. 14x14 keeps it the same render size as the
    // flag icons next to it in the same grid.
    return '<svg class="' . statH($class) . '" width="14" height="14" viewBox="0 0 24 24"'
        . ' data-icon="' . $icon['name'] . '" fill="none" stroke="currentColor" stroke-width="2"'
        . ' stroke-linecap="round" stroke-linejoin="round"'
        . ' xmlns="http://www.w3.org/2000/svg" role="img" aria-label="' . statH($key) . '">'
        . '<title>' . statH($key) . '</title>'
        . $icon['body']
        . '</svg>';
}

/**
 * Per-tracker data scope for the statistics module.
 *
 * Returns the UPPERCASE sub_id the current session is limited to, or null for
 * the global admin view (admin logs in with the REPASS/A2ROOT password and no
 * sub_id — see statistics/login.php).
 *
 * Statistics read queries MUST append `AND click_id = :scope` (binding
 * :scope => this value) whenever it is non-null: both clickrecord.click_id and
 * leadreport.click_id store UPPER(generate.sub_id), so this is the per-tracker
 * partition key. Admin (null) sees every tracker's rows unfiltered.
 */
function stat_scope_sub_id(): ?string
{
    $sub = $_SESSION['stat_sub_id'] ?? null;

    return is_string($sub) && $sub !== '' ? $sub : null;
}

/**
 * Is one click-log row visible to the current statistics session?
 *
 * The daily click log ({project_root}/statistics/temp/YYYY-MM-DD.json, written
 * by redirect/_meetups/clicks.php) is a SINGLE file shared by every tracker, so
 * it needs the same per-tracker partition the SQL readers apply through
 * `AND click_id = :scope`. It was previously read unfiltered, which let a
 * tracker-scoped session read every other tracker's click ids and visitor IP
 * addresses through /clicks/ and /realtime/json.parse.php.
 *
 * The writer stores click_id lowercased while stat_scope_sub_id() is uppercase,
 * hence the case-insensitive compare. Admin sessions (null scope) see all rows,
 * matching the SQL readers.
 */
function stat_click_log_row_in_scope(mixed $row): bool
{
    $scope = stat_scope_sub_id();

    if ($scope === null) {
        return true;
    }

    if (!is_array($row)) {
        return false;
    }

    $clickId = $row['click_id'] ?? null;

    if (!is_scalar($clickId)) {
        return false;
    }

    return strcasecmp(trim((string) $clickId), $scope) === 0;
}

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function statIsHttpsRequest(): bool
{
    return srp_request_is_https();
}

function statIsSafeAppPath(string $path, bool $allowQueryString): bool
{
    if ($path === '') {
        return false;
    }

    if (preg_match('/[\x00-\x1F\x7F]/', $path) === 1) {
        return false;
    }

    if (str_contains($path, '\\')) {
        return false;
    }

    if (str_contains($path, '://') || str_starts_with($path, '//')) {
        return false;
    }

    if (!$allowQueryString && (str_contains($path, '?') || str_contains($path, '#'))) {
        return false;
    }

    $pathOnly = $path;
    $queryPos = strpos($pathOnly, '?');

    if ($queryPos !== false) {
        if (!$allowQueryString) {
            return false;
        }

        $pathOnly = substr($pathOnly, 0, $queryPos);
    }

    $fragmentPos = strpos($pathOnly, '#');

    if ($fragmentPos !== false) {
        return false;
    }

    if ($pathOnly === '') {
        return false;
    }

    if ($pathOnly[0] !== '/') {
        $pathOnly = '/' . $pathOnly;
    }

    if (str_contains($pathOnly, '//')) {
        return false;
    }

    $segments = explode('/', $pathOnly);

    foreach ($segments as $segment) {
        if ($segment === '..') {
            return false;
        }

        if (preg_match('/%2e|%2f|%5c/i', $segment) === 1) {
            return false;
        }
    }

    return true;
}
