<?php

declare(strict_types=1);

if (!function_exists('load_env_file')) {
    function load_env_file(string $filePath): void
    {
        /** @var array<string, true> $loadedFiles */
        static $loadedFiles = [];

        $realPath = realpath($filePath);
        if ($realPath === false) {
            return;
        }

        if (isset($loadedFiles[$realPath])) {
            return;
        }

        if (!is_readable($realPath)) {
            return;
        }

        $lines = file($realPath, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return;
        }

        foreach ($lines as $line) {
            load_env_line($line);
        }

        $loadedFiles[$realPath] = true;
    }
}

if (!function_exists('load_env_line')) {
    function load_env_line(string $line): void
    {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            return;
        }

        if (str_starts_with($line, 'export ')) {
            $line = ltrim(substr($line, 7));
        }

        $separatorPosition = strpos($line, '=');
        if ($separatorPosition === false) {
            return;
        }

        $name = trim(substr($line, 0, $separatorPosition));
        if ($name === '' || preg_match('/^[A-Z0-9_]+$/', $name) !== 1) {
            return;
        }

        if (getenv($name) !== false || isset($_ENV[$name]) || isset($_SERVER[$name])) {
            return;
        }

        $value = load_env_normalize_value(substr($line, $separatorPosition + 1));

        // Auto-migrate: SRP_REPORT_DIR is no longer used — click log path is
        // hardcoded to statistics/temp/. Skip any domain-style value (e.g.
        // "report.hrhgrhg.cyou") so it is never set in the environment.
        if ($name === 'SRP_REPORT_DIR' && str_contains($value, '.')) {
            return;
        }

        putenv($name . '=' . $value);
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
}

if (!function_exists('load_env_normalize_value')) {
    function load_env_normalize_value(string $value): string
    {
        $value = trim($value);
        $length = strlen($value);

        if ($length >= 2) {
            $firstCharacter = $value[0];
            $lastCharacter = $value[$length - 1];

            if (
                ($firstCharacter === '"' && $lastCharacter === '"')
                || ($firstCharacter === '\'' && $lastCharacter === '\'')
            ) {
                $value = substr($value, 1, -1);

                if ($firstCharacter === '"') {
                    $value = strtr(
                        $value,
                        [
                            '\\n' => "\n",
                            '\\r' => "\r",
                            '\\t' => "\t",
                            '\\\\' => '\\',
                            '\\"' => '"',
                        ],
                    );
                }

                return $value;
            }
        }

        $commentPosition = strpos($value, ' #');

        if ($commentPosition !== false) {
            $value = rtrim(substr($value, 0, $commentPosition));
        }

        return $value;
    }
}

if (!function_exists('app_env')) {
    function app_env(string $key, ?string $default = null): ?string
    {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);
        if ($value === false || $value === null || $value === '') {
            return $default;
        }

        return is_string($value) ? $value : (string) $value;
    }
}

if (!function_exists('app_required_env')) {
    function app_required_env(string $key): string
    {
        $value = app_env($key);
        if ($value === null || $value === '') {
            throw new RuntimeException('Missing required environment variable: ' . $key);
        }

        return $value;
    }
}

if (!function_exists('app_normalize_cpanel_host')) {
    function app_normalize_cpanel_host(string $host): string
    {
        $host = trim($host);
        if ($host === '') {
            return '';
        }

        $host = preg_replace('#^https?://#i', '', $host) ?? $host;
        $host = explode('/', $host, 2)[0];
        $host = trim($host, " \t\n\r\0\x0B.");

        if (str_contains($host, ':') && substr_count($host, ':') === 1) {
            [$hostPart] = explode(':', $host, 2);
            $host = trim($hostPart);
        }

        if ($host === '') {
            return '';
        }

        if (preg_match('/[\/\\\\@?#\[\]]/', $host) === 1) {
            return '';
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $host;
        }

        $host = strtolower($host);
        if (strlen($host) > 253) {
            return '';
        }

        $hostPattern = '/^(?=.{1,253}$)(?!-)'
            . '(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
            . '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/';

        if (preg_match($hostPattern, $host) !== 1) {
            return '';
        }

        return $host;
    }
}

if (!function_exists('app_is_public_cpanel_host')) {
    function app_is_public_cpanel_host(string $host): bool
    {
        $host = app_normalize_cpanel_host($host);
        if ($host === '') {
            return false;
        }

        if (preg_match('/^(localhost|localdomain)$/i', $host) === 1) {
            return false;
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return filter_var(
                $host,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            ) !== false;
        }

        return str_contains($host, '.');
    }
}

if (!function_exists('app_detect_cpanel_host')) {
    function app_detect_cpanel_host(?string $configuredHost = null, int $port = 2083): string
    {
        $configured = app_normalize_cpanel_host((string) ($configuredHost ?? app_env('CPANEL_HOST', '')));
        if (app_is_public_cpanel_host($configured)) {
            return $configured;
        }

        $candidates = [];
        foreach (
            [
                $_SERVER['SERVER_NAME'] ?? '',
                $_SERVER['HTTP_HOST'] ?? '',
                gethostname() ?: '',
                php_uname('n') ?: '',
            ] as $candidate
        ) {
            $normalized = app_normalize_cpanel_host((string) $candidate);
            if (app_is_public_cpanel_host($normalized)) {
                $candidates[] = $normalized;
            }
        }

        $serverAddress = $_SERVER['SERVER_ADDR'] ?? '';
        $serverAddressIsPublic = is_string($serverAddress)
            && filter_var(
                $serverAddress,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
            ) !== false;

        if ($serverAddressIsPublic) {
            $reverse = gethostbyaddr($serverAddress);
            if (is_string($reverse) && $reverse !== $serverAddress) {
                $normalized = app_normalize_cpanel_host($reverse);
                if (app_is_public_cpanel_host($normalized)) {
                    $candidates[] = $normalized;
                }
            }
        }

        foreach (array_values(array_unique($candidates)) as $candidate) {
            if (app_cpanel_host_responds($candidate, $port)) {
                return $candidate;
            }
        }

        return $candidates[0] ?? ($configured !== '' ? $configured : 'localhost');
    }
}

if (!function_exists('app_cpanel_host_responds')) {
    function app_cpanel_host_responds(string $host, int $port = 2083): bool
    {
        $host = app_normalize_cpanel_host($host);
        if (!app_is_public_cpanel_host($host)) {
            return false;
        }

        $port = $port >= 1 && $port <= 65535 ? $port : 2083;

        if (extension_loaded('curl')) {
            $ch = curl_init('https://' . $host . ':' . $port . '/');
            if ($ch === false) {
                return false;
            }

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_NOBODY => true,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_TIMEOUT => 4,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            curl_exec($ch);
            $errno = curl_errno($ch);
            $httpCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);

            return $errno === 0 && $httpCode > 0;
        }

        $socket = @fsockopen('ssl://' . $host, $port, $errno, $error, 2.0);
        if (is_resource($socket)) {
            fclose($socket);

            return true;
        }

        return false;
    }
}

if (!function_exists('srp_detect_home_dir')) {
    /**
     * Absolute home directory of the cPanel account this deployment runs under.
     *
     * The canonical detector for the whole codebase: installer_lib.php delegates
     * here, and rotate-logs.sh mirrors the same rule in bash. Order matters —
     * the docroot's own location is the most trustworthy signal on cPanel
     * (accounts always live under /home<n>/<user>/), and unlike $HOME or posix_*
     * it stays correct when PHP runs as a different user than the account owner,
     * or under cron with a stripped environment.
     */
    function srp_detect_home_dir(): ?string
    {
        // 1. Derive from this file's own path. /home2/, /home3/ … are common on
        //    larger shared boxes, hence \d* rather than a bare /home/.
        $dir = str_replace('\\', '/', __DIR__);
        if (preg_match('#^(/home\d*/[^/]+)(?:/|$)#', $dir, $m) === 1 && @is_dir($m[1])) {
            return $m[1];
        }

        // 2. The account the PHP process actually belongs to.
        if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
            $pw = @posix_getpwuid(posix_geteuid());
            if (is_array($pw) && isset($pw['dir']) && is_string($pw['dir']) && @is_dir($pw['dir'])) {
                return rtrim(str_replace('\\', '/', $pw['dir']), '/');
            }
        }

        // 3. Environment, when the SAPI passes one through.
        $home = getenv('HOME');
        if (is_string($home) && $home !== '' && @is_dir($home)) {
            return rtrim(str_replace('\\', '/', $home), '/');
        }

        return null;
    }
}

if (!function_exists('srp_detect_error_log_path')) {
    /** Absolute path of this account's shared PHP error log, or null off cPanel. */
    function srp_detect_error_log_path(): ?string
    {
        $home = srp_detect_home_dir();

        if ($home === null) {
            return null;
        }

        $path = $home . '/logs/php.error.log';

        // A quote or newline would corrupt the INI/Apache line this same path is
        // written into by the installer; no real cPanel home contains one.
        return preg_match('/["\r\n]/', $path) === 1 ? null : $path;
    }
}

if (!function_exists('srp_configure_error_log')) {
    /**
     * Point error_log at this account's log, at runtime.
     *
     * Why this exists: .user.ini and .htaccess both hardcode an absolute path,
     * and neither format expands variables — so a tree copied between accounts
     * keeps pointing at the previous owner's home. PHP then silently falls back
     * to the server-wide log, which looks like "logging works" while
     * ~/logs/php.error.log stays empty and rotate-logs.sh finds nothing.
     * ini_set() is PHP_INI_ALL for error_log, so this wins over both files.
     *
     * A configuration that actually works is left alone: only an empty or
     * unusable setting (missing directory — exactly what a stale username
     * produces) gets replaced. That keeps a deliberate operator override
     * intact while still repairing the copied-tree case.
     *
     * Startup and parse errors raised before this file is included still go to
     * the previous target; those are the only ones this cannot catch.
     */
    function srp_configure_error_log(): void
    {
        static $done = false;

        if ($done) {
            return;
        }

        $done = true;

        $current = trim((string) ini_get('error_log'));

        if ($current !== '' && strtolower($current) !== 'syslog') {
            $dir = dirname($current);
            if (@is_dir($dir) && @is_writable($dir)) {
                return;
            }
        }

        $path = srp_detect_error_log_path();

        if ($path === null || !@is_dir(dirname($path)) || !@is_writable(dirname($path))) {
            return;
        }

        @ini_set('error_log', $path);
    }
}

if (!function_exists('srp_request_is_https')) {
    /**
     * Is this request HTTPS from the visitor's point of view?
     *
     * The canonical detector for the whole codebase. Every module-local helper
     * (ecHttps, ins_is_https, adminIsHttpsRequest, statIsHttpsRequest, rdHttps,
     * srp_is_https, …) delegates here so there is one rule instead of sixteen
     * copies that drift apart.
     *
     * They did drift: an audit found five copies that never checked the
     * Cloudflare headers, so on a Cloudflare deployment — where the origin
     * usually speaks plain HTTP and $_SERVER['HTTPS'] is unset — those callers
     * concluded "not HTTPS" and dropped the Secure flag from their session
     * cookies. Three of the five guarded admin/user portal sessions.
     *
     * Order is cheapest-first, and SERVER_PORT stays last: behind a proxy it
     * describes the origin hop, not the browser's connection.
     */
    function srp_request_is_https(): bool
    {
        $https = $_SERVER['HTTPS'] ?? null;
        if (is_string($https) && $https !== '' && strtolower($https) !== 'off') {
            return true;
        }

        $forwardedProto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null;
        if (is_string($forwardedProto) && strtolower($forwardedProto) === 'https') {
            return true;
        }

        $cfVisitor = $_SERVER['HTTP_CF_VISITOR'] ?? null;
        if (is_string($cfVisitor) && str_contains(strtolower($cfVisitor), '"scheme":"https"')) {
            return true;
        }

        $serverPort = $_SERVER['SERVER_PORT'] ?? null;

        return (is_numeric($serverPort) ? (int) $serverPort : 0) === 443;
    }
}

if (!function_exists('srp_url_host_allowed')) {
    /**
     * Whether a URL's host is permitted by the optional SRP_OFFER_ALLOWED_DOMAINS
     * allowlist (comma-separated domains). Empty/missing allowlist = allow all,
     * preserving existing behaviour until the operator opts in. Matches the
     * exact domain and any of its subdomains.
     */
    function srp_url_host_allowed(string $url): bool
    {
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));
        if ($host === '') {
            return false;
        }

        $raw = trim((string) app_env('SRP_OFFER_ALLOWED_DOMAINS', ''));
        if ($raw === '') {
            return true;
        }

        foreach (explode(',', $raw) as $domain) {
            $domain = strtolower(trim($domain));
            if ($domain === '') {
                continue;
            }
            if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                return true;
            }
        }

        return false;
    }
}

if (!function_exists('srp_url_is_self')) {
    /**
     * Whether a URL points back at the current request host. Used to guard
     * SRP_FILTER_URL / SRP_BLOCK_URL against being set to the redirect domain
     * itself, which would create a redirect loop. www-insensitive exact match.
     */
    function srp_url_is_self(string $url): bool
    {
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));
        if ($host === '') {
            return false;
        }
        $host = preg_replace('/^www\./', '', $host) ?? $host;

        $self = isset($_SERVER['HTTP_HOST']) && is_string($_SERVER['HTTP_HOST'])
            ? strtolower(trim($_SERVER['HTTP_HOST']))
            : '';
        $self = preg_replace('/:\d+$/', '', $self) ?? $self;
        $self = preg_replace('/^www\./', '', $self) ?? $self;
        $self = trim($self, '.');

        return $self !== '' && $host === $self;
    }
}

// Configure logging as early as possible: env.php is the first thing every
// entry point requires, so this runs before any application code can emit
// a warning that would otherwise land in the wrong file.
srp_configure_error_log();
