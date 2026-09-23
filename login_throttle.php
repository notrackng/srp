<?php

/**
 * Per-IP login throttle (file-based) shared by the admin panel and the .env
 * editor. Complements the existing per-session counters so that dropping the
 * session cookie no longer resets the failure count. Fails open on any I/O
 * error (never locks out legitimately or crashes the login flow).
 */

declare(strict_types=1);

require_once __DIR__ . '/ip_address.php';

if (!function_exists('srp_login_throttle_file')) {
    function srp_login_throttle_file(string $scope): ?string
    {
        $ip = getUserIP();

        // Fallback: getUserIP() returns '' only when no valid IP literal could
        // be extracted at all (malformed/absent REMOTE_ADDR). Without this, the
        // per-IP throttle silently no-ops for every such request, leaving login
        // brute-force protection to the per-session counter alone — which an
        // attacker defeats simply by dropping cookies between attempts. Raw
        // REMOTE_ADDR is the actual TCP peer and cannot be spoofed via headers,
        // so it still identifies a source even when not a validated IP literal.
        if ($ip === '') {
            $ip = isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR'])
                ? trim($_SERVER['REMOTE_ADDR'])
                : '';
        }

        if ($ip === '') {
            return null;
        }

        $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'srp_bb';
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            return null;
        }

        return $dir . DIRECTORY_SEPARATOR . 'lf_' . md5($scope . '|' . $ip) . '.json';
    }
}

if (!function_exists('srp_login_throttle_state')) {
    /**
     * @return array{fails:int,last:int}
     */
    function srp_login_throttle_state(string $scope, int $windowSeconds = 3600): array
    {
        $file = srp_login_throttle_file($scope);
        if ($file === null || !is_file($file)) {
            return ['fails' => 0, 'last' => 0];
        }

        $data = json_decode((string) @file_get_contents($file), true);
        if (!is_array($data) || !isset($data['c'], $data['t'])) {
            return ['fails' => 0, 'last' => 0];
        }

        $last = (int) $data['t'];
        if ((time() - $last) > $windowSeconds) {
            return ['fails' => 0, 'last' => 0];
        }

        return ['fails' => (int) $data['c'], 'last' => $last];
    }
}

if (!function_exists('srp_login_throttle_register_fail')) {
    function srp_login_throttle_register_fail(string $scope): void
    {
        $file = srp_login_throttle_file($scope);
        if ($file === null) {
            return;
        }

        // Read-modify-write under exclusive lock to prevent TOCTOU race
        // between concurrent login failures (same as rate limiter pattern).
        // Fail-open: if the file can't be opened or locked, skip silently.
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return;
        }

        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            return;
        }

        $raw    = (string) stream_get_contents($fp, 128, 0);
        $data   = $raw !== '' ? json_decode($raw, true) : null;
        $count  = 1;

        if (is_array($data) && isset($data['c']) && is_numeric($data['c'])) {
            $count = (int) $data['c'] + 1;
        }

        rewind($fp);
        ftruncate($fp, 0);
        fwrite($fp, (string) json_encode(['c' => $count, 't' => time()]));
        fflush($fp);

        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

if (!function_exists('srp_login_throttle_reset')) {
    function srp_login_throttle_reset(string $scope): void
    {
        $file = srp_login_throttle_file($scope);
        if ($file !== null && is_file($file)) {
            @unlink($file);
        }
    }
}

if (!function_exists('srp_login_lockout_seconds')) {
    /**
     * Canonical login-lockout ladder, shared by every password surface so the
     * policy lives in one place instead of a ternary copied per entry point.
     *
     *   >= 10 failures -> 1800s (30 min)
     *   >=  5 failures ->  900s (15 min)
     *   otherwise      ->    0s (not locked)
     *
     * @param int $fails Failure count for the scope (per-IP or per-session).
     * @return int Lock duration in seconds (0 = not locked).
     */
    function srp_login_lockout_seconds(int $fails): int
    {
        if ($fails >= 10) {
            return 1800;
        }

        if ($fails >= 5) {
            return 900;
        }

        return 0;
    }
}
