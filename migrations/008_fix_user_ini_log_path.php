<?php

declare(strict_types=1);

/**
 * Migration 008 — point every error_log directive at this account's real log.
 *
 * Two sets of files carry the path, in two syntaxes:
 *
 *   .user.ini   error_log = "/home/username/logs/php.error.log"
 *   .htaccess   php_value error_log "/home/username/logs/php.error.log"
 *               (inside the cPanel-generated php8_module / lsapi_module blocks)
 *
 * `username` is a literal placeholder — neither format performs variable
 * expansion, so the path can never resolve itself and has to be written in with
 * this account's name. PHP silently falls back to the server-wide log when the
 * path is unwritable, so the symptom is not an error: it is an empty
 * ~/logs/php.error.log and a rotate-logs.sh that finds nothing.
 *
 * env.php's srp_configure_error_log() already repairs this at runtime on every
 * request. This migration makes the files themselves correct as well, so the
 * startup errors raised before env.php loads also land in the right place.
 *
 * A fresh install no longer needs this: the installer that wrote user.ini at
 * install time has been removed, so this migration stands alone. It inlines the
 * two small helpers it used to take from installer_lib.php and calls
 * srp_detect_error_log_path() (env.php) directly.
 *
 * Idempotent: rewrites only files whose error_log line differs from the
 * detected path, and reports "already correct" otherwise. Only the error_log
 * line is touched — display_errors, log_errors and any operator additions are
 * preserved byte-for-byte.
 *
 * Usage:  php migrations/008_fix_user_ini_log_path.php [--dry-run]
 *
 * Note: LiteSpeed/PHP-FPM cache .user.ini for user_ini.cache_ttl seconds (300
 * by default), so the change can take up to five minutes to take effect.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("CLI only.\n");
}

$dryRun = in_array('--dry-run', $argv, true);
$root = dirname(__DIR__);

require_once $root . '/env.php';

/**
 * Files that can carry an error_log directive, and the syntax each one uses.
 *
 * @return array<string, 'ini'|'htaccess'>
 */
function mig008_error_log_files(): array
{
    return [
        '.user.ini' => 'ini',
        'public/.user.ini' => 'ini',
        'redirect/.user.ini' => 'ini',
        'statistics/.user.ini' => 'ini',
        '.htaccess' => 'htaccess',
        'public/.htaccess' => 'htaccess',
        'redirect/.htaccess' => 'htaccess',
        'statistics/.htaccess' => 'htaccess',
    ];
}

/**
 * Rewrite every error_log path in one file.
 *
 * @param string $syntax 'ini' (error_log = "...") or 'htaccess' (php_value error_log "...")
 * @return string 'updated' | 'unchanged' | 'absent' | 'failed'
 */
function mig008_rewrite_error_log(string $file, string $syntax, string $logPath): string
{
    if (!is_file($file)) {
        return 'absent';
    }

    $current = @file_get_contents($file);

    if (!is_string($current)) {
        return 'failed';
    }

    if ($syntax === 'htaccess') {
        // Replace only. NEVER append: php_value is a mod_php/LSAPI directive, and
        // adding it where neither module is loaded makes Apache refuse the whole
        // .htaccess with a 500 on every request.
        $updated = preg_replace(
            '/^([ \t]*)php_value[ \t]+error_log[ \t]+\S.*$/m',
            '${1}php_value error_log "' . $logPath . '"',
            $current,
            -1,
            $count,
        );
    } else {
        $updated = preg_replace(
            '/^[ \t]*error_log[ \t]*=.*$/m',
            'error_log = "' . $logPath . '"',
            $current,
            -1,
            $count,
        );

        // A .user.ini with no error_log line at all is safe to extend.
        if (is_string($updated) && $count === 0) {
            $updated = rtrim($current, "\r\n") . "\n" . 'error_log = "' . $logPath . '"' . "\n";
            $count = 1;
        }
    }

    if (!is_string($updated)) {
        return 'failed';
    }

    if ($count === 0) {
        return 'absent';
    }

    if ($updated === $current) {
        return 'unchanged';
    }

    return @file_put_contents($file, $updated, LOCK_EX) === false ? 'failed' : 'updated';
}

$logPath = srp_detect_error_log_path();

if ($logPath === null) {
    fwrite(STDERR, "Could not determine this account's home directory.\n");
    fwrite(STDERR, "Not a /home/<user>/ layout? Edit the error_log line in the .user.ini files by hand.\n");
    exit(1);
}

echo 'Detected error log path: ' . $logPath . PHP_EOL;

$logDir = dirname($logPath);
if (!is_dir($logDir)) {
    echo '  logs directory missing: ' . $logDir . ($dryRun ? " (would create)\n" : "\n");
    if (!$dryRun && !@mkdir($logDir, 0700, true) && !is_dir($logDir)) {
        fwrite(STDERR, '  WARNING: could not create ' . $logDir . PHP_EOL);
    }
}

echo PHP_EOL;

$changed = 0;
$failed = 0;

foreach (mig008_error_log_files() as $relative => $syntax) {
    $file = $root . '/' . $relative;

    if (!is_file($file)) {
        printf("  %-24s missing, skipped\n", $relative);
        continue;
    }

    if ($dryRun) {
        // Same rewrite the real run performs, against a scratch copy, so the
        // preview can never diverge from what applying would actually do.
        $temp = tempnam(sys_get_temp_dir(), 'srpini');

        if ($temp === false || @copy($file, $temp) === false) {
            printf("  %-24s cannot preview\n", $relative);
            $failed++;
            continue;
        }

        $outcome = mig008_rewrite_error_log($temp, $syntax, $logPath);
        @unlink($temp);
    } else {
        $outcome = mig008_rewrite_error_log($file, $syntax, $logPath);
    }

    switch ($outcome) {
        case 'updated':
            printf("  %-24s %s\n", $relative, $dryRun ? 'would update' : 'updated');
            $changed++;
            break;
        case 'unchanged':
            printf("  %-24s already correct\n", $relative);
            break;
        case 'absent':
            // A .htaccess with no php_value block is normal — public/ and
            // statistics/ ship without one, and the directive is never added
            // where it does not already exist (it 500s without mod_php/LSAPI).
            printf("  %-24s no error_log directive, skipped\n", $relative);
            break;
        default:
            printf("  %-24s FAILED (not writable?)\n", $relative);
            $failed++;
    }
}

echo PHP_EOL;

if ($dryRun) {
    echo 'Dry run: ' . $changed . ' file(s) would change. Re-run without --dry-run to apply.' . PHP_EOL;
    exit(0);
}

echo $changed . ' file(s) updated, ' . $failed . ' failed.' . PHP_EOL;

if ($failed > 0) {
    fwrite(STDERR, 'Fix permissions on the failed file(s) and re-run.' . PHP_EOL);
    exit(1);
}

echo 'Allow up to user_ini.cache_ttl seconds (default 300) for PHP to pick this up.' . PHP_EOL;
exit(0);
