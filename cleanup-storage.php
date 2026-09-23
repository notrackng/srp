<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit(1);
}

/**
 * Storage cleanup — run via cron daily:
 *   0 2 * * * php /path/to/cleanup-storage.php
 *
 * Companion to redirect/cleanup-cache.php, which only ever swept
 * sys_get_temp_dir(). This sweeps the two other spots in this deployment that
 * accumulate one file per request/day with nothing pruning them, which on a
 * cPanel account with a hard inode quota is a slow account-wide outage:
 *
 *   .env-editor-storage/sessions/*   — session files for editor.php. It calls
 *     session_save_path() to point PHP's session handler at a custom
 *     directory, so PHP's own probabilistic session GC (and any distro cron
 *     that only sweeps the default save_path, e.g. Debian's systemd
 *     phpsessionclean timer) never touches it. One file survives forever per
 *     visit that never comes back. TTL 2 days: the cookie itself is
 *     browser-session (lifetime 0), so anything idle this long is abandoned.
 *
 *   statistics/temp/*.json           — one raw click-log file per calendar
 *     day (statistics/clicks/index.php, statistics/realtime/json.parse.php),
 *     read only for "today"'s realtime dashboard; historical stats come from
 *     the database, not this file. TTL 14 days — generous margin over any
 *     dashboard use, short enough that the file (already >1 MB/day on this
 *     deployment) can't accumulate into real disk/inode pressure.
 *
 *   .env-editor-storage/backups/*.bak — Backup::make() in editor.php already
 *     prunes to BACKUP_RETENTION on every write *for that label*. A label
 *     backed up once and never touched again leaks its backups forever. TTL
 *     180 days as a long-tail safety net — far past any realistic restore
 *     window — so this never fights the editor's own retention logic.
 */

$projectRoot = __DIR__;
$now = time();
$removed = 0;
$errors = 0;

/**
 * @param string $dir
 * @param callable(string $filename): bool $matches Anchored filename predicate.
 * @param int $ttlSeconds
 */
function srp_cleanup_dir(string $dir, callable $matches, int $ttlSeconds, int &$removed, int &$errors): void
{
    if (!is_dir($dir)) {
        echo "skip   {$dir} (tidak ada)\n";
        return;
    }

    $entries = scandir($dir);
    if ($entries === false) {
        fwrite(STDERR, "Cannot scan directory: {$dir}\n");
        $errors++;
        return;
    }

    $now = time();
    $localRemoved = 0;

    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }

        if (!$matches($entry)) {
            continue;
        }

        $path = $dir . DIRECTORY_SEPARATOR . $entry;

        if (!is_file($path)) {
            continue;
        }

        $mtime = filemtime($path);
        if ($mtime === false || ($now - $mtime) <= $ttlSeconds) {
            continue;
        }

        if (@unlink($path)) {
            $removed++;
            $localRemoved++;
        } else {
            $errors++;
            fwrite(STDERR, "Failed to remove: {$path}\n");
        }
    }

    echo "swept  {$dir} ({$localRemoved} removed)\n";
}

// ── 1. Env editor session files ─────────────────────────────────────────────
srp_cleanup_dir(
    $projectRoot . '/.env-editor-storage/sessions',
    static fn(string $name): bool => str_starts_with($name, 'sess_'),
    2 * 86400,
    $removed,
    $errors,
);

// ── 2. Statistics daily click-log temp files ────────────────────────────────
srp_cleanup_dir(
    $projectRoot . '/statistics/temp',
    static fn(string $name): bool => preg_match('/^\d{4}-\d{2}-\d{2}\.json$/', $name) === 1,
    14 * 86400,
    $removed,
    $errors,
);

// ── 3. Long-tail orphaned env editor backups ────────────────────────────────
srp_cleanup_dir(
    $projectRoot . '/.env-editor-storage/backups',
    static fn(string $name): bool => preg_match('/^[A-Za-z0-9_-]+\.\d{8}-\d{6}\.[a-f0-9]{6}\.bak$/', $name) === 1,
    180 * 86400,
    $removed,
    $errors,
);

echo "Total: cleaned {$removed} files, {$errors} errors\n";

exit($errors > 0 ? 1 : 0);
