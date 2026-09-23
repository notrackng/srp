<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit(1);
}

/**
 * Cache cleanup — run via cron daily:
 *   0 2 * * * php /path/to/redirect/cleanup-cache.php
 *
 * Removes stale SRP cache files older than the configured TTLs:
 *   geo_*.json   — 7 days (country data rarely changes)
 *   asn_*.json   — 7 days (GeoResolver ASN cache; same kind of data as geo_)
 *   vpn_*.json   — 7 days (IP reputation is stable)
 *   click_*.json — 1 day  (dedup window is only 5 min)
 *   sl_*.json    — 1 hour (srp_shortlinks_find() cache TTL is 5 min; keep margin)
 *   slp_*.json   — 1 hour (srp_short_link_find() cache TTL is 5 min; keep margin.
 *                  Own prefix so it can never collide with sl_'s legacy-table
 *                  cache for the same short code.)
 *   rl_*.json    — 1 hour (rate-limit bucket window is only 60 s)
 *   rl_shorten_*.json — 1 hour (redirect/api/shorten.php per-IP rate limit; same
 *                        60 s window as rl_, kept as its own prefix so it reads
 *                        as a rate-limit bucket, not a short-link cache entry)
 *   lf_*.json    — 1 day  (login throttle; see note below)
 *   filter_url.txt — 30 days (runtime overrides should persist)
 *
 * lf_ files are written by login_throttle.php on a FAILED login and only
 * deleted on a SUCCESSFUL one, so one file per (scope, IP) survives forever
 * when an IP never logs in successfully — exactly what a distributed
 * brute-force against admin_login / env_editor / rd_login produces. Removing
 * them is safe: srp_login_throttle_state() already treats anything older than
 * its 1-hour window as zero failures, so a day-old file carries no state.
 *
 * A prefix missing from $rules is never cleaned. rl_ and asn_ were absent and
 * had accumulated ~16k files between them; anything added to the cache dir with
 * a new prefix must get a rule here too.
 */

const CACHE_DIR_NAME = 'srp_bb';

$cacheDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
    . DIRECTORY_SEPARATOR . CACHE_DIR_NAME;

if (!is_dir($cacheDir)) {
    if (!mkdir($cacheDir, 0750, true) && !is_dir($cacheDir)) {
        fwrite(STDERR, 'Cannot create cache directory: ' . $cacheDir . PHP_EOL);
        exit(1);
    }
    echo 'Created cache directory: ' . $cacheDir . PHP_EOL;
}

$now = time();
$removed = 0;
$errors = 0;

$rules = [
    'geo_'    => 7 * 86400,   // 7 days
    'asn_'    => 7 * 86400,   // 7 days  (GeoResolver asn cache TTL is 24 h; keep margin)
    'vpn_'    => 7 * 86400,   // 7 days
    'click_'  => 86400,       // 1 day
    'sl_'     => 3600,        // 1 hour  (srp_shortlinks_find() TTL is 5 min; keep margin)
    'slp_'    => 3600,        // 1 hour  (srp_short_link_find() TTL is 5 min; keep margin)
    'rl_shorten_' => 3600,    // 1 hour  (shorten API rate-limit window is 60 s; keep margin)
    'rl_'     => 3600,        // 1 hour  (rate-limit window is 60 s; keep margin)
    'lf_'     => 86400,       // 1 day   (throttle window is 1 h; keep forensic margin)
    'filter_' => 30 * 86400,  // 30 days
];

$files = scandir($cacheDir);
if ($files === false) {
    fwrite(STDERR, 'Cannot scan cache directory: ' . $cacheDir . PHP_EOL);
    exit(1);
}

foreach ($files as $file) {
    if ($file === '.' || $file === '..') {
        continue;
    }

    $path = $cacheDir . DIRECTORY_SEPARATOR . $file;

    if (!is_file($path)) {
        continue;
    }

    $matchedTtl = null;
    foreach ($rules as $prefix => $ttl) {
        if (str_starts_with($file, $prefix)) {
            $matchedTtl = $ttl;
            break;
        }
    }

    if ($matchedTtl === null) {
        continue; // unknown file — leave it
    }

    $age = $now - filemtime($path);
    if ($age > $matchedTtl) {
        if (@unlink($path)) {
            $removed++;
        } else {
            $errors++;
            fwrite(STDERR, 'Failed to remove: ' . $path . PHP_EOL);
        }
    }
}

echo sprintf(
    'Cleaned %d files, %d errors from %s' . PHP_EOL,
    $removed,
    $errors,
    $cacheDir,
);

/**
 * Second sweep — update-geoip.php scratch space.
 *
 * These live directly in sys_get_temp_dir(), NOT in srp_bb, so the loop above
 * never sees them. update-geoip.php removes its own scratch in a finally block,
 * but a killed or fatally-errored run skips that entirely and strands a ~4 MB
 * archive plus an ~8 MB extraction directory until the next reboot.
 *
 * TTL is one day: the job runs weekly and finishes in minutes, so anything this
 * old is guaranteed to be residue rather than a run in progress.
 */
$tmpRoot = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
$scratchTtl = 86400;
$scratchRemoved = 0;
$scratchErrors = 0;

$removeTree = static function (string $path) use (&$removeTree): bool {
    if (is_dir($path) && !is_link($path)) {
        foreach (scandir($path) ?: [] as $child) {
            if ($child === '.' || $child === '..') {
                continue;
            }
            $removeTree($path . DIRECTORY_SEPARATOR . $child);
        }

        return @rmdir($path);
    }

    return @unlink($path);
};

foreach (scandir($tmpRoot) ?: [] as $entry) {
    // Anchored prefix match only — never a substring, never a traversal.
    if (preg_match('/^geoip_(?:asn_)?(?:dl|ext)_/', $entry) !== 1) {
        continue;
    }

    $path = $tmpRoot . DIRECTORY_SEPARATOR . $entry;

    // Refuse anything that resolves outside the temp root (symlink games).
    $real = realpath($path);
    if ($real === false || !str_starts_with($real, $tmpRoot . DIRECTORY_SEPARATOR)) {
        continue;
    }

    $mtime = @filemtime($path);
    if ($mtime === false || ($now - $mtime) <= $scratchTtl) {
        continue;
    }

    if ($removeTree($path)) {
        $scratchRemoved++;
    } else {
        $scratchErrors++;
        fwrite(STDERR, 'Failed to remove geoip scratch: ' . $path . PHP_EOL);
    }
}

echo sprintf(
    'Cleaned %d geoip scratch entries, %d errors from %s' . PHP_EOL,
    $scratchRemoved,
    $scratchErrors,
    $tmpRoot,
);

exit(($errors + $scratchErrors) > 0 ? 1 : 0);
