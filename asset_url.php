<?php

/**
 * Static asset URL builder for the root and public modules.
 *
 * Appends a ?v=<mtime> stamp so an edited CSS/JS file gets a new URL and is
 * picked up immediately, even though .htaccess caches /assets/* for 30 days.
 * The statistics module has its own equivalent in statistics/stat_path.php
 * (statAssetUrl), which resolves that module's base path as well.
 *
 * Usage:
 *   <link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/portal-1.css') ?>">
 */

declare(strict_types=1);

if (!function_exists('srpAssetUrl')) {
    function srpAssetUrl(string $path): string
    {
        $path = trim($path);

        if ($path === '') {
            return '';
        }

        if ($path[0] !== '/') {
            $path = '/' . $path;
        }

        // Only ever emit paths inside assets/. Anything else is a caller bug and
        // must not become a URL — no traversal, no query, no scheme.
        if (preg_match('#\A/assets/(?:css|js|img)/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\z#', $path) !== 1) {
            return '';
        }

        if (str_contains($path, '..')) {
            return '';
        }

        // Stamp the file the WEB SERVER will actually serve, not the one next to
        // this script. Each module now carries its own assets/ tree, so on the
        // gen. host `/assets/css/x.css` resolves under public/, while __DIR__ is
        // the project root — stamping the root copy would pin the URL to an
        // mtime the served file never had, and an edit to the module copy would
        // stay invisible behind the 30-day cache. DOCUMENT_ROOT is set by the
        // server, never by the client, and $path is already validated above.
        $docRoot = (string) ($_SERVER['DOCUMENT_ROOT'] ?? '');
        $relative = str_replace('/', DIRECTORY_SEPARATOR, $path);

        $file = $docRoot !== ''
            ? rtrim($docRoot, '/\\') . $relative
            : __DIR__ . $relative;

        // Single-docroot mode, CLI, and any host whose docroot has no copy of
        // its own all fall back to the shared tree at the project root.
        if (!is_file($file)) {
            $file = __DIR__ . $relative;
        }

        $mtime = is_file($file) ? filemtime($file) : false;

        $url = $mtime !== false ? $path . '?v=' . $mtime : $path;

        return htmlspecialchars($url, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
