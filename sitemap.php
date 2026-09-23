<?php

declare(strict_types=1);

function sitemapCleanHost(string $host): string
{
    $host = strtolower(trim($host));

    if ($host === '') {
        return '';
    }

    if (strpos($host, ':') !== false) {
        $host = explode(':', $host, 2)[0];
    }

    $host = trim($host, ". \t\n\r\0\x0B");

    if ($host === '' || strlen($host) > 253) {
        return '';
    }

    if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $host)) {
        return '';
    }

    return $host;
}

function xmlEscape(string $value): string
{
    return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$host = sitemapCleanHost((string) ($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? ''));

if ($host === '') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo "Bad Request\n";
    exit;
}

$baseUrl = 'https://' . $host;
$lastmod = '2026-06-17';

$urls = [
    ['path' => '/', 'changefreq' => 'monthly', 'priority' => '1.0', 'lastmod' => $lastmod],
    ['path' => '/privacy.html', 'changefreq' => 'monthly', 'priority' => '0.8', 'lastmod' => $lastmod],
    ['path' => '/terms.html', 'changefreq' => 'monthly', 'priority' => '0.8', 'lastmod' => $lastmod],
    ['path' => '/abuse.html', 'changefreq' => 'monthly', 'priority' => '0.7', 'lastmod' => $lastmod],
];

header('Content-Type: application/xml; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: public, max-age=300');

echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
echo "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n";

foreach ($urls as $url) {
    echo "  <url>\n";
    echo '    <loc>' . xmlEscape($baseUrl . $url['path']) . "</loc>\n";
    echo '    <lastmod>' . xmlEscape($url['lastmod']) . "</lastmod>\n";
    echo '    <changefreq>' . xmlEscape($url['changefreq']) . "</changefreq>\n";
    echo '    <priority>' . xmlEscape($url['priority']) . "</priority>\n";
    echo "  </url>\n";
}

echo "</urlset>\n";
