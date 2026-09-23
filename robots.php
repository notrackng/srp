<?php

declare(strict_types=1);

function robotsCleanHost(string $host): string
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

$host = robotsCleanHost((string) ($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? ''));

if ($host === '') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo "Bad Request\n";
    exit;
}

header('Content-Type: text/plain; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cache-Control: public, max-age=300');

$sitemapUrl = 'https://' . $host . '/sitemap.xml';

echo "User-agent: facebookexternalhit\n";
echo "Allow: /\n\n";

echo "User-agent: Facebot\n";
echo "Allow: /\n\n";

echo "User-agent: meta-externalagent\n";
echo "Disallow: /\n\n";

echo "User-agent: Meta-ExternalAgent\n";
echo "Disallow: /\n\n";

echo "User-agent: FacebookBot\n";
echo "Disallow: /\n\n";

echo "User-agent: Meta-ExternalFetcher\n";
echo "Disallow: /\n\n";

echo "User-agent: *\n";
echo "Allow: /\n";
echo "Allow: /privacy.html\n";
echo "Allow: /terms.html\n";
echo "Allow: /abuse.html\n";
echo "Allow: /sitemap.xml\n";
echo "Allow: /robots.txt\n";
echo "Disallow: /public/\n";
echo "Disallow: /redirect/\n";
echo "Disallow: /statistics/\n";
echo "Disallow: /migrations/\n";
echo "Disallow: /vendor/\n";
echo "Disallow: /install-dashboard.php\n";
echo "Disallow: /install.php\n";
echo "Disallow: /schema.sql\n";
echo "Crawl-delay: 20\n";
echo "Content-Signal: ai-train=no, search=yes, ai-input=no\n\n";

echo 'Sitemap: ' . $sitemapUrl . "\n";
