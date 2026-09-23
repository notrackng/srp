<?php

declare(strict_types=1);

require_once __DIR__ . '/env.php';

require_once __DIR__ . '/asset_url.php';


function cleanHost(string $host): string
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

function rootDomain(string $host): string
{
    $parts = explode('.', $host);
    $count = count($parts);

    if ($count < 2) {
        return $host;
    }

    $secondLevelTlds = ['ac', 'co', 'com', 'edu', 'gov', 'net', 'org', 'sch', 'web'];

    if ($count >= 3 && strlen($parts[$count - 1]) === 2 && in_array($parts[$count - 2], $secondLevelTlds, true)) {
        return $parts[$count - 3] . '.' . $parts[$count - 2] . '.' . $parts[$count - 1];
    }

    return $parts[$count - 2] . '.' . $parts[$count - 1];
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Is this request HTTPS from the visitor's point of view?
 *
 * Delegates to srp_request_is_https() in env.php, the single rule for the
 * whole codebase. Kept as a named wrapper so existing call sites and this
 * module's vocabulary stay unchanged.
 */
function isHttpsRequest(): bool
{
    return srp_request_is_https();
}

try {
    $nonce = base64_encode(random_bytes(18));
} catch (Throwable $e) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo "Internal Server Error\n";
    exit;
}

$host = cleanHost((string) ($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? ''));

if ($host === '') {
    http_response_code(400);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo "Bad Request\n";
    exit;
}

$page = strtolower((string) ($_GET['page'] ?? ''));
$allowedPages = ['privacy', 'terms', 'abuse'];

if (!in_array($page, $allowedPages, true)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo "Not Found\n";
    exit;
}

$rootDomain = rootDomain($host);
$serviceUrl = 'https://' . $host;
$currentUrl = $serviceUrl . '/' . $page . '.html';
$privacyEmail = 'privacy@' . $rootDomain;
$abuseEmail = 'abuse@' . $rootDomain;
$lastUpdated = '2026-04-14';

$legal = [
    'privacy' => [
        'title' => 'Privacy Policy',
        'lead' => 'This Privacy Policy explains how ' . $serviceUrl . ' handles information when visitors access short URLs, routed links, or public service pages.',
        'sections' => [
            ['1. Information We Collect', 'When a visitor accesses a short URL or public page, the service may automatically process the requested path, IP address, timestamp, HTTP referrer if provided by the browser, user-agent string, device/browser metadata, routing outcome, and basic security signals. We do not require names, email addresses, passwords, or account information from regular visitors who only follow short links.'],
            ['2. How We Use Information', 'Operational data is used to resolve and serve the correct redirect destination, maintain routing reliability, detect spam or malicious traffic, investigate abuse, improve service stability, generate aggregate non-identifiable usage statistics, and protect the service from automated attacks.'],
            ['3. URL Safety Screening', 'Destination URLs submitted to this service may be screened before activation or during operation. Screening may include automated checks against threat intelligence, malware databases, phishing indicators, reputation systems, or the Google Safe Browsing API. When Google Safe Browsing is used, destination URL data may be sent to Google for safety verification.'],
            ['4. Cookies and Sessions', 'Regular visitors following short links are not intentionally assigned third-party tracking cookies by this service. Administrative areas may use a PHP session cookie such as PHPSESSID strictly for authentication, security, CSRF protection, and session integrity.'],
            ['5. Data Sharing', 'We do not sell visitor data. Operational data may be shared only when required for security screening, abuse mitigation, infrastructure operation, legal compliance, fraud prevention, or protection of the rights and safety of users, visitors, service operators, or third parties.'],
            ['6. Data Retention', 'Click logs, request metadata, abuse records, and diagnostic events are retained only as long as reasonably necessary for security, fraud prevention, analytics, legal, operational, or troubleshooting purposes. Data may be deleted, anonymized, aggregated, or rotated according to operational requirements.'],
            ['7. Security Measures', 'The service uses technical safeguards such as HTTPS enforcement, input validation, CSRF protection for state-changing requests, Content Security Policy headers, hardened sessions, access control, rate limiting where applicable, and abuse monitoring. No internet service can guarantee absolute security.'],
            ['8. Visitor Choices', 'Visitors may limit referrer disclosure through browser settings, VPNs, privacy tools, or browser-level tracking protections. Some routing, security, or abuse-prevention features may still require basic request metadata to operate correctly.'],
            ['9. Contact', 'Privacy-related requests may be sent to ' . $privacyEmail . '. Include the affected URL, approximate request time, IP address used if relevant, and enough context to locate the related record.'],
            ['10. Changes to This Policy', 'This Privacy Policy may be updated from time to time. Updates are reflected by changing the Last updated date on this page. Continued use of the service after changes means the updated policy applies.'],
        ],
    ],
    'terms' => [
        'title' => 'Terms of Service',
        'lead' => 'These Terms of Service govern access to and use of ' . $serviceUrl . ', including short URL redirection, routed links, and related public pages.',
        'sections' => [
            ['1. Acceptance', 'By accessing this website, using a short URL, or submitting a destination URL to the service, you agree to these Terms of Service and all applicable laws and regulations. If you do not agree, do not use the service.'],
            ['2. Service Description', 'The service provides URL shortening, redirection, routing, safety checks, abuse controls, and related operational functions. Redirect behavior may depend on configuration, security screening, availability, policy enforcement, or abuse-prevention rules.'],
            ['3. Lawful Use Only', 'You may not use the service for phishing, malware distribution, spam, credential theft, impersonation, fraud, unauthorized access, evasion, illegal content, platform abuse, deceptive traffic, or any activity that harms users, networks, platforms, infrastructure, or third parties.'],
            ['4. Destination URLs', 'Destination URLs may be reviewed, blocked, disabled, rate-limited, logged, or removed when they appear unsafe, abusive, unlawful, deceptive, unavailable, or inconsistent with service policy. The service does not endorse or control third-party destinations.'],
            ['5. Abuse and Enforcement', 'We may investigate reports, suspend links, block traffic, preserve logs, contact infrastructure providers, or take other protective actions when abuse, fraud, security risk, or legal concern is detected.'],
            ['6. Availability', 'The service is provided on an operational best-effort basis. Access may be modified, interrupted, limited, suspended, or discontinued without prior notice for maintenance, abuse prevention, security, legal, or infrastructure reasons.'],
            ['7. No Warranty', 'The service is provided as-is and as-available. We do not warrant uninterrupted availability, error-free operation, fitness for a particular purpose, accuracy of third-party destinations, or absence of harmful content outside our control.'],
            ['8. Limitation of Liability', 'To the maximum extent permitted by applicable law, the service operator is not liable for indirect, incidental, consequential, special, punitive, or loss-of-data damages arising from use, misuse, downtime, blocked links, third-party destinations, or unauthorized activity.'],
            ['9. Changes', 'These Terms may be updated for operational, legal, security, or policy reasons. Continued access to the service after updates means you accept the revised Terms.'],
        ],
    ],
    'abuse' => [
        'title' => 'Abuse Reporting',
        'lead' => 'Use this page to report phishing, malware, spam, illegal content, impersonation, unsafe redirects, copyright concerns, or other misuse involving ' . $serviceUrl . '.',
        'sections' => [
            ['1. What to Report', 'Report suspected phishing, malware, credential theft, spam, scam activity, impersonation, illegal content, copyright abuse, platform policy violations, deceptive redirects, or other harmful use of this service.'],
            ['2. Required Information', 'Include the affected URL, final destination if known, timestamp with timezone, screenshots or evidence, description of the issue, your role or authority if applicable, and a contact address for follow-up. Incomplete reports may delay review.'],
            ['3. Investigation Process', 'Reports may be reviewed manually or automatically. We may disable links, block destinations, preserve logs, rate-limit traffic, contact infrastructure providers, or request additional evidence. Submission of a report does not guarantee a specific outcome.'],
            ['4. Urgent Matters', 'For immediate threats to life, active compromise, law-enforcement matters, or emergency legal requests, contact the relevant hosting provider, registrar, network operator, platform provider, or competent authority directly in parallel with submitting an abuse report.'],
            ['5. False or Abusive Reports', 'False, misleading, automated, retaliatory, or abusive reports may be ignored, filtered, rate-limited, or blocked. Do not submit confidential credentials, private keys, payment data, or unrelated personal data in abuse reports.'],
            ['6. Abuse Contact', 'Send abuse reports to ' . $abuseEmail . '. Privacy requests should be sent to ' . $privacyEmail . '. Include enough technical detail to identify the affected URL or traffic event.'],
            ['7. Scope', 'This abuse process applies only to URLs, redirects, pages, or service activity operating under ' . $host . '. Third-party destination sites are controlled by their own operators and may require separate reporting.'],
        ],
    ],
];

$data = $legal[$page];

header('Content-Type: text/html; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: same-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
header('Cache-Control: public, max-age=300');
header(
    "Content-Security-Policy: default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; object-src 'none'; img-src 'self' data: https:; font-src 'self' data:; style-src 'self' 'nonce-" . $nonce . "'; script-src 'self'; connect-src 'self'",
);

if (isHttpsRequest()) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= e($data['title']) ?> - <?= e($host) ?></title>
<meta name="description" content="<?= e($data['lead']) ?>">
<link rel="canonical" href="<?= e($currentUrl) ?>">
<link rel="stylesheet" href="<?= srpAssetUrl('/assets/css/legal.css') ?>">
</head>
<body>
<div class="scanline" aria-hidden="true"></div>
<div class="noise" aria-hidden="true"></div>
<main class="wrap">
<div class="vignette" aria-hidden="true"></div>
<article class="card">
<header class="top">
<div>
<div class="brand"><?= e($host) ?></div>
<h1><?= e($data['title']) ?></h1>
<p class="muted">Last updated: <?= e($lastUpdated) ?></p>
</div>
<div class="actions">
<a class="home-btn" href="/">Back to Home</a>
<nav class="nav" aria-label="Legal pages">
<a href="/privacy.html" aria-current="<?= $page === 'privacy' ? 'true' : 'false' ?>">Privacy</a>
<a href="/terms.html" aria-current="<?= $page === 'terms' ? 'true' : 'false' ?>">Terms</a>
<a href="/abuse.html" aria-current="<?= $page === 'abuse' ? 'true' : 'false' ?>">Abuse</a>
</nav>
</div>
</header>

<p class="lead"><?= e($data['lead']) ?></p>
<p class="notice">This page is a general operational policy notice for this service and is not jurisdiction-specific legal advice.</p>

<?php foreach ($data['sections'] as $section) : ?>
<section>
<h2><?= e($section[0]) ?></h2>
<p><?= e($section[1]) ?></p>
</section>
<?php endforeach; ?>

<p class="meta">
Page URL: <?= e($currentUrl) ?><br>
Service URL: <?= e($serviceUrl) ?><br>
Privacy contact: <?= e($privacyEmail) ?><br>
Abuse contact: <?= e($abuseEmail) ?>
</p>
</article>
</main>
</body>
</html>
