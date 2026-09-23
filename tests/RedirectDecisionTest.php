<?php

declare(strict_types=1);

require_once __DIR__ . '/../redirect/functions.php';

use PHPUnit\Framework\TestCase;

final class RedirectDecisionTest extends TestCase
{
    public function testAutomationClientDetectsDesktopClients(): void
    {
        foreach ([
            'curl/8.1.2',
            'Wget/1.21.4',
            'python-requests/2.31.0',
            'Python-urllib/3.11',
            'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0',
            'Go-http-client/1.1',
            'okhttp/4.11.0',
            'UptimeRobot/2.0',
            'Pingdom.com_bot_version_1.4',
        ] as $ua) {
            $this->assertTrue(srp_is_automation_client($ua), "should flag: $ua");
        }
    }

    public function testAutomationClientIgnoresRealBrowsers(): void
    {
        foreach ([
            '',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        ] as $ua) {
            $this->assertFalse(srp_is_automation_client($ua), "should not flag: $ua");
        }
    }

    public function testShouldDivertToFilter(): void
    {
        // Block ON → only confirmed-clean mobile (WAP) is diverted.
        $this->assertTrue(srp_should_divert_to_filter('WAP', false, true));
        $this->assertFalse(srp_should_divert_to_filter('WAP', true, true));
        $this->assertFalse(srp_should_divert_to_filter('WAP', null, true));
        $this->assertFalse(srp_should_divert_to_filter('TABLET', false, true));
        $this->assertFalse(srp_should_divert_to_filter('WEB', false, true));

        // Block OFF → any mobile visitor follows the window.
        $this->assertTrue(srp_should_divert_to_filter('WAP', true, false));
        $this->assertTrue(srp_should_divert_to_filter('WAP', null, false));
        $this->assertFalse(srp_should_divert_to_filter('WEB', null, false));
    }

    public function testTrafficDecisionCloakOutranksEverything(): void
    {
        // Preview probe always cloaks, even for landing links.
        $this->assertSame(
            ['action' => 'CLOAK', 'reason' => 'user-agent'],
            srp_traffic_decision(true, false, false, null, null, 'landing', false, null),
        );

        // Blocked ASN with block ON cloaks.
        $this->assertSame(
            ['action' => 'CLOAK', 'reason' => 'blocked-asn'],
            srp_traffic_decision(false, true, true, null, null, 'direct', false, null),
        );

        // Hosting and VPN/proxy cloaks carry their own reasons.
        $this->assertSame(
            ['action' => 'CLOAK', 'reason' => 'hosting'],
            srp_traffic_decision(false, true, false, null, true, 'direct', false, null),
        );
        $this->assertSame(
            ['action' => 'CLOAK', 'reason' => 'vpn-proxy'],
            srp_traffic_decision(false, true, false, true, false, 'direct', false, null),
        );

        // Block OFF → blocked ASN does NOT cloak.
        $this->assertSame(
            ['action' => 'REDIRECT', 'reason' => 'normal'],
            srp_traffic_decision(false, false, true, null, null, 'direct', false, null),
        );
    }

    public function testTrafficDecisionOrdering(): void
    {
        // Country block outranks the filter window.
        $this->assertSame(
            ['action' => 'BLOCK_COUNTRY', 'reason' => 'country'],
            srp_traffic_decision(false, true, false, false, false, 'direct', true, 'https://filter.example'),
        );

        // Filter diversion applies when country is not blocked.
        $this->assertSame(
            ['action' => 'DIVERT_FILTER', 'reason' => 'filter-window'],
            srp_traffic_decision(false, true, false, false, false, 'direct', false, 'https://filter.example'),
        );

        // Landing links are exempt from both country block and filter.
        $this->assertSame(
            ['action' => 'REDIRECT', 'reason' => 'normal'],
            srp_traffic_decision(false, true, false, false, false, 'landing', true, 'https://filter.example'),
        );
    }

    public function testLanding2NormalizationAndDecision(): void
    {
        $this->assertSame('landing', srp_normalize_lg('landing'));
        $this->assertSame('landing', srp_normalize_lg('1'));
        $this->assertSame('landing2', srp_normalize_lg('landing2'));
        $this->assertSame('landing2', srp_normalize_lg('2'));
        $this->assertSame('direct', srp_normalize_lg('direct'));

        $this->assertTrue(srp_is_landing_lg('landing'));
        $this->assertTrue(srp_is_landing_lg('landing2'));
        $this->assertFalse(srp_is_landing_lg('direct'));

        // Template 2 shares the landing exemption from country block + filter.
        $this->assertSame(
            ['action' => 'REDIRECT', 'reason' => 'normal'],
            srp_traffic_decision(false, true, false, false, false, 'landing2', true, 'https://filter.example'),
        );
    }

    public function testOfferDomainAllowlist(): void
    {
        // No allowlist configured → allow all valid hosts, reject unparseable.
        $this->assertTrue(srp_url_host_allowed('https://any.example/path'));
        $this->assertFalse(srp_url_host_allowed('not-a-url'));

        putenv('SRP_OFFER_ALLOWED_DOMAINS=offers.example,ads.example');
        $_ENV['SRP_OFFER_ALLOWED_DOMAINS'] = 'offers.example,ads.example';

        $this->assertTrue(srp_url_host_allowed('https://offers.example/x'));
        $this->assertTrue(srp_url_host_allowed('https://track.offers.example/x'));
        $this->assertFalse(srp_url_host_allowed('https://evil.example/x'));

        putenv('SRP_OFFER_ALLOWED_DOMAINS');
        unset($_ENV['SRP_OFFER_ALLOWED_DOMAINS']);
    }

    public function testUrlSelfGuard(): void
    {
        $_SERVER['HTTP_HOST'] = 'redirect.example.com';
        $this->assertTrue(srp_url_is_self('https://redirect.example.com/x'));
        $this->assertTrue(srp_url_is_self('https://www.redirect.example.com/x'));
        $this->assertFalse(srp_url_is_self('https://example.com/x'));
        $this->assertFalse(srp_url_is_self(''));
        unset($_SERVER['HTTP_HOST']);
    }
}
