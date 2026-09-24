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

    public function testTrafficDecisionDegradedReputationDoesNotCloakOnUnknownSignals(): void
    {
        // MaxMind / reputation outage or lookup failure: null means "unknown",
        // not "blocked". A degraded upstream must not cloak legitimate traffic.
        $this->assertSame(
            ['action' => 'REDIRECT', 'reason' => 'normal'],
            srp_traffic_decision(false, true, false, null, null, 'direct', false, null),
        );

        $this->assertSame(
            ['action' => 'REDIRECT', 'reason' => 'normal'],
            srp_traffic_decision(false, true, false, false, null, 'direct', false, null),
        );

        $this->assertSame(
            ['action' => 'REDIRECT', 'reason' => 'normal'],
            srp_traffic_decision(false, true, false, null, false, 'direct', false, null),
        );
    }

    public function testOfferAllowlistParse(): void
    {
        // Blank → the override is absent, so the caller falls through to
        // auto-detection. parse() cannot express that itself; it only reports
        // an empty list, which is why the caller keys off the raw string.
        $this->assertSame([], srp_offer_allowlist_parse(''));
        $this->assertSame([], srp_offer_allowlist_parse('   '));

        // Set but unparseable → explicitly empty, which denies every host.
        $this->assertSame([], srp_offer_allowlist_parse(','));
        $this->assertSame([], srp_offer_allowlist_parse(' , , '));

        $this->assertSame(['offers.example'], srp_offer_allowlist_parse(' offers.example '));
        $this->assertSame(
            ['offers.example', 'ads.example'],
            srp_offer_allowlist_parse('offers.example,ads.example'),
        );

        // Empty segments are dropped, never turned into empty-string entries.
        $this->assertSame(
            ['a.example', 'b.example'],
            srp_offer_allowlist_parse('a.example,, b.example ,'),
        );
    }

    public function testOfferHostMatching(): void
    {
        $domains = ['offers.example', 'Ads.Example'];

        // Exact and subdomain match, case-insensitive on both sides.
        $this->assertTrue(srp_offer_host_allowed_by('offers.example', $domains));
        $this->assertTrue(srp_offer_host_allowed_by('track.offers.example', $domains));
        $this->assertTrue(srp_offer_host_allowed_by('ads.example', $domains));
        $this->assertTrue(srp_offer_host_allowed_by('x.y.ads.example', $domains));

        // Suffix match must land on a dot boundary, not a bare string suffix.
        $this->assertFalse(srp_offer_host_allowed_by('evil.example', $domains));
        $this->assertFalse(srp_offer_host_allowed_by('notoffers.example', $domains));
        $this->assertFalse(srp_offer_host_allowed_by('offers.example.evil.example', $domains));

        // An empty list denies. The fail-open for "nothing configured" lives in
        // srp_url_host_allowed(), which is the only place that can tell "not
        // configured" apart from "configured to deny everything".
        $this->assertFalse(srp_offer_host_allowed_by('offers.example', []));

        // Entries that normalise to empty are skipped, not treated as wildcards.
        $this->assertFalse(srp_offer_host_allowed_by('offers.example', ['', '   ']));
    }

    public function testOfferDomainAllowlistExplicitOverride(): void
    {
        // Unparseable URL has no host at all, so the result is decided before
        // the allowlist is consulted — independent of ambient state.
        $this->assertFalse(srp_url_host_allowed('not-a-url'));

        $this->setAllowlistOverride('offers.example,ads.example');

        try {
            $this->assertTrue(srp_url_host_allowed('https://offers.example/x'));
            $this->assertTrue(srp_url_host_allowed('https://track.offers.example/x'));
            $this->assertFalse(srp_url_host_allowed('https://evil.example/x'));
        } finally {
            $this->clearAllowlistOverride();
        }
    }

    public function testOfferDomainAllowlistEmptyOverrideDeniesEverything(): void
    {
        // A set-but-unparseable override is an explicit allow-nothing, NOT a
        // fail-open. Guards the distinction the old inline code made implicitly.
        $this->setAllowlistOverride(',');

        try {
            $this->assertFalse(srp_url_host_allowed('https://offers.example/x'));
            $this->assertFalse(srp_url_host_allowed('https://any.example/x'));
        } finally {
            $this->clearAllowlistOverride();
        }
    }

    public function testOfferDomainAllowlistFailsOpenWhenNothingConfigured(): void
    {
        // Deterministic fail-open: no override, no cached auto-detect snapshot,
        // and no DB credentials, so auto-detection cannot yield anything.
        // Without this the assertion would depend on the live `offering` table
        // and on a temp-dir cache no test creates — the ambient coupling that
        // made this test unreproducible.
        $cacheFile = srp_offer_domains_cache_file();
        $hadCache = is_file($cacheFile);
        $previousCache = $hadCache ? (string) file_get_contents($cacheFile) : null;

        $this->clearAllowlistOverride();
        $this->clearDbCredentials();

        try {
            @unlink($cacheFile);

            $this->assertTrue(srp_url_host_allowed('https://any.example/path'));
            $this->assertFalse(srp_url_host_allowed('not-a-url'));
        } finally {
            if ($hadCache && $previousCache !== null) {
                @file_put_contents($cacheFile, $previousCache);
            } else {
                @unlink($cacheFile);
            }
        }
    }

    public function testOfferDomainAllowlistAutoDetectSnapshot(): void
    {
        // Drives the auto-detect branch from a cache snapshot this test owns,
        // rather than from whatever the live host happens to have. Skipped when
        // the shared temp dir cannot be verified private, because then the
        // snapshot is deliberately ignored and the DB would be consulted.
        $cacheFile = srp_offer_domains_cache_file();

        if (!srp_offer_domains_cache_dir_is_private(dirname($cacheFile))) {
            $this->markTestSkipped('auto-detect cache dir is not private in this environment');
        }

        $hadCache = is_file($cacheFile);
        $previousCache = $hadCache ? (string) file_get_contents($cacheFile) : null;

        $this->clearAllowlistOverride();
        $this->clearDbCredentials();

        try {
            file_put_contents($cacheFile, '["offers.example"]');
            touch($cacheFile); // keep it inside the 300s TTL

            $this->assertTrue(srp_url_host_allowed('https://offers.example/x'));
            $this->assertTrue(srp_url_host_allowed('https://track.offers.example/x'));
            $this->assertFalse(srp_url_host_allowed('https://evil.example/x'));
        } finally {
            if ($hadCache && $previousCache !== null) {
                @file_put_contents($cacheFile, $previousCache);
            } else {
                @unlink($cacheFile);
            }
        }
    }

    /**
     * app_env() reads $_ENV, then $_SERVER, then getenv() with no memoisation,
     * so all three have to be cleared to reliably remove a value.
     */
    private function setAllowlistOverride(string $value): void
    {
        putenv('SRP_OFFER_ALLOWED_DOMAINS=' . $value);
        $_ENV['SRP_OFFER_ALLOWED_DOMAINS'] = $value;
        $_SERVER['SRP_OFFER_ALLOWED_DOMAINS'] = $value;
    }

    private function clearAllowlistOverride(): void
    {
        putenv('SRP_OFFER_ALLOWED_DOMAINS');
        unset(
            $_ENV['SRP_OFFER_ALLOWED_DOMAINS'],
            $_SERVER['SRP_OFFER_ALLOWED_DOMAINS'],
        );
    }

    private function clearDbCredentials(): void
    {
        putenv('DB_USER');
        putenv('DB_PASSWORD');
        putenv('DB_NAME');
        unset(
            $_ENV['DB_USER'],
            $_ENV['DB_PASSWORD'],
            $_ENV['DB_NAME'],
            $_SERVER['DB_USER'],
            $_SERVER['DB_PASSWORD'],
            $_SERVER['DB_NAME'],
        );
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
