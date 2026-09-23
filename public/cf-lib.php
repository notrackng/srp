<?php

declare(strict_types=1);

/**
 * Shared Cloudflare API library.
 * Included by addondomain/cf.php (admin) and api/cf_sync.php (user portal).
 * Every function accepts an optional $token — if empty, falls back to CF_API_TOKEN env.
 *
 * Public entry point for zone provisioning:
 *   cfApplyAllRecommended($zoneId, $token)
 */

function cfResolveToken(string $token = ''): string
{
    $resolved = $token !== '' ? $token : app_required_env('CF_API_TOKEN');

    // Normalize accidental .env/UI paste issues:
    // - wrapping quotes
    // - whitespace
    // - full auth header: "Authorization: Bearer <token>"
    // - bearer value only: "Bearer <token>"
    $resolved = trim((string) $resolved);
    $resolved = trim($resolved, " \t\n\r\0\x0B\"'");

    $normalized = preg_replace('/^Authorization\s*:\s*Bearer\s+/i', '', $resolved);
    if (is_string($normalized)) {
        $resolved = trim($normalized);
    }

    $normalized = preg_replace('/^Bearer\s+/i', '', $resolved);
    if (is_string($normalized)) {
        $resolved = trim($normalized);
    }

    $resolved = trim($resolved, " \t\n\r\0\x0B\"'");

    if ($resolved === '') {
        $msg = 'CF_API_TOKEN missing — set token only, without Bearer.';
        error_log('[cf-sync] ' . $msg);

        throw new RuntimeException($msg);
    }

    // Do not enforce exact token length. Cloudflare validates the real token.
    // Local guard only blocks obvious malformed values before repeated API calls.
    if (preg_match('/^[A-Za-z0-9_-]{20,200}$/', $resolved) !== 1) {
        $msg = 'CF_API_TOKEN malformed (length=' . strlen($resolved)
            . ') — paste token only, without Bearer, quotes, spaces, or hidden characters.';
        error_log('[cf-sync] ' . $msg);

        throw new RuntimeException($msg);
    }

    return $resolved;
}

/**
 * Convert Cloudflare API errors into a compact, token-safe summary.
 *
 * @return list<string>
 */
function cfApiErrorEntries(array $data): array
{
    $entries = [];

    foreach (($data['errors'] ?? []) as $err) {
        if (!is_array($err)) {
            continue;
        }

        $code = (string) ($err['code'] ?? '?');
        $message = trim((string) ($err['message'] ?? 'unknown'));
        $entries[] = '[' . $code . '] ' . ($message !== '' ? $message : 'unknown');
    }

    return $entries;
}

function cfApiErrorSummary(array $data): string
{
    $entries = cfApiErrorEntries($data);

    return $entries !== [] ? implode('; ', $entries) : 'success=false';
}

function cfApiResponseHasAuthFailure(array $data): bool
{
    foreach (($data['errors'] ?? []) as $err) {
        if (!is_array($err)) {
            continue;
        }

        $code = (int) ($err['code'] ?? 0);
        $message = strtolower((string) ($err['message'] ?? ''));

        // 10405 commonly appears as "Method not allowed for this authentication scheme"
        // on feature endpoints that are not compatible with zone API tokens. Treat it
        // as an unsupported optional endpoint, not as a fatal token failure.
        if ($code === 10405) {
            continue;
        }

        if (in_array($code, [10000, 9103, 9109, 6003, 6111], true)) {
            return true;
        }

        if (str_contains($message, 'authentication') || str_contains($message, 'unauthorized')) {
            return true;
        }
    }

    return false;
}

/**
 * Track fatal Cloudflare auth/resource failures in one sync run.
 *
 * @return list<string>
 */
function cfSyncTrackAuthFailure(?string $entry = null, bool $reset = false): array
{
    static $errors = [];

    if ($reset) {
        $errors = [];

        return [];
    }

    if ($entry !== null) {
        $errors[] = $entry;
    }

    return $errors;
}

function cfSyncHasAuthFailure(): bool
{
    return cfSyncTrackAuthFailure() !== [];
}

/**
 * Preflight check before sending many PATCH/PUT calls.
 *
 * @return array{ok: bool, status_code?: int, err?: string}
 */
function cfPreflightZoneAccess(string $zoneId, string $token = ''): array
{
    $zoneId = trim($zoneId);
    if (preg_match('/^[a-f0-9]{32}$/i', $zoneId) !== 1) {
        return ['ok' => false, 'status_code' => 422, 'err' => 'invalid-zone-id'];
    }

    $resp = cfApi('GET', '/zones/' . $zoneId, null, $token);
    if (($resp['success'] ?? false) === true && isset($resp['result'])) {
        return ['ok' => true];
    }

    $summary = cfApiErrorSummary($resp);
    $authFailure = cfApiResponseHasAuthFailure($resp);

    return [
        'ok' => false,
        'status_code' => $authFailure ? 403 : 502,
        'err' => ($authFailure ? 'cf-token-zone-access-denied' : 'cf-zone-access-check-failed') . ': ' . $summary,
    ];
}


/**
 * Hard-disable optional Cloudflare API groups in auto-provisioning.
 *
 * This blocks /rulesets plus Page Shield, RUM, and Email Routing before cURL is
 * opened, so stale callers in older UI/API files cannot trigger plan-gated or
 * entitlement-gated Cloudflare requests.
 *
 * The /managed_headers endpoint is intentionally allowed for:
 * - Remove "X-Powered-By" headers
 * - Add security headers
 */
function cfIsDisabledOptionalApiPath(string $path): bool
{
    return str_contains($path, '/rulesets')
        || str_contains($path, '/page_shield')
        || str_contains($path, '/rum/site_info')
        || str_contains($path, '/email/routing/enable');
}

/**
 * @return array<string, mixed>
 */
function cfSkippedOptionalApiResponse(string $method, string $path): array
{
    $verb = strtoupper($method);
    $msg = $verb . ' ' . $path . ' skipped: optional Cloudflare feature disabled by project policy.';
    error_log('[cf-sync] ' . $msg);

    return [
        'success'    => true,
        'errors'     => [],
        'messages'   => [['message' => $msg]],
        'result'     => null,
        '_http_code' => 0,
        '_skipped'   => true,
    ];
}

/**
 * Make a Cloudflare API v4 call.
 */
function cfApi(
    string $method,
    string $path,
    ?array $body = null,
    string $token = '',
    bool $trackFailure = true,
    bool $allowDisabledOptionalPath = false,
): array {
    if (!$allowDisabledOptionalPath && cfIsDisabledOptionalApiPath($path)) {
        return cfSkippedOptionalApiResponse($method, $path);
    }

    $url = 'https://api.cloudflare.com/client/v4' . $path;
    $ch  = curl_init($url);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER     => [
            'Authorization: Bearer ' . cfResolveToken($token),
            'Content-Type: application/json',
            'Accept: application/json',
        ],
        CURLOPT_CUSTOMREQUEST  => strtoupper($method),
    ]);

    if ($body !== null) {
        curl_setopt(
            $ch,
            CURLOPT_POSTFIELDS,
            json_encode($body, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR),
        );
    }

    $raw      = curl_exec($ch);
    $errno    = curl_errno($ch);
    $curlErr  = curl_error($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $verb = strtoupper($method);

    if ($errno !== 0 || $raw === false) {
        $reason = $curlErr !== '' ? $curlErr : curl_strerror($errno);
        $msg = $verb . ' ' . $path . ' → transport error: ' . $reason;
        if ($trackFailure) {
            error_log('[cf-sync] ' . $msg);
            cfSyncTrackError($msg);
        }

        throw new RuntimeException('CF API transport error: ' . $reason);
    }

    $data = json_decode((string) $raw, true);
    if (!is_array($data)) {
        $msg = $verb . ' ' . $path . ' → non-JSON response (http=' . $httpCode . ')';
        if ($trackFailure) {
            error_log('[cf-sync] ' . $msg);
            cfSyncTrackError($msg);
        }

        throw new RuntimeException('CF API returned non-JSON response.');
    }

    $data['_http_code'] = $httpCode;

    if (($data['success'] ?? false) !== true) {
        $summary = cfApiErrorSummary($data);
        $msg = $verb . ' ' . $path . ' (http=' . $httpCode . '): ' . $summary;
        if ($trackFailure) {
            error_log('[cf-sync] ' . $msg);
            cfSyncTrackError($msg);

            if (cfApiResponseHasAuthFailure($data)) {
                cfSyncTrackAuthFailure($msg);
            }
        }
    }

    return $data;
}

/**
 * Accumulate failed CF API calls within one sync run so the caller can report
 * them. Pass a message to record; pass reset=true to clear; call with no args to
 * read the collected list.
 *
 * @return list<string>
 */
function cfSyncTrackError(?string $entry = null, bool $reset = false): array
{
    static $errors = [];

    if ($reset) {
        $errors = [];

        return [];
    }

    if ($entry !== null) {
        $errors[] = $entry;
    }

    return $errors;
}


// ---------------------------------------------------------------------------
// Cloudflare feature gates and disabled Rulesets helpers
// ---------------------------------------------------------------------------

function cfEnvFlag(string $key, bool $default = false): bool
{
    if (!function_exists('app_env')) {
        return $default;
    }

    $raw = strtolower(trim((string) app_env($key, $default ? '1' : '0')));

    return in_array($raw, ['1', 'true', 'yes', 'on'], true);
}

/**
 * Create or update a zone phase entrypoint ruleset.
 *
 * Cloudflare returns not_found when a phase entrypoint has not been created yet.
 * In that case, create a zone ruleset instead of reporting a noisy warning.
 *
 * @param list<array<string, mixed>> $rules
 */
function cfUpsertZonePhaseRuleset(
    string $zoneId,
    string $phase,
    string $name,
    array $rules,
    string $token = '',
): void {
    unset($zoneId, $phase, $name, $rules, $token);
    // Intentionally disabled. Auto-provision no longer creates or updates
    // Cloudflare Rulesets because many accounts/plans reject these calls.
}

// ---------------------------------------------------------------------------
// Zone settings (PATCH /zones/{id}/settings/*)
// ---------------------------------------------------------------------------

function cfApplySettings(string $zoneId, string $token = ''): void
{
    // Baseline settings only. Do not force settings that are deprecated,
    // plan-gated, dashboard-only, or already managed by Cloudflare defaults.
    $settings = [
        'ssl'                      => ['value' => 'full'],
        'always_use_https'         => ['value' => 'on'],
        'automatic_https_rewrites' => ['value' => 'on'],
        'min_tls_version'          => ['value' => '1.2'],
        'tls_1_3'                  => ['value' => 'on'],
        'opportunistic_encryption' => ['value' => 'on'],

        'security_level'           => ['value' => 'medium'],
        'browser_check'            => ['value' => 'on'],
        'challenge_ttl'            => ['value' => 1800],
        'email_obfuscation'        => ['value' => 'on'],
        'hotlink_protection'       => ['value' => 'on'],
        'server_side_exclude'      => ['value' => 'on'],

        'http3'                    => ['value' => 'on'],
        '0rtt'                     => ['value' => 'on'],
        'ipv6'                     => ['value' => 'on'],
        'websockets'               => ['value' => 'on'],
        'opportunistic_onion'      => ['value' => 'on'],
        'pseudo_ipv4'              => ['value' => 'add_header'],
        'ip_geolocation'           => ['value' => 'on'],

        'brotli'                   => ['value' => 'on'],
        'early_hints'              => ['value' => 'on'],
        // Strict nonce-based CSP pages must not be rewritten by Rocket Loader.
        'rocket_loader'            => ['value' => 'off'],
        'minify'                   => ['value' => ['css' => 'on', 'html' => 'on', 'js' => 'on']],
        'browser_cache_ttl'        => ['value' => 14400],
        'cache_level'              => ['value' => 'aggressive'],
        'always_online'            => ['value' => 'on'],
    ];

    // Verified working on a Free zone. On by default; set
    // CF_APPLY_OPTIONAL_SETTINGS=0 to opt back out.
    if (cfEnvFlag('CF_APPLY_OPTIONAL_SETTINGS', true)) {
        $settings += [
            'h2_prioritization' => ['value' => 'on'],
            'fonts'             => ['value' => 'on'],
        ];
    }

    // Paid/add-on features. On by default so every recommended setting is
    // applied; each PATCH here is still best-effort (caught below), so on an
    // account without these entitlements Cloudflare rejects them and it just
    // surfaces as a cf_warnings toast, never a hard failure. Set
    // CF_APPLY_PAID_FEATURES=0 to silence those warnings on a non-paid plan.
    if (cfEnvFlag('CF_APPLY_PAID_FEATURES', true)) {
        $settings += [
            'polish'         => ['value' => 'lossless'],
            'mirage'         => ['value' => 'on'],
            'image_resizing' => ['value' => 'on'],
            'speed_brain'    => ['value' => 'on'],
        ];
    }

    foreach ($settings as $key => $body) {
        if (cfSyncHasAuthFailure()) {
            return;
        }

        try {
            cfApi('PATCH', '/zones/' . $zoneId . '/settings/' . $key, $body, $token);
        } catch (Throwable $e) {
            // Best-effort — transport/runtime errors are already tracked by cfApi().
        }
    }
}

/**
 * Force zone security_level to a specific value (e.g. 'under_attack').
 * Kept separate from cfApplySettings()'s baseline ('medium') so callers can
 * choose to apply it selectively instead of it always riding along with
 * every other zone setting.
 */
/**
 * Take ownership of the zone's SSL/TLS mode and keep it there.
 *
 * Why this exists: cfApplySettings() has always written `ssl => full`, but
 * nothing defended it. Cloudflare's **Automatic SSL/TLS** enrolment moves a zone
 * to Full (strict) on its own once it thinks the origin has a valid certificate
 * — and while that enrolment is `auto`, Cloudflare ignores the manual `ssl`
 * value the sync writes. The sync therefore reported success on every run while
 * the zone stayed strict.
 *
 * Under Full (strict) Cloudflare validates the origin certificate, so any
 * tracker hostname whose Origin CA cert failed to install, expired, or is not
 * in the SAN list starts answering **error 526** — the whole redirect path for
 * that domain goes down, silently, with no code change to blame.
 *
 * Order matters: opt out of the automatic enrolment FIRST, then set the mode.
 * Doing it the other way round writes a value the automatic mode may discard.
 *
 * `full` and not `strict` is deliberate. Strict is the stronger setting, but the
 * deployment shape here — wildcard tracker hostnames, addon domains created at
 * runtime, and Origin CA installs reliable enough to need their own
 * `addondomain.cf_cert_installed` tracking column — means one failed install
 * equals one dead domain. Revisit strict only once that coverage is auditable.
 */
function cfPinSslMode(string $zoneId, string $token = ''): void
{
    $mode = strtolower(trim((string) app_env('CF_SSL_MODE', 'full')));
    if (!in_array($mode, ['off', 'flexible', 'full', 'strict'], true)) {
        $mode = 'full';
    }

    // Not every zone is enrolled in Automatic SSL/TLS, and the endpoint is not
    // available on every plan. A failure here must not abort the sync or spam
    // the error log — pinning the mode below is the part that matters, so this
    // call is made with failure tracking off and its outcome only logged.
    try {
        $resp = cfApi(
            'PATCH',
            '/zones/' . $zoneId . '/settings/ssl_automatic_mode',
            ['value' => 'custom'],
            $token,
            false,
        );

        if (empty($resp['success'])) {
            error_log('[cf-sync] ssl_automatic_mode not opted out (zone may not be enrolled): '
                . cfApiErrorSummary($resp));
        }
    } catch (Throwable $e) {
        error_log('[cf-sync] ssl_automatic_mode opt-out skipped: ' . $e->getMessage());
    }

    try {
        $resp = cfApi('PATCH', '/zones/' . $zoneId . '/settings/ssl', ['value' => $mode], $token);

        if (empty($resp['success'])) {
            cfSyncTrackError('ssl_mode: ' . cfApiErrorSummary($resp));
        }
    } catch (Throwable $e) {
        cfSyncTrackError('ssl_mode: ' . $e->getMessage());
    }
}

function cfSetSecurityLevel(string $zoneId, string $level, string $token = ''): bool
{
    try {
        $resp = cfApi('PATCH', '/zones/' . $zoneId . '/settings/security_level', ['value' => $level], $token);
        if (empty($resp['success'])) {
            $msg = (string) ($resp['errors'][0]['message'] ?? 'security-level-failed');
            cfSyncTrackError('security_level: ' . $msg);

            return false;
        }

        return true;
    } catch (Throwable $e) {
        cfSyncTrackError('security_level: ' . $e->getMessage());

        return false;
    }
}

/**
 * Enable HSTS with max-age 1 year, includeSubDomains, preload, nosniff.
 */
function cfApplyHsts(string $zoneId, string $token = ''): void
{
    try {
        cfApi('PATCH', '/zones/' . $zoneId . '/settings/security_header', [
            'value' => [
                'strict_transport_security' => [
                    'enabled'            => true,
                    'max_age'            => 31536000,
                    'include_subdomains' => true,
                    'preload'            => true,
                    'nosniff'            => true,
                ],
            ],
        ], $token);
    } catch (Throwable $e) {
        // Best-effort.
    }
}

// ---------------------------------------------------------------------------
// HTTP Response Headers Transform (disabled)
// ---------------------------------------------------------------------------

function cfApplyHeaderRules(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled: this project now avoids Cloudflare Rulesets API
    // during auto-provisioning to prevent plan-gated and expression-parse noise.
}

// ---------------------------------------------------------------------------
// Optional feature-specific endpoints (disabled)
// ---------------------------------------------------------------------------

function cfEnableClientSideSecurity(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled. Page Shield / connection monitor is entitlement-gated
    // and returns noisy warnings on zones without the feature.
}

function cfEnableLeakedCredentials(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled. The legacy /leaked-credential-checks endpoint can
    // return 10405 Method not allowed for API token auth on some accounts/plans.
}

/**
 * Disabled: custom firewall rules use Cloudflare Rulesets API.
 */
function cfApplyCustomFirewallRules(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled: this project now avoids Cloudflare Rulesets API
    // during auto-provisioning to prevent plan-gated and expression-parse noise.
}

/**
 * @deprecated Use cfApplyCustomFirewallRules().
 */
function cfAllowFacebookCrawler(string $zoneId, string $token = ''): void
{
    cfApplyFacebookOgWafSkipRule($zoneId, $token);
}

function cfFacebookOgWafSkipEnabled(): bool
{
    return cfEnvFlag('CF_ENABLE_FACEBOOK_OG_WAF_SKIP', false);
}

function cfFacebookOgCrawlerExpression(): string
{
    $uaNeedles = [
        'facebookexternalhit',
        'facebot',
        'facebookcatalog',
        'facebookbot',
        'meta-externalagent',
        'meta-externalfetcher',
    ];

    $uaExpressions = [];
    foreach ($uaNeedles as $needle) {
        $uaExpressions[] = 'lower(http.user_agent) contains "' . $needle . '"';
    }

    // ip.geoip.asnum is deprecated. Use ip.src.asnum for current Ruleset Engine rules.
    return '(ip.src.asnum in {32934 63293} and (' . implode(' or ', $uaExpressions) . '))';
}

/**
 * @return array<string, mixed>
 */
function cfFacebookOgWafSkipRule(): array
{
    return [
        'action' => 'skip',
        'action_parameters' => [
            // Skip the remaining rules in the current Custom Rules ruleset.
            'ruleset' => 'current',

            // Modern Ruleset Engine phases.
            'phases' => [
                'http_request_firewall_managed',
                'http_ratelimit',
            ],

            // Legacy/non-Ruleset security products where applicable.
            'products' => [
                'securityLevel',
                'waf',
                'rateLimit',
            ],
        ],
        'expression' => cfFacebookOgCrawlerExpression(),
        'description' => 'SRP: Skip WAF for Meta/Facebook OG crawler',
        'enabled' => true,
        'logging' => ['enabled' => false],
    ];
}

/**
 * Apply the Facebook OG crawler skip rule only when explicitly enabled.
 *
 * This is intentionally narrow: Meta ASN + Meta crawler UA. UA-only matching is
 * not allowed because it would become a spoofable WAF bypass.
 */
function cfApplyFacebookOgWafSkipRule(string $zoneId, string $token = ''): void
{
    if (!cfFacebookOgWafSkipEnabled()) {
        return;
    }

    $phase = 'http_request_firewall_custom';
    $rule = cfFacebookOgWafSkipRule();
    $entrypointPath = '/zones/' . $zoneId . '/rulesets/phases/' . $phase . '/entrypoints';

    try {
        $existing = cfApi('GET', $entrypointPath, null, $token, false, true);
        $httpCode = (int) ($existing['_http_code'] ?? 0);

        if (($existing['success'] ?? false) === true && !empty($existing['result']['id'])) {
            $rulesetId = (string) $existing['result']['id'];
            $rules = is_array($existing['result']['rules'] ?? null) ? $existing['result']['rules'] : [];
            $targetDescription = (string) $rule['description'];

            foreach ($rules as $existingRule) {
                if (!is_array($existingRule)) {
                    continue;
                }

                if ((string) ($existingRule['description'] ?? '') !== $targetDescription) {
                    continue;
                }

                $ruleId = (string) ($existingRule['id'] ?? '');
                if ($ruleId === '') {
                    continue;
                }

                cfApi(
                    'PUT',
                    '/zones/' . $zoneId . '/rulesets/' . $rulesetId . '/rules/' . $ruleId,
                    $rule,
                    $token,
                    true,
                    true,
                );

                return;
            }

            $firstRuleId = '';
            foreach ($rules as $existingRule) {
                if (is_array($existingRule) && !empty($existingRule['id'])) {
                    $firstRuleId = (string) $existingRule['id'];
                    break;
                }
            }

            if ($firstRuleId !== '') {
                $rule['position'] = ['before' => $firstRuleId];
            }

            cfApi(
                'POST',
                '/zones/' . $zoneId . '/rulesets/' . $rulesetId . '/rules',
                $rule,
                $token,
                true,
                true,
            );

            return;
        }

        if ($httpCode !== 404 && $httpCode !== 0) {
            $summary = cfApiErrorSummary($existing);
            cfSyncTrackError('GET ' . $entrypointPath . ' (http=' . $httpCode . '): ' . $summary);
            if (cfApiResponseHasAuthFailure($existing)) {
                cfSyncTrackAuthFailure('GET ' . $entrypointPath . ' (http=' . $httpCode . '): ' . $summary);
            }

            return;
        }

        cfApi(
            'POST',
            '/zones/' . $zoneId . '/rulesets',
            [
                'name' => 'SRP Facebook OG crawler WAF skip',
                'description' => 'Allow Meta/Facebook crawlers to fetch OG preview without challenge/block.',
                'kind' => 'zone',
                'phase' => $phase,
                'rules' => [$rule],
            ],
            $token,
            true,
            true,
        );
    } catch (Throwable $e) {
        // Best-effort. Transport/runtime errors are already tracked by cfApi().
    }
}

// ---------------------------------------------------------------------------
// DNS provisioning
// ---------------------------------------------------------------------------

/**
 * Provision exact DNS records matching the production template.
 */
function cfProvisionDns(string $zoneId, string $domain, string $serverIp, string $token = ''): array
{
    $desired = [
        ['type' => 'A',     'name' => '@',      'content' => $serverIp, 'proxied' => true],
        ['type' => 'A',     'name' => '*',      'content' => $serverIp, 'proxied' => true],
        ['type' => 'CNAME', 'name' => 'www',    'content' => $domain,   'proxied' => true],
        ['type' => 'MX',    'name' => '@',      'content' => '.',       'proxied' => false, 'priority' => 0],
        ['type' => 'TXT',   'name' => '@',      'content' => 'v=spf1 -all', 'proxied' => false],
        ['type' => 'TXT',   'name' => '_dmarc', 'content' => 'v=DMARC1; p=reject; adkim=s; aspf=s; pct=100', 'proxied' => false],
    ];

    $log = [];

    foreach ($desired as $rec) {
        try {
            $fullName = $rec['name'] === '@' ? $domain : $rec['name'] . '.' . $domain;

            $existing = cfApi(
                'GET',
                '/zones/' . $zoneId . '/dns_records?type=' . urlencode((string) $rec['type']) . '&name=' . urlencode($fullName),
                null,
                $token,
            );

            $body = [
                'type'    => $rec['type'],
                'name'    => $fullName,
                'content' => $rec['content'],
                'ttl'     => 1,
                'proxied' => $rec['proxied'],
            ];

            if ($rec['type'] === 'MX') {
                $body['priority'] = (int) $rec['priority'];
            }

            if (!empty($existing['result'][0]['id'])) {
                cfApi('PUT', '/zones/' . $zoneId . '/dns_records/' . $existing['result'][0]['id'], $body, $token);
                $log[] = 'updated:' . $rec['type'] . ':' . $fullName;
            } else {
                cfApi('POST', '/zones/' . $zoneId . '/dns_records', $body, $token);
                $log[] = 'created:' . $rec['type'] . ':' . $fullName;
            }
        } catch (Throwable $e) {
            $log[] = 'error:' . $rec['type'] . ':' . ($rec['name'] === '@' ? $domain : $rec['name'] . '.' . $domain) . ':' . $e->getMessage();
        }
    }

    return $log;
}

// ---------------------------------------------------------------------------
// Bot Fight Mode (force OFF)
// ---------------------------------------------------------------------------

function cfDisableBotFightMode(string $zoneId, string $token = ''): void
{
    // Bot Fight Mode challenges anything Cloudflare deems "likely automated",
    // which includes the Meta/Facebook OG crawlers this project depends on for
    // link previews — exactly the "Cf-Mitigated: challenge" 403 seen on tracker
    // zones. `fight_mode` is the Free-plan Bot Fight Mode flag, so unlike Super
    // Bot Fight Mode (`sbfm`) this call is not plan-gated.
    //
    // Not every zone is enrolled in Bot Management; on those zones this call
    // returns an error. That must not abort the sync or spam the warning list,
    // so failure tracking is off and the outcome is only logged.
    try {
        $resp = cfApi(
            'PUT',
            '/zones/' . $zoneId . '/bot_management',
            ['fight_mode' => false],
            $token,
            false,
        );

        if (empty($resp['success'])) {
            error_log('[cf-sync] bot_fight_mode off: ' . cfApiErrorSummary($resp));
        }
    } catch (Throwable $e) {
        error_log('[cf-sync] bot_fight_mode off skipped: ' . $e->getMessage());
    }
}

// ---------------------------------------------------------------------------
// Real User Monitoring (disabled)
// ---------------------------------------------------------------------------

function cfEnableRum(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled. RUM auto-install is optional and may return
    // authentication/entitlement noise for zone API tokens.
}

// ---------------------------------------------------------------------------
// Email Routing (disabled)
// ---------------------------------------------------------------------------

function cfEnableEmailRouting(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled. Email Routing conflicts with existing MX records
    // and must not be enabled automatically on production domains.
}

// ---------------------------------------------------------------------------
// Configuration Rule (disabled)
// ---------------------------------------------------------------------------

function cfApplyConfigRules(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled: this project now avoids Cloudflare Rulesets API
    // during auto-provisioning to prevent plan-gated and expression-parse noise.
}

// ---------------------------------------------------------------------------
// WAF Managed Rules (disabled)
// ---------------------------------------------------------------------------

function cfEnableWafManagedRules(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled: this project now avoids Cloudflare Rulesets API
    // during auto-provisioning to prevent plan-gated and expression-parse noise.
}

// ---------------------------------------------------------------------------
// Managed Transforms (disabled)
// ---------------------------------------------------------------------------

function cfApplyManagedTransforms(string $zoneId, string $token = ''): void
{
    try {
        cfApi('PATCH', '/zones/' . $zoneId . '/managed_headers', [
            'managed_response_headers' => [
                [
                    'id'      => 'remove_x-powered-by_header',
                    'enabled' => true,
                ],
                [
                    'id'      => 'add_security_headers',
                    'enabled' => true,
                ],
            ],
        ], $token);
    } catch (Throwable $e) {
        // Best-effort — transport/runtime errors are already tracked by cfApi().
    }
}

// ---------------------------------------------------------------------------
// Cache Rules (disabled)
// ---------------------------------------------------------------------------

function cfApplyCacheRules(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled: this project now avoids Cloudflare Rulesets API
    // during auto-provisioning to prevent plan-gated and expression-parse noise.
}

// ---------------------------------------------------------------------------
// Advanced Rate Limiting Rules (disabled)
// ---------------------------------------------------------------------------

function cfApplyRateLimitingRules(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled: this project now avoids Cloudflare Rulesets API
    // during auto-provisioning to prevent plan-gated and expression-parse noise.
}

// ---------------------------------------------------------------------------
// DNSSEC
// ---------------------------------------------------------------------------

function cfEnableDnssec(string $zoneId, string $token = ''): void
{
    try {
        cfApi('PATCH', '/zones/' . $zoneId . '/dnssec', ['status' => 'active'], $token);
    } catch (Throwable $e) {
        // Best-effort.
    }
}

// ---------------------------------------------------------------------------
// DDoS L7 Override (disabled)
// ---------------------------------------------------------------------------

function cfApplyDdosOverride(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled: this project now avoids Cloudflare Rulesets API
    // during auto-provisioning to prevent plan-gated and expression-parse noise.
}

// ---------------------------------------------------------------------------
// Native Bot Management removed
// ---------------------------------------------------------------------------

function cfEnableAiBotProtection(string $zoneId, string $token = ''): void
{
    unset($zoneId, $token);
    // Intentionally disabled. Native Bot Management requires specific plan and
    // token permissions. Custom WAF UA rules remain managed separately.
}

// ---------------------------------------------------------------------------
// Smart Performance
// ---------------------------------------------------------------------------

function cfEnableSmartPerformance(string $zoneId, string $token = ''): void
{
    try {
        cfApi('PATCH', '/zones/' . $zoneId . '/argo/tiered_caching', ['value' => 'on'], $token);
    } catch (Throwable $e) {
        // Best-effort.
    }

    // Smart Topology: lets Cloudflare pick the nearest upper-tier data center
    // automatically instead of requiring a manually-chosen single upper tier.
    // Free (Caching tab), and only meaningful once Tiered Cache above is on, so
    // it stays in this function rather than becoming its own call site. Separate
    // try/catch: a zone without Smart Topology entitlement must not abort the
    // tiered_caching PATCH above.
    try {
        cfApi('PATCH', '/zones/' . $zoneId . '/cache/tiered_cache_smart_topology_enable', ['value' => 'on'], $token);
    } catch (Throwable $e) {
        // Best-effort.
    }
}

/**
 * One-click Cloudflare Speed optimizations.
 *
 * Maps to the Cloudflare dashboard "Speed > Optimization > Recommendations"
 * toggles, plus the free Caching-tab setting Cloudflare pairs with Tiered
 * Cache by default. Applies only the settings that improve load times and
 * reliability: compression (Brotli), minification, HTTP/3 + 0-RTT, Early
 * Hints, HTTP/2 prioritization, font shaping, image optimization
 * (Polish/Mirage/Image Resizing/Speed Brain), browser cache TTL, aggressive
 * cache level, Always Online, and Argo Tiered Caching + Smart Topology.
 *
 * Deliberately NOT included: Argo Smart Routing and Cache Reserve. Both are
 * genuine Speed/Traffic recommendations but carry ongoing usage-based
 * Cloudflare billing (Argo: per-GB traffic; Cache Reserve: per-GB storage)
 * independent of the zone's plan — a "one-click optimize" action must not
 * silently start a new charge. Enable those manually in the CF dashboard if
 * wanted.
 *
 * Rocket Loader is intentionally NOT enabled here: nonce-based CSP pages must
 * not be rewritten (see cfApplySettings()).
 *
 * Every PATCH is best-effort. Plan-gated features (Polish, Mirage, Image
 * Resizing, Speed Brain) fail silently when the plan lacks them.
 */
function cfApplySpeedOptimizations(string $zoneId, string $token = ''): void
{
    $settings = [
        'brotli'            => ['value' => 'on'],
        'minify'            => ['value' => ['css' => 'on', 'html' => 'on', 'js' => 'on']],
        'http3'             => ['value' => 'on'],
        '0rtt'              => ['value' => 'on'],
        'early_hints'       => ['value' => 'on'],
        'h2_prioritization' => ['value' => 'on'],
        'fonts'             => ['value' => 'on'],
        'browser_cache_ttl' => ['value' => 14400],
        'cache_level'       => ['value' => 'aggressive'],
        'always_online'     => ['value' => 'on'],
    ];

    // Paid/add-on image & performance features. On by default so every
    // recommended setting is attempted; each PATCH stays best-effort, so on a
    // plan without the entitlement Cloudflare rejects it and it surfaces only
    // as a warning, never a hard failure. Set CF_APPLY_PAID_FEATURES=0 to
    // silence those warnings on a non-paid plan.
    if (cfEnvFlag('CF_APPLY_PAID_FEATURES', true)) {
        $settings += [
            'polish'         => ['value' => 'lossless'],
            'mirage'         => ['value' => 'on'],
            'image_resizing' => ['value' => 'on'],
            'speed_brain'    => ['value' => 'on'],
        ];
    }

    foreach ($settings as $key => $body) {
        if (cfSyncHasAuthFailure()) {
            return;
        }

        try {
            cfApi('PATCH', '/zones/' . $zoneId . '/settings/' . $key, $body, $token);
        } catch (Throwable $e) {
            // Best-effort — transport/runtime errors are already tracked by cfApi().
        }
    }

    // Argo Tiered Caching — reduces origin load and raises cache-hit ratio.
    cfEnableSmartPerformance($zoneId, $token);
}


// ---------------------------------------------------------------------------
// Cloudflare Origin CA + cPanel SSL installation
// ---------------------------------------------------------------------------

function cfNormalizeHostname(string $hostname): string
{
    $hostname = strtolower(rtrim(trim($hostname), '.'));
    if ($hostname === '' || strlen($hostname) > 253) {
        throw new RuntimeException('invalid-domain');
    }

    if (filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
        throw new RuntimeException('invalid-domain');
    }

    return $hostname;
}

function cfNormalizeCpanelSslDomain(string $hostname): string
{
    $hostname = strtolower(rtrim(trim($hostname), '.'));
    if (str_starts_with($hostname, '*.')) {
        $apex = cfNormalizeHostname(substr($hostname, 2));

        return '*.' . $apex;
    }

    return cfNormalizeHostname($hostname);
}

function cfOriginCertInstallTargetForDomain(string $domain): string
{
    $domain = cfNormalizeHostname($domain);
    $mode = strtolower(trim((string) app_env('CF_ORIGIN_CERT_INSTALL_TARGET', 'wildcard')));

    if (in_array($mode, ['apex', 'root', 'primary', 'domain'], true)) {
        return $domain;
    }

    // Default for SRP wildcard/multi-subdomain routing. Do not install the
    // generated Origin CA certificate on the primary/apex domain unless the env
    // explicitly asks for apex/root/primary/domain mode.
    return '*.' . $domain;
}

/**
 * Domains that must never receive auto-installed Origin CA certificates.
 * Use this to protect the SRP/app/control-panel domain, for example:
 *   CF_ORIGIN_CERT_EXCLUDE_DOMAINS=taaawon.com
 *
 * @return list<string>
 */
function cfOriginCertExcludedDomains(): array
{
    $values = [];

    foreach (['CF_ORIGIN_CERT_EXCLUDE_DOMAINS', 'APP_DOMAIN', 'SRP_APP_DOMAIN'] as $key) {
        $raw = trim((string) app_env($key, ''));
        if ($raw === '') {
            continue;
        }

        foreach (preg_split('/[,\s]+/', $raw) ?: [] as $item) {
            $item = trim($item);
            if ($item !== '') {
                $values[] = $item;
            }
        }
    }

    $appUrl = trim((string) app_env('APP_URL', ''));
    if ($appUrl !== '') {
        $host = parse_url($appUrl, PHP_URL_HOST);
        if (is_string($host) && trim($host) !== '') {
            $values[] = $host;
        }
    }

    $normalized = [];
    foreach ($values as $value) {
        try {
            $value = strtolower(trim($value));
            if (str_starts_with($value, '*.')) {
                $value = substr($value, 2);
            }
            $normalized[] = cfNormalizeHostname($value);
        } catch (Throwable $e) {
            // Ignore malformed exclude entry.
        }
    }

    return array_values(array_unique($normalized));
}

function cfAssertOriginCertAllowedDomain(string $sourceDomain, string $installDomain): void
{
    $sourceDomain = cfNormalizeHostname($sourceDomain);
    $installDomain = cfNormalizeCpanelSslDomain($installDomain);

    if (cfEnvFlag('CF_ORIGIN_CERT_REQUIRE_WILDCARD_TARGET', true) && !str_starts_with($installDomain, '*.')) {
        throw new RuntimeException('origin-cert-refused-non-wildcard-target: ' . $installDomain);
    }

    $installApex = str_starts_with($installDomain, '*.') ? substr($installDomain, 2) : $installDomain;
    foreach (cfOriginCertExcludedDomains() as $blockedDomain) {
        if ($sourceDomain === $blockedDomain || $installApex === $blockedDomain) {
            throw new RuntimeException('origin-cert-refused-app-domain: ' . $blockedDomain . ' is excluded; select a global/addon domain row instead');
        }
    }
}

function cfCpanelHost(): string
{
    $rawHost = trim((string) app_env('CPANEL_HOST', 'localhost'));
    $rawHost = preg_replace('#^https?://#i', '', $rawHost) ?? $rawHost;
    $rawHost = explode('/', $rawHost, 2)[0];
    if (str_contains($rawHost, ':')) {
        [$rawHost] = explode(':', $rawHost, 2);
    }

    if (function_exists('app_detect_cpanel_host')) {
        $rawHost = app_detect_cpanel_host($rawHost, (int) app_env('CPANEL_PORT', '2083'));
    } elseif (function_exists('app_normalize_cpanel_host')) {
        $rawHost = app_normalize_cpanel_host($rawHost);
    }

    return trim($rawHost) !== '' ? trim($rawHost) : 'localhost';
}

function cfCpanelPort(): int
{
    $port = (int) app_env('CPANEL_PORT', '2083');
    return ($port >= 1 && $port <= 65535) ? $port : 2083;
}

function cfCpanelSslVerify(): bool
{
    return cfEnvFlag('CPANEL_SSL_VERIFY', true);
}

/**
 * Cloudflare Origin CA root certificate bundle.
 * Use ECC root for origin-ecc certificates and RSA root for origin-rsa.
 */
function cfCloudflareOriginCaBundle(string $requestType): string
{
    $requestType = strtolower(trim($requestType));

    $eccRoot = <<<'PEM'
-----BEGIN CERTIFICATE-----
MIICiTCCAi6gAwIBAgIUXZP3MWb8MKwBE1Qbawsp1sfA/Y4wCgYIKoZIzj0EAwIw
gY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTgwNgYDVQQL
Ey9DbG91ZEZsYXJlIE9yaWdpbiBTU0wgRUNDIENlcnRpZmljYXRlIEF1dGhvcml0
eTAeFw0xOTA4MjMyMTA4MDBaFw0yOTA4MTUxNzAwMDBaMIGPMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEZ
MBcGA1UEChMQQ2xvdWRGbGFyZSwgSW5jLjE4MDYGA1UECxMvQ2xvdWRGbGFyZSBP
cmlnaW4gU1NMIEVDQyBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASR+sGALuaGshnUbcxKry+0LEXZ4NY6JUAtSeA6g87K3jaA
xpIg9G50PokpfWkhbarLfpcZu0UAoYy2su0EhN7wo2YwZDAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUhTBdOypw1O3VkmcH/es5
tBoOOKcwHwYDVR0jBBgwFoAUhTBdOypw1O3VkmcH/es5tBoOOKcwCgYIKoZIzj0E
AwIDSQAwRgIhAKilfntP2ILGZjwajktkBtXE1pB4Y/fjAfLkIRUzrI15AiEA5UCL
XYZZ9m2c3fKwIenMMojL1eqydsgqj/wK4p5kagQ=
-----END CERTIFICATE-----
PEM;

    $rsaRoot = <<<'PEM'
-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIID+rOSdTGfGcwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV
BAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91
ZEZsYXJlIE9yaWdpbiBTU0wgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlhMB4XDTE5MDgyMzIx
MDgwMFoXDTI5MDgxNTE3MDAwMFowgYsxCzAJBgNVBAYTAlVTMRkwFwYDVQQKExBD
bG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91ZEZsYXJlIE9yaWdpbiBTU0wg
Q2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMw
EQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAwEiVZ/UoQpHmFsHvk5isBxRehukP8DG9JhFev3WZtG76WoTthvLJFRKFCHXm
V6Z5/66Z4S09mgsUuFwvJzMnE6Ej6yIsYNCb9r9QORa8BdhrkNn6kdTly3mdnykb
OomnwbUfLlExVgNdlP0XoRoeMwbQ4598foiHblO2B/LKuNfJzAMfS7oZe34b+vLB
yrP/1bgCSLdc1AxQc1AC0EsQQhgcyTJNgnG4va1c7ogPlwKyhbDyZ4e59N5lbYPJ
SmXI/cAe3jXj1FBLJZkwnoDKe0v13xeF+nF32smSH0qB7aJX2tBMW4TWtFPmzs5I
lwrFSySWAdwYdgxw180yKU0dvwIDAQABo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUJOhTV118NECHqeuU27rhFnj8KaQw
HwYDVR0jBBgwFoAUJOhTV118NECHqeuU27rhFnj8KaQwDQYJKoZIhvcNAQELBQAD
ggEBAHwOf9Ur1l0Ar5vFE6PNrZWrDfQIMyEfdgSKofCdTckbqXNTiXdgbHs+TWoQ
wAB0pfJDAHJDXOTCWRyTeXOseeOi5Btj5CnEuw3P0oXqdqevM1/+uWp0CM35zgZ8
VD4aITxity0djzE6Qnx3Syzz+ZkoBgTnNum7d9A66/V636x4vTeqbZFBr9erJzgz
hhurjcoacvRNhnjtDRM0dPeiCJ50CP3wEYuvUzDHUaowOsnLCjQIkWbR7Ni6KEIk
MOz2U0OBSif3FTkhCgZWQKOOLo1P42jHC3ssUZAtVNXrCk3fw9/E15k8NPkBazZ6
0iykLhH1trywrKRMVw67F44IE8Y=
-----END CERTIFICATE-----
PEM;

    return $requestType === 'origin-ecc' ? $eccRoot . PHP_EOL : $rsaRoot . PHP_EOL;
}

/**
 * @return array{key:string, csr:string, request_type:string}
 */
function cfGenerateOriginCsr(string $commonName, string $requestType): array
{
    if (!extension_loaded('openssl')) {
        throw new RuntimeException('openssl-extension-missing');
    }

    $requestType = strtolower(trim($requestType));
    if (!in_array($requestType, ['origin-ecc', 'origin-rsa'], true)) {
        $requestType = 'origin-ecc';
    }

    $config = [
        'digest_alg'       => 'sha256',
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    if ($requestType === 'origin-ecc' && defined('OPENSSL_KEYTYPE_EC')) {
        $config['private_key_type'] = OPENSSL_KEYTYPE_EC;
        $config['curve_name'] = 'prime256v1';
    } else {
        $requestType = 'origin-rsa';
    }

    $privateKey = openssl_pkey_new($config);
    if ($privateKey === false) {
        throw new RuntimeException('origin-key-generate-failed');
    }

    $dn = [
        'commonName'       => $commonName,
        'organizationName' => 'SRP Origin',
    ];

    $csr = openssl_csr_new($dn, $privateKey, ['digest_alg' => 'sha256']);
    if ($csr === false) {
        throw new RuntimeException('origin-csr-generate-failed');
    }

    $keyPem = '';
    if (!openssl_pkey_export($privateKey, $keyPem)) {
        throw new RuntimeException('origin-key-export-failed');
    }

    $csrPem = '';
    if (!openssl_csr_export($csr, $csrPem)) {
        throw new RuntimeException('origin-csr-export-failed');
    }

    return ['key' => $keyPem, 'csr' => $csrPem, 'request_type' => $requestType];
}

/**
 * @return array{certificate:string,id:string,expires_on:string,request_type:string,hostnames:list<string>,install_domain:string,private_key:string}
 */
function cfCreateOriginCertificate(string $domain, string $token = ''): array
{
    $domain = cfNormalizeHostname($domain);
    $installDomain = cfOriginCertInstallTargetForDomain($domain);
    cfAssertOriginCertAllowedDomain($domain, $installDomain);

    $oneCertPerWildcard = cfEnvFlag('CF_ORIGIN_CERT_ONE_CERT_PER_DOMAIN', true);
    if ($oneCertPerWildcard) {
        // SRP rule: one global/addon domain wildcard equals one Origin CA cert.
        // Do not combine app domain, apex domain, or other global domains into
        // the same certificate SAN list.
        if (!str_starts_with($installDomain, '*.')) {
            throw new RuntimeException('origin-cert-refused-non-wildcard-target: ' . $installDomain);
        }

        $expectedWildcard = '*.' . $domain;
        if ($installDomain !== $expectedWildcard) {
            throw new RuntimeException('origin-cert-refused-cross-domain-target: source=' . $domain . ' install=' . $installDomain);
        }
    }

    $requestType = strtolower(trim((string) app_env('CF_ORIGIN_CERT_TYPE', 'origin-ecc')));
    $csrBundle = cfGenerateOriginCsr($installDomain, $requestType);
    $requestType = $csrBundle['request_type'];

    $validity = (int) app_env('CF_ORIGIN_CERT_VALIDITY_DAYS', '5475');
    if (!in_array($validity, [7, 30, 90, 365, 730, 1095, 5475], true)) {
        $validity = 5475;
    }

    if ($oneCertPerWildcard) {
        $hostnames = [$installDomain];
    } else {
        $hostnames = [$installDomain];

        if ($installDomain === $domain && cfEnvFlag('CF_ORIGIN_CERT_INCLUDE_WILDCARD', true)) {
            $hostnames[] = '*.' . $domain;
        }

        if ($installDomain === '*.' . $domain && cfEnvFlag('CF_ORIGIN_CERT_INCLUDE_APEX', false)) {
            $hostnames[] = $domain;
        }

        $hostnames = array_values(array_unique($hostnames));
    }

    $resp = cfApi('POST', '/certificates', [
        'csr'                => $csrBundle['csr'],
        'hostnames'          => $hostnames,
        'request_type'       => $requestType,
        'requested_validity' => $validity,
    ], $token);

    if (empty($resp['success']) || empty($resp['result']['certificate'])) {
        throw new RuntimeException('origin-cert-create-failed: ' . cfApiErrorSummary($resp));
    }

    $result = $resp['result'];

    return [
        'certificate'     => (string) $result['certificate'],
        'id'              => (string) ($result['id'] ?? ''),
        'expires_on'      => (string) ($result['expires_on'] ?? ''),
        'request_type'    => $requestType,
        'hostnames'       => array_values(array_filter($hostnames, 'is_string')),
        'install_domain'  => $installDomain,
        'private_key'     => $csrBundle['key'],
    ];
}

/**
 * @return array<string, mixed>
 */
function cfCpanelUapi(string $module, string $function, array $params): array
{
    $user = trim((string) app_required_env('CPANEL_USER'));
    $token = trim((string) app_env('CPANEL_API_TOKEN', ''));
    $password = (string) app_env('CPANEL_PASSWORD', '');

    if ($token === '' && $password === '') {
        throw new RuntimeException('cpanel-auth-missing');
    }

    $url = 'https://' . cfCpanelHost() . ':' . cfCpanelPort()
        . '/execute/' . rawurlencode($module) . '/' . rawurlencode($function);

    $curl = curl_init($url);
    if ($curl === false) {
        throw new RuntimeException('cpanel-curl-init-failed');
    }

    $headers = ['Accept: application/json'];
    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query($params),
        CURLOPT_SSL_VERIFYHOST => cfCpanelSslVerify() ? 2 : 0,
        CURLOPT_SSL_VERIFYPEER => cfCpanelSslVerify(),
        CURLOPT_HTTPHEADER     => $headers,
    ];

    if ($token !== '') {
        $options[CURLOPT_HTTPHEADER] = array_merge($headers, ['Authorization: cpanel ' . $user . ':' . $token]);
    } else {
        $options[CURLOPT_HTTPAUTH] = CURLAUTH_BASIC;
        $options[CURLOPT_USERPWD] = $user . ':' . $password;
    }

    curl_setopt_array($curl, $options);
    $raw = curl_exec($curl);
    $errno = curl_errno($curl);
    $error = curl_error($curl);
    $httpCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if ($raw === false || $errno !== 0) {
        throw new RuntimeException('cpanel-transport-failed: ' . ($error !== '' ? $error : curl_strerror($errno)));
    }

    $data = json_decode((string) $raw, true);
    if (!is_array($data)) {
        throw new RuntimeException('cpanel-non-json-response');
    }
    $data['_http_code'] = $httpCode;

    if ($httpCode < 200 || $httpCode >= 300) {
        throw new RuntimeException('cpanel-http-' . $httpCode);
    }

    return $data;
}

/**
 * Strip any PEM block (private key, certificate, CSR) from upstream error text
 * before it is logged or returned. cfCpanelUapiError() reads this off a cPanel
 * response to a call whose request body just carried the origin certificate's
 * private key and cert in plaintext (cfInstallSslToCpanel()); some APIs echo
 * back invalid input verbatim in their error text. Same rationale as
 * cf_create_token.php's Bearer-token redaction on Cloudflare error messages —
 * never trust upstream error text not to contain the secret that was just sent.
 */
function cfRedactPemBlocks(string $text): string
{
    return preg_replace('/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/', '[redacted]', $text)
        ?? '[redacted]';
}

function cfCpanelUapiError(array $resp): string
{
    $errors = [];
    foreach (['errors', 'messages', 'warnings'] as $key) {
        if (!empty($resp[$key]) && is_array($resp[$key])) {
            foreach ($resp[$key] as $item) {
                if (is_string($item) && trim($item) !== '') {
                    $errors[] = trim($item);
                }
            }
        }
    }

    if (!empty($resp['data']['errors']) && is_array($resp['data']['errors'])) {
        foreach ($resp['data']['errors'] as $item) {
            if (is_string($item) && trim($item) !== '') {
                $errors[] = trim($item);
            }
        }
    }

    if (isset($resp['error']) && is_string($resp['error']) && trim($resp['error']) !== '') {
        $errors[] = trim($resp['error']);
    }

    $summary = $errors !== [] ? implode('; ', array_unique($errors)) : 'cpanel-uapi-error';

    return cfRedactPemBlocks($summary);
}

/**
 * Install a Cloudflare Origin CA certificate in cPanel.
 * The cabundle is mandatory for cPanel to verify Cloudflare Origin CA.
 */
function cfInstallSslToCpanel(string $domain, string $certificatePem, string $privateKeyPem, string $requestType): void
{
    $domain = cfNormalizeCpanelSslDomain($domain);
    $caBundle = cfCloudflareOriginCaBundle($requestType);

    $params = [
        'domain'   => $domain,
        'cert'     => $certificatePem,
        'key'      => $privateKeyPem,
        'cabundle' => $caBundle,
    ];

    $resp = cfCpanelUapi('SSL', 'install_ssl', $params);
    $status = (int) ($resp['status'] ?? 0);
    if ($status !== 1) {
        $message = cfCpanelUapiError($resp);
        throw new RuntimeException('cpanel-install-ssl-failed: ' . $message);
    }
}

/**
 * @return array<string, mixed>
 */
function cfCreateAndInstallOriginCertificate(string $zoneId, string $domain, string $token = ''): array
{
    $zoneId = trim($zoneId);
    if (preg_match('/^[a-f0-9]{32}$/i', $zoneId) !== 1) {
        throw new RuntimeException('invalid-zone-id');
    }

    $created = cfCreateOriginCertificate($domain, $token);
    $requestType = (string) $created['request_type'];

    $installDomain = (string) ($created['install_domain'] ?? cfOriginCertInstallTargetForDomain($domain));

    cfInstallSslToCpanel(
        $installDomain,
        (string) $created['certificate'],
        (string) $created['private_key'],
        $requestType,
    );

    // Default OFF since the 526 incident. This used to default ON, and the
    // combination was the bug: the certificate installed above covers only
    // `*.domain` (CF_ORIGIN_CERT_ONE_CERT_PER_DOMAIN forces a single-wildcard
    // SAN list, and CF_ORIGIN_CERT_INSTALL_TARGET defaults to the wildcard), yet
    // flipping the zone to strict makes Cloudflare validate the origin
    // certificate for EVERY hostname on it. The apex — served by the root
    // index.php — is not in that SAN list, so it began answering
    // **526 Invalid SSL certificate** the moment a cert was installed. Narrow
    // the coverage, widen the validation.
    //
    // SSL mode now has exactly one owner: cfPinSslMode(), which pins CF_SSL_MODE
    // (full) on every sync. Turning this back on without also widening the SAN
    // list re-creates the outage, and the next sync would flip it back anyway.
    if (cfEnvFlag('CF_ORIGIN_CERT_SET_STRICT', false)) {
        $resp = cfApi('PATCH', '/zones/' . $zoneId . '/settings/ssl', ['value' => 'strict'], $token);
        if (empty($resp['success'])) {
            throw new RuntimeException('origin-cert-strict-mode-failed: ' . cfApiErrorSummary($resp));
        }
    }

    return [
        'ok'           => true,
        'installed'    => true,
        'ssl_mode'     => cfEnvFlag('CF_ORIGIN_CERT_SET_STRICT', false) ? 'strict' : 'unchanged',
        'cert_id'      => $created['id'],
        'expires_on'   => $created['expires_on'],
        'source_domain' => cfNormalizeHostname($domain),
        'install_domain' => $installDomain,
        'cpanel_api_host' => cfCpanelHost(),
        'request_type' => $requestType,
        'hostnames'    => $created['hostnames'],
        'cert_scope'   => cfEnvFlag('CF_ORIGIN_CERT_ONE_CERT_PER_DOMAIN', true) ? 'single-wildcard' : 'custom-san',
    ];
}

/**
 * Remove the installed Cloudflare Origin CA certificate for a domain and
 * trigger cPanel's own AutoSSL to issue a publicly-trusted certificate
 * (normally Let's Encrypt) in its place.
 *
 * Not atomic: removal and AutoSSL issuance are two independent cPanel
 * operations with no combined "swap" primitive, and AutoSSL is not
 * synchronous — start_autossl_check() only queues/starts the check, it does
 * not wait for a certificate to be issued and installed. There is a real
 * window, from seconds to a few minutes depending on account load, where the
 * domain has no valid SSL certificate at all. Callers driving a UI must
 * surface this to the operator before calling.
 *
 * AutoSSL triggered this way is account-wide (this cPanel account's
 * user-level UAPI does not expose a per-domain AutoSSL trigger, only WHM's
 * root-level API does, which this app does not have credentials for) — it
 * checks every domain on the account, not just this one, so it may take a
 * while and is not scoped to $domain.
 *
 * @return array{ok: bool, removed: bool, autossl_triggered: bool, install_domain: string, cpanel_api_host: string}
 */
function cfReplaceOriginCertWithCpanelSsl(string $domain): array
{
    $installDomain = cfOriginCertInstallTargetForDomain($domain);
    $cpanelDomain = cfNormalizeCpanelSslDomain($installDomain);

    $removed = false;
    try {
        $resp = cfCpanelUapi('SSL', 'delete_ssl', ['domain' => $cpanelDomain]);
        $status = (int) ($resp['status'] ?? 0);
        if ($status === 1) {
            $removed = true;
        } else {
            $message = cfCpanelUapiError($resp);
            // "No SSL installed for this domain" is not a failure for this
            // caller's purpose — there is nothing to remove, which is fine;
            // proceed to trigger AutoSSL regardless. Any other error is
            // reported but does not block the AutoSSL trigger below: leaving
            // a stale Origin CA cert in place is strictly better than also
            // skipping the one action that can actually fix it.
            error_log('[cf-origin-cert] delete_ssl for ' . $cpanelDomain . ' — ' . $message);
        }
    } catch (Throwable $e) {
        error_log('[cf-origin-cert] delete_ssl for ' . $cpanelDomain . ' threw: ' . $e->getMessage());
    }

    $autosslTriggered = false;
    try {
        $resp = cfCpanelUapi('SSL', 'start_autossl_check', []);
        $autosslTriggered = (int) ($resp['status'] ?? 0) === 1;
        if (!$autosslTriggered) {
            error_log('[cf-origin-cert] start_autossl_check failed: ' . cfCpanelUapiError($resp));
        }
    } catch (Throwable $e) {
        error_log('[cf-origin-cert] start_autossl_check threw: ' . $e->getMessage());
    }

    return [
        'ok' => $removed || $autosslTriggered,
        'removed' => $removed,
        'autossl_triggered' => $autosslTriggered,
        'install_domain' => $cpanelDomain,
        'cpanel_api_host' => cfCpanelHost(),
    ];
}

// ---------------------------------------------------------------------------
// Token Self-Provisioning
// ---------------------------------------------------------------------------

/**
 * @return array<string, mixed>
 */
function cfCreateTokenDiscoverPermissions(string $token): array
{
    try {
        $resp = cfApi('GET', '/user/tokens/permission_groups', null, $token);

        if (!($resp['success'] ?? false) || empty($resp['result'])) {
            return [];
        }

        $map = [
            '_by_scope' => [],
            '_groups'   => [],
        ];

        foreach ($resp['result'] as $group) {
            $id   = (string) ($group['id'] ?? '');
            $name = (string) ($group['name'] ?? '');

            if ($id === '' || $name === '') {
                continue;
            }

            $scopes = $group['scopes'] ?? ($group['meta']['scopes'] ?? []);
            if (is_string($scopes)) {
                $scopes = [$scopes];
            }

            if (!is_array($scopes)) {
                $scopes = [];
            }

            $key = cfPermissionKey($name);
            $entry = [
                'id'     => $id,
                'name'   => $name,
                'key'    => $key,
                'scopes' => array_values(array_filter($scopes, 'is_string')),
            ];

            $map['_groups'][] = $entry;

            if (!isset($map[$key])) {
                $map[$key] = $id;
            }

            foreach ($entry['scopes'] as $scope) {
                if (!isset($map['_by_scope'][$scope])) {
                    $map['_by_scope'][$scope] = [];
                }

                $map['_by_scope'][$scope][$key] = $entry;
            }
        }

        return $map;
    } catch (Throwable $e) {
        return [];
    }
}

function cfPermissionKey(string $name): string
{
    $key = strtolower(trim($name));

    return preg_replace('/[^a-z0-9]+/', '_', $key) ?? $key;
}

/**
 * @param array<string, mixed> $permGroups
 * @param array<int, string> $keys
 * @return array<int, array{id: string}>
 */
function cfPermissionIdsForScope(array $permGroups, string $scope, array $keys): array
{
    $scoped = $permGroups['_by_scope'][$scope] ?? [];

    if (!is_array($scoped)) {
        return [];
    }

    $ids = [];

    foreach ($keys as $key) {
        if (!empty($scoped[$key]['id']) && is_string($scoped[$key]['id'])) {
            $ids[] = ['id' => $scoped[$key]['id']];
        }
    }

    return $ids;
}

/**
 * @param array<string, mixed> $permGroups
 * @return array<string, mixed>
 */
function cfCreateZoneToken(
    string $creatingToken,
    string $accountId,
    string $name,
    array $permGroups,
): array {
    $zonePermKeys = [
        'zone_write',
        'zone_settings_write',
        'dns_write',
        'ssl_and_certificates_write',
        'managed_headers_write',
        'transform_rules_write',
        'cache_purge',
        'zone_read',
    ];

    $zonePermIds = cfPermissionIdsForScope($permGroups, 'com.cloudflare.api.account.zone', $zonePermKeys);

    if ($zonePermIds === []) {
        return ['ok' => false, 'error' => 'missing-zone-permission-groups'];
    }

    $accountResource = ($accountId !== '')
        ? 'com.cloudflare.api.account.' . $accountId
        : 'com.cloudflare.api.account.*';

    $zoneResources = ($accountId !== '')
        ? [$accountResource => ['com.cloudflare.api.account.zone.*' => '*']]
        : ['com.cloudflare.api.account.zone.*' => '*'];

    $policies = [
        [
            'effect'            => 'allow',
            'resources'         => $zoneResources,
            'permission_groups' => $zonePermIds,
        ],
    ];

    $createPermIds = array_merge(
        cfPermissionIdsForScope($permGroups, 'com.cloudflare.api.account.zone', ['zone_write']),
        cfPermissionIdsForScope($permGroups, 'com.cloudflare.api.account', ['account_settings_read']),
    );

    if ($createPermIds !== []) {
        $policies[] = [
            'effect'            => 'allow',
            'resources'         => [$accountResource => '*'],
            'permission_groups' => $createPermIds,
        ];
    }

    try {
        $resp = cfApi('POST', '/user/tokens', [
            'name'     => $name,
            'policies' => $policies,
        ], $creatingToken);

        if (!($resp['success'] ?? false)) {
            $msg = (string) ($resp['errors'][0]['message'] ?? 'cf-api-error');

            return ['ok' => false, 'error' => $msg];
        }

        $result = $resp['result'] ?? [];

        return [
            'ok'    => true,
            'token' => (string) ($result['value'] ?? ''),
            'id'    => (string) ($result['id'] ?? ''),
            'name'  => (string) ($result['name'] ?? $name),
        ];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

// ---------------------------------------------------------------------------
// One-click: apply ALL recommended settings at once
// ---------------------------------------------------------------------------

function cfApplyAllRecommended(string $zoneId, string $token = ''): void
{
    $preflight = cfPreflightZoneAccess($zoneId, $token);
    if (empty($preflight['ok'])) {
        cfSyncTrackAuthFailure((string) ($preflight['err'] ?? 'cf-zone-preflight-failed'));
        return;
    }

    /** @var list<callable(string, string): void> $steps */
    $steps = [
        // Core zone settings plus Managed Transforms only. Rulesets API calls are intentionally removed.
        'cfApplySettings',
        // Bot Fight Mode must be off on tracker zones or Meta/Facebook OG
        // crawlers get "Cf-Mitigated: challenge" and previews break. Free-plan
        // flag, best-effort, applied right after the baseline security settings.
        'cfDisableBotFightMode',
        // Runs after cfApplySettings, not before: it opts the zone out of
        // Cloudflare's Automatic SSL/TLS enrolment and then re-asserts the mode,
        // so it must have the last word on `ssl`. See cfPinSslMode() for why a
        // zone drifting to Full (strict) takes the redirect path down with 526.
        'cfPinSslMode',
        'cfEnableSmartPerformance',
        'cfApplyHsts',
        'cfApplyManagedTransforms',
        'cfApplyFacebookOgWafSkipRule',
        'cfEnableDnssec',

        // Optional entitlement-gated endpoints remain disabled:
        // Page Shield, RUM auto-install, Email Routing, broad Rulesets, and Bot features.
        // The Facebook OG crawler WAF skip rule is opt-in via CF_ENABLE_FACEBOOK_OG_WAF_SKIP=1.
    ];

    foreach ($steps as $step) {
        if (cfSyncHasAuthFailure()) {
            return;
        }

        $step($zoneId, $token);
    }
}
