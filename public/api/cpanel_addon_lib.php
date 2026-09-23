<?php

declare(strict_types=1);

/**
 * Shared cPanel addon-domain helper.
 * No output, no session mutation, no secrets in logs/responses.
 */

function addonLoadEnvFileFallback(string $path): void
{
    if (!is_file($path) || !is_readable($path)) {
        return;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }

        [$key, $value] = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);

        if ($key === '' || preg_match('/^[A-Z0-9_]+$/i', $key) !== 1) {
            continue;
        }

        if (
            (str_starts_with($value, '"') && str_ends_with($value, '"'))
            || (str_starts_with($value, "'") && str_ends_with($value, "'"))
        ) {
            $value = substr($value, 1, -1);
        }

        if (getenv($key) === false) {
            putenv($key . '=' . $value);
            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
        }
    }
}

function addonEnv(string $key, ?string $default = null): ?string
{
    if (function_exists('app_env')) {
        $value = app_env($key, $default);

        return $value === null ? $default : (string) $value;
    }

    $value = getenv($key);
    if ($value === false) {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? null;
    }

    if ($value === null) {
        return $default;
    }

    return (string) $value;
}

function addonNormalizeCpanelRedirectDir(string $value): string
{
    $dir = trim(str_replace('\\', '/', $value));
    $dir = trim($dir, "/ \t\n\r\0\x0B");
    if ($dir === '') {
        $dir = 'public_html';
    }

    return str_ends_with(strtolower($dir), '/redirect') ? $dir : $dir . '/redirect';
}

/**
 * @return array{ok: bool, error: string}
 */
function addonBootstrapCpanelDependencies(): array
{
    static $loaded = false;
    static $result = ['ok' => true, 'error' => ''];

    if ($loaded) {
        return $result;
    }

    $loaded = true;
    $projectRoot = dirname(__DIR__);
    $accountRoot = dirname(__DIR__, 2);

    $xmlApiPath = $projectRoot . '/xmlapi.php';
    if (!is_file($xmlApiPath)) {
        error_log('addon-domain-lib: missing xmlapi.php');
        $result = ['ok' => false, 'error' => 'cpanel-client-unavailable'];

        return $result;
    }

    require_once $xmlApiPath;

    foreach ([$projectRoot . '/env.php', $accountRoot . '/env.php'] as $envBootstrapPath) {
        if (is_file($envBootstrapPath)) {
            require_once $envBootstrapPath;
            break;
        }
    }

    foreach ([$projectRoot . '/.env', $accountRoot . '/.env'] as $envPath) {
        if (function_exists('load_env_file')) {
            load_env_file($envPath);
        } else {
            addonLoadEnvFileFallback($envPath);
        }
    }

    if (!class_exists('xmlapi')) {
        error_log('addon-domain-lib: xmlapi class unavailable');
        $result = ['ok' => false, 'error' => 'cpanel-client-unavailable'];

        return $result;
    }

    $result = ['ok' => true, 'error' => ''];

    return $result;
}

function addonNormalizeDomain(string $domain): ?string
{
    $domain = strtolower(trim($domain));
    $domain = preg_replace('/^https?:\/\//i', '', $domain) ?? '';
    $domain = trim($domain, " \t\n\r\0\x0B./");

    if ($domain === '' || strlen($domain) > 253) {
        return null;
    }

    if (preg_match('/[\/\\:@?#\[\]]/', $domain) === 1) {
        return null;
    }

    if (preg_match('/^(localhost|localdomain)$/i', $domain) === 1) {
        return null;
    }

    if (filter_var($domain, FILTER_VALIDATE_IP) !== false) {
        return null;
    }

    if (preg_match('/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $domain) !== 1) {
        return null;
    }

    return $domain;
}

function addonSafeLogText(string $text): string
{
    $text = preg_replace('/(token|password|pass|authorization|auth|secret)[^,}]{0,160}/i', '$1-redacted', $text) ?? $text;
    $text = preg_replace('/[^a-z0-9._:@=+\-\/\s]+/i', ' ', $text) ?? $text;
    $text = trim(preg_replace('/\s+/', ' ', $text) ?? $text);

    return substr($text, 0, 260);
}

/**
 * @return array{host:string, port:int}
 */
function addonCpanelEndpointFromEnv(): array
{
    $rawHost = trim((string) addonEnv('CPANEL_HOST', 'localhost'));
    $rawPort = trim((string) addonEnv('CPANEL_PORT', '2083'));

    $rawHost = preg_replace('#^https?://#i', '', $rawHost) ?? $rawHost;
    $rawHost = explode('/', $rawHost, 2)[0];
    $parsedPort = 0;

    if (str_contains($rawHost, ':')) {
        [$hostPart, $portPart] = explode(':', $rawHost, 2);
        $rawHost = $hostPart;
        $parsedPort = (int) $portPart;
    }

    $host = function_exists('app_normalize_cpanel_host')
        ? app_normalize_cpanel_host($rawHost)
        : trim($rawHost);
    if ($host === '') {
        $host = 'localhost';
    }

    $port = (int) $rawPort;
    if ($port < 1 || $port > 65535) {
        $port = $parsedPort > 0 ? $parsedPort : 2083;
    }

    if (function_exists('app_detect_cpanel_host')) {
        $host = app_detect_cpanel_host($host, $port);
    }

    return ['host' => $host, 'port' => $port];
}

function addonMakeCpanelClient(): xmlapi
{
    $endpoint = addonCpanelEndpointFromEnv();

    $client = new xmlapi($endpoint['host']);
    $client->set_port($endpoint['port']);
    $client->set_output('json');
    $client->set_debug(0);

    if (method_exists($client, 'set_protocol')) {
        $client->set_protocol('https');
    }

    return $client;
}

/**
 * @return array<string, mixed>|null
 */
function addonNormalizeCpanelResult(mixed $result): ?array
{
    if ($result === null || $result === false) {
        return null;
    }

    if (is_string($result)) {
        $decoded = json_decode($result, true);

        return is_array($decoded) ? $decoded : ['raw' => $result];
    }

    if (is_array($result)) {
        return $result;
    }

    if (is_object($result)) {
        $encoded = json_encode($result);
        if ($encoded === false) {
            return ['object' => get_class($result)];
        }

        $decoded = json_decode($encoded, true);

        return is_array($decoded) ? $decoded : ['object' => get_class($result)];
    }

    return ['raw' => (string) $result];
}

function addonStringContainsAny(string $text, array $needles): bool
{
    $text = strtolower($text);
    foreach ($needles as $needle) {
        if (str_contains($text, strtolower((string) $needle))) {
            return true;
        }
    }

    return false;
}

function addonCpanelResultText(array $data): string
{
    $encoded = json_encode($data);
    if ($encoded === false) {
        return '';
    }

    return strtolower($encoded);
}

/**
 * Normalize cpanelresult.data into a list of rows (API2 may return a single
 * associative row or a list of rows).
 *
 * @return array<int, array<string, mixed>>
 */
function addonCpanelResultRows(array $data): array
{
    $rows = $data['cpanelresult']['data'] ?? null;
    if (!is_array($rows)) {
        return [];
    }

    // single associative row → wrap as list
    if (array_key_exists('result', $rows) || array_key_exists('reason', $rows)) {
        return [$rows];
    }

    return array_values(array_filter($rows, 'is_array'));
}

/**
 * Phrases that unambiguously mean "cPanel rejected this operation".
 *
 * Checked BEFORE the already-exists tolerance, because several rejection texts
 * contain the substring "exists" themselves ("does not exist", "exists on
 * another account"). Without that ordering a hard rejection is read as a benign
 * idempotent re-run — which is how a failed park once slipped through and
 * resurfaced later as an opaque wildcard error.
 *
 * @return list<string>
 */
function addonCpanelHardFailurePhrases(): array
{
    return [
        'does not belong',
        'not belong to',
        'does not exist',
        'owned by another user',
        'another account',
        'not owned',
        'do not own',
        'permission denied',
        'access denied',
        'not authorized',
        'not allowed',
        'invalid domain',
    ];
}

/**
 * Phrases meaning "already provisioned", i.e. a safe idempotent re-run.
 *
 * Deliberately does NOT include a bare "exists": that matched failure texts too.
 * Losing a little tolerance here is cheap because every caller re-verifies the
 * real state afterwards (addonCpanelWaitParked / addonCpanelWildcardExists), so
 * a false "not ok" costs one extra check, while a false "ok" hides a failure.
 *
 * @return list<string>
 */
function addonCpanelAlreadyDonePhrases(): array
{
    return ['already', 'is configured', 'already configured'];
}

/**
 * Did a cPanel API2/UAPI call succeed?
 *
 * Fails CLOSED: anything this function cannot positively interpret is reported
 * as not-ok and logged. That is safe here because both call sites treat it as a
 * hint only and confirm the real state with a follow-up query — so a false
 * negative costs a re-check, whereas the old fail-open default let a rejected
 * operation continue as if it had worked.
 */
function addonCpanelResultIsOk(mixed $result, bool $allowAlreadyExists): bool
{
    $data = addonNormalizeCpanelResult($result);
    if ($data === null) {
        return false;
    }

    // A hard rejection anywhere in the payload settles it, whatever the shape.
    if (addonStringContainsAny(addonCpanelResultText($data), addonCpanelHardFailurePhrases())) {
        return false;
    }

    $cpanel = $data['cpanelresult'] ?? null;
    if (is_array($cpanel)) {
        // API-level error (bad params, auth, module disabled, …)
        $apiError = trim((string) ($cpanel['error'] ?? ''));
        if ($apiError !== '') {
            return $allowAlreadyExists
                && addonStringContainsAny($apiError, addonCpanelAlreadyDonePhrases());
        }

        // event.result === 0 → the API call itself failed
        $eventResult = $cpanel['event']['result'] ?? null;
        if ($eventResult !== null && (int) $eventResult !== 1) {
            return false;
        }

        // per-operation result is the source of truth for API2
        foreach (addonCpanelResultRows($data) as $row) {
            if (!array_key_exists('result', $row)) {
                continue;
            }

            if ((int) $row['result'] === 1) {
                return true;
            }

            $reason = strtolower((string) ($row['reason'] ?? ''));
            if ($allowAlreadyExists && addonStringContainsAny($reason, addonCpanelAlreadyDonePhrases())) {
                return true;
            }

            return false;
        }

        // call executed and no row-level failure was reported
        if ($eventResult !== null) {
            return (int) $eventResult === 1;
        }
    }

    // UAPI shape fallbacks
    $uapiStatus = $data['result']['status'] ?? null;
    if ($uapiStatus !== null) {
        return (int) $uapiStatus === 1;
    }

    $status = $data['status'] ?? null;
    if ($status !== null) {
        return (int) $status === 1;
    }

    // textual last resort (hard-failure phrases were already ruled out above)
    $text = addonCpanelResultText($data);
    if ($allowAlreadyExists && addonStringContainsAny($text, ['already exists', 'already configured', 'is already configured'])) {
        return true;
    }

    if (addonStringContainsAny($text, ['"error"', '"errors"']) && addonStringContainsAny($text, ['failed', 'denied', 'invalid'])) {
        return false;
    }

    // Unrecognised shape. Fail closed and leave a trace: the caller will confirm
    // the real state anyway, and without this line an unknown response used to
    // pass silently as success.
    error_log('addon-domain-lib: unrecognised cPanel result shape, treating as failure — ' . addonSafeLogText($text));

    return false;
}

/**
 * Extract a human-readable failure reason from a cPanel API2 result, safe to
 * surface to the operator (no secrets).
 */
function addonCpanelResultReason(mixed $result): string
{
    $data = addonNormalizeCpanelResult($result);
    if ($data === null) {
        return 'no-response';
    }

    $cpanel = $data['cpanelresult'] ?? null;
    if (is_array($cpanel)) {
        $apiError = trim((string) ($cpanel['error'] ?? ''));
        if ($apiError !== '') {
            return addonSafeLogText($apiError);
        }

        foreach (addonCpanelResultRows($data) as $row) {
            $reason = trim((string) ($row['reason'] ?? ''));
            if ($reason !== '') {
                return addonSafeLogText($reason);
            }
        }
    }

    return '';
}

function addonCpanelResultLogSummary(mixed $result): string
{
    $data = addonNormalizeCpanelResult($result);
    if ($data === null) {
        return 'null-result';
    }

    return addonSafeLogText(addonCpanelResultText($data));
}

/**
 * Read a list-style API2 result (e.g. Park::listparkeddomains,
 * SubDomain::listsubdomains) into a flat list of lowercased domain strings.
 *
 * @return array<int, string>
 */
function addonCpanelListDomainNames(xmlapi $client, string $user, string $module, string $func): array
{
    $result = $client->api2_query($user, $module, $func, []);
    $data   = addonNormalizeCpanelResult($result);
    if ($data === null) {
        return [];
    }

    $names = [];
    foreach (addonCpanelResultRows($data) as $row) {
        $name = strtolower(trim((string) ($row['domain'] ?? '')));
        if ($name !== '') {
            $names[] = $name;
        }
    }

    return $names;
}

function addonCpanelDomainIsParked(xmlapi $client, string $user, string $domain): bool
{
    return in_array(
        strtolower($domain),
        addonCpanelListDomainNames($client, $user, 'Park', 'listparkeddomains'),
        true,
    );
}

/**
 * Poll the parked-domain list a few times, because Park::park often lands a
 * couple of seconds after the HTTP client has already timed out. Kept short to
 * stay within the web request's execution budget.
 */
function addonCpanelWaitParked(xmlapi $client, string $user, string $domain, int $attempts = 3, int $sleepSeconds = 2): bool
{
    for ($i = 0; $i < $attempts; $i++) {
        if (addonCpanelDomainIsParked($client, $user, $domain)) {
            return true;
        }
        if ($i < $attempts - 1) {
            sleep($sleepSeconds);
        }
    }

    return false;
}

function addonCpanelWildcardExists(xmlapi $client, string $user, string $domain): bool
{
    return in_array(
        '*.' . strtolower($domain),
        addonCpanelListDomainNames($client, $user, 'SubDomain', 'listsubdomains'),
        true,
    );
}

/**
 * Read one DNS record type and return the values of $key, lowercased and with
 * the trailing root dot stripped. Returns [] on NXDOMAIN or resolver failure —
 * callers distinguish "no records" from "wrong records" themselves.
 *
 * @return list<string>
 */
function addonDnsRecordValues(string $domain, int $type, string $key): array
{
    $records = @dns_get_record($domain, $type);
    if (!is_array($records)) {
        return [];
    }

    $values = [];
    foreach ($records as $record) {
        if (!is_array($record)) {
            continue;
        }

        $value = rtrim(strtolower(trim((string) ($record[$key] ?? ''))), '.');
        if ($value !== '') {
            $values[] = $value;
        }
    }

    return $values;
}

/**
 * Lighter gate: may this domain be STORED at all?
 *
 * Onboarding is circular by nature:
 *
 *     add domain → Cloudflare zone created → app shows the CF nameservers →
 *     operator sets them at the registrar → only then can cPanel park
 *
 * At step one the domain legitimately does not point here yet — the operator
 * cannot know the Cloudflare nameservers until the zone exists. So storage
 * rejects only a name that does not resolve AT ALL — a typo, or a domain that
 * was never registered. A real, freshly bought domain still gets in.
 *
 * @return array{ok:bool,error:string}
 */
function addonDnsResolves(string $domain): array
{
    $ok = ['ok' => true, 'error' => ''];

    $enabled = strtolower(trim((string) addonEnv('ADDON_DNS_PRECHECK', '1')));
    if (in_array($enabled, ['0', 'false', 'off', 'no'], true)) {
        return $ok;
    }

    if (addonDnsRecordValues($domain, DNS_NS, 'target') !== []) {
        return $ok;
    }

    if (addonDnsRecordValues($domain, DNS_A, 'ip') !== []) {
        return $ok;
    }

    // Third lookup only on the failure path: a registered domain whose delegated
    // nameservers are not answering yet still has an SOA, and must not be thrown
    // out as if it were a typo.
    if (addonDnsRecordValues($domain, DNS_SOA, 'mname') !== []) {
        return $ok;
    }

    return [
        'ok'    => false,
        'error' => 'dns-unresolved: ' . $domain . ' does not resolve at all. Check the spelling, '
            . 'or register the domain and let DNS propagate before adding it.',
    ];
}

/**
 * Park the domain and create the wildcard (*.domain) subdomain pointing at the
 * redirect dir. Verification-based and idempotent: success is reported only when
 * the wildcard subdomain actually exists.
 *
 * Park is a slow operation (it rebuilds Apache vhosts + DNS) and frequently
 * exceeds the HTTP client timeout while still completing server-side. We
 * therefore never abort on a park "no-response": we re-read the parked-domain
 * list to learn whether it actually landed, then proceed to the wildcard step.
 *
 * @return array{ok:bool,error:string}
 */
function addonCpanelParkAndWildcard(xmlapi $client, string $user, string $domain, string $dir): array
{
    // Already provisioned — nothing to do (idempotent re-run / retry).
    if (addonCpanelWildcardExists($client, $user, $domain)) {
        return ['ok' => true, 'error' => ''];
    }

    // --- Park the domain (tolerate a client-side timeout) ---------------------
    if (!addonCpanelDomainIsParked($client, $user, $domain)) {
        // 10s, not 15s. When park is slow the response never arrives in time
        // anyway, so budget spent waiting on it is budget taken from the
        // verification below — and verification is what actually establishes
        // whether it worked. max_execution_time is 30s for the whole request.
        $client->set_timeout(10);
        $parkResult = $client->api2_query($user, 'Park', 'park', ['domain' => $domain]);
        // Capture the transport error NOW: addonCpanelWaitParked() below issues
        // more queries that reset xmlapi::$lastError, masking the real cause.
        $parkTransport = $client->get_last_error();
        $client->set_timeout(20);

        // A transport timeout is NOT evidence of failure. Park rebuilds Apache
        // vhosts and DNS and routinely outlives the HTTP call while completing
        // server-side: aisharogers.baby was parked successfully even though the
        // call timed out and the old 3-attempt (4s) window missed the landing —
        // leaving the domain parked with no wildcard, and reporting a failure
        // that had not happened. So poll roughly twice as long after a timeout.
        $parkTimedOut = stripos($parkTransport, 'timed out') !== false
            || stripos($parkTransport, 'curl[28]') !== false;
        $parkAttempts = $parkTimedOut ? 6 : 3;

        // The parked-domain list — not the response — is the source of truth.
        if (
            !addonCpanelResultIsOk($parkResult, true)
            && !addonCpanelWaitParked($client, $user, $domain, $parkAttempts)
        ) {
            $reason = addonCpanelReasonWithTransport($parkResult, $parkTransport);
            error_log('addon-domain-lib: park failed domain=' . $domain . ' reason=' . $reason . ' result=' . addonCpanelResultLogSummary($parkResult));

            return ['ok' => false, 'error' => 'cpanel-park-failed: ' . $reason];
        }
    }

    // --- Create the wildcard subdomain (*.domain → redirect dir) --------------
    $subParams = [
        'domain' => '*',
        'rootdomain' => $domain,
        'dir' => $dir,
    ];

    $subdomainResult = $client->api2_query($user, 'SubDomain', 'addsubdomain', $subParams);
    $subTransport = $client->get_last_error();

    // Wildcard may collide with a stale entry — remove then re-add and retry.
    if (!addonCpanelResultIsOk($subdomainResult, true) && !addonCpanelWildcardExists($client, $user, $domain)) {
        $client->api2_query($user, 'SubDomain', 'delsubdomain', ['domain' => '*.' . $domain]);
        $subdomainResult = $client->api2_query($user, 'SubDomain', 'addsubdomain', $subParams);
        $subTransport = $client->get_last_error();
    }

    // Source of truth: does the wildcard actually exist now?
    if (!addonCpanelWildcardExists($client, $user, $domain)) {
        $reason = addonCpanelReasonWithTransport($subdomainResult, $subTransport);
        error_log('addon-domain-lib: wildcard subdomain failed domain=' . $domain . ' reason=' . $reason . ' result=' . addonCpanelResultLogSummary($subdomainResult));

        return ['ok' => false, 'error' => 'cpanel-wildcard-failed: ' . $reason];
    }

    return ['ok' => true, 'error' => ''];
}

/**
 * Best-effort human-readable failure reason. Falls back to the transport-level
 * curl error (timeout / connection refused / HTTP 401) when cPanel returned
 * nothing, so logs no longer collapse every distinct failure into "no-response".
 */
function addonCpanelFailureReason(mixed $result, xmlapi $client): string
{
    $transport = $client->get_last_error();

    return addonCpanelReasonWithTransport($result, $transport);
}

/**
 * Build a failure reason from the API result, falling back to a transport-level
 * error (curl timeout / connection refused / HTTP 401) captured at call time.
 * Callers must capture get_last_error() immediately after the failing query —
 * later queries reset it, which is how distinct failures collapsed to
 * "no-response".
 */
function addonCpanelReasonWithTransport(mixed $result, string $transportError): string
{
    $reason = addonCpanelResultReason($result);
    if ($reason === '' || $reason === 'no-response') {
        $reason = $transportError !== '' ? $transportError : 'no-response';
    }

    return $reason;
}

/**
 * @return array{ok:bool,error:string}
 */
function addonPerformCpanelAddonDomain(string $domain): array
{
    $bootstrap = addonBootstrapCpanelDependencies();
    if (!$bootstrap['ok']) {
        return $bootstrap;
    }

    $user = trim((string) addonEnv('CPANEL_USER', ''));
    if ($user === '') {
        error_log('addon-domain-lib: missing CPANEL_USER');

        return ['ok' => false, 'error' => 'missing-cpanel-user'];
    }

    $dirEnv = trim((string) addonEnv('CPANEL_SUBDOMAIN_DIR', ''));
    $dir = addonNormalizeCpanelRedirectDir($dirEnv !== '' ? $dirEnv : 'public_html');

    $token = trim((string) addonEnv('CPANEL_API_TOKEN', ''));
    if ($token !== '') {
        $client = addonMakeCpanelClient();
        if (method_exists($client, 'token_auth')) {
            $client->token_auth($user, $token);
            $result = addonCpanelParkAndWildcard($client, $user, $domain, $dir);
            if ($result['ok']) {
                return $result;
            }
            error_log('addon-domain-lib: token auth attempt failed error=' . $result['error']);

            return $result;
        } else {
            error_log('addon-domain-lib: token_auth method unavailable');
        }
    }

    $pass = (string) addonEnv('CPANEL_PASSWORD', '');
    if ($pass === '') {
        return ['ok' => false, 'error' => $token !== '' ? 'cpanel-token-auth-failed' : 'missing-cpanel-auth'];
    }

    $client = addonMakeCpanelClient();
    $client->password_auth($user, $pass);

    return addonCpanelParkAndWildcard($client, $user, $domain, $dir);
}

/**
 * Authenticated cPanel client using whichever credential is configured
 * (API token preferred, password fallback). Returns null if neither exists.
 */
function addonMakeAuthenticatedCpanelClient(string $user): ?xmlapi
{
    $token = trim((string) addonEnv('CPANEL_API_TOKEN', ''));
    $client = addonMakeCpanelClient();

    if ($token !== '' && method_exists($client, 'token_auth')) {
        $client->token_auth($user, $token);

        return $client;
    }

    $pass = (string) addonEnv('CPANEL_PASSWORD', '');
    if ($pass === '') {
        return null;
    }

    $client->password_auth($user, $pass);

    return $client;
}

/**
 * Remove an addon domain from cPanel: delete its wildcard subdomain and unpark
 * it. Best-effort and idempotent — a "does not exist" outcome is treated as
 * success so callers can still drop the local record.
 *
 * @return array{ok:bool,error:string}
 */
function addonPerformCpanelDeleteDomain(string $domain): array
{
    $bootstrap = addonBootstrapCpanelDependencies();
    if (!$bootstrap['ok']) {
        return $bootstrap;
    }

    $user = trim((string) addonEnv('CPANEL_USER', ''));
    if ($user === '') {
        error_log('addon-domain-lib: missing CPANEL_USER (delete)');

        return ['ok' => false, 'error' => 'missing-cpanel-user'];
    }

    $client = addonMakeAuthenticatedCpanelClient($user);
    if ($client === null) {
        return ['ok' => false, 'error' => 'missing-cpanel-auth'];
    }

    // Wildcard subdomain first, then the parked/addon domain.
    $client->api2_query($user, 'SubDomain', 'delsubdomain', ['domain' => '*.' . $domain]);
    $client->api2_query($user, 'Park', 'unpark', ['domain' => $domain]);

    // Absence is the source of truth, deliberately NOT addonCpanelResultIsOk():
    // a removal that reports "does not exist" has still achieved the goal, yet
    // that phrase is (correctly) a hard failure for the create path. Checking
    // state keeps the old best-effort tolerance for an already-gone entry while
    // still catching a removal that genuinely did not happen.
    //
    // Unpark rebuilds vhosts and DNS exactly like park, so an entry can linger a
    // moment after the call returns. Both conditions are polled in one loop so
    // the waits are shared rather than doubled — this runs inside a web request.
    $wildcardGone = false;
    $unparked     = false;

    for ($attempt = 0; $attempt < 3; $attempt++) {
        $wildcardGone = $wildcardGone || !addonCpanelWildcardExists($client, $user, $domain);
        $unparked     = $unparked || !addonCpanelDomainIsParked($client, $user, $domain);

        if ($wildcardGone && $unparked) {
            return ['ok' => true, 'error' => ''];
        }

        if ($attempt < 2) {
            sleep(2);
        }
    }

    $remaining = [];
    if (!$wildcardGone) {
        $remaining[] = '*.' . $domain;
    }
    if (!$unparked) {
        $remaining[] = $domain;
    }

    $reason = 'still present in cPanel: ' . implode(', ', $remaining);
    error_log('addon-domain-lib: delete incomplete domain=' . $domain . ' reason=' . addonSafeLogText($reason));

    return ['ok' => false, 'error' => 'cpanel-delete-incomplete: ' . $reason];
}
