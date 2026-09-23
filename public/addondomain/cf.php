<?php

declare(strict_types=1);

$cfStandalone = !defined('ADDON_CF_NO_ROUTER');

if ($cfStandalone) {
    /** @var PDO $pdo */
    $pdo = require __DIR__ . '/../../connection_pdo.php';
} else {
    /** @var PDO $pdo */
    $pdo = require __DIR__ . '/../../connection_pdo.php';
}
include_once __DIR__ . '/../session_guards.php';
include_once dirname(__DIR__, 2) . '/env.php';
load_env_file(dirname(__DIR__, 2) . '/.env');
include_once __DIR__ . '/../cf-lib.php';

if ($cfStandalone) {
    header('Content-Type: application/json; charset=utf-8');
}

/**
 * Persist CF data back to the addondomain row.
 */
function cfSaveToDB(PDO $pdo, int $id, string $zoneId, string $status, string $ns): void
{
    $stmt = $pdo->prepare(
        'UPDATE addondomain SET cf_zone_id = :zone_id, cf_status = :cf_status, cf_ns = :cf_ns WHERE id = :id',
    );
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare CF update.');
    }
    $stmt->execute(['zone_id' => $zoneId, 'cf_status' => $status, 'cf_ns' => $ns, 'id' => $id]);
}

/**
 * Whether the optional `addondomain.cf_cert_installed` column exists.
 * Cached per-request. Lets the app run before migration 003 has been applied
 * (the auto-SSL "once" guarantee then degrades to the client-side guard).
 */
function cfHasCertColumn(PDO $pdo): bool
{
    static $cache = null;
    if (is_bool($cache)) {
        return $cache;
    }

    $stmt = $pdo->prepare(
        'SELECT 1 FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :c LIMIT 1',
    );
    $stmt->execute(['t' => 'addondomain', 'c' => 'cf_cert_installed']);
    $result = $stmt->fetchColumn() !== false;
    $cache = $result;

    return $result;
}

/**
 * Record whether the CF Origin Certificate is currently installed for a row.
 * No-op when the column is absent (pre-migration).
 */
function cfMarkCertInstalled(PDO $pdo, int $id, bool $installed = true): void
{
    if (!cfHasCertColumn($pdo)) {
        return;
    }

    $stmt = $pdo->prepare('UPDATE addondomain SET cf_cert_installed = :installed WHERE id = :id');
    $stmt->execute(['installed' => $installed ? 1 : 0, 'id' => $id]);
}

/**
 * Fetch the domain string for a given addondomain row.
 * Returns ['id'=>int, 'domain'=>string, 'cf_zone_id'=>string, 'cf_status'=>string,
 *          'cf_ns'=>string, 'cf_cert_installed'=>int].
 */
function cfGetRow(PDO $pdo, int $id): array
{
    $certSelect = cfHasCertColumn($pdo)
        ? ', COALESCE(cf_cert_installed, 0) AS cf_cert_installed'
        : ', 0 AS cf_cert_installed';

    $stmt = $pdo->prepare(
        'SELECT id, domain,
                COALESCE(cf_zone_id,\'\') AS cf_zone_id,
                COALESCE(cf_status,\'\')  AS cf_status,
                COALESCE(cf_ns,\'\')      AS cf_ns' . $certSelect . '
         FROM addondomain WHERE id = :id',
    );
    if (!$stmt) {
        throw new RuntimeException('Failed to prepare row query.');
    }
    $stmt->execute(['id' => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        jsonError(404, 'not-found');
    }

    return $row;
}

/**
 * Provision or refresh a Cloudflare zone for an addondomain row, apply the
 * standard SRP Cloudflare settings, and provision DNS records including *.
 *
 * @return array<string, mixed>
 */
function cfProvisionAddonDomainZone(PDO $pdo, int $id): array
{
    if ($id < 1) {
        return ['ok' => false, 'status_code' => 422, 'err' => 'invalid-id'];
    }

    $row    = cfGetRow($pdo, $id);
    $domain = (string) $row['domain'];

    $zoneId   = '';
    $cfStatus = '';
    $cfNsJson = '';

    if ($row['cf_zone_id'] !== '') {
        $directResp = cfApi('GET', '/zones/' . $row['cf_zone_id']);
        if (($directResp['success'] ?? false) && isset($directResp['result'])) {
            $zone     = $directResp['result'];
            $zoneId   = (string) ($zone['id'] ?? $row['cf_zone_id']);
            $cfStatus = (string) ($zone['status'] ?? 'unknown');
            $cfNsJson = json_encode($zone['name_servers'] ?? [], JSON_THROW_ON_ERROR);
        }
    }

    if ($zoneId === '') {
        $listResp = cfApi('GET', '/zones?name=' . urlencode($domain));
        if (!empty($listResp['result']) && is_array($listResp['result'])) {
            $zone     = $listResp['result'][0];
            $zoneId   = (string) ($zone['id'] ?? '');
            $cfStatus = (string) ($zone['status'] ?? 'pending');
            $cfNsJson = json_encode($zone['name_servers'] ?? []) ?: '[]';
        }
    }

    if ($zoneId === '') {
        $accountId  = app_env('CF_ACCOUNT_ID', '');
        $createBody = ['name' => $domain, 'jump_start' => true];
        if ($accountId !== '') {
            $createBody['account'] = ['id' => $accountId];
        }

        $createResp = cfApi('POST', '/zones', $createBody);
        if (empty($createResp['success'])) {
            $alreadyExists = false;
            foreach (($createResp['errors'] ?? []) as $cfErr) {
                if (($cfErr['code'] ?? 0) === 1061) {
                    $alreadyExists = true;
                    break;
                }
            }

            if ($alreadyExists) {
                $fallback = cfApi('GET', '/zones?name=' . urlencode($domain));
                if (!empty($fallback['result'][0])) {
                    $zone     = $fallback['result'][0];
                    $zoneId   = (string) ($zone['id'] ?? '');
                    $cfStatus = (string) ($zone['status'] ?? 'pending');
                    $cfNsJson = json_encode($zone['name_servers'] ?? []) ?: '[]';
                } else {
                    return ['ok' => false, 'status_code' => 409, 'err' => 'zone-exists'];
                }
            } else {
                $rawMsg = (string) ($createResp['errors'][0]['message'] ?? 'zone-create-failed');
                error_log('cfProvisionAddonDomainZone create failed domain=' . $domain . ' msg=' . $rawMsg);
                $msg = str_contains($rawMsg, 'zone.create')
                    ? 'cf-token-zone-create-denied'
                    : 'zone-create-failed';

                return ['ok' => false, 'status_code' => 200, 'err' => $msg];
            }
        } else {
            $zone     = $createResp['result'];
            $zoneId   = (string) ($zone['id'] ?? '');
            $cfStatus = (string) ($zone['status'] ?? 'pending');
            $cfNsJson = json_encode($zone['name_servers'] ?? []) ?: '[]';
        }
    }

    if ($zoneId === '') {
        return ['ok' => false, 'status_code' => 502, 'err' => 'zone-id-missing'];
    }

    cfSaveToDB($pdo, $id, $zoneId, $cfStatus, $cfNsJson);

    $dnsLog = [];
    cfSyncTrackError(null, true); // reset failure accumulator for this run
    cfSyncTrackAuthFailure(null, true); // reset fatal auth/resource accumulator

    $accessCheck = cfPreflightZoneAccess($zoneId);
    if (empty($accessCheck['ok'])) {
        $accessErr = (string) ($accessCheck['err'] ?? 'cf-zone-access-denied');
        error_log('cfProvisionAddonDomainZone preflight failed zone=' . $zoneId . ' err=' . $accessErr);
        $safeAccessErr = ((int) ($accessCheck['status_code'] ?? 403)) === 403
            ? 'cf-zone-access-denied'
            : 'cf-zone-access-check-failed';

        return [
            'ok' => false,
            'status_code' => (int) ($accessCheck['status_code'] ?? 403),
            'err' => $safeAccessErr,
            'zone_id' => $zoneId,
            'cf_status' => $cfStatus,
            'cf_ns' => $cfNsJson !== '' ? (json_decode($cfNsJson, true) ?: []) : [],
            'dns_log' => [],
            'cf_warnings' => count(cfSyncTrackError()),
            'cf_warning_sample' => array_slice(cfSyncTrackError(), 0, 6),
        ];
    }

    cfApplyAllRecommended($zoneId);

    // security_level is no longer force-set here. cfApplySettings() (part of
    // cfApplyAllRecommended() above) already applies the zone's baseline
    // ('medium'). Forcing 'under_attack' on every sync used to challenge
    // every visitor on every managed domain, including real traffic, with no
    // way to leave it off — every re-sync silently reverted any manual
    // downgrade. Use cfSetSecurityLevel($zoneId, 'under_attack') as a
    // deliberate, one-off incident-response action instead, not a standing
    // default.

    if (cfSyncHasAuthFailure()) {
        $authSample = array_slice(cfSyncTrackAuthFailure(), 0, 2);
        if ($authSample !== []) {
            error_log('cfProvisionAddonDomainZone auth failure zone=' . $zoneId . ' sample=' . implode(' | ', $authSample));
        }

        return [
            'ok' => false,
            'status_code' => 403,
            'err' => 'cf-token-permission-denied',
            'zone_id' => $zoneId,
            'cf_status' => $cfStatus,
            'cf_ns' => $cfNsJson !== '' ? (json_decode($cfNsJson, true) ?: []) : [],
            'dns_log' => [],
            'cf_warnings' => count(cfSyncTrackError()),
            'cf_warning_sample' => array_slice(cfSyncTrackError(), 0, 6),
        ];
    }

    $serverIp = app_env('CF_SERVER_IP', '');
    if ($serverIp !== '') {
        $dnsLog = cfProvisionDns($zoneId, $domain, $serverIp);
    }

    $originCert = null;
    if (cfEnvFlag('CF_ORIGIN_CERT_AUTO_INSTALL', false)) {
        try {
            $originCert = cfCreateAndInstallOriginCertificate($zoneId, $domain);
        } catch (Throwable $e) {
            error_log('cfProvisionAddonDomainZone origin cert auto-install failed zone=' . $zoneId . ' domain=' . $domain . ' err=' . $e->getMessage());
            return [
                'ok' => false,
                'status_code' => 502,
                'err' => 'origin-cert-install-failed',
                'zone_id' => $zoneId,
                'cf_status' => $cfStatus,
                'cf_ns' => $cfNsJson !== '' ? (json_decode($cfNsJson, true) ?: []) : [],
                'dns_log' => $dnsLog,
                'cf_warnings' => count(cfSyncTrackError()),
                'cf_warning_sample' => array_slice(cfSyncTrackError(), 0, 6),
            ];
        }
    }

    $cfWarnings = cfSyncTrackError();

    try {
        $freshResp = cfApi('GET', '/zones/' . $zoneId);
        if (($freshResp['success'] ?? false) && isset($freshResp['result'])) {
            $fresh    = $freshResp['result'];
            $cfStatus = (string) ($fresh['status'] ?? $cfStatus);
            $existingNs = is_string($cfNsJson) ? (json_decode($cfNsJson, true) ?: []) : [];
            $cfNsJson = json_encode($fresh['name_servers'] ?? $existingNs) ?: '[]';
            cfSaveToDB($pdo, $id, $zoneId, $cfStatus, $cfNsJson);
        }
    } catch (Throwable $e) {
        // Keep the status fetched earlier.
    }

    $cfNs = $cfNsJson !== '' ? json_decode($cfNsJson, true) : [];
    if (!is_array($cfNs)) {
        $cfNs = [];
    }

    return [
        'ok'           => true,
        'zone_id'      => $zoneId,
        'cf_status'    => $cfStatus,
        'cf_ns'        => $cfNs,
        'dns_log'      => $dnsLog,
        'cf_warnings'  => count($cfWarnings),
        'cf_warning_sample' => array_slice($cfWarnings, 0, 6),
        'origin_cert' => $originCert,
    ];
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/**
 * zone_add — add/verify domain in Cloudflare; fetch NS records; apply
 * all security + performance settings, provision DNS, add security headers.
 */
function cfActionZoneAdd(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    $result = cfProvisionAddonDomainZone($pdo, $id);
    if (empty($result['ok'])) {
        jsonError((int) ($result['status_code'] ?? 500), (string) ($result['err'] ?? 'cf-sync-failed'));
    }

    echo json_encode($result, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
}

/**
 * refresh_status — re-fetch zone status and NS from CF.
 */
function cfActionRefreshStatus(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row    = cfGetRow($pdo, $id);
    $zoneId = $row['cf_zone_id'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('GET', '/zones/' . $zoneId);
    if (empty($resp['success'])) {
        $msg = isset($resp['errors'][0]['message']) && is_string($resp['errors'][0]['message'])
            ? $resp['errors'][0]['message']
            : 'zone-fetch-failed';
        error_log('cfActionRefreshStatus failed: ' . $msg);
        jsonError(200, 'zone-fetch-failed');
    }

    $zone     = $resp['result'];
    $cfStatus = $zone['status'] ?? 'unknown';
    $cfNsJson = json_encode($zone['name_servers'] ?? []) ?: '[]';

    cfSaveToDB($pdo, $id, $zoneId, $cfStatus, $cfNsJson);

    echo json_encode([
        'ok'                => true,
        'zone_id'           => $zoneId,
        'cf_status'         => $cfStatus,
        'cf_ns'             => json_decode($cfNsJson, true) ?: [],
        'cf_cert_installed' => (int) ($row['cf_cert_installed'] ?? 0),
    ]);
}

/**
 * purge_cache — purge everything for a zone.
 */
function cfActionPurgeCache(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row    = cfGetRow($pdo, $id);
    $zoneId = $row['cf_zone_id'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('POST', '/zones/' . $zoneId . '/purge_cache', ['purge_everything' => true]);
    if (empty($resp['success'])) {
        $msg = isset($resp['errors'][0]['message']) && is_string($resp['errors'][0]['message'])
            ? $resp['errors'][0]['message']
            : 'purge-failed';
        error_log('cfActionPurgeCache failed: ' . $msg);
        jsonError(200, 'purge-failed');
    }

    echo json_encode(['ok' => true]);
}

/**
 * ssl_mode — set SSL mode to 'off'|'flexible'|'full'|'strict'.
 */
function cfActionSslMode(PDO $pdo, array $params): void
{
    $id   = (int) ($params['id'] ?? 0);
    $mode = (string) ($params['mode'] ?? 'full');
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }
    $allowed = ['off', 'flexible', 'full', 'strict'];
    if (!in_array($mode, $allowed, true)) {
        jsonError(422, 'invalid-mode');
    }

    $row    = cfGetRow($pdo, $id);
    $zoneId = $row['cf_zone_id'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('PATCH', '/zones/' . $zoneId . '/settings/ssl', ['value' => $mode]);
    if (empty($resp['success'])) {
        $msg = isset($resp['errors'][0]['message']) && is_string($resp['errors'][0]['message'])
            ? $resp['errors'][0]['message']
            : 'ssl-mode-failed';
        error_log('cfActionSslMode failed: ' . $msg);
        jsonError(200, 'ssl-mode-failed');
    }

    echo json_encode(['ok' => true, 'mode' => $mode]);
}

/**
 * always_https — toggle Always Use HTTPS on/off.
 */
function cfActionAlwaysHttps(PDO $pdo, array $params): void
{
    $id    = (int) ($params['id'] ?? 0);
    $value = ((string) ($params['value'] ?? 'on')) === 'on' ? 'on' : 'off';
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row    = cfGetRow($pdo, $id);
    $zoneId = $row['cf_zone_id'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('PATCH', '/zones/' . $zoneId . '/settings/always_use_https', ['value' => $value]);
    if (empty($resp['success'])) {
        $msg = isset($resp['errors'][0]['message']) && is_string($resp['errors'][0]['message'])
            ? $resp['errors'][0]['message']
            : 'always-https-failed';
        error_log('cfActionAlwaysHttps failed: ' . $msg);
        jsonError(200, 'always-https-failed');
    }

    echo json_encode(['ok' => true, 'value' => $value]);
}

/**
 * speed — one-click apply Cloudflare Speed > Optimization recommendations
 * (compression, minify, HTTP/3, image optimization, cache, Argo Tiered Caching).
 */
function cfActionSpeed(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row    = cfGetRow($pdo, $id);
    $zoneId = trim((string) $row['cf_zone_id']);

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    cfSyncTrackError(null, true);    // reset failure accumulator for this run
    cfSyncTrackAuthFailure(null, true); // reset fatal auth/resource accumulator

    cfApplySpeedOptimizations($zoneId);

    $warnings = cfSyncTrackError();

    echo json_encode([
        'ok'       => true,
        'zone_id'  => $zoneId,
        'warnings' => count($warnings),
        'sample'   => array_slice($warnings, 0, 6),
    ]);
}

/**
 * origin_cert_install — create Cloudflare Origin CA certificate, install to cPanel, set Full Strict.
 */
function cfActionOriginCertInstall(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row = cfGetRow($pdo, $id);
    $zoneId = trim((string) $row['cf_zone_id']);
    $domain = (string) $row['domain'];

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    // Auto path (auto=1) is idempotent: never re-issue once recorded as
    // installed. Manual clicks (no auto flag) still force a fresh install.
    $auto = ($params['auto'] ?? null) === '1';
    if ($auto && (int) ($row['cf_cert_installed'] ?? 0) === 1) {
        echo json_encode(['ok' => true, 'already_installed' => true, 'cf_cert_installed' => 1], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);

        return;
    }

    $accessCheck = cfPreflightZoneAccess($zoneId);
    if (empty($accessCheck['ok'])) {
        $accessErr = (string) ($accessCheck['err'] ?? 'cf-zone-access-denied');
        error_log('cfActionOriginCertInstall preflight failed zone=' . $zoneId . ' err=' . $accessErr);
        $safeAccessErr = ((int) ($accessCheck['status_code'] ?? 403)) === 403
            ? 'cf-zone-access-denied'
            : 'cf-zone-access-check-failed';
        jsonError((int) ($accessCheck['status_code'] ?? 403), $safeAccessErr);
    }

    try {
        $result = cfCreateAndInstallOriginCertificate($zoneId, $domain);
    } catch (Throwable $e) {
        error_log('cfActionOriginCertInstall failed: ' . $e->getMessage());
        jsonError(502, 'origin-cert-install-failed');
    }

    cfMarkCertInstalled($pdo, $id);

    echo json_encode(['ok' => true, 'origin_cert' => $result, 'cf_cert_installed' => 1], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
}

/**
 * origin_cert_to_cpanel — remove the installed Cloudflare Origin CA
 * certificate and trigger cPanel's own AutoSSL to issue a publicly-trusted
 * certificate in its place. See cfReplaceOriginCertWithCpanelSsl() for the
 * important non-atomic/not-instant caveats; the confirming client UI must
 * surface those before calling this.
 */
function cfActionOriginCertToCpanel(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row = cfGetRow($pdo, $id);
    $domain = (string) $row['domain'];

    try {
        $result = cfReplaceOriginCertWithCpanelSsl($domain);
    } catch (Throwable $e) {
        error_log('cfActionOriginCertToCpanel failed: ' . $e->getMessage());
        jsonError(502, 'origin-cert-to-cpanel-failed');
    }

    // Origin CA cert is no longer what's installed (removed above, or was
    // already absent) — clear the flag regardless of whether AutoSSL has
    // finished issuing its replacement yet.
    cfMarkCertInstalled($pdo, $id, false);

    echo json_encode(
        ['ok' => true, 'result' => $result, 'cf_cert_installed' => 0],
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR,
    );
}

/**
 * zone_delete — permanently delete a zone from Cloudflare by zone_id.
 */
function cfActionZoneDelete(array $params): void
{
    $zoneId = trim((string) ($params['zone_id'] ?? ''));
    if ($zoneId === '') {
        jsonError(422, 'invalid-zone-id');
    }

    $resp = cfApi('DELETE', '/zones/' . $zoneId);
    if (empty($resp['success'])) {
        $msg = isset($resp['errors'][0]['message']) && is_string($resp['errors'][0]['message'])
            ? $resp['errors'][0]['message']
            : 'zone-delete-failed';
        error_log('cfActionZoneDelete failed: ' . $msg);
        jsonError(200, 'zone-delete-failed');
    }

    echo json_encode(['ok' => true, 'zone_id' => $zoneId]);
}

/**
 * zone_unlink — delete the Cloudflare zone and clear cf_* columns on the row,
 * WITHOUT deleting the addondomain row itself (unlike zone_delete, which is
 * only ever called as part of removing the whole row). Lets an admin stop
 * managing a domain through Cloudflare while keeping it in the system —
 * e.g. to re-point it elsewhere or re-add it fresh later.
 */
function cfActionZoneUnlink(PDO $pdo, array $params): void
{
    $id = (int) ($params['id'] ?? 0);
    if ($id < 1) {
        jsonError(422, 'invalid-id');
    }

    $row = cfGetRow($pdo, $id);
    $zoneId = trim((string) $row['cf_zone_id']);

    if ($zoneId === '') {
        jsonError(409, 'no-zone-id');
    }

    $resp = cfApi('DELETE', '/zones/' . $zoneId);
    if (empty($resp['success'])) {
        $msg = isset($resp['errors'][0]['message']) && is_string($resp['errors'][0]['message'])
            ? $resp['errors'][0]['message']
            : 'zone-delete-failed';
        error_log('cfActionZoneUnlink failed id=' . $id . ' zone=' . $zoneId . ' msg=' . $msg);
        jsonError(200, 'zone-delete-failed');
    }

    cfSaveToDB($pdo, $id, '', '', '[]');

    if (cfHasCertColumn($pdo)) {
        $stmt = $pdo->prepare('UPDATE addondomain SET cf_cert_installed = 0 WHERE id = :id');
        $stmt->execute(['id' => $id]);
    }

    echo json_encode(['ok' => true, 'id' => $id]);
}

// ---------------------------------------------------------------------------
// .env read / write helpers
// ---------------------------------------------------------------------------

function envFilePath(): string
{
    return dirname(__DIR__, 2) . '/.env';
}

function envReadAll(): array
{
    $path = envFilePath();
    if (!is_readable($path)) {
        return [];
    }
    $result = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#' || !str_contains($line, '=')) {
            continue;
        }
        [$k, $v] = explode('=', $line, 2);
        $result[trim($k)] = trim($v);
    }

    return $result;
}

function envWriteKeys(array $updates): void
{
    $path  = envFilePath();
    $lines = is_readable($path) ? (file($path, FILE_IGNORE_NEW_LINES) ?: []) : [];

    $written = [];
    foreach ($lines as &$line) {
        $trimmed = trim($line);
        if ($trimmed === '' || $trimmed[0] === '#' || !str_contains($trimmed, '=')) {
            continue;
        }
        [$k] = explode('=', $trimmed, 2);
        $k = trim($k);
        if (array_key_exists($k, $updates)) {
            $line      = $k . '=' . $updates[$k];
            $written[$k] = true;
        }
    }
    unset($line);

    foreach ($updates as $k => $v) {
        if (!isset($written[$k])) {
            $lines[] = $k . '=' . $v;
        }
    }

    foreach ($lines as $line) {
        if (preg_match('/[\r\n\0]/', $line) === 1) {
            throw new RuntimeException('Invalid .env content.');
        }
    }

    file_put_contents($path, implode("\n", $lines) . "\n", LOCK_EX);
}

// ---------------------------------------------------------------------------
// Config actions
// ---------------------------------------------------------------------------

function cfMaskSecretConfigValue(string $key, string $value): string
{
    if ($value === '') {
        return '';
    }

    $maskKeys = ['CF_API_TOKEN', 'TINYURL_API_KEY', 'MAXMIND_LICENSE_KEY', 'POSTBACK_SECRET'];
    if (!in_array($key, $maskKeys, true)) {
        return $value;
    }

    $len = strlen($value);
    if ($len <= 8) {
        return str_repeat(chr(0xE2) . chr(0x80) . chr(0xA2), $len);
    }

    return substr($value, 0, 4) . str_repeat(chr(0xE2) . chr(0x80) . chr(0xA2), min($len - 8, 28)) . substr($value, -4);
}

function cfActionConfigGet(): void
{
    $keys = ['CF_API_TOKEN', 'CF_ACCOUNT_ID', 'CF_SERVER_IP', 'CF_NS1', 'CF_NS2', 'CF_NS3', 'CF_NS4', 'TINYURL_API_KEY', 'MAXMIND_LICENSE_KEY', 'POSTBACK_SECRET'];
    $env  = envReadAll();
    $out  = [];
    foreach ($keys as $key) {
        $val = $env[$key] ?? '';
        $out[$key] = cfMaskSecretConfigValue($key, $val);
    }
    echo json_encode(['ok' => true, 'config' => $out]);
}

function cfNormalizeConfigValue(string $key, string $value): string
{
    $value = trim($value);

    if (preg_match('/[\r\n\0]/', $value) === 1) {
        jsonError(422, 'invalid-config-value');
    }

    if ($key === 'CF_API_TOKEN') {
        try {
            return cfResolveToken($value);
        } catch (Throwable $e) {
            error_log('cfNormalizeConfigValue token resolve failed: ' . $e->getMessage());
            jsonError(422, 'invalid-cf-api-token');
        }
    }

    if ($key === 'CF_ACCOUNT_ID') {
        if (preg_match('/^[a-f0-9]{32}$/i', $value) !== 1) {
            jsonError(422, 'invalid-cf-account-id');
        }

        return strtolower($value);
    }

    if ($key === 'CF_SERVER_IP') {
        if (filter_var($value, FILTER_VALIDATE_IP) === false) {
            jsonError(422, 'invalid-cf-server-ip');
        }

        return $value;
    }

    if (in_array($key, ['CF_NS1', 'CF_NS2', 'CF_NS3', 'CF_NS4'], true)) {
        if (preg_match('/^(?=.{1,253}\.?$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/i', $value) !== 1) {
            jsonError(422, 'invalid-cf-nameserver');
        }

        return rtrim(strtolower($value), '.');
    }

    if (in_array($key, ['TINYURL_API_KEY', 'MAXMIND_LICENSE_KEY', 'POSTBACK_SECRET'], true)) {
        return trim($value);
    }

    jsonError(422, 'unsupported-config-key');
}

function cfActionConfigSave(array $params): void
{
    $allowed = ['CF_API_TOKEN', 'CF_ACCOUNT_ID', 'CF_SERVER_IP', 'CF_NS1', 'CF_NS2', 'CF_NS3', 'CF_NS4', 'TINYURL_API_KEY', 'MAXMIND_LICENSE_KEY', 'POSTBACK_SECRET'];
    $updates = [];
    foreach ($allowed as $key) {
        if (!isset($params[$key])) {
            continue;
        }

        $raw = trim((string) $params[$key]);
        if ($raw === '' || str_contains($raw, chr(0xE2) . chr(0x80) . chr(0xA2))) {
            continue;
        }

        $updates[$key] = cfNormalizeConfigValue($key, $raw);
    }
    if (!empty($updates)) {
        envWriteKeys($updates);
    }
    echo json_encode(['ok' => true, 'saved' => array_keys($updates)]);
}

function cfRequireAddonDomainSchema(PDO $pdo): void
{
    foreach (['cf_zone_id', 'cf_status', 'cf_ns'] as $column) {
        $stmt = $pdo->prepare(
            'SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = :table_name AND column_name = :column_name LIMIT 1',
        );
        if (!$stmt) {
            jsonError(500, 'schema-check-failed');
        }

        $stmt->execute(['table_name' => 'addondomain', 'column_name' => $column]);
        $exists = $stmt->fetchColumn() !== false;

        if (!$exists) {
            jsonError(500, 'schema-not-installed');
        }
    }
}


// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

if ($cfStandalone) {
    try {
        startAdminGuardSession();
        if (empty($_SESSION['admin_authenticated'])) {
            jsonError(403, 'unauthorized');
        }

        $params = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
        $action = (string) ($params['action'] ?? '');

        // config_get is read-only — no CSRF required
        if ($action !== 'config_get' && !hasValidSessionCsrf('admin_panel', requestCsrfToken())) {
            jsonError(419, 'invalid-csrf');
        }

        // Config actions don't need a DB connection
        if ($action === 'config_get') {
            cfActionConfigGet();
            exit;
        }
        if ($action === 'config_save') {
            cfActionConfigSave($params);
            exit;
        }

        cfRequireAddonDomainSchema($pdo);

        switch ($action) {
            case 'zone_add':
                cfActionZoneAdd($pdo, $params);
                break;
            case 'refresh_status':
                cfActionRefreshStatus($pdo, $params);
                break;
            case 'purge_cache':
                cfActionPurgeCache($pdo, $params);
                break;
            case 'ssl_mode':
                cfActionSslMode($pdo, $params);
                break;
            case 'always_https':
                cfActionAlwaysHttps($pdo, $params);
                break;
            case 'speed':
                cfActionSpeed($pdo, $params);
                break;
            case 'origin_cert_install':
                cfActionOriginCertInstall($pdo, $params);
                break;
            case 'origin_cert_to_cpanel':
                cfActionOriginCertToCpanel($pdo, $params);
                break;
            case 'zone_delete':
                cfActionZoneDelete($params);
                break;
            case 'zone_unlink':
                cfActionZoneUnlink($pdo, $params);
                break;
            default:
                jsonError(400, 'unknown-action');
        }
    } catch (Throwable $e) {
        error_log('cf router failed: ' . $e->getMessage());

        $message = $e->getMessage();

        // Surface config gaps to the admin panel with a safe, actionable code —
        // only the variable NAME is returned, never a secret value.
        if (preg_match('/^Missing required environment variable: ([A-Z0-9_]+)$/', $message, $m) === 1) {
            jsonError(400, 'missing-env:' . strtolower($m[1]));
        }

        // Keep a deterministic client-safe message for token config errors.
        if (str_starts_with($message, 'CF_API_TOKEN')) {
            jsonError(400, 'cf-token-config-invalid');
        }
        jsonError(500, 'server-error');
    }
}
