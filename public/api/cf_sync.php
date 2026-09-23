<?php

declare(strict_types=1);

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../../connection_pdo.php';

include_once __DIR__ . '/../session_guards.php';
include_once __DIR__ . '/../../env.php';
load_env_file(dirname(__DIR__, 2) . '/.env');
include_once __DIR__ . '/../cf-lib.php';
require_once __DIR__ . '/cf_token_crypto.php';

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError(405, 'method-not-allowed');
}

/**
 * Fixed-window per-user rate limit. Each call runs cfApplyAllRecommended()
 * (~25+ Cloudflare API requests) plus cfProvisionDns() (up to ~12 more) on top
 * of the zone create/lookup itself — 40-50 Cloudflare API calls per sync. This
 * endpoint uses either the user's own CF token or, when they have not
 * configured one, the shared account-wide CF_API_TOKEN also used by the admin
 * panel and every other tracker. With no limiter, as few as ~25 requests to
 * this endpoint inside Cloudflare's ~1200-req/5min per-token cap would exhaust
 * it and break Cloudflare access for everyone sharing that token — not just
 * the caller. Fail-open on I/O error, matching every other throttle in this
 * app: availability of the sync feature must not depend on temp-dir health.
 */
function cfSyncRateLimited(string $subId, int $maxPerWindow = 5, int $windowSeconds = 600): bool
{
    $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR
        . (defined('SRP_CACHE_DIR_NAME') ? SRP_CACHE_DIR_NAME : 'srp_bb');
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return false;
    }

    $file = $dir . DIRECTORY_SEPARATOR . 'rl_cfsync_' . md5($subId) . '.json';

    $fp = @fopen($file, 'c+');
    if ($fp === false) {
        return false;
    }

    $limited = false;

    if (flock($fp, LOCK_EX)) {
        $raw  = (string) stream_get_contents($fp, 256, 0);
        $data = $raw !== '' ? json_decode($raw, true) : null;

        $now   = time();
        $count = 1;
        $start = $now;

        if (is_array($data) && isset($data['c'], $data['t']) && ($now - (int) $data['t']) < $windowSeconds) {
            $count = (int) $data['c'] + 1;
            $start = (int) $data['t'];
        }

        if ($count > $maxPerWindow) {
            $limited = true;
        } else {
            rewind($fp);
            ftruncate($fp, 0);
            fwrite($fp, (string) json_encode(['c' => $count, 't' => $start]));
            fflush($fp);
        }

        flock($fp, LOCK_UN);
    }

    fclose($fp);

    return $limited;
}

/**
 * Persist CF zone data for a user-owned domain (lookup by domain + sub_domain).
 */
function cfSyncSaveToDB(PDO $pdo, string $domain, string $subDomain, string $zoneId, string $status, string $nsJson): void
{
    $stmt = $pdo->prepare(
        'UPDATE addondomain SET cf_zone_id = :zone_id, cf_status = :cf_status, cf_ns = :cf_ns WHERE domain = :domain AND sub_domain = :sub_domain',
    );
    if (!$stmt) {
        throw new RuntimeException('DB prepare failed.');
    }
    $stmt->execute([
        'zone_id' => $zoneId,
        'cf_status' => $status,
        'cf_ns' => $nsJson,
        'domain' => $domain,
        'sub_domain' => $subDomain,
    ]);
}

try {
    startUserGuardSession();
    $sessionSubId = authenticatedUserSubId();
    if ($sessionSubId === '') {
        jsonError(403, 'unauthorized');
    }
    if (!hasValidSessionCsrf('user_portal', requestCsrfToken())) {
        jsonError(419, 'invalid-csrf');
    }

    if (cfSyncRateLimited($sessionSubId)) {
        header('Retry-After: 600');
        jsonError(429, 'too-many-requests');
    }

    $domain    = trim((string) ($_POST['domain'] ?? ''));
    $subDomain = strtoupper(trim((string) ($_POST['sub_domain'] ?? '')));

    if ($domain === '' || $subDomain === '') {
        jsonError(422, 'missing-fields');
    }
    if ($subDomain !== $sessionSubId) {
        jsonError(403, 'forbidden');
    }

    // Confirm domain belongs to this user
    $stmt = $pdo->prepare('SELECT id FROM addondomain WHERE domain = :domain AND sub_domain = :sub_domain LIMIT 1');
    if (!$stmt) {
        jsonError(500, 'db-error');
    }
    $stmt->execute(['domain' => $domain, 'sub_domain' => $subDomain]);
    $check = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$check) {
        jsonError(403, 'domain-not-found');
    }

    // Prefer user-specific CF credentials, fall back to admin env
    $cfToken     = '';
    $cfAccountId = '';
    $uStmt = $pdo->prepare('SELECT cf_token, cf_account_id FROM `generate` WHERE sub_id = :sub_id LIMIT 1');
    if ($uStmt) {
        $uStmt->execute(['sub_id' => $sessionSubId]);
        $uRow = $uStmt->fetch(PDO::FETCH_ASSOC);
        $cfToken     = trim(cf_token_decrypt((string) ($uRow['cf_token'] ?? '')));
        $cfAccountId = trim((string) ($uRow['cf_account_id'] ?? ''));
    }
    if ($cfToken === '') {
        $cfToken     = app_env('CF_API_TOKEN', '');
        $cfAccountId = app_env('CF_ACCOUNT_ID', '');
    }

    if ($cfToken === '') {
        jsonError(500, 'cf-not-configured');
    }
    if ($cfAccountId === '') {
        jsonError(500, 'cf-account-missing');
    }

    $zoneId        = '';
    $cfStatus      = '';
    $nameServers   = [];
    $alreadyExists = false;

    // Attempt to create zone with explicit account binding.
    $createBody = ['name' => $domain, 'jump_start' => true];
    $createBody['account'] = ['id' => $cfAccountId];
    $createResp = cfApi('POST', '/zones', $createBody, $cfToken);

    if ($createResp['success'] ?? false) {
        $zone        = $createResp['result'];
        $zoneId      = $zone['id']           ?? '';
        $cfStatus    = $zone['status']        ?? 'pending';
        $nameServers = $zone['name_servers']  ?? [];
    } else {
        // Check if zone already exists (CF error code 1061)
        foreach (($createResp['errors'] ?? []) as $cfErr) {
            if (($cfErr['code'] ?? 0) === 1061) {
                $alreadyExists = true;
                break;
            }
        }

        if ($alreadyExists) {
            $listResp = cfApi('GET', '/zones?name=' . rawurlencode($domain), null, $cfToken);
            if (($listResp['success'] ?? false) && !empty($listResp['result'][0])) {
                $zone        = $listResp['result'][0];
                $zoneId      = $zone['id']          ?? '';
                $cfStatus    = $zone['status']       ?? 'pending';
                $nameServers = $zone['name_servers'] ?? [];
            } else {
                jsonError(409, 'zone-exists');
            }
        } else {
            $firstMsg = $createResp['errors'][0]['message'] ?? 'cf-api-failed';
            $firstMsg = is_string($firstMsg) ? $firstMsg : 'cf-api-failed';
            error_log('[cf-sync] zone create failed domain=' . $domain . ' msg=' . $firstMsg);
            jsonError(400, 'cf-api-failed');
        }
    }

    if ($zoneId !== '') {
        cfApplyAllRecommended($zoneId, $cfToken);

        // security_level is no longer force-set here, matching
        // cfProvisionAddonDomainZone() (the admin panel's equivalent path).
        // cfApplySettings() (part of cfApplyAllRecommended() above) already
        // applies the zone's baseline ('medium'). Forcing 'under_attack' on
        // every sync used to challenge every visitor with no way to leave it
        // off, and silently reverted any manual downgrade on the next sync.

        $serverIp = app_env('CF_SERVER_IP', '');
        if ($serverIp !== '') {
            cfProvisionDns($zoneId, $domain, $serverIp, $cfToken);
        }

        // Always refresh status — nameservers may have propagated between the initial
        // zone fetch and now, or CF may have activated the zone asynchronously.
        try {
            $freshResp = cfApi('GET', '/zones/' . $zoneId, null, $cfToken);
            if (($freshResp['success'] ?? false) && isset($freshResp['result']['status'])) {
                $cfStatus    = (string) $freshResp['result']['status'];
                $nameServers = (array) ($freshResp['result']['name_servers'] ?? $nameServers);
            }
        } catch (Throwable $e) {
            // keep status from initial fetch
        }
    }

    // Persist zone data to addondomain row
    cfSyncSaveToDB($pdo, $domain, $subDomain, $zoneId, $cfStatus, json_encode($nameServers) ?: '[]');

    echo json_encode([
        'ok'             => true,
        'zone_id'        => $zoneId,
        'status'         => $cfStatus,
        'name_servers'   => $nameServers,
        'already_exists' => $alreadyExists,
        'skipped'        => false,
    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    error_log('[cf-sync] Unhandled error: ' . $e->getMessage());
    jsonError(500, 'server-error');
}
