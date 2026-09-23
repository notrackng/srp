<?php

declare(strict_types=1);

include_once('../session_guards.php');
include_once(dirname(__DIR__, 2) . '/env.php');
load_env_file(dirname(__DIR__, 2) . '/.env');

header('Content-Type: application/json; charset=utf-8');

function cpanelGet(string $url, string $authHeader, int $timeout = 8): ?array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER     => [$authHeader],
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 5,
    ]);
    $resp  = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($resp === false || $errno !== 0) {
        return null;
    }
    $data = json_decode((string) $resp, true);

    return is_array($data) ? $data : null;
}

function normalizeNs(string $ns): string
{
    return rtrim(strtolower(trim($ns)), '.');
}

function isCloudflarens(string $ns): bool
{
    return str_contains(strtolower($ns), 'cloudflare');
}

try {
    startAdminGuardSession();
    if (empty($_SESSION['admin_authenticated'])) {
        jsonError(403, 'unauthorized');
    }

    $user  = app_env('CPANEL_USER', '');
    $token = app_env('CPANEL_API_TOKEN', '');
    $pass  = app_env('CPANEL_PASSWORD', '');
    $port  = (int) app_env('CPANEL_PORT', '2083');
    $host  = app_detect_cpanel_host(app_env('CPANEL_HOST', 'localhost'), $port);

    if ($user === '' || ($token === '' && $pass === '')) {
        echo json_encode(['ok' => false, 'ns' => [], 'err' => 'cpanel-not-configured']);
        exit;
    }

    $authHeader = $token !== ''
        ? 'Authorization: cpanel ' . $user . ':' . $token
        : 'Authorization: Basic ' . base64_encode($user . ':' . $pass);

    $base   = sprintf('https://%s:%d', $host, $port);
    $nsList = [];

    // ── Strategy 0: .env CF_NS1..CF_NS4 (authoritative when configured) ──
    // If any nameserver is defined in .env, use that exclusively and skip
    // the cPanel/DNS auto-detection strategies below.
    foreach (['CF_NS1', 'CF_NS2', 'CF_NS3', 'CF_NS4'] as $key) {
        $v = normalizeNs((string) app_env($key, ''));
        if ($v !== '') {
            $nsList[] = $v;
        }
    }
    if (!empty($nsList)) {
        $nsList = array_values(array_unique(array_filter($nsList)));
        echo json_encode(['ok' => true, 'ns' => $nsList]);
        exit;
    }

    // ── Strategy 1: read /var/cpanel/nameserverips (server config file) ──
    // Format: ns1.host.com=1.2.3.4  (one per line)
    foreach (['/var/cpanel/nameserverips', '/etc/nameserverips'] as $file) {
        if (!is_readable($file)) {
            continue;
        }
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) {
            continue;
        }
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $ns = normalizeNs(explode('=', $line)[0]);
            if ($ns !== '' && !isCloudflarens($ns)) {
                $nsList[] = $ns;
            }
        }
        if (!empty($nsList)) {
            break;
        }
    }

    // ── Strategy 2: UAPI Nameservers/get_nameservers ─────────────────────
    if (empty($nsList)) {
        $resp = cpanelGet($base . '/execute/Nameservers/get_nameservers', $authHeader);
        if ($resp !== null) {
            $raw = $resp['result']['data']['nameservers'] ?? $resp['result']['data'] ?? [];
            if (is_array($raw)) {
                foreach ($raw as $ns) {
                    if (is_string($ns) && $ns !== '' && !isCloudflarens($ns)) {
                        $nsList[] = normalizeNs($ns);
                    }
                }
            }
        }
    }

    // ── Strategy 3: ZoneEdit fetchzone — NS records, skip Cloudflare ─────
    if (empty($nsList)) {
        $mainDomain = '';
        $domResp = cpanelGet($base . '/execute/DomainInfo/main_domain', $authHeader);
        if ($domResp !== null) {
            $mainDomain = $domResp['result']['data']['domain'] ?? '';
        }
        if ($mainDomain !== '') {
            $q = http_build_query([
                'cpanel_jsonapi_user'       => $user,
                'cpanel_jsonapi_apiversion' => '2',
                'cpanel_jsonapi_module'     => 'ZoneEdit',
                'cpanel_jsonapi_func'       => 'fetchzone',
                'domain'                    => $mainDomain,
            ]);
            $zoneResp = cpanelGet($base . '/json-api/cpanel?' . $q, $authHeader, 10);
            if ($zoneResp !== null) {
                $records = $zoneResp['cpanelresult']['data'][0]['record'] ?? [];
                // Collect NS records that are NOT Cloudflare
                $zoneNs = [];
                $soaMname = '';
                foreach ($records as $rec) {
                    $type = $rec['type'] ?? '';
                    if ($type === 'NS') {
                        $ns = normalizeNs($rec['address'] ?? '');
                        if ($ns !== '' && !isCloudflarens($ns)) {
                            $zoneNs[] = $ns;
                        }
                    }
                    if ($type === 'SOA' && $soaMname === '') {
                        $mname = normalizeNs($rec['mname'] ?? $rec['address'] ?? '');
                        if ($mname !== '' && !isCloudflarens($mname)) {
                            $soaMname = $mname;
                        }
                    }
                }
                $nsList = $zoneNs ?: ($soaMname !== '' ? [$soaMname] : []);
            }
        }
    }

    // ── Strategy 4: DNS lookup on CPANEL_HOST domain ─────────────────────
    // e.g. host = cp.hawkhost.com → lookup hawkhost.com NS
    if (empty($nsList)) {
        $parts      = explode('.', $host);
        $hostDomain = count($parts) >= 2
            ? implode('.', array_slice($parts, -2))
            : '';
        if ($hostDomain !== '' && $hostDomain !== 'localhost') {
            $records = @dns_get_record($hostDomain, DNS_NS);
            if (is_array($records)) {
                foreach ($records as $r) {
                    $ns = normalizeNs($r['target'] ?? '');
                    if ($ns !== '' && !isCloudflarens($ns)) {
                        $nsList[] = $ns;
                    }
                }
            }
        }
    }

    // ── Strategy 5: fallback to env CF_NS1/CF_NS2/CF_NS3/CF_NS4 ─────────
    if (empty($nsList)) {
        foreach (['CF_NS1', 'CF_NS2', 'CF_NS3', 'CF_NS4'] as $key) {
            $v = normalizeNs((string) app_env($key, ''));
            if ($v !== '') {
                $nsList[] = $v;
            }
        }
    }

    $nsList = array_values(array_unique(array_filter(array_map('normalizeNs', $nsList))));
    sort($nsList);

    echo json_encode(['ok' => true, 'ns' => $nsList]);
} catch (Throwable $e) {
    echo json_encode(['ok' => false, 'ns' => [], 'err' => 'server-error']);
}
