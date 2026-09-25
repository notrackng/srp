<?php

/**
 * Sentinel stored in offering.country_code to mean "any country".
 *
 * Deliberately not a real ISO code: meetup_sanitize_country_code() only ever
 * yields two lowercase letters, so this value can never collide with a genuine
 * per-country row. Declared here at the top — `const` at file scope is a runtime
 * statement and is not hoisted.
 */

declare(strict_types=1);

const MEETUP_OFFER_ANY_COUNTRY = 'GLOBAL';

/** @var PDO $pdo */
$pdo = require __DIR__ . '/../connection.config.php';
require_once dirname(__DIR__, 2) . '/Base64URL.php';
require_once __DIR__ . '/../redirect_payload.php';
require_once __DIR__ . '/../sanitize.php';

$redirectPayload = srp_redirect_payload_decode($_GET['rk'] ?? null);

if ($redirectPayload === null) {
    meetup_fail(400);
}

$click_id = meetup_sanitize_token($redirectPayload['click_id'], 128);
$country_code = meetup_sanitize_country_code($redirectPayload['country_code']);
$device_type = meetup_sanitize_token($redirectPayload['device_type'], 32);
$ip_address = meetup_sanitize_ip($redirectPayload['ip_address']);
$user_lp = meetup_sanitize_token($redirectPayload['user_lp'], 64);

if ($click_id === null || $country_code === null || $device_type === null || $user_lp === null) {
    meetup_fail(400);
}

try {
    // The link's network (user_lp) is the PRIMARY discriminator, and every
    // lookup below is scoped to it. The offer URL carries that network's own
    // tracking parameters, so resolving a TRAFEE link to a LOSPOLLOS smartlink
    // would break attribution and credit the wrong account.
    //
    // Within the matched network, country narrows the choice:
    //   1. this network + the visitor's country
    //   2. this network + MEETUP_OFFER_ANY_COUNTRY (the "all countries" row)
    //   3. this network, whatever country_code it carries
    //
    // Tier 2 is needed because meetup_sanitize_country_code() only ever yields
    // two lowercase letters, so $country_code can never equal the 'GLOBAL'
    // sentinel stored in the column.
    //
    // There is deliberately NO cross-network fallback: when a network has no
    // row at all, 404 is the correct answer. Serving another network's
    // smartlink is worse than serving nothing.
    $linkNetwork = strtoupper($user_lp);

    $offerRow = meetup_fetch_offer_for_network($pdo, $linkNetwork, $country_code)
        ?? meetup_fetch_offer_for_network($pdo, $linkNetwork, MEETUP_OFFER_ANY_COUNTRY)
        ?? meetup_fetch_offer_for_network($pdo, $linkNetwork, null);

    if ($offerRow === null) {
        error_log('[srp] no offer row for network=' . $linkNetwork . ' country=' . $country_code);
        meetup_fail(404);
    }

    $redirect = html_entity_decode($offerRow['offer'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $resolvedNetwork = meetup_sanitize_token($offerRow['network'], 64);

    if ($redirect === '' || $resolvedNetwork === null) {
        meetup_fail(500);
    }

    $placeholders = ['{sub_id}', '{click_id}'];
    $replacements = [
        strtoupper($click_id),
        base64url_encode(
            strtoupper($click_id)
            . ',' . strtoupper($country_code)
            . ',' . ($ip_address !== '' ? $ip_address : '0.0.0.0')
            . ',' . strtoupper($device_type)
            . ',' . strtoupper($resolvedNetwork),
        ),
    ];
    $offer = str_replace($placeholders, $replacements, $redirect);

    $offerUrl = meetup_sanitize_offer_url($offer);
    if ($offerUrl === null) {
        error_log('[srp] offer URL invalid/blocked for network=' . $linkNetwork);
        meetup_fail(500);
    }

    if ($click_id !== '') {
        require __DIR__ . '/clicks.php';
    }
} catch (Throwable $e) {
    error_log('Meetup offer lookup failed: ' . $e->getMessage());
    meetup_fail(500);
}

$nonce = bin2hex(random_bytes(16));

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Referrer-Policy: no-referrer');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Content-Type: text/html; charset=UTF-8');
header(
    "Content-Security-Policy: default-src 'none'; script-src 'nonce-{$nonce}'; "
    . "base-uri 'none'; frame-ancestors 'none'",
);

$safeUrl = htmlspecialchars($offerUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8');
echo '<!DOCTYPE html><html><head>'
    . '<meta charset="UTF-8">'
    . '<meta name="referrer" content="no-referrer">'
    . '<meta http-equiv="refresh" content="0;url=' . $safeUrl . '">'
    . '</head><body><script nonce="' . htmlspecialchars($nonce, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '">window.location.replace('
    . json_encode($offerUrl, JSON_UNESCAPED_SLASHES) . ');</script></body></html>';
exit;

/**
 * Offer lookup scoped to one network.
 *
 * $countryCode narrows within that network; pass null to accept any country_code.
 * Keeps the random-id rotation so several rows on the same network still share
 * traffic evenly.
 *
 * @return array{offer: string, network: string}|null
 */
function meetup_fetch_offer_for_network(PDO $pdo, string $network, ?string $countryCode): ?array
{
    // WHERE fragment is built only from these fixed literals; every value is
    // bound, so the network and country never reach the SQL text. The outer
    // query and the range subquery below each get their OWN placeholder names
    // (network/network2, country_code/country_code2) bound to the same values,
    // rather than reusing one placeholder twice in the statement — this
    // connection runs with PDO::ATTR_EMULATE_PREPARES=false (real MySQL
    // prepares), and re-parenting one bound value onto every occurrence of a
    // repeated named placeholder is a PDO SQL-parser behavior, not a MySQL
    // wire-protocol guarantee, so this sidesteps relying on it.
    $where = 'network = :network';
    $whereSub = 'network = :network2';
    $params = ['network' => $network, 'network2' => $network];

    if ($countryCode !== null) {
        $where .= ' AND country_code = :country_code';
        $whereSub .= ' AND country_code = :country_code2';
        $params['country_code'] = $countryCode;
        $params['country_code2'] = $countryCode;
    }

    // One round trip instead of two: the MIN/MAX range and the random-id pick
    // used to be separate queries (plus a same-tier retry for the race window
    // between them). Folding the range into a subquery keeps the identical
    // selection algorithm — random id within [min,max], then the first row at
    // or after it — as a single atomic statement, which also removes that
    // race window outright (nothing can delete a row between "read the range"
    // and "fetch by id" when both happen inside one query).
    $statement = $pdo->prepare(
        'SELECT offer, network FROM offering '
        . 'WHERE ' . $where . ' AND id >= ('
        . 'SELECT FLOOR(MIN(id) + RAND() * (MAX(id) - MIN(id))) FROM offering WHERE ' . $whereSub
        . ') ORDER BY id ASC LIMIT 1',
    );
    $statement->execute($params);
    $row = $statement->fetch();

    if (!is_array($row)) {
        return null;
    }

    $offer = is_string($row['offer']) ? $row['offer'] : '';
    $network = is_string($row['network']) ? $row['network'] : '';

    return [
        'offer' => $offer,
        'network' => $network,
    ];
}

function meetup_sanitize_offer_url(string $value): ?string
{
    $value = trim($value);
    if ($value === '' || strlen($value) > 2048) {
        return null;
    }

    if (filter_var($value, FILTER_VALIDATE_URL) === false) {
        return null;
    }

    $scheme = strtolower((string) parse_url($value, PHP_URL_SCHEME));
    if ($scheme !== 'https') {
        return null;
    }

    // Self-referral guard: an offering.offer row pointing back at this domain
    // would loop the paying click back into the app instead of an advertiser.
    // Matches the same check public/s.php and the legacy-shortlink branch of
    // redirect/index.php apply to their final redirect target — this is that
    // same class of destination and deserves the same guard. Checked before
    // the shared allowlist on purpose: srp_url_host_allowed() auto-detects its
    // domain list FROM the offering table when no explicit allowlist is set,
    // so a self-pointing offer row would otherwise auto-allowlist itself.
    if (srp_url_is_self($value)) {
        error_log('[srp] offer target blocked — points back at this domain: ' . strtolower((string) parse_url($value, PHP_URL_HOST)));

        return null;
    }

    if (!srp_url_host_allowed($value)) {
        error_log('[srp] offer target blocked — host not in SRP_OFFER_ALLOWED_DOMAINS: ' . strtolower((string) parse_url($value, PHP_URL_HOST)));

        return null;
    }

    return $value;
}

function meetup_fail(int $statusCode): never
{
    http_response_code($statusCode);
    header('Content-Type: text/plain; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    exit;
}
