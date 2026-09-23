<?php

declare(strict_types=1);

namespace Srp\Redirect;

/**
 * FilterEngine — Timed filter cycle management for redirect traffic.
 *
 * Controls the 2-min filter / 3-min normal repeating cycle. Filter timing and
 * URL can be overridden at runtime via files in the srp_bb/ cache directory
 * (written by the admin "Redirect Decision" panel).
 *
 * Priority chain (highest first):
 *   1. Unified runtime file: {tmp}/srp_bb/filter_config.json
 *      ({filter_seconds, cycle_seconds, filter_url} — one atomic snapshot)
 *   2. Legacy split files: filter_timing.json + filter_url.txt (pre-unification)
 *   3. Environment: SRP_FILTER_SECONDS / SRP_CYCLE_SECONDS / SRP_FILTER_URL
 *   4. Constants: SRP_FILTER_DURATION / SRP_CYCLE_LENGTH / SRP_FILTER_URL
 *
 * Usage:
 *   $engine = new FilterEngine('srp_bb');
 *   if ($engine->isFilterMode()) { redirect to $engine->getFilterUrl(); }
 */
final class FilterEngine
{
    /**
     * Runtime cycle bounds — the single named source of the timing validation
     * limits. The admin panel writer (public/redirect-decision.php) mirrors these
     * values; its mirror sites carry a "keep in sync with FilterEngine" comment.
     */
    public const MIN_CYCLE_SECONDS = 60;
    public const MAX_CYCLE_SECONDS = 86400;

    /**
     * Byte cap for a filter URL. Bounds the legacy filter_url.txt read in
     * getFilterUrl() and keeps the unified filter_config.json envelope inside
     * the 2560-byte window readUnifiedConfig() reads. The admin panel's save
     * handler validates writes against this same constant.
     */
    public const MAX_FILTER_URL_LENGTH = 2048;

    private readonly string $cacheDir;
    private readonly int $defaultFilterSeconds;
    private readonly int $defaultCycleSeconds;
    private readonly string $defaultFilterUrl;

    /**
     * Memoized parse of the unified filter_config.json snapshot, or null when
     * the file is absent/invalid. Read once per instance so getTiming() and
     * getFilterUrl() always agree on a single consistent snapshot.
     *
     * @var array{filter:int,cycle:int,url:?string,block_vpn_asn:?bool}|null
     */
    private ?array $unifiedConfig = null;

    private bool $unifiedConfigLoaded = false;

    public function __construct(
        string $cacheSubDir,
        int $defaultFilterSeconds = 120,
        int $defaultCycleSeconds = 300,
        string $defaultFilterUrl = '',
    ) {
        $this->cacheDir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR . $cacheSubDir;
        $this->defaultFilterSeconds = $defaultFilterSeconds;
        $this->defaultCycleSeconds = $defaultCycleSeconds;
        $this->defaultFilterUrl = $defaultFilterUrl;
    }

    /**
     * Check if current time falls within the filter window.
     *
     * @param int|null $now Unix timestamp (injectable for testing).
     */
    public function isFilterMode(?int $now = null): bool
    {
        [$filterSeconds, $cycleSeconds] = $this->getTiming();
        $now ??= time();

        // filterSeconds <= 0 disables the window; cycleSeconds <= 0 would make the
        // modulo below a DivisionByZeroError, so treat it as disabled too.
        if ($filterSeconds <= 0 || $cycleSeconds <= 0) {
            return false;
        }

        return ($now % $cycleSeconds) < $filterSeconds;
    }

    /**
     * Get filter/cycle durations in seconds: [filterSeconds, cycleSeconds].
     *
     * @return array{0: int, 1: int}
     */
    public function getTiming(): array
    {
        // 1. Unified runtime snapshot (authoritative when present)
        $unified = $this->readUnifiedConfig();
        if ($unified !== null) {
            return [$unified['filter'], $unified['cycle']];
        }

        // 2. Legacy runtime cache file
        $file = $this->cacheDir . DIRECTORY_SEPARATOR . 'filter_timing.json';
        if (is_file($file)) {
            $raw = @file_get_contents($file, false, null, 0, 256);
            $data = is_string($raw) ? json_decode($raw, true) : null;
            if (
                is_array($data) && isset($data['filter_seconds'], $data['cycle_seconds'])
                && is_numeric($data['filter_seconds']) && is_numeric($data['cycle_seconds'])
            ) {
                $filter = (int) $data['filter_seconds'];
                $cycle  = (int) $data['cycle_seconds'];

                if (
                    $cycle >= self::MIN_CYCLE_SECONDS && $cycle <= self::MAX_CYCLE_SECONDS
                    && $filter >= 0 && $filter <= $cycle
                ) {
                    return [$filter, $cycle];
                }
            }
        }

        // 3. Environment
        $envFilter = (int) app_env('SRP_FILTER_SECONDS', '-1');
        $envCycle  = (int) app_env('SRP_CYCLE_SECONDS', '-1');
        if (
            $envCycle >= self::MIN_CYCLE_SECONDS && $envCycle <= self::MAX_CYCLE_SECONDS
            && $envFilter >= 0 && $envFilter <= $envCycle
        ) {
            return [$envFilter, $envCycle];
        }

        // 4. Defaults
        return [$this->defaultFilterSeconds, $this->defaultCycleSeconds];
    }

    /**
     * Get the filter-mode redirect URL, or null if none configured.
     * When null, the filter window redirects traffic to the normal path.
     */
    public function getFilterUrl(): ?string
    {
        // 1. Unified runtime snapshot (authoritative when present)
        $unified = $this->readUnifiedConfig();
        if ($unified !== null) {
            return $unified['url'];
        }

        // 2. Legacy runtime cache file
        $cacheFile = $this->cacheDir . DIRECTORY_SEPARATOR . 'filter_url.txt';
        if (is_file($cacheFile)) {
            $raw = @file_get_contents($cacheFile, false, null, 0, self::MAX_FILTER_URL_LENGTH);
            $url = is_string($raw) ? trim($raw) : '';
            if (self::isValidHttpsUrl($url)) {
                return $url;
            }
        }

        // 3. Environment
        $envUrl = app_env('SRP_FILTER_URL', '');
        if (
            $envUrl !== null
            && $envUrl !== ''
            && self::isValidHttpsUrl($envUrl)
        ) {
            return $envUrl;
        }

        // 4. Default
        if ($this->defaultFilterUrl !== '' && self::isValidHttpsUrl($this->defaultFilterUrl)) {
            return $this->defaultFilterUrl;
        }

        return null;
    }

    /**
     * Whether VPN/proxy + blocked-ASN traffic should be blocked (served the OG
     * cloak page) instead of the offer redirect.
     *
     * Precedence matches getTiming()/getFilterUrl():
     *   1. Unified runtime snapshot (block_vpn_asn)
     *   2. Environment SRP_BLOCK_VPN_ASN
     *   3. Default true (block) — fail-closed, consistent with the project's
     *      "security decisions fail closed" rule.
     */
    public function getBlockVpnAsn(): bool
    {
        $unified = $this->readUnifiedConfig();
        if ($unified !== null && isset($unified['block_vpn_asn'])) {
            return $unified['block_vpn_asn'];
        }

        $env = app_env('SRP_BLOCK_VPN_ASN', '');
        if (is_string($env) && $env !== '') {
            return filter_var($env, FILTER_VALIDATE_BOOL);
        }

        return true;
    }

    /**
     * Read and validate the unified runtime config, memoized per instance so a
     * single engine yields one consistent {timing, url} snapshot even though
     * getTiming() and getFilterUrl() are separate calls. The panel writes the
     * file as one atomic rename, so a reader never sees timing and URL from two
     * different generations.
     *
     * Treated as all-or-nothing: if timing is structurally invalid the whole
     * file is ignored (returns null) and callers fall through to the legacy
     * split files, then env, then defaults.
     *
     * @return array{filter:int,cycle:int,url:?string,block_vpn_asn:?bool}|null
     */
    private function readUnifiedConfig(): ?array
    {
        if ($this->unifiedConfigLoaded) {
            return $this->unifiedConfig;
        }
        $this->unifiedConfigLoaded = true;

        $file = $this->cacheDir . DIRECTORY_SEPARATOR . 'filter_config.json';
        if (!is_file($file)) {
            return $this->unifiedConfig = null;
        }

        $raw = @file_get_contents($file, false, null, 0, 2560);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (
            !is_array($data)
            || !isset($data['filter_seconds'], $data['cycle_seconds'])
            || !is_numeric($data['filter_seconds'])
            || !is_numeric($data['cycle_seconds'])
        ) {
            return $this->unifiedConfig = null;
        }

        $filter = (int) $data['filter_seconds'];
        $cycle  = (int) $data['cycle_seconds'];
        if (
            $cycle < self::MIN_CYCLE_SECONDS || $cycle > self::MAX_CYCLE_SECONDS
            || $filter < 0 || $filter > $cycle
        ) {
            return $this->unifiedConfig = null;
        }

        $urlRaw = isset($data['filter_url']) && is_string($data['filter_url'])
            ? trim($data['filter_url'])
            : '';
        $url = self::isValidHttpsUrl($urlRaw) ? $urlRaw : null;

        // Optional flag; null when absent so callers fall through to env/default.
        $blockVpnAsn = isset($data['block_vpn_asn']) && is_bool($data['block_vpn_asn'])
            ? $data['block_vpn_asn']
            : null;

        return $this->unifiedConfig = [
            'filter' => $filter,
            'cycle' => $cycle,
            'url' => $url,
            'block_vpn_asn' => $blockVpnAsn,
        ];
    }

    /**
     * Whether a string is a filter URL this engine will actually use.
     *
     * Public and static so the admin panel's save handler can validate against
     * the same rule the engine applies when reading, instead of keeping its own
     * copy: a URL the panel accepts is by construction one the engine honors.
     * Length is checked separately by the caller, against
     * MAX_FILTER_URL_LENGTH.
     */
    public static function isValidHttpsUrl(string $url): bool
    {
        return $url !== ''
            && filter_var($url, FILTER_VALIDATE_URL) !== false
            && strtolower((string) parse_url($url, PHP_URL_SCHEME)) === 'https';
    }
}
