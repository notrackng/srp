<?php

declare(strict_types=1);

/*
 * Append-only writer for the daily click log at
 * {project_root}/statistics/temp/YYYY-MM-DD.json.
 *
 * Function definitions come first because they are guarded with
 * function_exists() (conditional declarations are NOT hoisted), and the
 * procedural section below calls them.
 */

if (!function_exists('meetup_with_click_id')) {
    /**
     * Prepend the `id` key so encoded field order matches the legacy writer
     * (id, click_id, country_code, device_type, ip_address, info, time).
     *
     * @param array<string, scalar> $record
     * @return array<string, scalar|int>
     */
    function meetup_with_click_id(array $record, int $id): array
    {
        return ['id' => $id] + $record;
    }
}

if (!function_exists('meetup_write_click_array')) {
    /**
     * Overwrite the file with a complete JSON array (used for the first element
     * and the corrupt-file rebuild path).
     *
     * @param resource $fp
     * @param list<array<array-key, mixed>> $rows
     */
    function meetup_write_click_array($fp, array $rows): void
    {
        $json = json_encode($rows, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            return;
        }

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $json);
        fflush($fp);
    }
}

if (!function_exists('meetup_rebuild_click_array')) {
    /**
     * Fallback for a file that is not a recognisable JSON array: decode what is
     * there, append the new record with a continued id, and rewrite. Matches the
     * legacy writer's tolerance of corrupt content (resets to a valid array).
     *
     * @param resource $fp
     * @param array<string, scalar> $record
     */
    function meetup_rebuild_click_array($fp, int $size, array $record): void
    {
        fseek($fp, 0, SEEK_SET);
        $raw = (string) fread($fp, max(1, $size));
        $decoded = json_decode($raw, true);
        $rows = is_array($decoded) ? array_values(array_filter($decoded, 'is_array')) : [];

        $lastId = 0;
        $last = end($rows);
        if (is_array($last) && isset($last['id']) && is_numeric($last['id'])) {
            $lastId = (int) $last['id'];
        }

        $rows[] = meetup_with_click_id($record, $lastId + 1);
        meetup_write_click_array($fp, $rows);
    }
}

if (!function_exists('meetup_append_click_record')) {
    /**
     * Append one record to a single-line JSON-array log in O(1) amortised time
     * by splicing the new element in before the closing bracket, instead of
     * decoding and re-encoding the whole file on every click (which was O(n)
     * per write → O(n^2) per day).
     *
     * The on-disk format (a JSON array of {id,...} objects, single line) and the
     * contiguous incremental `id` relied on by the realtime poller are preserved
     * byte-for-byte, so no reader changes are required. Fails closed: a log-write
     * problem never interrupts the redirect flow.
     *
     * @param array<string, scalar> $record record fields without `id`
     */
    function meetup_append_click_record(string $filename, array $record): void
    {
        $fp = @fopen($filename, 'c+');
        if ($fp === false) {
            return;
        }

        try {
            if (!flock($fp, LOCK_EX)) {
                return;
            }

            $stat = fstat($fp);
            $size = is_array($stat) ? (int) $stat['size'] : 0;

            // Empty / new file → fresh single-element array.
            if ($size <= 0) {
                meetup_write_click_array($fp, [meetup_with_click_id($record, 1)]);

                return;
            }

            // Read a bounded tail to locate the closing bracket and the last id
            // without reading the whole file.
            $window = $size > 65536 ? 65536 : $size;
            fseek($fp, $size - $window, SEEK_SET);
            $tail = (string) fread($fp, $window);

            $bracketPos = strrpos($tail, ']');
            if ($bracketPos === false) {
                // Not a recognisable array — rebuild safely from a full decode.
                meetup_rebuild_click_array($fp, $size, $record);

                return;
            }

            // Byte offset of the closing ']' within the whole file.
            $bracketOffset = max(0, $size - ($window - $bracketPos));

            // "[]" (possibly with trailing whitespace) → no leading comma.
            $beforeBracket = rtrim(substr($tail, 0, $bracketPos));
            $isEmptyArray = $beforeBracket !== '' && substr($beforeBracket, -1) === '[';

            // ids are monotonic, so the final "id":N in the tail is the largest.
            $lastId = 0;
            if (preg_match_all('/"id"\s*:\s*(\d+)/', $tail, $matches) > 0) {
                $lastId = (int) end($matches[1]);
            }

            $element = json_encode(
                meetup_with_click_id($record, $lastId + 1),
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
            );
            if (!is_string($element)) {
                return;
            }

            $suffix = ($isEmptyArray ? '' : ',') . $element . ']';

            // Readers (stats panels) read this file without a lock, so during the
            // truncate→append below a concurrent read can briefly see a bracket-less
            // array. They already fail-soft to an empty list, and this window is much
            // smaller than the legacy full-file rewrite it replaces.
            ftruncate($fp, $bracketOffset);
            fseek($fp, $bracketOffset, SEEK_SET);
            fwrite($fp, $suffix);
            fflush($fp);
        } catch (Throwable) {
            // silent fail-close for legacy include flow
        } finally {
            fclose($fp); // releases the lock
        }
    }
}

// ── Procedural entry (runs on every include from r.php) ───────────────────────
$baseDir = dirname(__DIR__, 2) . '/statistics/temp';
$today = gmdate('Y-m-d');                       // UTC: canonical click-log clock
$yesterday = gmdate('Y-m-d', strtotime('-1 day')); // strtotime('-1 day') is now-86400 (TZ-independent); gmdate renders it in UTC
$filename = $baseDir . '/' . $today . '.json';
$yesterdayFile = $baseDir . '/' . $yesterday . '.json';

$clickId = isset($click_id) && is_scalar($click_id) ? strtolower(trim((string) $click_id)) : '';
$countryCode = isset($country_code) && is_scalar($country_code) ? strtolower(trim((string) $country_code)) : '';
$deviceType = isset($device_type) && is_scalar($device_type) ? strtolower(trim((string) $device_type)) : '';
$ipAddress = isset($ip_address) && is_scalar($ip_address) ? trim((string) $ip_address) : '';
$userLp = isset($user_lp) && is_scalar($user_lp) ? trim((string) $user_lp) : '';

if (!is_dir($baseDir)) {
    mkdir($baseDir, 0700, true);
}

meetup_append_click_record($filename, [
    'click_id' => $clickId,
    'country_code' => $countryCode,
    'device_type' => $deviceType,
    'ip_address' => $ipAddress,
    'info' => $userLp,
    'time' => $today,
]);

if (is_file($yesterdayFile)) {
    @unlink($yesterdayFile);
}
