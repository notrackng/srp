#!/usr/bin/env bash
#
# inode-snapshot.sh — daily inode/disk snapshot + cron-job health check.
#
# Why this exists: `df -i` reports usage for the whole shared filesystem
# (/dev/sdc1), not just this cPanel account, so a single point-in-time read
# is not a meaningful signal by itself — it has to be read as a trend over
# many days, and only alongside confirmation that this project's own cleanup
# jobs (cache-cleanup, cleanup-storage, geoip update, log rotation) are
# actually firing. This script appends one snapshot per run so that trend
# exists to read later, without anyone needing to be watching in real time.
#
# Cron (daily 04:10, 10 min after rotate-logs.sh — see setup-cron.sh):
#   10 4 * * * /bin/bash /home/<user>/<project>/inode-snapshot.sh >/dev/null 2>&1
#
# NOTE: this file must keep LF line endings (same caveat as rotate-logs.sh).

set -uo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LOG_DIR="${PROJECT_DIR}/redirect/logs"
OUT="${LOG_DIR}/inode-snapshot.log"

mkdir -p "$LOG_DIR"

{
    echo "===== $(date -u +'%Y-%m-%d %H:%M:%S UTC') ====="
    echo "-- df -i (whole shared filesystem, not just this account) --"
    df -i /home/taawonap 2>&1 | tail -n +1
    echo "-- last line of each cron job's log (freshness check) --"
    for f in cache-cleanup.log cleanup-storage.log geoip-update.log rotate-logs.log; do
        path="${LOG_DIR}/${f}"
        if [[ -f "$path" ]]; then
            printf '%-22s mtime=%s  last: %s\n' \
                "$f" \
                "$(date -u -d "@$(stat -c %Y "$path")" +'%Y-%m-%d %H:%M' 2>/dev/null || echo '?')" \
                "$(tail -n 1 "$path")"
        else
            printf '%-22s (belum ada)\n' "$f"
        fi
    done
    echo
} >> "$OUT"
