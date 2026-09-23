#!/usr/bin/env bash
#
# rotate-logs.sh — size-capped rotation for the SRP/NGIX log files.
#
# Why this exists: php.error.log is written by every module and never rotated,
# so it grows without bound (it was already ~7.6 MB when this was added). A full
# disk on a cPanel account takes the whole site down, including the redirect hot
# path, so the log has to be capped.
#
# Rotation strategy is copy-truncate, NOT rename:
#   PHP under LiteSpeed can hold the log file open. Renaming it would leave the
#   running process writing to an unlinked inode, and the "new" log would stay
#   empty until the next PHP restart. Copying then truncating in place keeps the
#   inode — and every open file descriptor — valid.
#
# Usage:
#   bash rotate-logs.sh --dry-run          # show what would happen, change nothing
#   bash rotate-logs.sh                    # rotate anything over the size cap
#   bash rotate-logs.sh --force            # rotate regardless of size
#   bash rotate-logs.sh --max-size 20 --keep 10
#
# Cron (daily 04:00 — see setup-cron.sh for the project's other jobs):
#   0 4 * * * /bin/bash /home/<user>/<project>/rotate-logs.sh >/dev/null 2>&1
#
# NOTE: this file must keep LF line endings. A CRLF copy uploaded from Windows
# will not execute (same caveat as setup-cron.sh).

set -uo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MAX_SIZE_MB=10   # rotate once a log exceeds this
KEEP=5           # how many compressed generations to retain
DRY_RUN=false
FORCE=false

# ── Locate this deployment ────────────────────────────────────────────────────
# Everything is derived from where THIS script sits, never hardcoded: these
# paths used to name one specific account and domain, so a copy deployed
# anywhere else silently rotated nothing at all (every path missing = no work,
# exit 0, no complaint). PROJECT_DIR is the docroot holding rotate-logs.sh;
# HOME_DIR is the cPanel account above it, which is where ~/logs lives.
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# cPanel accounts live under /home/<user>/ (or /home2/, /home3/ … on bigger
# shared boxes). Fall back to $HOME, then to the parent directory, so the script
# still does something sensible off cPanel.
if [[ "$PROJECT_DIR" =~ ^(/home[0-9]*/[^/]+)(/|$) ]]; then
    HOME_DIR="${BASH_REMATCH[1]}"
elif [[ -n "${HOME:-}" && -d "$HOME" ]]; then
    HOME_DIR="$HOME"
else
    HOME_DIR="$(dirname -- "$PROJECT_DIR")"
fi

# Logs to manage. The PHP error log lives outside the docroot on purpose; the
# cron logs sit inside redirect/, which is itself a document root in the
# per-subdomain deployment mode (they are denied over HTTP by redirect/.htaccess).
# rotate-logs.log is this script's own cron output. Including it is safe
# precisely because of copy-truncate: cron holds it open via `>>`, and
# truncating in place keeps that descriptor valid.
#
# Keep the error-log path in step with the .user.ini files, which the installer
# points at "$HOME_DIR/logs/php.error.log" (ins_write_user_ini in installer_lib.php).
#
# The per-webroot error_log files below are created automatically by PHP
# (each webroot's .user.ini sets its own error_log path) and are never
# truncated by anything else — same unbounded-growth problem as
# php.error.log, just one file per docroot instead of one for the account.
LOG_FILES=(
    "$HOME_DIR/logs/php.error.log"
    "$PROJECT_DIR/error_log"
    "$PROJECT_DIR/public/error_log"
    "$PROJECT_DIR/redirect/error_log"
    "$PROJECT_DIR/statistics/error_log"
    "$PROJECT_DIR/statistics/realtime/error_log"
    "$PROJECT_DIR/statistics/postback/error_log"
    "$PROJECT_DIR/redirect/logs/cache-cleanup.log"
    "$PROJECT_DIR/redirect/logs/geoip-update.log"
    "$PROJECT_DIR/redirect/logs/rotate-logs.log"
    "$PROJECT_DIR/redirect/logs/cleanup-storage.log"
    "$PROJECT_DIR/redirect/logs/inode-snapshot.log"
    "$PROJECT_DIR/redirect/logs/inode-snapshot-cron.log"
)

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)  DRY_RUN=true; shift ;;
        --force)    FORCE=true; shift ;;
        --max-size) MAX_SIZE_MB="${2:-10}"; shift 2 ;;
        --keep)     KEEP="${2:-5}"; shift 2 ;;
        -h|--help)
            sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Try: bash $0 --help" >&2
            exit 2
            ;;
    esac
done

if ! [[ "$MAX_SIZE_MB" =~ ^[0-9]+$ ]] || [[ "$MAX_SIZE_MB" -lt 1 ]]; then
    echo "--max-size must be a positive integer (MB)" >&2
    exit 2
fi

if ! [[ "$KEEP" =~ ^[0-9]+$ ]] || [[ "$KEEP" -lt 1 ]]; then
    echo "--keep must be a positive integer" >&2
    exit 2
fi

MAX_BYTES=$(( MAX_SIZE_MB * 1024 * 1024 ))

human() {
    local b=$1
    if   [[ $b -ge 1048576 ]]; then awk -v b="$b" 'BEGIN{printf "%.1f MB", b/1048576}'
    elif [[ $b -ge 1024    ]]; then awk -v b="$b" 'BEGIN{printf "%.1f KB", b/1024}'
    else echo "${b} B"
    fi
}

run() {
    if [[ "$DRY_RUN" == true ]]; then
        echo "      would run: $*"
    else
        "$@"
    fi
}

rotated_any=false

for LOG in "${LOG_FILES[@]}"; do
    if [[ ! -f "$LOG" ]]; then
        echo "skip   $LOG (tidak ada)"
        continue
    fi

    if [[ ! -w "$LOG" ]]; then
        echo "SKIP   $LOG (tidak bisa ditulis — cek permission)" >&2
        continue
    fi

    size=$(stat -c %s "$LOG" 2>/dev/null || echo 0)

    if [[ "$FORCE" != true && "$size" -lt "$MAX_BYTES" ]]; then
        echo "ok     $LOG ($(human "$size") < $(human "$MAX_BYTES"))"
        continue
    fi

    echo "rotate $LOG ($(human "$size"))"
    rotated_any=true

    # Drop the oldest generation, then shift the rest up by one.
    if [[ -f "${LOG}.${KEEP}.gz" ]]; then
        run rm -f "${LOG}.${KEEP}.gz"
    fi

    for (( i = KEEP - 1; i >= 1; i-- )); do
        if [[ -f "${LOG}.${i}.gz" ]]; then
            run mv -f "${LOG}.${i}.gz" "${LOG}.$(( i + 1 )).gz"
        fi
    done

    # Copy-truncate: preserve the inode so any process holding the file open
    # keeps writing to the same descriptor.
    if [[ "$DRY_RUN" == true ]]; then
        echo "      would run: cp \"$LOG\" \"${LOG}.1\" && gzip \"${LOG}.1\" && : > \"$LOG\""
    else
        if cp "$LOG" "${LOG}.1"; then
            : > "$LOG"
            if gzip -f "${LOG}.1"; then
                chmod 640 "${LOG}.1.gz" 2>/dev/null || true
                echo "       -> ${LOG}.1.gz"
            else
                echo "       ! gzip gagal; arsip tertinggal sebagai ${LOG}.1" >&2
            fi
        else
            echo "       ! copy gagal; log dibiarkan apa adanya" >&2
        fi
    fi
done

if [[ "$DRY_RUN" == true ]]; then
    echo
    echo "DRY-RUN — tidak ada perubahan yang disimpan."
elif [[ "$rotated_any" == false ]]; then
    echo
    echo "Tidak ada log yang melewati batas ${MAX_SIZE_MB} MB."
fi
