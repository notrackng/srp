#!/usr/bin/env bash
# =============================================================================
#  SRP — Auto Cron Setup
#  Usage: bash setup-cron.sh [--php /usr/local/bin/php] [--dry-run]
#
#  Safe to run multiple times — skips jobs that already exist.
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHP_BIN=""
DRY_RUN=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --php)    PHP_BIN="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()      { echo -e "${GREEN}  ✔${RESET}  $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET}  $*"; }
info()    { echo -e "${CYAN}  →${RESET}  $*"; }
err()     { echo -e "${RED}  ✖${RESET}  $*" >&2; }
section() { echo -e "\n${BOLD}$*${RESET}"; }

# ── Detect PHP binary ─────────────────────────────────────────────────────────
detect_php() {
    if [[ -n "$PHP_BIN" ]]; then
        if [[ -x "$PHP_BIN" ]]; then
            echo "$PHP_BIN"
            return
        fi

        local fallback_bin=""
        if command -v php >/dev/null 2>&1; then
            fallback_bin="$(command -v php)"
            warn "PHP binary tidak tersedia: $PHP_BIN; memakai fallback: $fallback_bin"
            echo "$fallback_bin"
            return
        fi

        warn "PHP binary tidak tersedia: $PHP_BIN"
    fi

    # Coba lokasi umum
    local candidates=(
        "$(command -v php 2>/dev/null || true)"
        /usr/local/bin/php
        /usr/bin/php
        /opt/cpanel/ea-php83/root/usr/bin/php
        /opt/cpanel/ea-php82/root/usr/bin/php
        /opt/cpanel/ea-php81/root/usr/bin/php
    )

    for bin in "${candidates[@]}"; do
        if [[ -n "$bin" && -x "$bin" ]]; then
            echo "$bin"
            return
        fi
    done

    err "PHP binary tidak ditemukan. Gunakan: bash setup-cron.sh --php /path/to/php"
    exit 1
}

# ── Tulis ulang crontab, aman untuk existing string kosong ────────────────────
commit_crontab() {
    local existing="$1"
    local new_line="$2"

    if [[ -n "$existing" ]]; then
        printf '%s\n%s\n' "$existing" "$new_line" | crontab -
    else
        printf '%s\n' "$new_line" | crontab -
    fi
}

# ── Add cron job — idempotent, dan self-healing bila PHP_BIN/path berubah ─────
add_cron() {
    local schedule="$1"
    local command="$2"
    local label="$3"
    local log_file="$4"
    local match_key="$5" # substring unik job ini (path script) dipakai untuk deteksi & replace

    local full_cmd="${schedule} cd \"${SCRIPT_DIR}\" && ${command} >> ${log_file} 2>&1"

    # `crontab -l` keluar dengan status non-zero saat user belum punya crontab
    # sama sekali (akun cPanel baru) — kasus paling umum saat script ini pertama
    # kali dijalankan. `|| true` WAJIB ada di sini: tanpanya, di bawah `set -e`,
    # baris ini menghentikan seluruh script sebelum sempat menulis job apa pun.
    local existing
    existing="$(crontab -l 2>/dev/null || true)"

    if grep -qF "$match_key" <<< "$existing"; then
        if grep -qF "$full_cmd" <<< "$existing"; then
            warn "${label} — sudah ada, skip"
            return 0
        fi

        if [[ "$DRY_RUN" == true ]]; then
            info "[DRY-RUN] Akan diperbarui: ${full_cmd}"
            return 0
        fi

        # Job sudah ada tapi baris berubah (mis. --php memperbaiki binary yang
        # salah) — ganti baris lama, jangan biarkan dua entri berjalan dobel.
        existing="$(grep -vF "$match_key" <<< "$existing" || true)"
        commit_crontab "$existing" "$full_cmd"
        ok "${label} — diperbarui (PHP binary/path berubah)"
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Akan ditambahkan: ${full_cmd}"
        return 0
    fi

    commit_crontab "$existing" "$full_cmd"
    ok "${label} — ditambahkan"
}

# =============================================================================
#  MAIN
# =============================================================================

section "SRP Cron Setup"
echo "  Base path : ${SCRIPT_DIR}"
echo ""

# ── Detect PHP ────────────────────────────────────────────────────────────────
section "Deteksi PHP"
PHP_BIN="$(detect_php)"
PHP_VER="$("$PHP_BIN" -r 'echo PHP_VERSION;' 2>/dev/null || echo 'unknown')"
ok "PHP binary : ${PHP_BIN}"
ok "PHP version: ${PHP_VER}"

# ── Buat logs directory ───────────────────────────────────────────────────────
section "Persiapan"
LOG_DIR="${SCRIPT_DIR}/redirect/logs"
if [[ ! -d "$LOG_DIR" ]]; then
    mkdir -p "$LOG_DIR"
    ok "Dibuat: ${LOG_DIR}"
else
    ok "Sudah ada: ${LOG_DIR}"
fi

# ── Verifikasi scripts ada ────────────────────────────────────────────────────
CLEANUP_SCRIPT="${SCRIPT_DIR}/redirect/cleanup-cache.php"
GEOIP_SCRIPT="${SCRIPT_DIR}/redirect/update-geoip.php"
STORAGE_SCRIPT="${SCRIPT_DIR}/cleanup-storage.php"
ROTATE_SCRIPT="${SCRIPT_DIR}/rotate-logs.sh"
SNAPSHOT_SCRIPT="${SCRIPT_DIR}/inode-snapshot.sh"
CLEANUP_OK=false
GEOIP_OK=false
STORAGE_OK=false
ROTATE_OK=false
SNAPSHOT_OK=false

if [[ -f "$CLEANUP_SCRIPT" ]]; then
    ok "Ditemukan: $(basename "$CLEANUP_SCRIPT")"
    CLEANUP_OK=true
else
    warn "Script tidak ditemukan, job dilewati: ${CLEANUP_SCRIPT}"
fi

if [[ -f "$GEOIP_SCRIPT" ]]; then
    ok "Ditemukan: $(basename "$GEOIP_SCRIPT")"
    GEOIP_OK=true
else
    warn "Script tidak ditemukan, job dilewati: ${GEOIP_SCRIPT}"
fi

if [[ -f "$STORAGE_SCRIPT" ]]; then
    ok "Ditemukan: $(basename "$STORAGE_SCRIPT")"
    STORAGE_OK=true
else
    warn "Script tidak ditemukan, job dilewati: ${STORAGE_SCRIPT}"
fi

if [[ -f "$ROTATE_SCRIPT" ]]; then
    ok "Ditemukan: $(basename "$ROTATE_SCRIPT")"
    ROTATE_OK=true
else
    warn "Script tidak ditemukan, job dilewati: ${ROTATE_SCRIPT}"
fi

if [[ -f "$SNAPSHOT_SCRIPT" ]]; then
    ok "Ditemukan: $(basename "$SNAPSHOT_SCRIPT")"
    SNAPSHOT_OK=true
else
    warn "Script tidak ditemukan, job dilewati: ${SNAPSHOT_SCRIPT}"
fi

# ── Define cron jobs ──────────────────────────────────────────────────────────
section "Mendaftarkan Cron Jobs"

if [[ "$DRY_RUN" == true ]]; then
    warn "Mode DRY-RUN — tidak ada perubahan yang disimpan"
fi

# Job 1 — Cache cleanup setiap hari jam 02:00
if [[ "$CLEANUP_OK" == true ]]; then
    add_cron \
        "0 2 * * *" \
        "\"${PHP_BIN}\" \"${CLEANUP_SCRIPT}\"" \
        "Cache cleanup (daily 02:00)" \
        "${LOG_DIR}/cache-cleanup.log" \
        "${CLEANUP_SCRIPT}"
fi

# Job 2 — GeoIP update setiap Rabu jam 03:00
if [[ "$GEOIP_OK" == true ]]; then
    add_cron \
        "0 3 * * 3" \
        "\"${PHP_BIN}\" \"${GEOIP_SCRIPT}\"" \
        "GeoIP update (Wed 03:00)" \
        "${LOG_DIR}/geoip-update.log" \
        "${GEOIP_SCRIPT}"
fi

# Job 3 — Storage cleanup (env-editor sessions, statistics temp, orphaned
# backups) setiap hari jam 02:30 — offset 30 menit dari cache cleanup supaya
# tidak berebut I/O di menit yang sama.
if [[ "$STORAGE_OK" == true ]]; then
    add_cron \
        "30 2 * * *" \
        "\"${PHP_BIN}\" \"${STORAGE_SCRIPT}\"" \
        "Storage cleanup (daily 02:30)" \
        "${LOG_DIR}/cleanup-storage.log" \
        "${STORAGE_SCRIPT}"
fi

# Job 4 — Log rotation setiap hari jam 04:00. Harus dijalankan lewat bash,
# BUKAN php — rotate-logs.sh adalah shell script, dan sebuah job lama di
# crontab akun ini sempat salah invoke lewat php binary (parse error, redirect
# shell tidak pernah berjalan karena quoting rusak), sehingga error_log/log
# rotation tidak pernah benar-benar jalan. match_key di bawah cukup untuk
# mendeteksi & mengganti baris lama itu.
if [[ "$ROTATE_OK" == true ]]; then
    BASH_BIN="$(command -v bash || echo /bin/bash)"
    add_cron \
        "0 4 * * *" \
        "\"${BASH_BIN}\" \"${ROTATE_SCRIPT}\"" \
        "Log rotation (daily 04:00)" \
        "${LOG_DIR}/rotate-logs.log" \
        "${ROTATE_SCRIPT}"
fi

# Job 5 — Inode/disk snapshot setiap hari jam 04:10, 10 menit setelah log
# rotation, supaya snapshotnya mencerminkan hasil semua job hari itu. Ini
# bukan pembersih — cuma mencatat trend df -i + status tiap log cron ke satu
# file, supaya bisa dibaca kapan saja tanpa perlu "menunggu" di sesi manapun.
if [[ "$SNAPSHOT_OK" == true ]]; then
    BASH_BIN="${BASH_BIN:-$(command -v bash || echo /bin/bash)}"
    add_cron \
        "10 4 * * *" \
        "\"${BASH_BIN}\" \"${SNAPSHOT_SCRIPT}\"" \
        "Inode/disk snapshot (daily 04:10)" \
        "${LOG_DIR}/inode-snapshot-cron.log" \
        "${SNAPSHOT_SCRIPT}"
fi

# ── Verifikasi hasil ──────────────────────────────────────────────────────────
section "Crontab saat ini"
echo ""
crontab -l 2>/dev/null | grep -E "cleanup-cache|update-geoip|cleanup-storage|rotate-logs|inode-snapshot" | while read -r line; do
    echo -e "  ${CYAN}${line}${RESET}"
done || true

echo ""
ok "Selesai."
echo ""
echo -e "  Log files:"
echo -e "    ${LOG_DIR}/cache-cleanup.log"
echo -e "    ${LOG_DIR}/geoip-update.log"
echo -e "    ${LOG_DIR}/cleanup-storage.log"
echo -e "    ${LOG_DIR}/rotate-logs.log"
echo -e "    ${LOG_DIR}/inode-snapshot.log        (trend harian df -i + status tiap job)"
echo ""
echo -e "  Lihat semua cron: ${BOLD}crontab -l${RESET}"
echo ""
