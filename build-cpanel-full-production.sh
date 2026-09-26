#!/usr/bin/env bash
#
# Build the clean, full-production cPanel release package for SRP.
#
# Layout produced:
#
#     <zip>/public_html/          <- main domain DocumentRoot
#         .htaccess               <- host routing for gen./s./r./wildcard
#         index.php 404.php env.php ...
#         assets/  public/  statistics/  redirect/
#         vendor/                 <- composer --no-dev, pre-optimised
#         migrations/  schema.sql  .env.example ...
#
# The application root IS the DocumentRoot: the root .htaccess resolves hosts by
# probing %{DOCUMENT_ROOT}/public, /statistics and /redirect, so gen.<domain>,
# s.<domain>, r.<domain> and every wildcard tracker host are served from this
# single docroot. No per-subdomain DocumentRoot is required.
#
# Set DOCROOT_WRAPPER='' for the flat variant: identical contents with no
# public_html/ prefix, for installs that extract into the account home
# (e.g. ~/yourdomain.com) and point each subdomain at <root>/public,
# <root>/statistics, <root>/redirect, as INSTALL.md section B describes.
#
# Packaging is fail-closed:
#   1. Root-entry allowlist - a new dev artefact cannot leak into a release just
#      by existing on disk.
#   2. Always-deny list for secrets and generated state (.env, install.token,
#      install.lock, .user.ini, report_auth.php, repass.php, logs, archives),
#      re-checked against the finished zip. A surviving entry deletes the zip
#      and fails the build.
#   3. Required-entry assertion - a missing runtime file deletes the zip and
#      fails the build.
#
# Usage:
#   bash build-cpanel-full-production.sh
#   DOCROOT_WRAPPER='' OUTPUT=srp-flat-cpanel.zip bash build-cpanel-full-production.sh
#
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${OUTPUT:-srp-full-production-cpanel.zip}"
DOCROOT_WRAPPER="${DOCROOT_WRAPPER-public_html}"
MANIFEST="${OUTPUT%.zip}.manifest.txt"

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

ZIP_PATH="$REPO_ROOT/$OUTPUT"
[ -f "$ZIP_PATH" ] && rm -f "$ZIP_PATH"
[ -f "$REPO_ROOT/$MANIFEST" ] && rm -f "$REPO_ROOT/$MANIFEST"

# ── Packaging policy ──────────────────────────────────────────────────────────

# Root files that belong in a production release (.env.example is required by
# INSTALL.md section B step 3: `cp .env.example .env`).
ALLOW_FILES=(
    .env.example
    .htaccess
    404.php
    INSTALL.md
    README.md
    asset_url.php
    Base64URL.php
    cleanup-storage.php
    composer.json
    composer.lock
    connection_pdo.php
    deploy-production.sh
    domain_readiness.php
    env.php
    favicon.ico
    health.php
    imgp_handler.php
    index.php
    inode-snapshot.sh
    install-sh.txt
    ip_address.php
    legal.php
    login_throttle.php
    logo.svg
    robots.php
    robots.txt
    rotate-logs.sh
    schema.sql
    setup-cron.sh
    sitemap.php
)

# Root directories that belong in a production release. Composer installs
# --no-dev, so vendor/ ships production dependencies only.
ALLOW_DIRS=(
    assets
    migrations
    public
    redirect
    statistics
    vendor
)

# Never ship these, wherever they appear in the tree.
#
# Deliberately not denied: *.sql. schema.sql is a required release file, and the
# allowlist already prevents any other .sql dump from being picked up.
DENY_RE='(^|/)\.env$|(^|/)\.env\.(?!example$)|(^|/)install\.(token|lock)$|(^|/)\.user\.ini$|(^|/)report_auth\.php$|(^|/)repass\.php$|\.log$|(^|/)error_log$|(^|/)logs/|\.(zip|rar|7z|tar|tgz|gz|bz2|bak|old|orig|swp|dump)$|(^|/)\.(git|continue|vscode|github)($|/)|(^|/)\.DS_Store$|(^|/)Thumbs\.db$|(^|/)desktop\.ini$|~$'

# Assets that must exist in the finished zip, or the build is a failure.
REQUIRED_ENTRIES=(
    .htaccess
    index.php
    env.php
    connection_pdo.php
    schema.sql
    .env.example
    health.php
    vendor/autoload.php
    public/index.php
    public/login.php
    public/install.php
    statistics/index.php
    statistics/login.php
    redirect/index.php
    redirect/shorten-web.php
)

# ── Stage the allowlisted tree ────────────────────────────────────────────────
PREFIX=''
[ -n "$DOCROOT_WRAPPER" ] && [ "$DOCROOT_WRAPPER" != '.' ] && PREFIX="${DOCROOT_WRAPPER#/}"

DOCROOT="$STAGING/${PREFIX%/}"
mkdir -p "$DOCROOT"

staged=0
denied=()

for name in "${ALLOW_FILES[@]}"; do
    [ -f "$REPO_ROOT/$name" ] || continue
    if [[ "$name" =~ $DENY_RE ]]; then denied+=("$name"); continue; fi
    cp -p "$REPO_ROOT/$name" "$DOCROOT/$name"
    staged=$((staged + 1))
done

for name in "${ALLOW_DIRS[@]}"; do
    [ -d "$REPO_ROOT/$name" ] || continue
    while IFS= read -r -d '' item; do
        rel="${item#"$REPO_ROOT"/}"
        # Deny only real files; keep directories so empty runtime dirs survive.
        if [ -f "$item" ] && [[ "$rel" =~ $DENY_RE ]]; then denied+=("$rel"); continue; fi
        mkdir -p "$DOCROOT/$(dirname "$rel")"
        cp -Rp "$item" "$DOCROOT/$rel"
        staged=$((staged + 1))
    done < <(find "$REPO_ROOT/$name" -mindepth 1 -print0 | sort -z)
done

# ── Write the zip ─────────────────────────────────────────────────────────────
if command -v zip >/dev/null 2>&1; then
    ( cd "$STAGING" && zip -r -q -X "$ZIP_PATH" "${PREFIX%/}" )
else
    echo "ERROR: 'zip' not found. On Windows use build-cpanel-full-production.ps1." >&2
    exit 1
fi

# ── Verify the finished zip ───────────────────────────────────────────────────
fail=()
listing="$(unzip -Z1 "$ZIP_PATH")"

while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    probe="${entry#"${PREFIX%/}/"}"
    [[ "$probe" == */ ]] && continue
    [[ "$probe" =~ $DENY_RE ]] && fail+=("denied entry survived: $probe")
done <<<"$listing"

for req in "${REQUIRED_ENTRIES[@]}"; do
    if ! grep -qxF "${PREFIX%/}/$req" <<<"$listing"; then
        fail+=("required entry missing: $req")
    fi
done

if [ ${#fail[@]} -gt 0 ]; then
    rm -f "$ZIP_PATH"
    echo "BUILD FAILED - zip deleted:" >&2
    printf '  %s\n' "${fail[@]}" >&2
    exit 1
fi

# ── Summary ───────────────────────────────────────────────────────────────────
file_count="$(grep -vc '/$' <<<"$listing" || true)"
raw_bytes="$(du -sb "$DOCROOT" | cut -f1)"
if command -v sha256sum >/dev/null 2>&1; then
    sha="$(sha256sum "$ZIP_PATH" | cut -d' ' -f1)"
else
    sha="$(shasum -a 256 "$ZIP_PATH" | cut -d' ' -f1)"
fi

{
    echo "SRP full-production cPanel package"
    echo "built        : $(date -Is)"
    echo "source       : $REPO_ROOT"
    echo "zip          : $ZIP_PATH"
    echo "sha256       : $sha"
    if [ -n "$PREFIX" ]; then
        echo "layout       : ${PREFIX}/ (main domain docroot)"
    else
        echo "layout       : flat - extract into account root"
    fi
    echo "entries      : $file_count file(s) in zip, $staged path(s) staged"
    echo "size         : $(du -h "$ZIP_PATH" | cut -f1) zipped from $raw_bytes bytes raw"
    if [ ${#denied[@]} -gt 0 ]; then
        echo "Excluded secrets/state: $(printf '%s\n' "${denied[@]}" | sort -u | paste -sd, -)"
    fi
    echo ""
    echo "After extracting, apply permissions from INSTALL.md section B step 0:"
    echo "  find . -type d -exec chmod 750 {} \\;"
    echo "  find . -type f -exec chmod 640 {} \\;"
    echo "  chmod 750 deploy-production.sh setup-cron.sh rotate-logs.sh inode-snapshot.sh"
    echo "750/640 suits suexec / per-account PHP-FPM hosts; use 755/644 if the"
    echo "host runs PHP as a generic user (DSO). Zip files carry no Unix mode bits,"
    echo "so this step is mandatory."
} | tee "$REPO_ROOT/$MANIFEST"

echo ""
echo "Manifest: $REPO_ROOT/$MANIFEST"
echo "RESULT: OK"
