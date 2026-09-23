#!/usr/bin/env bash
set -Eeuo pipefail

echo "=== ENVIRONMENT ==="
pwd

PHP_BIN="$(command -v php || true)"
COMPOSER_BIN="$(command -v composer || true)"

if [[ -z "$PHP_BIN" ]]; then
    echo "ERROR: PHP CLI not found." >&2
    exit 1
fi

if [[ -z "$COMPOSER_BIN" ]]; then
    echo "ERROR: Composer not found." >&2
    exit 1
fi

echo "PHP_BIN=$PHP_BIN"
echo "COMPOSER_BIN=$COMPOSER_BIN"

"$PHP_BIN" -v
"$COMPOSER_BIN" --version

echo "=== REQUIRED FILES ==="

required_files=(
    "composer.json"
    "composer.lock"
    "redirect/update-geoip.php"
    "setup-cron.sh"
    "rotate-logs.sh"
    "inode-snapshot.sh"
)

for file in "${required_files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Required file missing: $file" >&2
        exit 1
    fi
done

echo "=== COMPOSER VALIDATE ==="
"$COMPOSER_BIN" validate --strict

echo "=== COMPOSER INSTALL ==="
"$COMPOSER_BIN" install \
    --no-dev \
    --prefer-dist \
    --optimize-autoloader \
    --no-interaction

echo "=== COMPOSER AUTOLOAD ==="
"$COMPOSER_BIN" dump-autoload \
    --no-dev \
    --optimize \
    --classmap-authoritative \
    --no-interaction

echo "=== PERMISSIONS ==="

find . -type d -exec chmod 755 {} \;
find . -type f -exec chmod 644 {} \;

chmod 600 .env 2>/dev/null || true
chmod 750 setup-cron.sh
chmod 750 rotate-logs.sh
chmod 750 inode-snapshot.sh

# Restore executable permission for this deployment script.
if [[ -f "$0" ]]; then
    chmod 750 "$0" 2>/dev/null || true
fi

echo "=== GEOIP ==="
"$PHP_BIN" redirect/update-geoip.php

echo "=== CRON ==="
echo "PHP_BIN=$PHP_BIN"
bash setup-cron.sh --php "$PHP_BIN"

echo "=== LOG ROTATION ==="
bash rotate-logs.sh

echo "=== INODE SNAPSHOT ==="
bash inode-snapshot.sh

echo "=== VERIFY PERMISSIONS ==="
stat -c '%a %n' \
    .env \
    setup-cron.sh \
    rotate-logs.sh \
    inode-snapshot.sh \
    2>/dev/null || true

echo "=== CRONTAB ==="
crontab -l 2>/dev/null || true

echo "=== DONE ==="
