# SRP — Smart Redirect Proxy

Platform link-redirect/tracking berbasis PHP: portal admin, engine redirect
(dengan traffic filtering — bot/preview detection, geo block, VPN/proxy/
datacenter detection), dan modul statistik/reporting + penerima postback.

- **PHP**: 8.3+
- **Database**: MySQL / MariaDB
- **Web server**: LiteSpeed / Apache (`mod_rewrite` + `.htaccess`)
- **Lisensi**: proprietary

## Arsitektur

| Host | Docroot | Fungsi |
| --- | --- | --- |
| `gen.<domain>` | `public/` | Portal admin + portal user |
| `s.<domain>` | `statistics/` | Reporting + penerima postback |
| `r.<domain>` | `redirect/` | API shorten + landing |
| `*.<domain>` | `redirect/` | Hostname link tracker |

## Instalasi

Panduan lengkap (installer otomatis via web + jalur manual, migrasi database,
konfigurasi cron, toggle VPN/proxy block, troubleshooting) ada di
**[INSTALL.md](INSTALL.md)**.

Ringkas untuk setup dev lokal:

```bash
composer install
cp .env.example .env && chmod 600 .env

# generate secret
php -r "foreach(['AF_SECRET','SRP_API_KEY','POSTBACK_SECRET','SRP_RK_SECRET','CF_TOKEN_ENC_KEY'] as \$k) echo \$k.'='.bin2hex(random_bytes(32)).PHP_EOL;"

# generate hash password admin
php -r "echo password_hash('PASSWORD_ANDA', PASSWORD_BCRYPT).PHP_EOL;"

mysql -u USER -p DBNAME < schema.sql
```

Isi `.env` dengan nilai di atas plus kredensial DB/cPanel/Cloudflare sesuai
kebutuhan (lihat komentar di `.env.example`).

## Development

```bash
composer check   # cs (PSR-12) + stan (PHPStan) + test (PHPUnit)
composer cs       # lint saja
composer stan     # static analysis saja
composer test     # unit test saja
composer fix      # auto-format (PHP-CS-Fixer)
```

## Keamanan

- `.env` dan file secret sejenis (`install.token`, `statistics/report_auth.php`,
  `statistics/repass.php`, `*/.user.ini`) **tidak pernah** di-commit — sudah di
  `.gitignore`.
- Semua login (admin, statistics, env editor, Redirect Decision) melewati
  throttle per-IP.
- Detail lebih lanjut: [INSTALL.md § G — Keamanan](INSTALL.md#g-keamanan).

Menemukan celah keamanan? Jangan buka issue publik — hubungi maintainer
langsung.
