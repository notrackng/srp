# SRP / NGIX — Panduan Instalasi

Dokumen instalasi langkah demi langkah untuk **Smart Redirect Proxy (SRP)**.
Dua jalur tersedia: **otomatis** (web installer) dan **manual**.

---

## Prasyarat

| Kebutuhan | Detail |
| --- | --- |
| PHP | 8.3+ |
| Ekstensi wajib | `pdo_mysql`, `curl`, `json`, `mbstring`, `openssl` |
| Ekstensi opsional | `gd`, `zip`, `maxminddb` |
| Database | MySQL / MariaDB |
| Web server | LiteSpeed / Apache + `mod_rewrite` + `.htaccess` |
| Hosting | cPanel (untuk otomasi; opsional) |

Paket rilis sudah menyertakan `vendor/` — **Composer tidak wajib di server**.
Composer hanya perlu dijalankan kalau deploy dari checkout mentah (bukan dari
paket rilis) atau sengaja mau regenerate `vendor/`:

```bash
composer install --no-dev --prefer-dist --optimize-autoloader --no-interaction
composer dump-autoload --no-dev --optimize --classmap-authoritative
```

Kalau pakai paket rilis (zip), lewati dua baris di atas — `vendor/` di
dalamnya sudah teroptimasi, dan server tujuan mungkin tidak punya Composer
sama sekali.

---

## Arsitektur

| Host | Docroot | Fungsi |
| --- | --- | --- |
| `gen.<domain>` | `public/` | Portal admin + portal user |
| `s.<domain>` | `statistics/` | Reporting + penerima postback |
| `r.<domain>` | `redirect/` | API shorten + landing |
| `*.<domain>` | `redirect/` | Hostname link tracker |

---

## A. Instalasi otomatis (web installer)

### Langkah 1 — Siapkan prasyarat

- Database MySQL + user (cPanel → MySQL Databases).
- cPanel API token (cPanel → Manage API Tokens) — untuk otomasi subdomain/cron.
- Cloudflare API token + Account ID — untuk otomasi zone.
- Token installer (lihat Langkah 2) — wajib dibuat lebih dulu.

### Langkah 2 — Buat token, lalu buka installer

`public/install.php` tidak bisa diakses tanpa `install.token`: file ini dibuat
manual di server (tidak pernah dikirim lewat request), dan tanpanya installer
membalas **404** — bukan sekadar 403 — sehingga deployment yang belum disiapkan
tidak mengaku punya installer sama sekali.

```bash
cd ~/yourdomain.com
php -r "echo bin2hex(random_bytes(32));" > install.token
chmod 600 install.token
```

Lalu buka:

```text
https://gen.<domain>/install.php
```

dan tempel isi `install.token` di prompt yang muncul. Token dikirim lewat POST
(bukan URL) dan percobaan yang gagal berbagi throttle per-IP milik aplikasi (8
kegagalan/jam).

Installer aktif selama `install.lock` belum ada. Setelah finalize, installer
mengunci diri dengan **403 "Already installed"** dan token verifikasi di sesi
tidak lagi relevan — hapus `install.token` setelah selesai.

### Langkah 3 — System Check (Panel 1)

Klik **Re-check**. Item **required** yang gagal menghalangi langkah berikutnya.

### Langkah 4 — Database (Panel 2)

1. Isi Host, Port, User, Password, Database name, Socket (opsional).
2. Klik **Test connection**.
3. Klik **Import schema.sql** — membuat 7 tabel dan memverifikasinya.

### Langkah 5 — Domain & Server (Panel 3)

- Isi **Base domain**, **Project dir**, **Server IP** (klik **Detect server IP**),
  **Report host**.
- Isi kredensial **cPanel** (klik **Detect** untuk host) dan **Cloudflare**.

| Tombol | Fungsi |
| --- | --- |
| **Create subdomains (cPanel)** | Buat `gen`, `s`, `r`, dan wildcard `*` (wildcard terakhir) |
| **Provision Cloudflare zone** | Buat zone + DNS (apex, wildcard, www, MX, SPF, DMARC) + recommended settings |

### Langkah 6 — Admin & Security (Panel 4)

Empat password: **admin portal**, **statistics report**, **env editor**,
**Redirect Decision**. Kosongkan → digenerate saat finalize & ditampilkan sekali.

### Langkah 7 — Cron (Panel 5)

Isi path **absolut** binary PHP (mis. `/usr/local/bin/php`), klik **Add cron jobs**.

### Langkah 8 — Finalize (Panel 6)

Menulis `statistics/report_auth.php`, `.env`, path `error_log`, dan `install.lock`.
**Salin secret & password yang tampil — hanya muncul sekali.**

---

## B. Instalasi manual

```bash
cd ~/yourdomain.com
```

**0. Ekstrak & permission** (kalau deploy dari paket rilis / zip):

```bash
unzip -q srp-release-YYYY-MM-DD.zip
find . -type d -exec chmod 750 {} \;
find . -type f -exec chmod 640 {} \;
```

`750`/`640` cocok untuk hosting cPanel yang menjalankan PHP sebagai user akun
sendiri (suexec / PHP-FPM per-akun — skema paling umum). Kalau server tujuan
pakai mode DSO (PHP jalan sebagai user generik `apache`/`nobody`), pakai
`755`/`644` sebagai gantinya. `.env` diset `600` terpisah di Langkah 3, setelah
filenya dibuat.

**1. Database** — buat database + user di cPanel.

**2. Skema:**

```bash
mysql -u USER -p DBNAME < schema.sql
```

**3. Konfigurasi:**

```bash
cp .env.example .env && chmod 600 .env
nano .env
```

Generate secret:

```bash
php -r "foreach(['AF_SECRET','SRP_API_KEY','POSTBACK_SECRET','SRP_RK_SECRET','CF_TOKEN_ENC_KEY'] as \$k) echo \$k.'='.bin2hex(random_bytes(32)).PHP_EOL;"
```

Generate hash password:

```bash
php -r "echo password_hash('PASSWORD_ANDA', PASSWORD_BCRYPT).PHP_EOL;"
```

Isi `ADMIN_PASSWORD_HASH`, `A2ROOT_PASSWORD_HASH`, `ENV_EDITOR_PASSWORD_HASH`, `RD_PASSWORD_HASH`.

**4. Subdomain** (cPanel → Subdomains):

```text
gen.<domain> → <root>/public
s.<domain>  → <root>/statistics
r.<domain>  → <root>/redirect
*.<domain>  → <root>/redirect   (wildcard, terakhir)
```

**5. Password report** — sebelum `report_auth.php` ada, halaman ini digerbangi
`report_password.token` (mekanisme sama dengan `install.token` di Langkah 2:
tanpanya halaman membalas **404**, bukan menampilkan form setup ke siapa pun
yang lebih dulu sampai):

```bash
cd <root>
php -r "echo bin2hex(random_bytes(32));" > report_password.token
chmod 600 report_password.token
```

Buka `https://s.<domain>/report-password.php`, tempel isi
`report_password.token` di prompt yang muncul, lalu buat password admin.
Setelah `report_auth.php` tercipta, token tidak lagi diperiksa — hapus
`report_password.token` setelah selesai.

**6. Cron:**

```text
0 2 * * *   /usr/local/bin/php <root>/redirect/cleanup-cache.php
0 3 * * 3   /usr/local/bin/php <root>/redirect/update-geoip.php
30 2 * * *  /usr/local/bin/php <root>/cleanup-storage.php
0 4 * * *   /bin/bash <root>/rotate-logs.sh >/dev/null 2>&1
```

`rotate-logs.sh` dan `cleanup-storage.php` tidak opsional di akun cPanel yang
punya kuota inode: tanpa keduanya, `<root>/redirect/logs/*.log`, `error_log`
tiap webroot, `$HOME/logs/php.error.log`, `.env-editor-storage/sessions/`,
dan `statistics/temp/*.json` semua tumbuh tanpa batas. **`rotate-logs.sh`
wajib dijalankan lewat `/bin/bash`, jangan lewat binary PHP** — ini shell
script, bukan PHP, dan baris crontab yang salah ketik interpreter-nya akan
gagal diam-diam (tidak ada rotasi, tidak ada error yang terlihat siapa pun)
alih-alih menolak untuk jalan.

Paling gampang: jalankan `bash <root>/setup-cron.sh --php /usr/local/bin/php`
daripada mengetik keempat baris manual — idempoten (aman dijalankan berkali-
kali) dan otomatis memperbaiki diri kalau interpreter/path-nya salah di run
berikutnya.

Setelah deploy baru, dua hal ini boleh dijalankan manual sekali supaya tidak
menunggu jadwal cron pertama:

```bash
php <root>/redirect/update-geoip.php   # isi GeoLite2 mmdb, bukan Rabu 03:00
bash <root>/rotate-logs.sh             # uji rotasi log — TANPA --php, script ini
                                        # bash murni, tidak menerima flag itu
```

`rotate-logs.sh` **tidak punya flag `--php`** — flag itu cuma milik
`setup-cron.sh`. Menjalankan `bash rotate-logs.sh --php ...` langsung gagal
dengan `Unknown option: --php` (exit 2) dan tidak merotasi apa pun. Kalau
cuma mau lihat apa yang akan terjadi tanpa mengubah file: `bash
<root>/rotate-logs.sh --dry-run`.

**7. Kunci installer** (opsional):

```bash
php -r "file_put_contents('install.lock', json_encode(['installed_at'=>gmdate('Y-m-d H:i:s'),'installer_version'=>'manual']).PHP_EOL);"
```

---

## C. Verifikasi

```bash
curl https://<domain>/health.php   # 200 = OK, 503 = ada masalah
```

Cek host: `gen.<domain>` (login portal), `r.<domain>/<token>` (engine, token
salah → 400), `s.<domain>` (statistics).

---

## D. Migrasi database

Script CLI mandiri, jalankan manual:

```bash
php migrations/00N_name.php            # terapkan
php migrations/00N_name.php --dry-run  # preview
```

| File | Isi |
| --- | --- |
| `002_hash_generate_passwords.php` | Hash password tracker |
| `003_add_cf_cert_installed.php` | `addondomain.cf_cert_installed` |
| `004_clickrecord_unique_click_date.php` | Unique key `clickrecord` |
| `005_encrypt_cf_tokens.php` | Enkripsi token CF per-user |
| `006_add_leadreport_notified_at.php` | `leadreport.notified_at` |
| `007_unique_addondomain.php` | Unique key `addondomain` |
| `008_fix_user_ini_log_path.php` | Path `error_log` di `.user.ini` |
| `009_add_generate_block_vpn_asn.php` | `generate.block_vpn_asn` |
| `010_rotate_cf_token_enc_key.php` | Rotasi `CF_TOKEN_ENC_KEY` — re-enkripsi `generate.cf_token` sebelum `.env` diubah (lihat komentar di file: `--new-key=<64hex>`, `--dry-run`) |

---

## E. Zona waktu tanggal konversi (`POSTBACK_TIMEZONE`)

`clickrecord.click_date` dan `leadreport.conversion_date` adalah kolom tanggal
yang menjadi bagian kunci join antara klik dan konversi. Seluruh kode menurunkan
tanggal ini dalam **UTC**: penulis klik (`redirect/_meetups/`) memakai `gmdate()`,
dan semua reader di `statistics/` juga UTC.

Penerima postback (`statistics/postback/`) menurunkan tanggal yang sama dari
`POSTBACK_TIMEZONE` (default `UTC`). Karena itu:

- **Biarkan `POSTBACK_TIMEZONE=UTC`.** Ini bukan preferensi tampilan — ia
  menulis kolom `click_date`/`conversion_date` yang di-join.
- Kalau di-set ke zona non-UTC, baris `clickrecord` yang dibuat lewat jalur
  postback mendarat di tanggal kalender berbeda dari klik yang membuatnya, dan
  atribusi konversi (serta payout) pada join harian jadi salah.
- Host sebaiknya juga berjalan pada UTC; jika tidak, perubahan clock ini tetap
  benar (kode memaksa UTC), tetapi baris historis yang ditulis sebelum perubahan
  memakai zona lama dapat menunjukkan patahan satu hari di batas tengah malam.

---

## F. Toggle Block VPN / proxy / datacenter

| Level | Lokasi | Penyimpanan |
| --- | --- | --- |
| Global | Panel Redirect Decision | `SRP_BLOCK_VPN_ASN` di `.env` |
| Per-tracker | Portal user → tab GENERATE | `generate.block_vpn_asn` |

Toggle ini mengatur ketiga sinyal non-preview bersama: blocked-ASN
(`srp_is_blocked_asn()`), hosting/datacenter (`srp_is_hosting_ip()` — daftar ASN
kurasi + heuristik nama organisasi), dan VPN/proxy.

- **ON** → visitor VPN/proxy/datacenter/blocked-ASN mendapat halaman OG cloak,
  click tidak dicatat.
- **OFF** → ketiganya mengikuti redirect normal ke final URL.

Visitor bot/preview (crawler) selalu dicloak, terlepas dari toggle. Jika lookup
ASN gagal — mmdb hilang atau basi — deteksi hosting fail-open (tidak dicloak),
agar outage lookup tidak memblokir visitor sah.

Flag per-tracker dibakar ke setiap link saat generate, jadi link lama tetap
membawa setting saat dibuat.

---

## G. Keamanan

- `A2ROOT_PASSWORD` = master override semua portal — buat kuat & unik.
- Jangan ubah `CF_TOKEN_ENC_KEY` di `.env` secara langsung pada deployment hidup —
  setiap baris `generate.cf_token` yang sudah terenkripsi jadi tidak terbaca.
  Rotasi lewat `migrations/010_rotate_cf_token_enc_key.php` (re-enkripsi dulu,
  baru ubah `.env` — lihat komentar di file tersebut untuk urutan lengkap).
- `statistics/report_auth.php` gitignored, jangan pernah dikirim.
- `install.token` dan `report_password.token` gitignored — hapus dari server setelah setup selesai.
- `.env` tidak pernah di-commit.
- `migrations/` dan `tests/` diblok dari HTTP.
- Semua login melewati throttle per-IP (`login_throttle.php`).

---

## H. Troubleshooting

| Gejala | Solusi |
| --- | --- |
| `install.php` 403 | `install.lock` sudah ada — hapus untuk instal ulang |
| `install.php` 404 | `install.token` belum ada / kurang dari 32 karakter — buat ulang (Langkah 2) |
| `report-password.php` 404 | `report_auth.php` belum ada DAN `report_password.token` belum ada / kurang dari 32 karakter — buat ulang (Langkah 5) |
| Import schema disabled | Test connection belum sukses |
| `pdo_mysql` gagal | Aktifkan di cPanel → Select PHP Version |
| Cron menolak path | Harus absolut (`/usr/local/bin/php`) |
| Postback 500 | `POSTBACK_SECRET` kosong / `.env` tak terbaca |
| CSS/JS 404 | Subdomain belum diarahkan ke docroot modul |

Instal ulang: hapus `install.lock` (backup `.env` dulu — finalize menimpa `.env`).
