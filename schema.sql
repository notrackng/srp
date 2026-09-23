-- =============================================================================
-- Genv2 — Full Database Schema
-- =============================================================================
-- Satu database yang dipakai bersama oleh tiga modul:
--   public/      → generate, addondomain, offering
--   redirect/    → srp_short_links, shortlinks (legacy)
--   statistics/  → clickrecord (tulis dari redirect/_meetups/ & statistics/postback/)
--                  leadreport  (tulis dari statistics/postback/)
-- =============================================================================

SET NAMES utf8mb4;
SET foreign_key_checks = 0;

-- -----------------------------------------------------------------------------
-- 1. generate
--    Tracker milik masing-masing user.
--    sub_id selalu disimpan UPPERCASE; menjadi foreign key logis ke clickrecord.
--    cf_token / cf_account_id: credential Cloudflare per-user,
--    di-migrate otomatis via ALTER TABLE pada pemanggilan pertama user_cf_config.php.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `generate` (
  `id`             INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  `sub_id`         VARCHAR(64)      NOT NULL,
  `password`       VARCHAR(255)     NOT NULL,
  `password_plain` VARCHAR(255)     NOT NULL DEFAULT '',
  `gen_url`        TEXT             NOT NULL,
  `sm_url`         VARCHAR(128)     NOT NULL DEFAULT '',
  `cf_token`       VARCHAR(500)     DEFAULT NULL,
  `cf_account_id`  VARCHAR(64)      DEFAULT NULL,
  `block_vpn_asn`  TINYINT(1)       NOT NULL DEFAULT 1,
  `created_at`     TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_sub_id` (`sub_id`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 2. addondomain
--    Domain yang dimiliki user atau masuk pool global.
--    sub_domain = 'GLOBAL'  → domain masuk pool bersama semua user.
--    sub_domain = <SUB_ID>  → domain eksklusif milik tracker tersebut.
--    cf_zone_id / cf_status / cf_ns: wajib tersedia dari schema install;
--    request path hanya memvalidasi schema, tidak menjalankan DDL.
--    cf_cert_installed: 1 setelah CF Origin Certificate dipasang otomatis
--    (sekali) saat domain pertama berstatus active. Kolom opsional —
--    request path mendeteksi keberadaannya; jika belum ada, fitur degrade
--    aman (lihat migrations/003_add_cf_cert_installed.php).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `addondomain` (
  `id`          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  `sub_domain`  VARCHAR(64)   NOT NULL,
  `domain`      VARCHAR(255)  NOT NULL,
  `cf_zone_id`  VARCHAR(64)   DEFAULT NULL,
  `cf_status`   VARCHAR(32)   DEFAULT NULL,
  `cf_ns`       TEXT          DEFAULT NULL,
  `cf_cert_installed` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at`  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_addondomain_sub_domain_domain` (`sub_domain`, `domain`),
  KEY `idx_sub_domain` (`sub_domain`),
  KEY `idx_sub_domain_id` (`sub_domain`, `id`),
  KEY `idx_domain`     (`domain`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 3. offering
--    Daftar campaign / offer yang dikelola admin.
--    country_code dan ua disimpan UPPERCASE.
--    network digunakan sebagai toggle-button di portal user.
--    r.php memilih baris secara acak berdasarkan country_code atau network.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `offering` (
  `id`            INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  `country_code`  VARCHAR(10)   NOT NULL,
  `ua`            VARCHAR(64)   NOT NULL,
  `offer`         TEXT          NOT NULL,
  `network`       VARCHAR(64)   NOT NULL,
  `created_at`    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_country_code` (`country_code`),
  KEY `idx_country_code_id` (`country_code`, `id`),
  KEY `idx_network`      (`network`),
  KEY `idx_network_id`   (`network`, `id`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 4. clickrecord
--    Hitungan klik dan lead per tracker per hari.
--    Dibuat otomatis oleh redirect/_meetups/index.php (CREATE TABLE IF NOT EXISTS).
--    Ditulis oleh redirect/_meetups/index.php (klik) dan
--    statistics/postback/index.php (lead + payout).
--    Dibaca oleh statistics/ (realtime, performance, click views).
--
--    Catatan tipe kolom:
--      leads  — disimpan sebagai TEXT di DDL asli kode, tapi dioperasikan
--               secara numerik (leads + 1). Kolom ini dipertahankan TEXT
--               agar identik dengan CREATE TABLE yang digenerate runtime.
--      payout — idem; dioperasikan via CAST(? AS DECIMAL(18,2)).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `clickrecord` (
  `id`          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  `click_id`    VARCHAR(128)  NOT NULL,
  `clicks`      INT UNSIGNED  NOT NULL DEFAULT 0,
  `leads`       TEXT          NOT NULL,
  `payout`      TEXT          NOT NULL,
  `click_date`  DATE          NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_click_id_date` (`click_id`(64), `click_date`),
  KEY `idx_click_date_id` (`click_date`, `id`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 5. leadreport
--    Satu baris per konversi postback yang diterima statistics/postback/index.php.
--    click_id di sini adalah nilai UPPERCASE hasil decode payload base64url.
--    Transaksi INSERT ke leadreport + UPDATE/INSERT clickrecord dilakukan atomic.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `leadreport` (
  `id`               INT UNSIGNED   NOT NULL AUTO_INCREMENT,
  `click_id`         VARCHAR(128)   NOT NULL,
  `ip_address`       VARCHAR(45)    NOT NULL,
  `country`          VARCHAR(10)    NOT NULL,
  `payout`           VARCHAR(20)    NOT NULL,
  `conversion_date`  DATE           NOT NULL,
  `currency_symbol`  VARCHAR(5)     NOT NULL DEFAULT '$',
  `network`          VARCHAR(64)    NOT NULL,
  `traffic`          VARCHAR(255)   NOT NULL,
  `idempotency_key`  VARCHAR(64)    NULL DEFAULT NULL,
  `created_at`       TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `notified_at`      DATETIME       NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_idempotency`     (`idempotency_key`),
  KEY `idx_click_id`                (`click_id`),
  KEY `idx_conversion_date`         (`conversion_date`),
  KEY `idx_conversion_date_id`      (`conversion_date`, `id`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 6. srp_short_links
--    Short link yang dibuat oleh redirect/api/shorten.php (sistem baru).
--    DDL ini identik dengan yang digenerate oleh srp_short_link_ensure_table()
--    di redirect/public_link.php.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `srp_short_links` (
  `id`             INT UNSIGNED   NOT NULL AUTO_INCREMENT,
  `short_code`     VARCHAR(32)    NOT NULL,
  `click_id`       VARCHAR(64)    NOT NULL,
  `user_lp`        VARCHAR(64)    NOT NULL,
  `lg`             VARCHAR(16)    NOT NULL,
  `canonical_url`  VARCHAR(2048)  NOT NULL DEFAULT '',
  `title`          VARCHAR(200)   NOT NULL DEFAULT '',
  `image_url`      VARCHAR(2048)  NOT NULL DEFAULT '',
  `is_active`      TINYINT(1)     NOT NULL DEFAULT 1,
  `created_at`     TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_short_code` (`short_code`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- 7. shortlinks
--    Short link yang dibuat dan dikelola oleh public/shortlinks/response.php.
--    Diakses via public/s.php → GET /s-{code} (302 redirect + OG meta untuk bot).
--    Juga dibaca oleh srp_shortlinks_find() di redirect/public_link.php sebagai
--    fallback ketika short_code tidak ditemukan di srp_short_links.
--    DDL ini identik dengan slEnsureTable() di public/shortlinks/response.php.
--    created_at disimpan sebagai Unix timestamp (INT), bukan TIMESTAMP.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `shortlinks` (
  `code`        VARCHAR(14)   NOT NULL,
  `long_url`    TEXT          NOT NULL,
  `og_title`    VARCHAR(512)  NOT NULL DEFAULT '',
  `og_image`    TEXT          NOT NULL DEFAULT '',
  `created_at`  INT UNSIGNED  NOT NULL DEFAULT 0,
  PRIMARY KEY (`code`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;

-- =============================================================================
-- Upgrades for existing databases (idempotent)
--   Folded in from the former migrations/*.sql. Safe to run on a fresh import
--   (columns already exist via CREATE TABLE above → skipped) and on a live DB
--   that predates these columns (added in place). Imported via the mysql CLI.
--     001 → leadreport.idempotency_key
--     003 → generate.password_plain
-- =============================================================================
DELIMITER $$
DROP PROCEDURE IF EXISTS `srp_apply_upgrades` $$
CREATE PROCEDURE `srp_apply_upgrades`()
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'generate' AND COLUMN_NAME = 'password_plain'
  ) THEN
    ALTER TABLE `generate`
      ADD COLUMN `password_plain` VARCHAR(255) NOT NULL DEFAULT '' AFTER `password`;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'leadreport' AND COLUMN_NAME = 'idempotency_key'
  ) THEN
    ALTER TABLE `leadreport`
      ADD COLUMN `idempotency_key` VARCHAR(64) NULL DEFAULT NULL AFTER `traffic`,
      ADD UNIQUE KEY `uniq_idempotency` (`idempotency_key`);
  END IF;
END $$
DELIMITER ;

CALL `srp_apply_upgrades`();
DROP PROCEDURE IF EXISTS `srp_apply_upgrades`;

-- -----------------------------------------------------------------------------

SET foreign_key_checks = 1;
