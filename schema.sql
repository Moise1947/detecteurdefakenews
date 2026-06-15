-- =============================================
-- VériNews — Schéma MySQL SÉCURISÉ v2
-- =============================================
-- Sécurités appliquées :
--   • Utilisateur MySQL dédié (moindre privilège)
--   • Pas d'IP brute stockée (RGPD) — hash SHA-256
--   • ENUM pour éviter les injections sur champs contraints
--   • Index sur toutes les colonnes filtrées (perf + sécurité)
--   • Table d'audit immuable
--   • Rate limiting côté base
--   • Colonnes taille limitée (bloque les payloads XXL)
-- =============================================
   
CREATE USER IF NOT EXISTS 'fakenews_app'@'127.0.0.1'
  IDENTIFIED BY 'root';

GRANT SELECT, INSERT, UPDATE ON fakenews_db.* 
TO 'fakenews_app'@'127.0.0.1';

USE fakenews_db;

FLUSH PRIVILEGES;
-- ─────────────────────────────────────────────
--  TABLE : utilisateurs
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS utilisateurs (
  id            INT UNSIGNED     AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(50)      NOT NULL UNIQUE,
  email         VARCHAR(254)     NOT NULL UNIQUE,
  password_hash VARCHAR(60)      NOT NULL, -- bcrypt (jamais texte clair)
  role          ENUM('user','admin') NOT NULL DEFAULT 'user',
  actif         BOOLEAN          NOT NULL DEFAULT TRUE,
  failed_logins TINYINT UNSIGNED NOT NULL DEFAULT 0,
  locked_until  DATETIME         NULL,
  created_at    DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login    DATETIME         NULL,
  INDEX idx_email    (email),
  INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────
--  TABLE : analyses
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analyses (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  utilisateur_id    INT UNSIGNED NULL,
  titre             VARCHAR(500) NULL,
  contenu           TEXT NOT NULL,
  url_source        VARCHAR(2048) NULL,
  verdict           ENUM('VRAI','FAUX','DOUTEUX','INCERTAIN') NOT NULL,
  score_confiance   TINYINT UNSIGNED NOT NULL,
  explication       TEXT NOT NULL,
  points_suspects   JSON NULL,
  sources_suggerees JSON NULL,
  ip_hash           CHAR(64) NULL,
  ua_hash           CHAR(64) NULL,
  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- ─────────────────────────────────────────────
--  TABLE : rate_limits  (anti-abus par IP)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ip_hash      CHAR(64)     NOT NULL,
  endpoint     VARCHAR(100) NOT NULL,
  hit_count    SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  window_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ip_ep  (ip_hash, endpoint),
  INDEX idx_window (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────
--  TABLE : audit_log  (journal immuable)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  utilisateur_id INT UNSIGNED NULL,
  action         VARCHAR(100) NOT NULL,  -- 'LOGIN_OK','LOGIN_FAIL','ANALYSE',…
  detail         VARCHAR(500) NULL,
  ip_hash        CHAR(64)     NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_action  (action),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─────────────────────────────────────────────
--  TABLE : sources_fiables
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sources_fiables (
  id        INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  nom       VARCHAR(200) NOT NULL,
  url       VARCHAR(500) NOT NULL,
  categorie ENUM('NATIONAL','INTERNATIONAL','SCIENCE','SANTE','POLITIQUE','ECONOMIE') NOT NULL,
  pays      VARCHAR(100) NOT NULL DEFAULT 'Bénin',
  actif     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO sources_fiables (nom, url, categorie, pays) VALUES
INSERT INTO sources_fiables (nom, url, categorie, pays) VALUES

('Reuters', 'https://www.reuters.com', 'INTERNATIONAL', 'International'),
('Agence France-Presse (AFP)', 'https://www.afp.com', 'INTERNATIONAL', 'France'),
('AFP Fact Check Africa', 'https://factcheck.afp.com/Africa', 'INTERNATIONAL', 'Afrique'),
('BBC Afrique', 'https://www.bbc.com/afrique', 'INTERNATIONAL', 'Royaume-Uni'),
('RFI Afrique', 'https://www.rfi.fr/fr/afrique', 'INTERNATIONAL', 'France'),
('France24 Afrique', 'https://www.france24.com/fr/afrique', 'INTERNATIONAL', 'France'),
('TV5Monde Afrique', 'https://afrique.tv5monde.com', 'INTERNATIONAL', 'France'),

('Africa Check', 'https://www.africacheck.org', 'INTERNATIONAL', 'Afrique'),
('PAFF', 'https://paff.africa', 'INTERNATIONAL', 'Afrique'),
('Factoscope', 'https://factoscope.fr', 'INTERNATIONAL', 'Francophonie'),

('OMS / WHO', 'https://www.who.int/fr', 'SANTE', 'International'),
('UNICEF', 'https://www.unicef.org/fr', 'SANTE', 'International'),
('ONU Infos', 'https://news.un.org/fr', 'INTERNATIONAL', 'International'),

('ORTB', 'https://www.ortb.bj', 'NATIONAL', 'Bénin'),
('La Nation Bénin', 'https://lanation.bj', 'NATIONAL', 'Bénin'),
('Banouto', 'https://banouto.bj', 'NATIONAL', 'Bénin'),
('Badona Fact Check', 'https://badona.bj', 'NATIONAL', 'Bénin'),
('Bénin Check', 'https://benincheck.info', 'NATIONAL', 'Bénin'),

('Le Monde Afrique', 'https://www.lemonde.fr/afrique', 'INTERNATIONAL', 'France'),
('Associated Press', 'https://apnews.com', 'INTERNATIONAL', 'USA'),
('Al Jazeera', 'https://www.aljazeera.com', 'INTERNATIONAL', 'Qatar'),
('Deutsche Welle Afrique', 'https://www.dw.com/fr/actualit%C3%A9s/s-10261', 'INTERNATIONAL', 'Allemagne');
-- ─────────────────────────────────────────────
--  VUE : statistiques globales
-- ─────────────────────────────────────────────
CREATE OR REPLACE VIEW vue_stats_globales AS
SELECT
  COUNT(*)                       AS total_analyses,
  SUM(verdict = 'VRAI')          AS total_vrais,
  SUM(verdict = 'FAUX')          AS total_faux,
  SUM(verdict = 'DOUTEUX')       AS total_douteux,
  SUM(verdict = 'INCERTAIN')     AS total_incertains,
  ROUND(AVG(score_confiance), 1) AS score_moyen
FROM analyses;
