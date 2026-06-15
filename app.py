"""
=======================================================
VériNews — Détecteur de Fake News  (version SÉCURISÉE)
=======================================================
"""

import os
import re
import json
import hmac
import hashlib
import logging
import anthropic

import bleach
import validators
import bcrypt
import mysql.connector
from mysql.connector import Error, pooling
from flask import Flask, request, jsonify, render_template, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from pythonjsonlogger import jsonlogger
from dotenv import load_dotenv

load_dotenv()

# ══════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════
logger = logging.getLogger("verinews")
handler = logging.StreamHandler()
handler.setFormatter(jsonlogger.JsonFormatter(
    "%(asctime)s %(levelname)s %(name)s %(message)s"
))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ══════════════════════════════════════════════
#  APPLICATION FLASK
# ══════════════════════════════════════════════
app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "")
if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
    raise RuntimeError(
        "FLASK_SECRET_KEY manquante ou trop courte (minimum 32 chars). "
        "Générez-en une avec : python -c \"import secrets; print(secrets.token_hex(64))\""
    )

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 Ko max

# ── CORS ──────────────────────────────────────
CORS(
    app,
    origins=os.getenv("CORS_ORIGINS", "http://localhost:5000").split(","),
    methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

# ── Headers de sécurité ───────────────────────
FORCE_HTTPS = os.getenv("FORCE_HTTPS", "False").lower() == "true"
Talisman(
    app,
    force_https=FORCE_HTTPS,
    strict_transport_security=FORCE_HTTPS,
    session_cookie_secure=FORCE_HTTPS,
    content_security_policy={
        "default-src": "'self'",
        "script-src":  "'self' 'unsafe-inline'",
        "style-src":   "'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src":    "https://fonts.gstatic.com",
        "img-src":     "'self' data:",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
    },
    referrer_policy="strict-origin-when-cross-origin",
    feature_policy={
        "geolocation": "'none'",
        "camera":      "'none'",
        "microphone":  "'none'",
    },
)

# ── Rate limiting ─────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[os.getenv("RATE_LIMIT_GLOBAL", "60") + " per minute"],
    storage_uri="memory://",
)

# ── Client Anthropic ──────────────────────────
_api_key = os.getenv("ANTHROPIC_API_KEY", "")
if not _api_key.startswith("sk-ant-"):
    raise RuntimeError("ANTHROPIC_API_KEY invalide ou manquante dans .env")
claude_client = anthropic.Anthropic(api_key=_api_key)


# ══════════════════════════════════════════════
#  POOL DE CONNEXIONS MYSQL
# ══════════════════════════════════════════════
_db_pool = None

def get_pool():
    global _db_pool
    if _db_pool is None:
        _db_pool = pooling.MySQLConnectionPool(
            pool_name="verinews",
            pool_size=5,
            host=os.getenv("DB_HOST", "127.0.0.1"),
            port=int(os.getenv("DB_PORT", 3306)),
            user=os.getenv("DB_USER", "fakenews_app"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "fakenews_db"),
            charset="utf8mb4",
            connection_timeout=5,
            use_pure=True,
        )
    return _db_pool

def get_conn():
    try:
        return get_pool().get_connection()
    except Error as exc:
        logger.error("db_pool_error", extra={"error": str(exc)})
        return None


# ══════════════════════════════════════════════
#  UTILITAIRES DE SÉCURITÉ
# ══════════════════════════════════════════════
_IP_SALT = os.getenv("IP_HASH_SALT", "default-salt-change-me").encode()

def hash_ip(ip: str) -> str:
    return hmac.new(_IP_SALT, ip.encode(), hashlib.sha256).hexdigest()

def hash_ua(ua: str) -> str:
    return hashlib.sha256(ua.encode()).hexdigest()

VERDICTS_VALIDES = {"VRAI", "FAUX", "DOUTEUX", "INCERTAIN"}

def sanitize_text(value: str, max_len: int = 8000) -> str:
    cleaned = bleach.clean(value, tags=[], strip=True)
    return cleaned[:max_len].strip()

def validate_url(url: str):
    if not url:
        return None
    url = url.strip()[:2048]
    if not validators.url(url):
        return None
    if not re.match(r'^https?://', url, re.IGNORECASE):
        return None
    return url

def audit(action: str, detail: str = "", utilisateur_id=None):
    ip   = hash_ip(request.remote_addr or "unknown")
    conn = get_conn()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_log (utilisateur_id, action, detail, ip_hash) "
            "VALUES (%s, %s, %s, %s)",
            (utilisateur_id, action[:100], detail[:500], ip)
        )
        conn.commit()
    except Error:
        pass
    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════
#  SYSTEM PROMPT
# ══════════════════════════════════════════════
SYSTEM_PROMPT = """Tu es un expert en fact-checking et détection de fake news.
Tu analyses des textes et tu détermines s'ils sont vrais, faux, douteux ou incertains.

Tu réponds UNIQUEMENT en JSON valide avec cette structure exacte :
{
  "verdict": "VRAI" | "FAUX" | "DOUTEUX" | "INCERTAIN",
  "score_confiance": <entier 0-100>,
  "explication": "<2 à 4 phrases en français>",
  "points_suspects": ["<point 1>", "<point 2>"],
  "sources_suggerees": ["<source 1>", "<source 2>"]
}

Règles :
- VRAI : confirmé par des sources fiables (score 70-100)
- FAUX : clairement erroné ou trompeur (score 0-30)
- DOUTEUX : partiellement vrai ou hors contexte (score 31-60)
- INCERTAIN : impossible à vérifier (score 40-60)
- points_suspects : max 5 éléments
- sources_suggerees : max 4 sources
- Ne génère PAS de texte avant ou après le JSON.
- Ne mets PAS de backticks autour du JSON."""


   
def analyser_avec_claude(contenu: str, titre: str = "") -> dict:
    """
    Mode DEMO temporaire sans API Claude.
    """

    return {
        "verdict": "DOUTEUX",
        "score_confiance": 65,
        "explication": (
            "Cette analyse est générée en mode démonstration. "
            "Le contenu semble contenir certaines affirmations "
            "qui nécessitent une vérification auprès de sources fiables."
        ),
        "points_suspects": [
            "Source originale difficile à vérifier",
            "Informations potentiellement sorties de leur contexte",
            "Absence de confirmation officielle"
        ],
        "sources_suggerees": [
            "Reuters",
            "AFP",
            "BBC Afrique",
            "Africa Check"
        ]
    }
    


# ══════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyser", methods=["POST"])
@limiter.limit(os.getenv("RATE_LIMIT_ANALYSE", "10") + " per minute")
def analyser():
    if not request.is_json:
        abort(415)

    try:
        body = request.get_json(force=False, silent=False)
    except Exception:
        return jsonify({"erreur": "JSON invalide."}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"erreur": "Corps JSON manquant."}), 400

    contenu    = sanitize_text(str(body.get("contenu", "")))
    titre      = sanitize_text(str(body.get("titre",   "")), 500)
    url_source = validate_url(str(body.get("url_source", "")))

    if len(contenu) < 20:
        return jsonify({"erreur": "Le texte doit contenir au moins 20 caractères."}), 400
    if len(contenu) > 8000:
        return jsonify({"erreur": "Le texte ne peut pas dépasser 8 000 caractères."}), 400

    try:
        resultat = analyser_avec_claude(contenu, titre)
    except json.JSONDecodeError:
        logger.error("claude_json_parse_error")
        return jsonify({"erreur": "Erreur interne lors de l'analyse. Réessayez."}), 500
    except ValueError as exc:
        logger.error("claude_validation_error", extra={"detail": str(exc)})
        return jsonify({"erreur": "Réponse inattendue de l'IA. Réessayez."}), 500
    except Exception as exc:
        logger.error("claude_api_error", extra={"detail": str(exc)})
        return jsonify({"erreur": "Service d'analyse temporairement indisponible."}), 503

    conn = get_conn()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO analyses
                  (titre, contenu, url_source, verdict, score_confiance,
                   explication, points_suspects, sources_suggerees,
                   ip_hash, ua_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    titre or None,
                    contenu,
                    url_source,
                    resultat["verdict"],
                    resultat["score_confiance"],
                    resultat["explication"],
                    json.dumps(resultat["points_suspects"],   ensure_ascii=False),
                    json.dumps(resultat["sources_suggerees"], ensure_ascii=False),
                    hash_ip(request.remote_addr or ""),
                    hash_ua(request.headers.get("User-Agent", "")),
                ),
            )
            conn.commit()
            resultat["id"] = cur.lastrowid
        except Error as exc:
            logger.error("db_insert_error", extra={"error": str(exc)})
        finally:
            cur.close()
            conn.close()

    audit("ANALYSE", f"verdict={resultat['verdict']} score={resultat['score_confiance']}")
    return jsonify(resultat), 200


@app.route("/api/historique", methods=["GET"])
@limiter.limit("30 per minute")
def historique():
    conn = get_conn()
    if not conn:
        return jsonify({"erreur": "Base de données indisponible."}), 503
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id,
                   COALESCE(titre, LEFT(contenu, 100)) AS apercu,
                   verdict,
                   score_confiance,
                   DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') AS date_analyse
            FROM analyses
            ORDER BY created_at DESC
            LIMIT 20
            """
        )
        return jsonify(cur.fetchall()), 200
    except Error as exc:
        logger.error("db_historique_error", extra={"error": str(exc)})
        return jsonify({"erreur": "Erreur interne."}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/statistiques", methods=["GET"])
@limiter.limit("30 per minute")
def statistiques():
    conn = get_conn()
    if not conn:
        return jsonify({"erreur": "Base de données indisponible."}), 503
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM vue_stats_globales")
        return jsonify(cur.fetchone() or {}), 200
    except Error as exc:
        logger.error("db_stats_error", extra={"error": str(exc)})
        return jsonify({"erreur": "Erreur interne."}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/sources", methods=["GET"])
@limiter.limit("30 per minute")
def sources():
    conn = get_conn()
    if not conn:
        return jsonify({"erreur": "Base de données indisponible."}), 503
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT nom, url, categorie, pays FROM sources_fiables "
            "WHERE actif = TRUE ORDER BY categorie, nom"
        )
        return jsonify(cur.fetchall()), 200
    except Error as exc:
        logger.error("db_sources_error", extra={"error": str(exc)})
        return jsonify({"erreur": "Erreur interne."}), 500
    finally:
        cur.close()
        conn.close()

print("🔥 ROUTE ANALYSER TOUCHÉE")
@app.route("/api/analyse/<int:analyse_id>", methods=["GET"])
@limiter.limit("30 per minute")
def detail_analyse(analyse_id: int):
    if analyse_id < 1:
        abort(404)
    conn = get_conn()
    if not conn:
        return jsonify({"erreur": "Base de données indisponible."}), 503
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT id, titre, LEFT(contenu, 500) AS contenu_apercu, url_source,
                   verdict, score_confiance, explication,
                   points_suspects, sources_suggerees,
                   DATE_FORMAT(created_at, '%d/%m/%Y %H:%i') AS date_analyse
            FROM analyses WHERE id = %s
            """,
            (analyse_id,),
        )
        row = cur.fetchone()
        if not row:
            abort(404)
        row["points_suspects"]   = json.loads(row["points_suspects"]   or "[]")
        row["sources_suggerees"] = json.loads(row["sources_suggerees"] or "[]")
        return jsonify(row), 200
    except Error as exc:
        logger.error("db_detail_error", extra={"error": str(exc)})
        return jsonify({"erreur": "Erreur interne."}), 500
    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════
#  GESTION DES ERREURS
# ══════════════════════════════════════════════

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"erreur": "Requête invalide."}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"erreur": "Ressource introuvable."}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"erreur": "Méthode HTTP non autorisée."}), 405

@app.errorhandler(413)
def payload_too_large(e):
    return jsonify({"erreur": "Payload trop volumineux (max 16 Ko)."}), 413

@app.errorhandler(415)
def unsupported_media(e):
    return jsonify({"erreur": "Content-Type doit être application/json."}), 415

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"erreur": "Trop de requêtes. Attendez une minute."}), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error("internal_server_error", extra={"error": str(e)})
    return jsonify({"erreur": "Erreur interne du serveur."}), 500


# ══════════════════════════════════════════════
#  POINT D'ENTRÉE
# ══════════════════════════════════════════════

def test_db():
    conn = get_conn()
    if conn:
        print("✅ Connexion MySQL OK")
        conn.close()
    else:
        print("❌ Connexion MySQL FAIL — vérifiez DB_PASSWORD dans .env")


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info("startup", extra={"debug": debug, "host": "0.0.0.0", "port": 5000})
    test_db()
    app.run(host="0.0.0.0", port=5000, debug=debug)