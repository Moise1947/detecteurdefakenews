# 🔍 VériNews — Détecteur de Fake News (Version Sécurisée)

> Stack : **Python 3.10+ · Flask · MySQL 8 · API Claude (Anthropic)**

---

## 🛡️ Mesures de sécurité implémentées

| # | Protection | Détail |
|---|-----------|--------|
| 1 | **Anti-injection SQL** | 100 % de requêtes paramétrées — aucune concaténation de chaîne |
| 2 | **Anti-XSS** | `bleach.clean()` côté serveur + `textContent` exclusivement côté client |
| 3 | **Rate limiting** | `flask-limiter` : 10 analyses/min par IP, 60 req/min global |
| 4 | **Headers HTTP** | `flask-talisman` : CSP, X-Frame-Options, HSTS, Referrer-Policy |
| 5 | **CORS restreint** | Seul votre domaine est autorisé (configurable dans `.env`) |
| 6 | **RGPD — IP hachée** | SHA-256 + salt HMAC : l'IP brute n'est jamais stockée |
| 7 | **Taille limitée** | Payload max 16 Ko ; contenu max 8 000 chars côté serveur ET client |
| 8 | **Moindre privilège MySQL** | Utilisateur applicatif `fakenews_app` : SELECT + INSERT + UPDATE seulement |
| 9 | **Validation du verdict IA** | Whitelist stricte — seuls VRAI/FAUX/DOUTEUX/INCERTAIN sont acceptés |
| 10 | **Pas de stack trace** | Erreurs génériques en prod ; détails dans les logs serveur uniquement |
| 11 | **Pool de connexions DB** | Timeout 5 s, 5 connexions max — résistance aux attaques lentes |
| 12 | **Logging structuré** | JSON logs sans données sensibles (pas de contenu utilisateur loggé) |
| 13 | **Audit trail** | Table `audit_log` immuable pour tracer les actions sensibles |
| 14 | **Validation URL** | Whitelist `http://` et `https://` uniquement (bloque `javascript:`, `data:`, etc.) |

---

## 📁 Structure

```
fakenews_detector/
├── app.py                  ← Serveur Flask sécurisé
├── requirements.txt        ← Dépendances Python
├── .env.example            ← Modèle de config (à copier en .env)
├── .gitignore              ← À créer (voir ci-dessous)
├── database/
│   └── schema.sql          ← BDD MySQL + utilisateur applicatif
└── templates/
    └── index.html          ← Interface web sécurisée
```

---

## 🚀 Installation

### Étape 1 — Prérequis

- Python 3.10+ : https://www.python.org
- MySQL 8.0+   : https://dev.mysql.com/downloads/

---

### Étape 2 — Clé API Claude

1. Allez sur https://console.anthropic.com
2. **API Keys → Create Key**
3. Copiez la clé (commence par `sk-ant-…`)

---

### Étape 3 — Base de données MySQL

```bash
mysql -u root -p
```

Dans MySQL :
```sql
source /chemin/vers/fakenews_detector/database/schema.sql
```

> ⚠️ **Avant d'exécuter** : ouvrez `schema.sql` et remplacez
> `REMPLACEZ_PAR_MOT_DE_PASSE_FORT_ICI` par un vrai mot de passe fort.
> Ce même mot de passe devra être mis dans `.env` (DB_PASSWORD).

---

### Étape 4 — Fichier de configuration

```bash
cp .env.example .env
```

Ouvrez `.env` et remplissez **chaque valeur** :

```env
ANTHROPIC_API_KEY=sk-ant-VOTRE_CLE

DB_HOST=127.0.0.1
DB_USER=fakenews_app
DB_PASSWORD=LE_MOT_DE_PASSE_CHOISI_A_LETAPE_3
DB_NAME=fakenews_db

# Générez avec : python -c "import secrets; print(secrets.token_hex(64))"
FLASK_SECRET_KEY=VOTRE_CLE_SECRETE_64_CHARS

# Générez avec : python -c "import secrets; print(secrets.token_hex(32))"
IP_HASH_SALT=VOTRE_SALT_32_CHARS
```

---

### Étape 5 — .gitignore (OBLIGATOIRE si vous utilisez Git)

Créez un fichier `.gitignore` à la racine du projet :

```
.env
__pycache__/
*.pyc
venv/
*.log
```

> ⚠️ Ne commitez JAMAIS `.env` — il contient vos clés secrètes.

---

### Étape 6 — Environnement virtuel Python

```bash
python -m venv venv

# Windows :
venv\Scripts\activate
# Mac / Linux :
source venv/bin/activate

pip install -r requirements.txt
```

---

### Étape 7 — Démarrer

**Développement :**
```bash
python app.py
```

**Production (recommandé) :**
```bash
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

Ouvrez **http://localhost:5000**

---

## 📡 API REST

| Méthode | Route | Limite | Description |
|---------|-------|--------|-------------|
| GET  | `/`                  | 60/min | Interface web |
| POST | `/api/analyser`      | 10/min | Analyser un texte |
| GET  | `/api/historique`    | 30/min | 20 dernières analyses |
| GET  | `/api/statistiques`  | 30/min | Stats globales |
| GET  | `/api/sources`       | 30/min | Sources fiables |
| GET  | `/api/analyse/<id>`  | 30/min | Détail d'une analyse |

### Exemple d'appel :

```bash
curl -X POST http://localhost:5000/api/analyser \
  -H "Content-Type: application/json" \
  -d '{"contenu": "Le gouvernement distribue 1 million FCFA à chaque citoyen demain."}'
```

### Réponse :

```json
{
  "id": 42,
  "verdict": "FAUX",
  "score_confiance": 7,
  "explication": "Aucune source officielle ne confirme cette information…",
  "points_suspects": ["Absence de source", "Montant irréaliste"],
  "sources_suggerees": ["ortb.bj", "AFP", "gouv.bj"]
}
```

---

## ❓ Dépannage

| Problème | Solution |
|---------|---------|
| `RuntimeError: FLASK_SECRET_KEY manquante` | Générez une clé et mettez-la dans `.env` |
| `RuntimeError: ANTHROPIC_API_KEY invalide` | Vérifiez votre clé sur console.anthropic.com |
| Erreur de connexion MySQL | Vérifiez que MySQL tourne et que les identifiants dans `.env` sont corrects |
| Port 5000 occupé | Changez `port=5000` en `port=5001` dans `app.py` |
| `pip install` échoue | Assurez-vous d'avoir activé l'environnement virtuel |

---

## 🔒 Checklist avant mise en production

- [ ] `FLASK_DEBUG=0` dans `.env`
- [ ] `FORCE_HTTPS=True` dans `.env` (si vous avez un certificat SSL)
- [ ] `CORS_ORIGINS=https://votre-domaine.com` (pas localhost)
- [ ] Démarrer avec Gunicorn (pas `python app.py`)
- [ ] Firewall : seul le port 80/443 exposé publiquement
- [ ] Sauvegardes MySQL automatiques activées
- [ ] `.env` exclu de Git (`.gitignore`)
