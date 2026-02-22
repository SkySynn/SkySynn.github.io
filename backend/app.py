"""
backend/app.py
API Flask — reçoit les prix des clients GUI, gère l'authentification
et pustout sur GitHub.

Variables d'environnement requises (à définir sur Render) :
  GITHUB_TOKEN      Personal Access Token (scope: repo)
  GITHUB_REPO       ex: "SkySynn/SkySynn.github.io"
  GITHUB_BRANCH     (optionnel, défaut: "main")
  GITHUB_DATA_PATH  (optionnel, défaut: "data/prices.json")
  JWT_SECRET_KEY    Clé secrète pour les tokens JWT (à définir !)
  ADMIN_EMAIL       Email du premier compte admin créé automatiquement
  ADMIN_PASSWORD    Mot de passe du premier compte admin
"""

import base64
import json
import os
from datetime import datetime, timezone, timedelta
from functools import wraps

import bcrypt
from flask_cors import CORS
import requests
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token,
    get_jwt_identity, jwt_required, get_jwt,
    verify_jwt_in_request
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
CORS(app)  # Autorise les appels depuis GitHub Pages

# ── Configuration ─────────────────────────────────────────────────────────────
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "changeme-please-set-env")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ── Rate limiting ──────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per hour", "20 per minute"],
    storage_uri="memory://",
)

# ── Config GitHub ──────────────────────────────────────────────────────────────
GITHUB_TOKEN     = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO      = os.environ.get("GITHUB_REPO", "")
GITHUB_BRANCH    = os.environ.get("GITHUB_BRANCH", "main")
GITHUB_DATA_PATH = os.environ.get("GITHUB_DATA_PATH", "data/prices.json")
GITHUB_CRAFTS_PATH = os.environ.get("GITHUB_CRAFTS_PATH", "data/crafts.json")

_GITHUB_BASE = f"https://api.github.com/repos/{GITHUB_REPO}/contents"
_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
}

# ── Modèle utilisateur ─────────────────────────────────────────────────────────
ROLES = ["visiteur", "basic", "premium", "admin"]

class User(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(50), unique=True, nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    password_h = db.Column(db.String(200), nullable=False)
    role       = db.Column(db.String(20), nullable=False, default="basic")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

# ── Initialisation DB + compte admin ──────────────────────────────────────────
def init_db():
    with app.app_context():
        db.create_all()
        admin_email = os.environ.get("ADMIN_EMAIL", "")
        admin_pass  = os.environ.get("ADMIN_PASSWORD", "")
        admin_user  = os.environ.get("ADMIN_USERNAME", "admin")
        if admin_email and admin_pass:
            existing = User.query.filter_by(email=admin_email).first()
            if not existing:
                hashed = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
                admin = User(username=admin_user, email=admin_email,
                             password_h=hashed, role="admin")
                db.session.add(admin)
                db.session.commit()
                print(f"[INIT] Compte admin créé : {admin_email}")

init_db()

# ── Validation ─────────────────────────────────────────────────────────────────
RARITES_VALIDES = {"commun", "rare", "mythique", "legendaire", "souvenir", "epique", "relique"}
PRIX_MAX        = 999_999_999
NOM_MAX_LEN     = 100

# ── Décorateur admin ───────────────────────────────────────────────────────────
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        uid = get_jwt_identity()
        user = User.query.get(uid)
        if not user or user.role != "admin":
            return jsonify({"error": "Accès réservé aux administrateurs"}), 403
        return fn(*args, **kwargs)
    return wrapper

# ── GitHub helpers ─────────────────────────────────────────────────────────────
def _get_remote_file(path):
    url  = f"{_GITHUB_BASE}/{path}"
    resp = requests.get(url, headers=_HEADERS, params={"ref": GITHUB_BRANCH})
    if resp.status_code == 404:
        return {}, None
    resp.raise_for_status()
    body    = resp.json()
    content = base64.b64decode(body["content"]).decode("utf-8")
    data    = json.loads(content)
    return data, body["sha"]

def _push_file(path, data, sha, message):
    url         = f"{_GITHUB_BASE}/{path}"
    content_b64 = base64.b64encode(
        json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    ).decode("utf-8")
    payload = {"message": message, "content": content_b64, "branch": GITHUB_BRANCH}
    if sha:
        payload["sha"] = sha
    resp = requests.put(url, headers=_HEADERS, json=payload)
    resp.raise_for_status()

def _get_remote_data():
    data, sha = _get_remote_file(GITHUB_DATA_PATH)
    if "items" not in data:
        data["items"] = {}
    return data, sha

def _push_data(data, sha, message):
    _push_file(GITHUB_DATA_PATH, data, sha, message)

# ── Seuil de bénéfice selon le rôle ───────────────────────────────────────────
ROLE_THRESHOLD = {
    "visiteur": 25.0,
    "basic":    25.0,
    "premium":  None,   # None = pas de limite
    "admin":    None,
}

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    email    = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))

    if not username or len(username) > 50:
        return jsonify({"error": "Nom d'utilisateur invalide (1-50 caractères)"}), 400
    if not email or "@" not in email or len(email) > 120:
        return jsonify({"error": "Email invalide"}), 400
    if len(password) < 6:
        return jsonify({"error": "Mot de passe trop court (6 caractères minimum)"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Cet email est déjà utilisé"}), 409
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Ce nom d'utilisateur est déjà pris"}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user   = User(username=username, email=email, password_h=hashed, role="basic")
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=str(user.id))
    return jsonify({"ok": True, "token": token, "user": user.to_dict()}), 201


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per hour")
def login():
    body = request.get_json(silent=True) or {}
    email    = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_h.encode()):
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({"ok": True, "token": token, "user": user.to_dict()})


@app.route("/api/me", methods=["GET"])
@jwt_required()
def me():
    uid  = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    return jsonify(user.to_dict())


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE CRAFTS (avec filtre par rôle)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/crafts", methods=["GET"])
def get_crafts():
    """
    Retourne les crafts filtrés selon le rôle du token JWT.
    Sans token → rôle 'visiteur' (seuil 25%).
    Les crafts au-dessus du seuil sont retournés avec 'locked: true'.
    """
    role = "visiteur"
    try:
        verify_jwt_in_request(optional=True)
        uid = get_jwt_identity()
        if uid:
            user = User.query.get(uid)
            if user:
                role = user.role
    except Exception:
        pass

    threshold = ROLE_THRESHOLD.get(role, 25.0)

    try:
        crafts_data, _ = _get_remote_file(GITHUB_CRAFTS_PATH)
        prices_data, _ = _get_remote_file(GITHUB_DATA_PATH)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    items  = prices_data.get("items", {})
    crafts = list((crafts_data.get("crafts") or {}).values())

    result = []
    for craft in crafts:
        composants = craft.get("composants", [])
        cout_total = 0
        all_known  = True

        for comp in composants:
            key      = f"{comp['nom']}|{comp['rarete']}"
            hist     = items.get(key, {}).get("historique", [])
            prix_u   = hist[-1]["prix"] if hist else None
            if prix_u is None:
                all_known = False
            else:
                cout_total += prix_u * comp["quantite"]

        craft_key  = f"{craft['nom']}|{craft['rarete']}"
        craft_hist = items.get(craft_key, {}).get("historique", [])
        prix_hdv   = craft_hist[-1]["prix"] if craft_hist else None

        benef_pct = None
        if all_known and cout_total > 0 and prix_hdv is not None:
            benef_pct = round(((prix_hdv - cout_total) / cout_total) * 100, 1)

        # Déterminer si ce craft est "locked" pour ce rôle
        locked = False
        if threshold is not None and benef_pct is not None and benef_pct > threshold:
            locked = True

        entry = {
            "nom":    craft["nom"],
            "rarete": craft["rarete"],
            "locked": locked,
        }
        if not locked:
            entry["composants"] = composants
            entry["cout"]       = cout_total if all_known and cout_total else None
            entry["hdv"]        = prix_hdv
            entry["benef_k"]    = round(prix_hdv - cout_total, 1) if benef_pct is not None else None
            entry["benef_pct"]  = benef_pct
        result.append(entry)

    return jsonify({"role": role, "threshold": threshold, "crafts": result})


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE PRIX (inchangée)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/prix", methods=["POST"])
@limiter.limit("10 per minute")
def recevoir_prix():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON invalide"}), 400

    nom    = str(body.get("nom", "")).strip().lower()
    rarete = str(body.get("rarete", "")).strip().lower()
    prix   = body.get("prix")

    if not nom or len(nom) > NOM_MAX_LEN:
        return jsonify({"error": "Nom invalide (vide ou trop long)"}), 400
    if rarete not in RARITES_VALIDES:
        return jsonify({"error": f"Rareté invalide : {rarete}"}), 400
    if not isinstance(prix, int) or prix <= 0 or prix > PRIX_MAX:
        return jsonify({"error": f"Prix invalide : {prix}"}), 400

    try:
        data, sha = _get_remote_data()
        key = f"{nom}|{rarete}"

        if key not in data["items"]:
            data["items"][key] = {"nom": nom, "rarete": rarete, "historique": []}

        data["items"][key]["historique"].append({
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "prix":      prix,
        })
        data["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        _push_data(data, sha, f"prix: {nom} [{rarete}] → {prix} kamas")
        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES ADMIN
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({"users": [u.to_dict() for u in users]})


@app.route("/api/admin/users/<int:user_id>", methods=["PATCH"])
@admin_required
def admin_update_user(user_id):
    body = request.get_json(silent=True) or {}
    new_role = str(body.get("role", "")).strip()

    if new_role not in ROLES:
        return jsonify({"error": f"Rôle invalide. Valeurs acceptées : {ROLES}"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    # Empêcher de rétrograder le dernier admin
    if user.role == "admin" and new_role != "admin":
        admin_count = User.query.filter_by(role="admin").count()
        if admin_count <= 1:
            return jsonify({"error": "Impossible de retirer le rôle du dernier admin"}), 400

    user.role = new_role
    db.session.commit()
    return jsonify({"ok": True, "user": user.to_dict()})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 404

    # Empêcher la suppression du dernier admin
    if user.role == "admin":
        admin_count = User.query.filter_by(role="admin").count()
        if admin_count <= 1:
            return jsonify({"error": "Impossible de supprimer le dernier admin"}), 400

    db.session.delete(user)
    db.session.commit()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False)
