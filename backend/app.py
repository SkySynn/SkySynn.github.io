"""
backend/app.py
API Flask — reçoit les prix des clients GUI et les pousse sur GitHub.

Variables d'environnement requises (à définir sur Render) :
  GITHUB_TOKEN      Personal Access Token (scope: repo)
  GITHUB_REPO       ex: "SkySynn/SkySynn.github.io"
  GITHUB_BRANCH     (optionnel, défaut: "main")
  GITHUB_DATA_PATH  (optionnel, défaut: "data/prices.json")
"""

import base64
import json
import os
from datetime import datetime

import requests
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# ── Rate limiting : 60 requêtes/heure par IP ──────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per hour", "10 per minute"],
    storage_uri="memory://",
)

# ── Config depuis variables d'environnement ───────────────────────────────
GITHUB_TOKEN     = os.environ.get("GITHUB_TOKEN", "")
GITHUB_REPO      = os.environ.get("GITHUB_REPO", "")
GITHUB_BRANCH    = os.environ.get("GITHUB_BRANCH", "main")
GITHUB_DATA_PATH = os.environ.get("GITHUB_DATA_PATH", "data/prices.json")

_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_DATA_PATH}"
_HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
}

# ── Validation ────────────────────────────────────────────────────────────
RARITES_VALIDES = {"commun", "rare", "mythique", "legendaire", "souvenir", "epique", "relique"}
PRIX_MAX        = 999_999_999
NOM_MAX_LEN     = 100

# ── GitHub helpers ────────────────────────────────────────────────────────

def _get_remote_data():
    resp = requests.get(_API_URL, headers=_HEADERS, params={"ref": GITHUB_BRANCH})
    if resp.status_code == 404:
        return {"last_updated": "", "items": {}}, None
    resp.raise_for_status()
    body    = resp.json()
    content = base64.b64decode(body["content"]).decode("utf-8")
    data    = json.loads(content)
    if "items" not in data:
        data["items"] = {}
    return data, body["sha"]


def _push_data(data, sha, message):
    content_b64 = base64.b64encode(
        json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    ).decode("utf-8")
    payload = {"message": message, "content": content_b64, "branch": GITHUB_BRANCH}
    if sha:
        payload["sha"] = sha
    resp = requests.put(_API_URL, headers=_HEADERS, json=payload)
    resp.raise_for_status()


# ── Route principale ──────────────────────────────────────────────────────

@app.route("/api/prix", methods=["POST"])
@limiter.limit("10 per minute")
def recevoir_prix():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON invalide"}), 400

    nom    = str(body.get("nom", "")).strip().lower()
    rarete = str(body.get("rarete", "")).strip().lower()
    prix   = body.get("prix")

    # Validation stricte
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
            "timestamp": datetime.now().isoformat(),
            "prix":      prix,
        })
        data["last_updated"] = datetime.now().isoformat()

        _push_data(data, sha, f"prix: {nom} [{rarete}] → {prix} kamas")
        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False)
