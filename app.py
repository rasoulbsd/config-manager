"""
API Manager Panel — Flask application for admin/user config distribution.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, Response, jsonify, request, send_from_directory
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATA_DIR = Path(os.environ.get("DATA_DIR", ".")).resolve()
DB_FILE = DATA_DIR / "database.json"

DEFAULT_ADMIN_USER = os.environ.get("ADMIN_USERNAME", "admin")
# Production: set ADMIN_PASSWORD; if unset on first boot, a random password is generated.
_raw_pw = os.environ.get("ADMIN_PASSWORD")
if _raw_pw is None or not str(_raw_pw).strip():
    ADMIN_PASSWORD_ENV = None
else:
    ADMIN_PASSWORD_ENV = str(_raw_pw).strip()
SYNC_ADMIN_FROM_ENV = os.environ.get("SYNC_ADMIN_FROM_ENV", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

STATIC_DIR = BASE_DIR / "static"


def _hash_password(plain: str) -> str:
    return generate_password_hash(plain, method="scrypt")


def _get_password_cipher() -> Fernet | None:
    secret = os.environ.get("PASSWORD_ENCRYPTION_KEY", "").strip()
    if not secret:
        return None
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def _encrypt_reveal_password(plain: str) -> str:
    cipher = _get_password_cipher()
    if not cipher or not plain:
        return ""
    return cipher.encrypt(plain.encode("utf-8")).decode("utf-8")


def _decrypt_reveal_password(token: str | None) -> str:
    if not token:
        return ""
    cipher = _get_password_cipher()
    if not cipher:
        return ""
    try:
        return cipher.decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def _verify_password(plain: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2:") or stored.startswith("scrypt:"):
        return check_password_hash(stored, plain)
    # Legacy plaintext (migrate on successful login)
    return stored == plain


def _migrate_legacy_passwords(data: dict) -> bool:
    """Migrate plaintext passwords to hashes. Returns True if file should be saved."""
    changed = False
    admin = data.get("admin") or {}
    pw = admin.get("password")
    if pw and not (pw.startswith("pbkdf2:") or pw.startswith("scrypt:")):
        admin["password_reveal"] = _encrypt_reveal_password(pw)
        admin["password"] = _hash_password(pw)
        changed = True
    data["admin"] = admin
    for u in data.get("users") or []:
        up = u.get("password")
        if up and not (up.startswith("pbkdf2:") or up.startswith("scrypt:")):
            u["password_reveal"] = _encrypt_reveal_password(up)
            u["password"] = _hash_password(up)
            changed = True
    return changed


def load_db() -> dict:
    if not DB_FILE.exists():
        pw = ADMIN_PASSWORD_ENV
        if not pw:
            pw = secrets.token_urlsafe(24)
            logger.warning(
                "No database and no ADMIN_PASSWORD set. Initial admin password generated. "
                "Set ADMIN_PASSWORD and restart, or retrieve this password from logs once."
            )
            print(f"INITIAL_ADMIN_PASSWORD={pw}", file=sys.stderr, flush=True)
        data = {
            "admin": {
                "username": DEFAULT_ADMIN_USER,
                "password": _hash_password(pw),
                "password_reveal": _encrypt_reveal_password(pw),
            },
            "users": [],
        }
        save_db(data)
        return data
    with open(DB_FILE, encoding="utf-8") as f:
        data = json.load(f)
    if SYNC_ADMIN_FROM_ENV and ADMIN_PASSWORD_ENV:
        # Optional escape hatch: force admin creds from env on each startup.
        admin = data.get("admin") or {}
        admin["username"] = DEFAULT_ADMIN_USER
        admin["password"] = _hash_password(ADMIN_PASSWORD_ENV)
        admin["password_reveal"] = _encrypt_reveal_password(ADMIN_PASSWORD_ENV)
        data["admin"] = admin
        save_db(data)
    if _migrate_legacy_passwords(data):
        save_db(data)
    return data


def save_db(data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DB_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(DB_FILE)


def _sanitize_db_for_admin_client(data: dict) -> dict:
    """Return a DB payload safe for admin UI (never expose password hashes)."""
    safe = {
        "admin": {
            "username": ((data.get("admin") or {}).get("username") or ""),
            "password": _decrypt_reveal_password((data.get("admin") or {}).get("password_reveal")),
            "has_password": bool(((data.get("admin") or {}).get("password") or "").strip()),
        },
        "users": [],
    }
    for user in data.get("users") or []:
        if not isinstance(user, dict):
            continue
        safe["users"].append(
            {
                "id": user.get("id"),
                "username": user.get("username", ""),
                "password": _decrypt_reveal_password(user.get("password_reveal")),
                "has_password": bool((user.get("password") or "").strip()),
                "enabled": bool(user.get("enabled", True)),
                "config": user.get("config", "") if isinstance(user.get("config"), str) else "",
            }
        )
    return safe


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"}), 200

    @app.get("/api/<path:_unused>")
    def block_api_get(_unused: str):
        return jsonify({"error": "Forbidden"}), 403

    @app.post("/api/login")
    def login():
        try:
            payload = request.get_json(force=True, silent=False) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON"}), 400
        u = (payload.get("username") or "").strip()
        p = payload.get("password") or ""
        if not u or not p:
            return jsonify({"error": "Unauthorized"}), 401

        db = load_db()
        admin = db["admin"]
        if u == admin["username"] and _verify_password(p, admin["password"]):
            if not (
                admin["password"].startswith("pbkdf2:")
                or admin["password"].startswith("scrypt:")
            ):
                admin["password"] = _hash_password(p)
                save_db(db)
            return jsonify({"role": "admin", "db": _sanitize_db_for_admin_client(db)})

        for user in db["users"]:
            if u == user["username"] and _verify_password(p, user["password"]):
                if not (
                    user["password"].startswith("pbkdf2:")
                    or user["password"].startswith("scrypt:")
                ):
                    user["password"] = _hash_password(p)
                    save_db(db)
                safe_user_data = {
                    "username": user["username"],
                    "config": user["config"],
                    "enabled": user["enabled"],
                }
                return jsonify({"role": "user", "user_data": safe_user_data})

        return jsonify({"error": "Unauthorized"}), 401

    @app.post("/api/save")
    def save():
        try:
            payload = request.get_json(force=True, silent=False) or {}
        except Exception:
            return jsonify({"error": "Invalid JSON"}), 400
        req_u = (payload.get("auth_user") or "").strip()
        req_p = payload.get("auth_pass") or ""
        new_db = payload.get("db")
        if not isinstance(new_db, dict):
            return jsonify({"error": "Bad request"}), 400

        db = load_db()
        admin = db["admin"]
        if req_u != admin["username"] or not _verify_password(req_p, admin["password"]):
            return jsonify({"error": "Forbidden"}), 403

        def normalize_password(
            plain_or_hash: str, previous_hash: str | None, previous_reveal: str | None
        ) -> tuple[str, str]:
            if not isinstance(plain_or_hash, str) or not plain_or_hash:
                if previous_hash:
                    return previous_hash, previous_reveal or ""
                generated = secrets.token_urlsafe(16)
                return _hash_password(generated), _encrypt_reveal_password(generated)
            if plain_or_hash.startswith("pbkdf2:") or plain_or_hash.startswith("scrypt:"):
                return plain_or_hash, previous_reveal or ""
            return _hash_password(plain_or_hash), _encrypt_reveal_password(plain_or_hash)

        try:
            if "admin" in new_db and isinstance(new_db["admin"], dict):
                na = new_db["admin"]
                nu = (na.get("username") or "").strip()
                if nu:
                    admin["username"] = nu
                np = na.get("password")
                if isinstance(np, str) and np:
                    admin["password"], admin["password_reveal"] = normalize_password(
                        np, admin.get("password"), admin.get("password_reveal")
                    )

            incoming_users = new_db.get("users")
            if isinstance(incoming_users, list):
                old_by_id = {
                    x["id"]: x for x in db["users"] if isinstance(x, dict) and x.get("id")
                }
                merged: list[dict] = []
                for inc in incoming_users:
                    if not isinstance(inc, dict):
                        continue
                    uid = inc.get("id") or f"user_{secrets.token_hex(8)}"
                    old = old_by_id.get(uid)
                    pw_in = inc.get("password")
                    normalized_hash, normalized_reveal = normalize_password(
                        pw_in if isinstance(pw_in, str) else "",
                        (old or {}).get("password"),
                        (old or {}).get("password_reveal"),
                    )
                    merged.append(
                        {
                            "id": uid,
                            "username": (inc.get("username") or "").strip() or "user",
                            "password": normalized_hash,
                            "password_reveal": normalized_reveal,
                            "enabled": bool(inc.get("enabled", True)),
                            "config": inc["config"]
                            if isinstance(inc.get("config"), str)
                            else "",
                        }
                    )
                db["users"] = merged

            save_db(db)
        except Exception as e:
            logger.exception("save failed: %s", e)
            return jsonify({"error": "Save failed"}), 500

        return jsonify({"status": "saved", "db": _sanitize_db_for_admin_client(db)})

    @app.get("/")
    def root():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/dashboard")
    def dashboard():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/<path:path>")
    def spa(path: str):
        if path.startswith("api/"):
            return jsonify({"error": "Not found"}), 404
        # Hash-only SPA: serve index for any non-file path
        candidate = STATIC_DIR / path
        if candidate.is_file() and STATIC_DIR in candidate.resolve().parents:
            return send_from_directory(STATIC_DIR, path)
        return send_from_directory(STATIC_DIR, "index.html")

    return app


app = create_app()


def parse_runtime_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run API Manager Panel web server.")
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "0.0.0.0"),
        help="Bind IP/host (default: HOST env or 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8080")),
        help="Bind port (default: PORT env or 8080)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.environ.get("FLASK_DEBUG") == "1",
        help="Enable Flask debug mode",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_runtime_args()
    app.run(host=args.host, port=args.port, debug=args.debug)
