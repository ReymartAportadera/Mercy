import os
import uuid
import logging
import firebase_admin
from firebase_admin import credentials, db
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load .env file if present
load_dotenv()

import json

# ── Initialize Firebase Admin SDK ─────────────────────────────────────────────
_cred_env = os.getenv("FIREBASE_SERVICE_ACCOUNT") or os.getenv("FIREBASE_CREDENTIALS_JSON")
_db_url   = os.getenv("FIREBASE_DB_URL")

_cred_obj = None

if _cred_env:
    if _cred_env.strip().startswith("{"):
        try:
            _cred_dict = json.loads(_cred_env)
            _cred_obj  = credentials.Certificate(_cred_dict)
        except Exception as exc:
            logger.warning("Could not parse FIREBASE_SERVICE_ACCOUNT JSON string: %s", exc)
    elif os.path.exists(_cred_env):
        _cred_obj = credentials.Certificate(_cred_env)
    elif not os.path.isabs(_cred_env):
        resolved_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), _cred_env)
        if os.path.exists(resolved_path):
            _cred_obj = credentials.Certificate(resolved_path)

if not _cred_obj:
    default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "serviceAccountKey.json")
    if os.path.exists(default_path):
        _cred_obj = credentials.Certificate(default_path)

if _cred_obj and _db_url:
    if not firebase_admin._apps:          # avoid re-initialising on reload
        firebase_admin.initialize_app(_cred_obj, {"databaseURL": _db_url})
else:
    logger.warning(
        "FIREBASE_SERVICE_ACCOUNT or FIREBASE_DB_URL is missing. "
        "Please add them to your environment variables or Vercel dashboard."
    )

# ── Uploaded-File Helpers ──────────────────────────────────────────────────────

def _sanitize_firebase_keys(obj):
    """Recursively sanitize keys for Firebase Realtime Database.
    Replaces forbidden key characters (/, ., $, #, [, ]) with spaces or parens."""
    if isinstance(obj, dict):
        clean_dict = {}
        for k, v in obj.items():
            clean_k = str(k).replace("/", " ").replace(".", " ").replace("$", "").replace("#", "").replace("[", "(").replace("]", ")")
            clean_dict[clean_k] = _sanitize_firebase_keys(v)
        return clean_dict
    elif isinstance(obj, list):
        return [_sanitize_firebase_keys(item) for item in obj]
    return obj


def save_uploaded_file(file_record: dict) -> str:
    """Persist a file record under uploaded_files and user_files/{user_id}."""
    file_id = file_record.get("id") or str(uuid.uuid4())
    file_record["id"] = file_id

    # Populate user email and username if missing
    user_id = file_record.get("user_id")
    if user_id and (not file_record.get("user_email") or not file_record.get("username")):
        u = get_user(user_id)
        if u:
            file_record["user_email"] = file_record.get("user_email") or u.get("email")
            file_record["username"] = file_record.get("username") or u.get("username")

    # Sanitize dictionary keys for Firebase compatibility (removes /, ., etc.)
    clean_record = _sanitize_firebase_keys(file_record)

    # Save to main uploaded_files node
    db.reference(f"uploaded_files/{file_id}").set(clean_record)

    # Save to user-specific index node for clean organized Firebase structure
    if user_id:
        db.reference(f"user_files/{user_id}/{file_id}").set(clean_record)

    logger.info("Saved file record %s for user %s (%s)", file_id, user_id, file_record.get("user_email"))
    return file_id


def get_uploaded_file(file_id: str) -> dict | None:
    return db.reference(f"uploaded_files/{file_id}").get()


def delete_uploaded_file(file_id: str) -> None:
    rec = get_uploaded_file(file_id)
    if rec and rec.get("user_id"):
        user_id = rec["user_id"]
        db.reference(f"user_files/{user_id}/{file_id}").delete()

    db.reference(f"uploaded_files/{file_id}").delete()
    logger.info("Deleted file record %s", file_id)


def list_user_files(user_id: str) -> list[dict]:
    all_files = db.reference("uploaded_files").get() or {}
    if not isinstance(all_files, dict):
        return []
    return [
        f for f in all_files.values()
        if isinstance(f, dict) and f.get("user_id") == user_id
    ]

# ── User Helpers ──────────────────────────────────────────────────────────────

def save_user(user_record: dict) -> str:
    """Persist a user record and return its UID."""
    uid = user_record.get("uid") or str(uuid.uuid4())
    user_record["uid"] = uid
    db.reference(f"users/{uid}").set(user_record)
    logger.info("Saved user %s", uid)
    return uid


def get_user(uid: str) -> dict | None:
    return db.reference(f"users/{uid}").get()


def get_user_by_email(email: str) -> dict | None:
    users = db.reference("users").get() or {}
    if not isinstance(users, dict):
        return None
    target_email = (email or "").strip().lower()
    for u in users.values():
        if isinstance(u, dict):
            u_email = (u.get("email") or "").strip().lower()
            if u_email and u_email == target_email:
                return u
    return None


def delete_user(uid: str) -> None:
    db.reference(f"users/{uid}").delete()
    logger.info("Deleted user %s", uid)

# ── User-Settings Helpers (Disabled / In-Memory Defaults) ───────────────────

def save_user_settings(uid: str, settings: dict) -> None:
    pass


def get_user_settings(uid: str) -> dict | None:
    return None


def delete_user_settings(uid: str) -> None:
    pass

def save_guest_scan(guest_id: str, scan_record: dict) -> None:
    """Disabled: Guest scans exist 100% in-memory/session only and are never saved to Firebase."""
    pass

def get_guest_scans(guest_id: str) -> list:
    """Disabled: Guest scans exist 100% in-memory/session only."""
    return []

# ── Password Reset OTP Helpers ─────────────────────────────────────────────────

def save_password_reset(token: str, record: dict) -> None:
    """Persist a password-reset OTP record under password_resets/{token}."""
    db.reference(f"password_resets/{token}").set(record)
    logger.info("Saved password reset token %s", token)


def get_password_reset(token: str) -> dict | None:
    """Retrieve a password-reset OTP record by token."""
    return db.reference(f"password_resets/{token}").get()


def delete_password_reset(token: str) -> None:
    """Delete a password-reset OTP record by token."""
    db.reference(f"password_resets/{token}").delete()
    logger.info("Deleted password reset token %s", token)
