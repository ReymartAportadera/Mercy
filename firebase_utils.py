import os
import uuid
import logging
import json
import firebase_admin
from firebase_admin import credentials, db
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load .env file if present
load_dotenv()

# In-memory fallback storage for when Firebase credentials are not provided (e.g. serverless cold start without env vars)
_FALLBACK_USERS = {}
_FALLBACK_FILES = {}
_FALLBACK_RESETS = {}

# ── Initialize Firebase Admin SDK ─────────────────────────────────────────────
_cred_env = os.getenv("FIREBASE_SERVICE_ACCOUNT") or os.getenv("FIREBASE_CREDENTIALS_JSON")
_db_url   = os.getenv("FIREBASE_DB_URL") or "https://trustfilemonitor-default-rtdb.firebaseio.com/"

_cred_obj = None

if _cred_env:
    if _cred_env.strip().startswith("{"):
        try:
            _cred_dict = json.loads(_cred_env)
            _cred_obj  = credentials.Certificate(_cred_dict)
        except Exception as exc:
            logger.warning("Could not parse FIREBASE_SERVICE_ACCOUNT JSON string: %s", exc)
    elif os.path.exists(_cred_env):
        try:
            _cred_obj = credentials.Certificate(_cred_env)
        except Exception as exc:
            logger.warning("Could not load certificate from path %s: %s", _cred_env, exc)
    elif not os.path.isabs(_cred_env):
        resolved_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), _cred_env)
        if os.path.exists(resolved_path):
            try:
                _cred_obj = credentials.Certificate(resolved_path)
            except Exception as exc:
                logger.warning("Could not load certificate from resolved path %s: %s", resolved_path, exc)

if not _cred_obj:
    default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "serviceAccountKey.json")
    if os.path.exists(default_path):
        try:
            _cred_obj = credentials.Certificate(default_path)
        except Exception as exc:
            logger.warning("Could not load serviceAccountKey.json: %s", exc)

if _cred_obj and _db_url:
    try:
        if not firebase_admin._apps:
            firebase_admin.initialize_app(_cred_obj, {"databaseURL": _db_url})
            logger.info("Firebase Admin SDK initialized successfully.")
    except Exception as exc:
        logger.error("Failed to initialize Firebase Admin SDK: %s", exc)
else:
    logger.warning(
        "FIREBASE_SERVICE_ACCOUNT or serviceAccountKey.json not available. "
        "Running in graceful fallback mode."
    )

def _is_firebase_ready() -> bool:
    return bool(firebase_admin._apps)

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

    clean_record = _sanitize_firebase_keys(file_record)
    _FALLBACK_FILES[file_id] = clean_record

    if _is_firebase_ready():
        try:
            db.reference(f"uploaded_files/{file_id}").set(clean_record)
            if user_id:
                db.reference(f"user_files/{user_id}/{file_id}").set(clean_record)
            logger.info("Saved file record %s for user %s (%s)", file_id, user_id, file_record.get("user_email"))
        except Exception as exc:
            logger.error("Firebase save_uploaded_file error: %s", exc)

    return file_id


def get_uploaded_file(file_id: str) -> dict | None:
    if _is_firebase_ready():
        try:
            rec = db.reference(f"uploaded_files/{file_id}").get()
            if rec:
                return rec
        except Exception as exc:
            logger.error("Firebase get_uploaded_file error: %s", exc)
    return _FALLBACK_FILES.get(file_id)


def delete_uploaded_file(file_id: str) -> None:
    if file_id in _FALLBACK_FILES:
        del _FALLBACK_FILES[file_id]

    if _is_firebase_ready():
        try:
            rec = get_uploaded_file(file_id)
            if rec and rec.get("user_id"):
                user_id = rec["user_id"]
                db.reference(f"user_files/{user_id}/{file_id}").delete()
            db.reference(f"uploaded_files/{file_id}").delete()
            logger.info("Deleted file record %s", file_id)
        except Exception as exc:
            logger.error("Firebase delete_uploaded_file error: %s", exc)


def list_user_files(user_id: str) -> list[dict]:
    if _is_firebase_ready():
        try:
            all_files = db.reference("uploaded_files").get() or {}
            if isinstance(all_files, dict):
                return [
                    f for f in all_files.values()
                    if isinstance(f, dict) and f.get("user_id") == user_id
                ]
        except Exception as exc:
            logger.error("Firebase list_user_files error: %s", exc)

    return [
        f for f in _FALLBACK_FILES.values()
        if isinstance(f, dict) and f.get("user_id") == user_id
    ]

# ── User Helpers ──────────────────────────────────────────────────────────────

def save_user(user_record: dict) -> str:
    """Persist a user record and return its UID."""
    uid = user_record.get("uid") or str(uuid.uuid4())
    user_record["uid"] = uid
    _FALLBACK_USERS[uid] = user_record

    if _is_firebase_ready():
        try:
            db.reference(f"users/{uid}").set(user_record)
            logger.info("Saved user %s to Firebase", uid)
        except Exception as exc:
            logger.error("Firebase save_user error: %s", exc)

    return uid


def get_user(uid: str) -> dict | None:
    if _is_firebase_ready():
        try:
            u = db.reference(f"users/{uid}").get()
            if u:
                return u
        except Exception as exc:
            logger.error("Firebase get_user error: %s", exc)
    return _FALLBACK_USERS.get(uid)


def get_user_by_email(email: str) -> dict | None:
    target_email = (email or "").strip().lower()
    if not target_email:
        return None

    if _is_firebase_ready():
        try:
            users = db.reference("users").get() or {}
            if isinstance(users, dict):
                for u in users.values():
                    if isinstance(u, dict):
                        u_email = (u.get("email") or "").strip().lower()
                        if u_email and u_email == target_email:
                            return u
        except Exception as exc:
            logger.error("Firebase get_user_by_email error: %s", exc)

    for u in _FALLBACK_USERS.values():
        if isinstance(u, dict):
            u_email = (u.get("email") or "").strip().lower()
            if u_email and u_email == target_email:
                return u
    return None


def delete_user(uid: str) -> None:
    if uid in _FALLBACK_USERS:
        del _FALLBACK_USERS[uid]

    if _is_firebase_ready():
        try:
            db.reference(f"users/{uid}").delete()
            logger.info("Deleted user %s from Firebase", uid)
        except Exception as exc:
            logger.error("Firebase delete_user error: %s", exc)

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
    _FALLBACK_RESETS[token] = record
    if _is_firebase_ready():
        try:
            db.reference(f"password_resets/{token}").set(record)
            logger.info("Saved password reset token %s to Firebase", token)
        except Exception as exc:
            logger.error("Firebase save_password_reset error: %s", exc)


def get_password_reset(token: str) -> dict | None:
    """Retrieve a password-reset OTP record by token."""
    if _is_firebase_ready():
        try:
            rec = db.reference(f"password_resets/{token}").get()
            if rec:
                return rec
        except Exception as exc:
            logger.error("Firebase get_password_reset error: %s", exc)
    return _FALLBACK_RESETS.get(token)


def delete_password_reset(token: str) -> None:
    """Delete a password-reset OTP record by token."""
    if token in _FALLBACK_RESETS:
        del _FALLBACK_RESETS[token]

    if _is_firebase_ready():
        try:
            db.reference(f"password_resets/{token}").delete()
            logger.info("Deleted password reset token %s from Firebase", token)
        except Exception as exc:
            logger.error("Firebase delete_password_reset error: %s", exc)

