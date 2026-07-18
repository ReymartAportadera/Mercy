import os
import uuid
import logging
import firebase_admin
from firebase_admin import credentials, db
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load .env file if present
load_dotenv()

# ── Initialize Firebase Admin SDK ─────────────────────────────────────────────
_cred_path = os.getenv("FIREBASE_SERVICE_ACCOUNT")
_db_url    = os.getenv("FIREBASE_DB_URL")

if not _cred_path:
    raise RuntimeError(
        "FIREBASE_SERVICE_ACCOUNT env var is not set. "
        "Download your service-account JSON from the Firebase console "
        "(Project Settings → Service accounts → Generate new private key) "
        "and set FIREBASE_SERVICE_ACCOUNT=/absolute/path/to/key.json in your .env file."
    )

if not _db_url:
    raise RuntimeError("FIREBASE_DB_URL env var is not set.")

if not firebase_admin._apps:          # avoid re-initialising on reload
    _cred = credentials.Certificate(_cred_path)
    firebase_admin.initialize_app(_cred, {"databaseURL": _db_url})

# ── Uploaded-File Helpers ──────────────────────────────────────────────────────

def save_uploaded_file(file_record: dict) -> str:
    """Persist a file record and return its ID."""
    file_id = file_record.get("id") or str(uuid.uuid4())
    file_record["id"] = file_id
    db.reference(f"uploaded_files/{file_id}").set(file_record)
    logger.info("Saved file record %s", file_id)
    return file_id


def get_uploaded_file(file_id: str) -> dict | None:
    return db.reference(f"uploaded_files/{file_id}").get()


def delete_uploaded_file(file_id: str) -> None:
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
    for u in users.values():
        if isinstance(u, dict) and u.get("email") == email:
            return u
    return None


def delete_user(uid: str) -> None:
    db.reference(f"users/{uid}").delete()
    logger.info("Deleted user %s", uid)

# ── User-Settings Helpers ─────────────────────────────────────────────────────

def save_user_settings(uid: str, settings: dict) -> None:
    db.reference(f"user_settings/{uid}").set(settings)


def get_user_settings(uid: str) -> dict | None:
    return db.reference(f"user_settings/{uid}").get()


def delete_user_settings(uid: str) -> None:
    db.reference(f"user_settings/{uid}").delete()
