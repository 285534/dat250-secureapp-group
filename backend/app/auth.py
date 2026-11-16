import hashlib
import hmac
import secrets

from argon2 import PasswordHasher, exceptions as argon2_exceptions
from fastapi import Request

from app.database import run_query


_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password with Argon2id and a unique salt."""
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify Argon2id hashes and support legacy SHA-256 hashes during migration."""
    if password_hash.startswith("$argon2"):
        try:
            return _password_hasher.verify(password_hash, password)
        except (argon2_exceptions.VerifyMismatchError,
                argon2_exceptions.VerificationError,
                argon2_exceptions.InvalidHashError):
            return False

    # Backwards compatibility for accounts created before the remediation.
    legacy_hash = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(legacy_hash, password_hash)


def password_hash_needs_upgrade(password_hash: str) -> bool:
    """Return True for legacy hashes or outdated Argon2 parameters."""
    if not password_hash.startswith("$argon2"):
        return True
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except argon2_exceptions.InvalidHashError:
        return True


def create_session(user_id: int) -> str:
    token = secrets.token_hex(16)
    run_query(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user_id, token),
        commit=True,
    )
    return token


def get_user_from_session(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None
    session = run_query(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token = %s
        """,
        (session_token,),
        fetchone=True,
    )
    return session


def clear_session(token: str):
    run_query("DELETE FROM sessions WHERE session_token = %s", (token,), commit=True)
