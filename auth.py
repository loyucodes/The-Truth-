"""
auth.py — Password hashing, JWT token creation/validation, and RBAC middleware.

Uses:
  • hashlib.pbkdf2_hmac  — password hashing (stdlib, no bcrypt needed)
  • cryptography         — HMAC-SHA256 for JWT signing
  • jwt (PyJWT)          — token encode / decode
"""

import os
import hashlib
import hmac
import json
import time
import functools
from datetime import datetime, timezone, timedelta
from flask import request, jsonify, g

import jwt as pyjwt

from roles import Role, Permission, ROLE_PERMISSIONS, SINGLETON_ROLES, has_permission
import database as db

# ── Config ─────────────────────────────────────────────────────────────
SECRET_KEY      = os.environ.get("TRUTH_SECRET", "change-me-in-production-please")
TOKEN_TTL_HOURS = int(os.environ.get("TRUTH_TOKEN_TTL", "12"))
ALGORITHM       = "HS256"

# ── Password hashing (PBKDF2-HMAC-SHA256) ─────────────────────────────

def hash_password(plain: str) -> str:
    """Return a salted PBKDF2 hash string: iterations$salt$hash (all hex)."""
    iterations = 260_000
    salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, iterations)
    return f"{iterations}${salt.hex()}${dk.hex()}"


def verify_password(plain: str, stored_hash: str) -> bool:
    """Constant-time verification against a stored PBKDF2 hash."""
    try:
        iterations_str, salt_hex, dk_hex = stored_hash.split("$")
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        dk_expected = bytes.fromhex(dk_hex)
        dk_actual = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, iterations)
        return hmac.compare_digest(dk_actual, dk_expected)
    except Exception:
        return False


# ── JWT helpers ────────────────────────────────────────────────────────

def _token_hash(raw_token: str) -> str:
    """SHA-256 of the raw JWT, stored in DB for revocation checks."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def generate_token(user_id: int, role: str,
                   ip: str = "", ua: str = "") -> str:
    """Mint a signed JWT and persist the session record."""
    expires = datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)
    payload = {
        "sub":  str(user_id),
        "role": role,
        "iat":  int(time.time()),
        "exp":  int(expires.timestamp()),
    }
    token = pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    db.create_session(
        user_id    = user_id,
        token_hash = _token_hash(token),
        expires_at = expires.strftime("%Y-%m-%d %H:%M:%S"),
        ip         = ip,
        ua         = ua,
    )
    return token


def validate_token(raw_token: str):
    """
    Decode and validate a JWT.
    Returns the payload dict on success, raises ValueError on failure.
    """
    try:
        payload = pyjwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
    except pyjwt.ExpiredSignatureError:
        raise ValueError("Token has expired. Please log in again.")
    except pyjwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")

    # Check the DB session record (covers revocation)
    session = db.get_session(_token_hash(raw_token))
    if session is None:
        raise ValueError("Session not found or has been revoked.")
    if not session["is_active"]:
        raise ValueError("User account is deactivated.")

    return payload


def revoke_token(raw_token: str):
    db.revoke_session(_token_hash(raw_token))


# ── Token extraction from request ─────────────────────────────────────

def _extract_bearer() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return request.cookies.get("auth_token")   # fallback for browser sessions


# ── Flask RBAC middleware decorators ──────────────────────────────────

def login_required(f):
    """Decorator: require a valid token; injects g.user_id and g.role."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        token = _extract_bearer()
        if not token:
            return jsonify({"error": "Authentication required."}), 401
        try:
            payload = validate_token(token)
        except ValueError as e:
            return jsonify({"error": str(e)}), 401
        g.user_id = int(payload["sub"])
        g.role    = payload["role"]
        g.token   = token
        return f(*args, **kwargs)
    return wrapped


def permission_required(permission: str):
    """
    Decorator factory: require a specific permission.
    Must be used *after* @login_required.

    Usage:
        @app.route("/posts/<id>/publish", methods=["POST"])
        @login_required
        @permission_required(Permission.PUBLISH)
        def publish_post(id): ...
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            role = getattr(g, "role", None)
            if not role or not has_permission(role, permission):
                return jsonify({
                    "error": "Forbidden.",
                    "detail": f"Your role '{role}' does not have '{permission}' permission.",
                    "required_permission": permission,
                    "publisher_roles": [
                        "editorial_adviser", "editor_in_chief",
                        "assoc_editor_in_chief", "managing_editor",
                        "assoc_managing_editor",
                    ],
                }), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator


def roles_required(*allowed_roles: str):
    """
    Decorator factory: restrict to specific roles (role-name check).
    Alternative to permission_required when you want explicit role gating.
    Must be used *after* @login_required.
    """
    allowed = set(allowed_roles)
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            role = getattr(g, "role", None)
            if role not in allowed:
                return jsonify({
                    "error": "Forbidden.",
                    "detail": f"Role '{role}' is not permitted to access this resource.",
                    "allowed_roles": sorted(allowed),
                }), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ── Registration guard ─────────────────────────────────────────────────

class RegistrationError(Exception):
    pass


def validate_registration(username: str, email: str,
                           password: str, role: str) -> None:
    """
    Raise RegistrationError if the registration attempt is invalid.
    Enforces singleton-role limits and role validity.
    """
    from roles import ROLE_PERMISSIONS, SINGLETON_ROLES

    if role not in ROLE_PERMISSIONS:
        raise RegistrationError(f"Unknown role: '{role}'.")

    if db.get_user_by_username(username):
        raise RegistrationError("Username already taken.")

    if db.get_user_by_email(email):
        raise RegistrationError("Email already registered.")

    if len(password) < 8:
        raise RegistrationError("Password must be at least 8 characters.")

    # Singleton enforcement
    if role in SINGLETON_ROLES:
        existing = db.count_users_with_role(role)
        if existing >= 1:
            from roles import ROLE_LABELS
            label = ROLE_LABELS.get(role, role)
            raise RegistrationError(
                f"The '{label}' position is already filled. "
                f"Only one account per singleton role is allowed."
            )
