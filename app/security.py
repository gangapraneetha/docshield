"""
DocShield Security Module
Provides Argon2 password hashing, cryptographically signed sessions,
CSRF protection, path-traversal prevention, and in-memory rate limiting.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

import app.config as config

# Initialize Argon2id Hasher with secure industry-standard defaults
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a plaintext password against the stored Argon2 hash."""
    try:
        return ph.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


# ==========================================
# Cryptographically Signed Session Management
# ==========================================

def create_session_token(user_id: int, username: str) -> str:
    """
    Creates a tamper-proof signed session token using HMAC-SHA256.
    Payload format: base64(json) . hmac_signature
    """
    now = int(time.time())
    expires_at = now + (config.SESSION_EXPIRE_HOURS * 3600)
    payload = {
        "user_id": user_id,
        "username": username,
        "iat": now,
        "exp": expires_at,
        "nonce": secrets.token_hex(8),
    }
    raw_payload = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    b64_payload = base64.urlsafe_b64encode(raw_payload).decode('utf-8').rstrip('=')
    
    signature = hmac.new(config.SECRET_KEY.encode('utf-8'), b64_payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{b64_payload}.{signature}"


def verify_session_token(token: str) -> Optional[dict]:
    """
    Verifies the HMAC signature and expiration of a session token.
    Returns the payload dictionary if valid, or None if invalid/expired.
    """
    if not token or "." not in token:
        return None
    try:
        b64_payload, signature = token.split(".", 1)
        expected_sig = hmac.new(config.SECRET_KEY.encode('utf-8'), b64_payload.encode('utf-8'), hashlib.sha256).hexdigest()
        
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signature, expected_sig):
            return None
        
        # Pad base64 string if necessary
        padding = 4 - (len(b64_payload) % 4)
        if padding != 4:
            b64_payload += "=" * padding
            
        raw_payload = base64.urlsafe_b64decode(b64_payload.encode('utf-8'))
        payload = json.loads(raw_payload.decode('utf-8'))
        
        # Check expiration
        if time.time() > payload.get("exp", 0):
            return None
            
        return payload
    except Exception:
        return None


# ==========================================
# CSRF Token Protection
# ==========================================

def generate_csrf_token(session_token: str) -> str:
    """
    Generates a deterministic yet secret-bound CSRF token for a given valid session.
    """
    if not session_token:
        return secrets.token_hex(32)
    return hmac.new(
        config.SECRET_KEY.encode('utf-8'),
        f"csrf:{session_token}".encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def verify_csrf_token(session_token: str, submitted_token: str) -> bool:
    """
    Verifies that the submitted CSRF token matches the session in constant time.
    """
    if not session_token or not submitted_token:
        return False
    expected = generate_csrf_token(session_token)
    return hmac.compare_digest(expected, submitted_token)


# ==========================================
# Rate Limiting (Brute-force protection)
# ==========================================

class LoginRateLimiter:
    """
    In-memory sliding window rate limiter for login attempts.
    Tracks failures per IP and per username to prevent credential stuffing.
    """
    def __init__(self):
        # key -> list of failure timestamps
        self._failures: dict[str, list[float]] = {}

    def is_rate_limited(self, key: str) -> Tuple[bool, int]:
        """
        Returns (is_limited, retry_after_seconds).
        """
        now = time.time()
        cutoff = now - config.LOGIN_RATE_LIMIT_WINDOW_SECONDS
        
        attempts = [t for t in self._failures.get(key, []) if t > cutoff]
        self._failures[key] = attempts
        
        if len(attempts) >= config.LOGIN_RATE_LIMIT_ATTEMPTS:
            oldest_relevant = attempts[0]
            retry_after = int(config.LOGIN_RATE_LIMIT_WINDOW_SECONDS - (now - oldest_relevant)) + 1
            return True, max(1, retry_after)
            
        return False, 0

    def record_failure(self, key: str):
        now = time.time()
        if key not in self._failures:
            self._failures[key] = []
        self._failures[key].append(now)

    def record_success(self, key: str):
        if key in self._failures:
            del self._failures[key]


rate_limiter = LoginRateLimiter()


# ==========================================
# File Security & Path Traversal Prevention
# ==========================================

def sanitize_filename(filename: str) -> str:
    """
    Strips directory separators and null bytes. Retains safe alphanumerics and dots.
    """
    clean = os.path.basename(filename)
    clean = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', clean)
    clean = re.sub(r'\.{2,}', '.', clean)  # prevent ..
    return clean[:120] if clean else "document.bin"


def safe_resolve_path(stored_filename: str) -> Optional[Path]:
    """
    Ensures the target file path strictly resolves within UPLOAD_DIR.
    Prevents path traversal attacks (e.g., ../../../etc/passwd).
    """
    try:
        base = config.UPLOAD_DIR.resolve()
        target = (base / stored_filename).resolve()
        if base in target.parents or base == target.parent:
            return target
        return None
    except Exception:
        return None
