"""
DocShield Authentication & Session Dependencies
Extracts and validates signed session tokens, handles CSRF tokens,
and injects authenticated user records into FastAPI routes.
"""
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status, Depends
from fastapi.responses import RedirectResponse
import sqlite3

from app.config import COOKIE_NAME, CSRF_COOKIE_NAME
from app.database import get_db
from app.security import verify_session_token, generate_csrf_token


def get_client_ip(request: Request) -> str:
    """Extracts client IP safely from headers or connection client."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_session_token_from_request(request: Request) -> Optional[str]:
    """Retrieves session cookie from request."""
    return request.cookies.get(COOKIE_NAME)


def get_current_user_optional(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db)
) -> Optional[Dict[str, Any]]:
    """
    Dependency that optionally retrieves the currently authenticated user.
    Returns None if unauthenticated or session is expired.
    """
    token = get_session_token_from_request(request)
    if not token:
        return None

    payload = verify_session_token(token)
    if not payload:
        return None

    user_id = payload.get("user_id")
    row = conn.execute(
        "SELECT id, username, email, created_at FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not row:
        return None

    return dict(row)


def require_authenticated_user(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db)
) -> Dict[str, Any]:
    """
    Strict dependency requiring an authenticated user.
    Raises HTTPException(401) for API/AJAX requests or redirects for browser navigation.
    """
    user = get_current_user_optional(request, conn)
    if not user:
        # Check if browser HTML navigation or API request
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": "/login?error=Session+expired.+Please+log+in+again."}
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required."
        )
    return user


def get_template_context(
    request: Request,
    user: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Constructs standard template context including CSRF token,
    logged in user, flash messages, and active query parameters.
    """
    token = get_session_token_from_request(request) or ""
    csrf_token = generate_csrf_token(token) if token else ""
    
    ctx = {
        "request": request,
        "current_user": user,
        "csrf_token": csrf_token,
        "error": request.query_params.get("error"),
        "success": request.query_params.get("success"),
        "query": request.query_params.get("q", "")
    }
    if extra:
        ctx.update(extra)
    return ctx
