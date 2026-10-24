"""
DocShield Authentication Routes
Handles user registration, Argon2 credential verification, secure session issuance,
login rate limiting, and audit trail integration.
"""
import re
from fastapi import APIRouter, Request, Response, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import sqlite3

from app.config import (
    BASE_DIR,
    COOKIE_NAME,
    COOKIE_SECURE,
    COOKIE_SAME_SITE,
    SESSION_EXPIRE_HOURS,
)
from app.database import get_db
from app.security import (
    hash_password,
    verify_password,
    create_session_token,
    rate_limiter,
)
from app.audit import log_audit
from app.auth import get_client_ip, get_current_user_optional, get_template_context

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


@router.get("/register", response_class=HTMLResponse)
async def register_page(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db)
):
    user = get_current_user_optional(request, conn)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context=get_template_context(request)
    )


@router.post("/register")
async def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)
    username = username.strip()
    email = email.strip().lower()

    # Validation checks
    if not USERNAME_REGEX.match(username):
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context=get_template_context(request, extra={"error": "Username must be 3-30 alphanumeric characters or underscores.", "entered_username": username, "entered_email": email}),
            status_code=400
        )

    if not EMAIL_REGEX.match(email):
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context=get_template_context(request, extra={"error": "Please enter a valid email address.", "entered_username": username, "entered_email": email}),
            status_code=400
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context=get_template_context(request, extra={"error": "Password must be at least 8 characters long.", "entered_username": username, "entered_email": email}),
            status_code=400
        )

    if password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context=get_template_context(request, extra={"error": "Passwords do not match.", "entered_username": username, "entered_email": email}),
            status_code=400
        )

    # Check existing user
    existing = conn.execute(
        "SELECT id, username, email FROM users WHERE username = ? OR email = ?",
        (username, email)
    ).fetchone()

    if existing:
        msg = "Username already taken." if existing["username"].lower() == username.lower() else "Email already registered."
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context=get_template_context(request, extra={"error": msg, "entered_username": username, "entered_email": email}),
            status_code=400
        )

    # Hash with Argon2
    p_hash = hash_password(password)

    cursor = conn.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, p_hash)
    )
    user_id = cursor.lastrowid

    # Audit log registration
    log_audit(
        conn=conn,
        action="USER_REGISTER",
        decision="ALLOWED",
        reason_code="account_created",
        user_id=user_id,
        details=f"User '{username}' registered successfully.",
        ip_address=ip
    )

    return RedirectResponse(
        url="/login?success=Registration+successful.+Please+log+in.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db)
):
    user = get_current_user_optional(request, conn)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context=get_template_context(request)
    )


@router.post("/login")
async def login_submit(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)
    username = username.strip()
    rate_limit_key = f"{ip}:{username.lower()}"

    # Rate limit check
    is_limited, retry_after = rate_limiter.is_rate_limited(rate_limit_key)
    if is_limited:
        log_audit(
            conn=conn,
            action="USER_LOGIN",
            decision="DENIED",
            reason_code="rate_limit_exceeded",
            details=f"Brute force protection triggered for '{username}' from {ip}.",
            ip_address=ip
        )
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context=get_template_context(request, extra={"error": f"Too many failed attempts. Please wait {retry_after} seconds before trying again.", "entered_username": username}),
            status_code=429
        )

    # Lookup user
    user = conn.execute(
        "SELECT id, username, email, password_hash FROM users WHERE username = ? OR email = ?",
        (username, username.lower())
    ).fetchone()

    # Constant-time verify password with Argon2
    is_valid = False
    if user:
        is_valid = verify_password(user["password_hash"], password)

    if not is_valid:
        rate_limiter.record_failure(rate_limit_key)
        log_audit(
            conn=conn,
            action="USER_LOGIN",
            decision="DENIED",
            reason_code="invalid_credentials",
            user_id=user["id"] if user else None,
            details=f"Failed login attempt for identifier '{username}'.",
            ip_address=ip
        )
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context=get_template_context(request, extra={"error": "Invalid username/email or password.", "entered_username": username}),
            status_code=401
        )

    # Success: reset rate limit counter
    rate_limiter.record_success(rate_limit_key)

    # Issue signed session token
    session_token = create_session_token(user["id"], user["username"])

    # Log successful login
    log_audit(
        conn=conn,
        action="USER_LOGIN",
        decision="ALLOWED",
        reason_code="login_success",
        user_id=user["id"],
        details=f"User '{user['username']}' logged in successfully.",
        ip_address=ip
    )

    redirect = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    redirect.set_cookie(
        key=COOKIE_NAME,
        value=session_token,
        max_age=SESSION_EXPIRE_HOURS * 3600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAME_SITE,
        path="/"
    )
    return redirect


@router.get("/logout")
@router.post("/logout")
async def logout(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)
    user = get_current_user_optional(request, conn)

    if user:
        log_audit(
            conn=conn,
            action="USER_LOGOUT",
            decision="ALLOWED",
            reason_code="logout_success",
            user_id=user["id"],
            details=f"User '{user['username']}' logged out.",
            ip_address=ip
        )

    response = RedirectResponse(url="/login?success=You+have+been+logged+out.", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return response
