"""
DocShield Configuration Module
Loads configuration from environment variables or falls back to secure defaults.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Application details
APP_NAME = os.getenv("APP_NAME", "DocShield")
SECRET_KEY = os.getenv("SECRET_KEY", "docshield-zero-trust-explainable-secret-key-32b-min")
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

# Database configuration
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "docshield.db")))

# Private File Storage (NEVER exposed to web server directly)
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(BASE_DIR / "storage" / "uploads")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Security and validation rules
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "10"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024
ALLOWED_EXTENSIONS = set(
    os.getenv("ALLOWED_EXTENSIONS", "pdf,png,jpg,jpeg,txt,docx,xlsx,csv,md").lower().split(",")
)

# Allowed MIME types mapped for content-type sniffing validation
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "text/plain",
    "text/csv",
    "text/markdown",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

# Session Cookie Configuration
COOKIE_NAME = "docshield_session"
CSRF_COOKIE_NAME = "docshield_csrf"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "False").lower() in ("true", "1", "yes")
COOKIE_SAME_SITE = os.getenv("COOKIE_SAME_SITE", "lax")
SESSION_EXPIRE_HOURS = int(os.getenv("SESSION_EXPIRE_HOURS", "12"))

# Rate Limiting
LOGIN_RATE_LIMIT_ATTEMPTS = int(os.getenv("LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "60"))
