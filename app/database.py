"""
DocShield Database Layer
Manages SQLite connection lifecycle, schema migrations, foreign keys,
and indexing for high-performance parameterized queries.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional
import app.config as config

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Documents table
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    filename TEXT NOT NULL,
    stored_filename TEXT UNIQUE NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents (owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_created ON documents (created_at DESC);

-- Document Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_type TEXT NOT NULL CHECK (permission_type IN ('view', 'download', 'edit')),
    is_revoked INTEGER NOT NULL DEFAULT 0 CHECK (is_revoked IN (0, 1)),
    granted_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    revoked_at TEXT,
    UNIQUE (document_id, user_id, permission_type)
);

CREATE INDEX IF NOT EXISTS idx_permissions_lookup 
    ON permissions (document_id, user_id, permission_type, is_revoked);
CREATE INDEX IF NOT EXISTS idx_permissions_user 
    ON permissions (user_id, is_revoked);

-- Tamper-Evident Audit Logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOWED', 'DENIED')),
    reason_code TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    prev_hash TEXT NOT NULL,
    current_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_document ON audit_logs (document_id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs (decision);

-- Real-time Notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'info' CHECK (type IN ('info', 'success', 'warning', 'danger')),
    is_read INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
);

CREATE INDEX IF NOT EXISTS idx_notifications_user 
    ON notifications (user_id, is_read, created_at DESC);
"""


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """
    Creates and configures an isolated SQLite connection with foreign keys enabled
    and row dictionary mapping. Dynamically resolves config.DATABASE_PATH.
    """
    target_path = str(db_path or config.DATABASE_PATH)
    conn = sqlite3.connect(target_path, timeout=10.0, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def get_db() -> Generator[sqlite3.Connection, None, None]:
    """
    FastAPI dependency yielding an isolated SQLite connection per request.
    Automatically commits on success or rolls back on exceptions.
    """
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def db_context(db_path: Optional[Path] = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for background, script, and startup tasks:
    with db_context() as conn:
    """
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[Path] = None):
    """
    Initializes database tables, constraints, and indexes.
    """
    with db_context(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
