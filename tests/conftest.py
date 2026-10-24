"""
Pytest Fixtures and Test Setup for DocShield
Configures isolated temporary databases and upload directories for zero side effects.
"""
import os
import shutil
import sqlite3
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

import app.config as config
from app.database import get_db, init_db, get_db_connection
from app.security import hash_password, create_session_token, generate_csrf_token
from main import app


@pytest.fixture(scope="session", autouse=True)
def test_env_setup(tmp_path_factory):
    """Sets up temporary test database and upload directory."""
    temp_dir = tmp_path_factory.mktemp("docshield_test_data")
    test_db = temp_dir / "test_docshield.db"
    test_uploads = temp_dir / "uploads"
    test_uploads.mkdir(parents=True, exist_ok=True)

    config.DATABASE_PATH = test_db
    config.UPLOAD_DIR = test_uploads

    # Initialize schema
    init_db(test_db)

    yield

    # Clean up
    if temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def db_conn():
    """Provides a fresh database connection for direct DB assertions."""
    conn = get_db_connection(config.DATABASE_PATH)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def client():
    """FastAPI TestClient instance."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def seeded_users(db_conn):
    """Seeds test users: alice, bob, charlie."""
    users = [
        ("alice", "alice@test.local", "Password123!"),
        ("bob", "bob@test.local", "Password123!"),
        ("charlie", "charlie@test.local", "Password123!"),
    ]
    created = {}
    for username, email, pwd in users:
        existing = db_conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not existing:
            cursor = db_conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hash_password(pwd))
            )
            created[username] = {"id": cursor.lastrowid, "username": username, "email": email, "password": pwd}
        else:
            created[username] = {"id": existing["id"], "username": username, "email": email, "password": pwd}
    db_conn.commit()
    return created


@pytest.fixture
def auth_client_alice(client, seeded_users):
    """TestClient authenticated as Alice."""
    token = create_session_token(seeded_users["alice"]["id"], "alice")
    client.cookies.set(config.COOKIE_NAME, token)
    return client, token, seeded_users["alice"]


@pytest.fixture
def auth_client_bob(seeded_users):
    """Fresh TestClient authenticated as Bob."""
    with TestClient(app) as bob_client:
        token = create_session_token(seeded_users["bob"]["id"], "bob")
        bob_client.cookies.set(config.COOKIE_NAME, token)
        yield bob_client, token, seeded_users["bob"]


@pytest.fixture
def auth_client_charlie(seeded_users):
    """Fresh TestClient authenticated as Charlie."""
    with TestClient(app) as charlie_client:
        token = create_session_token(seeded_users["charlie"]["id"], "charlie")
        charlie_client.cookies.set(config.COOKIE_NAME, token)
        yield charlie_client, token, seeded_users["charlie"]
