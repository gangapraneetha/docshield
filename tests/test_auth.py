"""
Tests for User Registration, Login, Argon2 Hashing, and Rate Limiting
"""
import pytest
from app.security import hash_password, verify_password, rate_limiter
import app.config as config


def test_argon2_password_hashing():
    """Verify that Argon2 produces secure, verifiable hashes."""
    pwd = "SuperSecretPassword2026!"
    hashed = hash_password(pwd)
    
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, pwd) is True
    assert verify_password(hashed, "WrongPassword!") is False


def test_user_registration_success(client, db_conn):
    """Test successful registration of a new user."""
    res = client.post("/register", data={
        "username": "newuser_99",
        "email": "newuser99@test.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=False)

    assert res.status_code == 303
    assert "/login" in res.headers["location"]

    # Verify user exists in database with Argon2 hash
    user = db_conn.execute("SELECT * FROM users WHERE username = ?", ("newuser_99",)).fetchone()
    assert user is not None
    assert user["email"] == "newuser99@test.com"
    assert verify_password(user["password_hash"], "Password123!") is True


def test_user_registration_validation(client):
    """Test registration validation rules (username length, invalid email, short password, mismatch)."""
    # 1. Invalid username
    r1 = client.post("/register", data={
        "username": "ab",
        "email": "valid@test.com",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    assert r1.status_code == 400
    assert "Username must be 3-30 alphanumeric" in r1.text

    # 2. Invalid email
    r2 = client.post("/register", data={
        "username": "valid_user",
        "email": "invalid-email-address",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    assert r2.status_code == 400
    assert "valid email" in r2.text

    # 3. Short password
    r3 = client.post("/register", data={
        "username": "valid_user",
        "email": "valid@test.com",
        "password": "123",
        "confirm_password": "123"
    })
    assert r3.status_code == 400
    assert "at least 8 characters" in r3.text

    # 4. Password mismatch
    r4 = client.post("/register", data={
        "username": "valid_user",
        "email": "valid@test.com",
        "password": "Password123!",
        "confirm_password": "DifferentPassword!"
    })
    assert r4.status_code == 400
    assert "Passwords do not match" in r4.text


def test_user_login_success(client, seeded_users):
    """Test login with valid credentials issues signed cookie."""
    res = client.post("/login", data={
        "username": "alice",
        "password": "Password123!"
    }, follow_redirects=False)

    assert res.status_code == 303
    assert "/dashboard" in res.headers["location"]
    assert config.COOKIE_NAME in res.cookies


def test_user_login_invalid_password(client):
    """Test login with invalid password returns 401."""
    res = client.post("/login", data={
        "username": "alice",
        "password": "IncorrectPassword!"
    })
    assert res.status_code == 401
    assert "Invalid username/email or password" in res.text


def test_login_rate_limiting(client):
    """Test brute force login rate limiting after multiple failures."""
    test_user = "bruteforce_target"
    
    # 5 failed attempts
    for _ in range(config.LOGIN_RATE_LIMIT_ATTEMPTS):
        res = client.post("/login", data={
            "username": test_user,
            "password": "wrong"
        })
        assert res.status_code in (401, 429)

    # 6th attempt must be 429 Too Many Requests
    r_limited = client.post("/login", data={
        "username": test_user,
        "password": "wrong"
    })
    assert r_limited.status_code == 429
    assert "Too many failed attempts" in r_limited.text
