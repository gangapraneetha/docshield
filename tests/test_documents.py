"""
Tests for Document Upload, Download, Sharing Lifecycle, Revocation, and Validation
"""
import io
import pytest
from app.security import generate_csrf_token
import app.config as config


def test_document_upload_success(auth_client_alice, db_conn):
    """Test authenticated document upload."""
    client, token, alice = auth_client_alice
    csrf_token = generate_csrf_token(token)

    file_content = b"Confidential Project Architecture Specification"
    file_obj = io.BytesIO(file_content)

    res = client.post(
        "/documents/upload",
        data={
            "title": "Architecture Spec",
            "description": "Internal technical design document",
            "csrf_token": csrf_token
        },
        files={"file": ("architecture.pdf", file_obj, "application/pdf")},
        follow_redirects=False
    )

    assert res.status_code == 303
    assert "/dashboard" in res.headers["location"]

    # Verify DB record
    doc = db_conn.execute("SELECT * FROM documents WHERE title = 'Architecture Spec'").fetchone()
    assert doc is not None
    assert doc["owner_id"] == alice["id"]
    assert doc["filename"] == "architecture.pdf"
    assert doc["file_size"] == len(file_content)

    # Verify physical file exists in private upload directory
    stored_path = config.UPLOAD_DIR / doc["stored_filename"]
    assert stored_path.exists()
    assert stored_path.read_bytes() == file_content


def test_owner_download_own_document(auth_client_alice, db_conn):
    """Owners must be able to download their own documents."""
    client, token, alice = auth_client_alice
    doc = db_conn.execute(
        "SELECT id FROM documents WHERE owner_id = ? AND title = 'Architecture Spec'",
        (alice["id"],)
    ).fetchone()

    res = client.get(f"/documents/{doc['id']}/download")
    assert res.status_code == 200
    assert res.content == b"Confidential Project Architecture Specification"


def test_unauthorized_user_cannot_reach_document(auth_client_alice, auth_client_bob, db_conn):
    """
    CRITICAL ZERO-TRUST REQUIREMENT:
    Bob genuinely CANNOT reach or download Alice's document without authorization.
    """
    _, _, alice = auth_client_alice
    bob_client, _, bob = auth_client_bob

    doc = db_conn.execute(
        "SELECT id FROM documents WHERE owner_id = ? AND title = 'Architecture Spec'",
        (alice["id"],)
    ).fetchone()

    # Bob attempts direct download
    res = bob_client.get(f"/documents/{doc['id']}/download")
    assert res.status_code == 403
    assert "no_matching_permission" in res.text or "Access denied" in res.text


def test_sharing_grants_access_and_revocation_denies_it(auth_client_alice, auth_client_bob, db_conn):
    """
    Full lifecycle:
    1. Alice shares document with Bob.
    2. Bob can now download.
    3. Alice revokes Bob's access.
    4. Bob is immediately denied again.
    """
    alice_client, alice_token, alice = auth_client_alice
    bob_client, _, bob = auth_client_bob
    csrf_alice = generate_csrf_token(alice_token)

    doc = db_conn.execute(
        "SELECT id FROM documents WHERE owner_id = ? AND title = 'Architecture Spec'",
        (alice["id"],)
    ).fetchone()
    doc_id = doc["id"]

    # 1. Alice shares with Bob
    share_res = alice_client.post(
        f"/documents/{doc_id}/share",
        data={
            "target_username": "bob",
            "permission_type": "download",
            "csrf_token": csrf_alice
        },
        follow_redirects=False
    )
    assert share_res.status_code == 303

    # 2. Bob downloads successfully
    bob_dl_res = bob_client.get(f"/documents/{doc_id}/download")
    assert bob_dl_res.status_code == 200
    assert bob_dl_res.content == b"Confidential Project Architecture Specification"

    # 3. Alice revokes Bob's access
    revoke_res = alice_client.post(
        f"/documents/{doc_id}/revoke",
        data={
            "target_user_id": bob["id"],
            "permission_type": "download",
            "csrf_token": csrf_alice
        },
        follow_redirects=False
    )
    assert revoke_res.status_code == 303

    # 4. Bob attempts download again -> REJECTED with 403
    bob_revoked_res = bob_client.get(f"/documents/{doc_id}/download")
    assert bob_revoked_res.status_code == 403
    assert "permission_revoked" in bob_revoked_res.text


def test_invalid_file_extension_rejected(auth_client_alice):
    """Disallowed executable or script file extensions must be rejected."""
    client, token, _ = auth_client_alice
    csrf = generate_csrf_token(token)

    for bad_file in ["malicious.exe", "script.sh", "payload.bat"]:
        res = client.post(
            "/documents/upload",
            data={"title": "Malicious", "csrf_token": csrf},
            files={"file": (bad_file, io.BytesIO(b"echo hacked"), "application/octet-stream")},
            follow_redirects=False
        )
        assert res.status_code == 303
        assert "not+supported" in res.headers["location"]


def test_oversized_upload_rejected(auth_client_alice, monkeypatch):
    """Files exceeding maximum allowed size must be rejected."""
    client, token, _ = auth_client_alice
    csrf = generate_csrf_token(token)

    # Mock maximum size to 100 bytes for fast testing
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 100)

    oversized = b"A" * 150
    res = client.post(
        "/documents/upload",
        data={"title": "Large File", "csrf_token": csrf},
        files={"file": ("large.pdf", io.BytesIO(oversized), "application/pdf")},
        follow_redirects=False
    )
    assert res.status_code == 303
    assert "exceeds+maximum+size" in res.headers["location"]
