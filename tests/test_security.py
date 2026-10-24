"""
Security Tests: IDOR, CSRF Enforcement, Unauthorized Action Prevention, Path Traversal
"""
import io
import pytest
from app.security import safe_resolve_path, generate_csrf_token
import app.config as config


def test_path_traversal_prevention():
    """Verify that path traversal attempts outside UPLOAD_DIR are blocked."""
    assert safe_resolve_path("../../../etc/passwd") is None
    assert safe_resolve_path("..\\..\\windows\\system32\\calc.exe") is None
    assert safe_resolve_path("valid_uuid_file.pdf") is not None


def test_idor_document_id_tampering(auth_client_bob, db_conn, seeded_users):
    """
    IDOR Attack Prevention:
    Bob tries sequential ID probing (1, 2, 3...) to access documents owned by Alice.
    The system must block access regardless of ID manipulation.
    """
    alice_id = seeded_users["alice"]["id"]
    cur = db_conn.execute(
        """
        INSERT INTO documents (title, filename, stored_filename, file_path, file_size, mime_type, owner_id)
        VALUES ('Classified Ledger', 'ledger.pdf', 'dummy_ledger.pdf', '/fake/path', 500, 'application/pdf', ?)
        """,
        (alice_id,)
    )
    doc_id = cur.lastrowid
    db_conn.commit()

    bob_client, _, _ = auth_client_bob

    # 1. Probing Alice's existing ID -> 403 Forbidden
    res_probe = bob_client.get(f"/documents/{doc_id}/download")
    assert res_probe.status_code == 403

    # 2. Probing random non-existent ID -> 404 Not Found
    res_fake = bob_client.get("/documents/888888/download")
    assert res_fake.status_code == 404


def test_csrf_protection_enforcement(auth_client_alice):
    """Actions missing valid CSRF tokens must be rejected."""
    client, token, _ = auth_client_alice

    # 1. Upload without CSRF token (rejected by FastAPI validator or CSRF check)
    res_upload = client.post(
        "/documents/upload",
        data={"title": "No CSRF"},
        files={"file": ("test.pdf", io.BytesIO(b"content"), "application/pdf")},
        follow_redirects=False
    )
    assert res_upload.status_code in (303, 400, 422)

    # 2. Upload with forged CSRF token (rejected by our cryptographic verify_csrf_token)
    res_forged = client.post(
        "/documents/upload",
        data={"title": "Forged CSRF", "csrf_token": "forged_invalid_token_12345"},
        files={"file": ("test.pdf", io.BytesIO(b"content"), "application/pdf")},
        follow_redirects=False
    )
    assert res_forged.status_code == 303
    assert "CSRF" in res_forged.headers["location"]


def test_unauthorized_sharing_and_deletion_blocked(auth_client_bob, db_conn, seeded_users):
    """
    Ensure non-owners CANNOT delete or re-share documents they do not own.
    """
    alice_id = seeded_users["alice"]["id"]
    charlie_id = seeded_users["charlie"]["id"]

    cur = db_conn.execute(
        """
        INSERT INTO documents (title, filename, stored_filename, file_path, file_size, mime_type, owner_id)
        VALUES ('Alice Secret Doc', 'doc.pdf', 'dummy_sec.pdf', '/fake/path', 500, 'application/pdf', ?)
        """,
        (alice_id,)
    )
    doc_id = cur.lastrowid
    db_conn.commit()

    bob_client, bob_token, _ = auth_client_bob
    csrf_bob = generate_csrf_token(bob_token)

    # Bob attempts to DELETE Alice's document -> 403 Forbidden
    del_res = bob_client.post(
        f"/documents/{doc_id}/delete",
        data={"csrf_token": csrf_bob}
    )
    assert del_res.status_code == 403

    # Bob attempts to SHARE Alice's document with Charlie -> 403 Forbidden
    share_res = bob_client.post(
        f"/documents/{doc_id}/share",
        data={
            "target_username": "charlie",
            "permission_type": "download",
            "csrf_token": csrf_bob
        }
    )
    assert share_res.status_code == 403
