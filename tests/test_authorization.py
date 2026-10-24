"""
Unit Tests for the Centralized Explainable Authorization Engine (authorize_document)
"""
import pytest
from app.authorization import authorize_document


def test_auth_engine_unauthenticated(db_conn):
    """Anonymous/unauthenticated users must be denied."""
    dec = authorize_document(db_conn, user_id=None, document_id=1, action="view")
    assert dec.allowed is False
    assert dec.reason == "user_not_authenticated"


def test_auth_engine_document_not_found(db_conn, seeded_users):
    """Non-existent document IDs must return document_not_found."""
    alice_id = seeded_users["alice"]["id"]
    dec = authorize_document(db_conn, user_id=alice_id, document_id=999999, action="view")
    assert dec.allowed is False
    assert dec.reason == "document_not_found"


def test_auth_engine_owner_access(db_conn, seeded_users):
    """Document owners must have full capability across all actions."""
    alice_id = seeded_users["alice"]["id"]

    # Insert test document owned by Alice
    cur = db_conn.execute(
        """
        INSERT INTO documents (title, filename, stored_filename, file_path, file_size, mime_type, owner_id)
        VALUES ('Secret Roadmap', 'roadmap.pdf', 'dummy_123.pdf', '/fake/path', 1024, 'application/pdf', ?)
        """,
        (alice_id,)
    )
    doc_id = cur.lastrowid
    db_conn.commit()

    for action in ["view", "download", "share", "revoke", "delete"]:
        decision = authorize_document(db_conn, user_id=alice_id, document_id=doc_id, action=action)
        assert decision.allowed is True
        assert decision.reason == "owner_access"
        assert decision.action == action


def test_auth_engine_owner_only_actions_denied_for_others(db_conn, seeded_users):
    """Non-owners cannot delete, share, or revoke permissions even if shared with them."""
    alice_id = seeded_users["alice"]["id"]
    bob_id = seeded_users["bob"]["id"]

    cur = db_conn.execute(
        """
        INSERT INTO documents (title, filename, stored_filename, file_path, file_size, mime_type, owner_id)
        VALUES ('Alice Vault Doc', 'vault.pdf', 'dummy_vault.pdf', '/fake/path', 1024, 'application/pdf', ?)
        """,
        (alice_id,)
    )
    doc_id = cur.lastrowid
    db_conn.commit()

    for restricted_action in ["delete", "share", "revoke"]:
        dec = authorize_document(db_conn, user_id=bob_id, document_id=doc_id, action=restricted_action)
        assert dec.allowed is False
        assert dec.reason == "owner_only_action"


def test_auth_engine_no_permission(db_conn, seeded_users):
    """Users without any permission grant must be denied."""
    alice_id = seeded_users["alice"]["id"]
    bob_id = seeded_users["bob"]["id"]

    cur = db_conn.execute(
        """
        INSERT INTO documents (title, filename, stored_filename, file_path, file_size, mime_type, owner_id)
        VALUES ('Private File', 'priv.txt', 'priv.txt', '/fake/path', 50, 'text/plain', ?)
        """,
        (alice_id,)
    )
    doc_id = cur.lastrowid
    db_conn.commit()

    dec = authorize_document(db_conn, user_id=bob_id, document_id=doc_id, action="view")
    assert dec.allowed is False
    assert dec.reason == "no_matching_permission"


def test_auth_engine_explicit_permissions_and_revocation(db_conn, seeded_users):
    """Tests granting view/download permissions, action mismatch, and revocation."""
    alice_id = seeded_users["alice"]["id"]
    bob_id = seeded_users["bob"]["id"]

    cur = db_conn.execute(
        """
        INSERT INTO documents (title, filename, stored_filename, file_path, file_size, mime_type, owner_id)
        VALUES ('Shared Spec', 'spec.pdf', 'spec.pdf', '/fake/path', 200, 'application/pdf', ?)
        """,
        (alice_id,)
    )
    doc_id = cur.lastrowid

    # 1. Grant Bob 'view' permission only
    db_conn.execute(
        "INSERT INTO permissions (document_id, user_id, granted_by, permission_type) VALUES (?, ?, ?, 'view')",
        (doc_id, bob_id, alice_id)
    )
    db_conn.commit()

    # Bob can view
    dec_view = authorize_document(db_conn, user_id=bob_id, document_id=doc_id, action="view")
    assert dec_view.allowed is True
    assert dec_view.reason == "explicit_view_permission"

    # Bob CANNOT download (only view was granted)
    dec_dl = authorize_document(db_conn, user_id=bob_id, document_id=doc_id, action="download")
    assert dec_dl.allowed is False
    assert dec_dl.reason == "no_matching_permission"

    # 2. Grant Bob 'download' permission
    db_conn.execute(
        "INSERT INTO permissions (document_id, user_id, granted_by, permission_type) VALUES (?, ?, ?, 'download')",
        (doc_id, bob_id, alice_id)
    )
    db_conn.commit()

    dec_dl_now = authorize_document(db_conn, user_id=bob_id, document_id=doc_id, action="download")
    assert dec_dl_now.allowed is True
    assert dec_dl_now.reason == "explicit_download_permission"

    # 3. Revoke Bob's download permission
    db_conn.execute(
        "UPDATE permissions SET is_revoked = 1, revoked_at = datetime('now') WHERE document_id = ? AND user_id = ? AND permission_type = 'download'",
        (doc_id, bob_id)
    )
    db_conn.commit()

    dec_revoked = authorize_document(db_conn, user_id=bob_id, document_id=doc_id, action="download")
    assert dec_revoked.allowed is False
    assert dec_revoked.reason == "permission_revoked"
