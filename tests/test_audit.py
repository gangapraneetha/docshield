"""
Tests for Tamper-Evident Audit Trails, Cryptographic Hash Chaining, and Explainability
"""
import pytest
from app.audit import log_audit, verify_audit_integrity, calculate_record_hash


def test_audit_logging_and_explainable_reasons(db_conn, seeded_users):
    """Verify that audit logs accurately record actor, action, decision, and explainable reason."""
    alice_id = seeded_users["alice"]["id"]

    # Insert a valid document first to satisfy SQLite foreign keys
    cur = db_conn.execute(
        """
        INSERT INTO documents (title, filename, stored_filename, file_path, file_size, mime_type, owner_id)
        VALUES ('Test Audit Doc', 'test.pdf', 'uuid_test.pdf', '/fake/path', 100, 'application/pdf', ?)
        """,
        (alice_id,)
    )
    doc_id = cur.lastrowid
    db_conn.commit()

    record = log_audit(
        conn=db_conn,
        action="DOCUMENT_VIEW",
        decision="ALLOWED",
        reason_code="owner_access",
        user_id=alice_id,
        document_id=doc_id,
        details="User alice viewed confidential roadmap",
        ip_address="192.168.1.50"
    )
    db_conn.commit()

    assert record["id"] is not None
    assert record["decision"] == "ALLOWED"
    assert record["reason_code"] == "owner_access"
    assert record["user_id"] == alice_id
    assert record["document_id"] == doc_id
    assert record["current_hash"] is not None


def test_cryptographic_hash_chain_integrity(db_conn, seeded_users):
    """Verify that sequential audit records form a verifiable cryptographic hash chain."""
    alice_id = seeded_users["alice"]["id"]
    bob_id = seeded_users["bob"]["id"]

    # Insert test doc to satisfy foreign key
    cur = db_conn.execute(
        """
        INSERT INTO documents (title, filename, stored_filename, file_path, file_size, mime_type, owner_id)
        VALUES ('Chain Test Doc', 'chain.pdf', 'uuid_chain.pdf', '/fake/path', 100, 'application/pdf', ?)
        """,
        (alice_id,)
    )
    doc_id = cur.lastrowid

    # Log sequential entries
    log_audit(db_conn, "USER_LOGIN", "ALLOWED", "login_success", user_id=alice_id)
    log_audit(db_conn, "DOCUMENT_UPLOAD", "ALLOWED", "owner_access", user_id=alice_id, document_id=doc_id)
    log_audit(db_conn, "DOCUMENT_DOWNLOAD", "DENIED", "no_matching_permission", user_id=bob_id, document_id=doc_id)
    db_conn.commit()

    # Verify chain
    result = verify_audit_integrity(db_conn)
    assert result["valid"] is True
    assert result["total_records"] >= 3


def test_audit_tamper_detection(db_conn, seeded_users):
    """
    CRITICAL AUDIT REQUIREMENT:
    If any record in the audit table is secretly modified or forged,
    the cryptographic verification algorithm MUST detect the tamper and identify the altered ID.
    """
    alice_id = seeded_users["alice"]["id"]

    # Log 3 clean entries
    r1 = log_audit(db_conn, "TEST_ACTION_1", "ALLOWED", "code_1", user_id=alice_id)
    r2 = log_audit(db_conn, "TEST_ACTION_2", "ALLOWED", "code_2", user_id=alice_id)
    r3 = log_audit(db_conn, "TEST_ACTION_3", "ALLOWED", "code_3", user_id=alice_id)
    db_conn.commit()

    # Pre-tamper verification
    assert verify_audit_integrity(db_conn)["valid"] is True

    # Tamper with record r2 in the database (e.g. malicious DBA changes details)
    db_conn.execute(
        "UPDATE audit_logs SET details = 'HACKED_AND_TAMPERED_DETAILS' WHERE id = ?",
        (r2["id"],)
    )
    db_conn.commit()

    # Post-tamper verification must FAIL and pinpoint r2["id"]
    tamper_result = verify_audit_integrity(db_conn)
    assert tamper_result["valid"] is False
    assert tamper_result["broken_at_id"] == r2["id"]
    assert "Data alteration detected" in tamper_result["message"]
