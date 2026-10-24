"""
DocShield Tamper-Evident Audit Logging Module
Implements cryptographic hash chaining (Merkle-style verification) for all
system events and authorization decisions to guarantee non-repudiation.
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

GENESIS_HASH = "0" * 64


def calculate_record_hash(
    prev_hash: str,
    user_id: Optional[int],
    document_id: Optional[int],
    action: str,
    decision: str,
    reason_code: str,
    details: str,
    timestamp: str
) -> str:
    """
    Computes deterministic SHA-256 hash over log data linked to previous record hash.
    """
    payload = f"{prev_hash}|{user_id}|{document_id}|{action}|{decision}|{reason_code}|{details}|{timestamp}"
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def log_audit(
    conn: sqlite3.Connection,
    action: str,
    decision: str,
    reason_code: str,
    user_id: Optional[int] = None,
    document_id: Optional[int] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """
    Appends an immutable, hash-chained record to the audit_logs table.
    Gracefully handles probed/invalid foreign key IDs to preserve strict FK integrity.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    clean_details = details or ""

    # Verify if document_id exists in documents table to satisfy SQLite foreign keys
    actual_doc_id = None
    if document_id is not None:
        row = conn.execute("SELECT 1 FROM documents WHERE id = ?", (document_id,)).fetchone()
        if row:
            actual_doc_id = document_id
        else:
            probed_info = f"[Probed Doc ID: {document_id}]"
            clean_details = f"{clean_details} {probed_info}".strip()

    # Fetch hash of latest record to maintain continuous chain
    last_row = conn.execute(
        "SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()

    prev_hash = last_row["current_hash"] if last_row else GENESIS_HASH
    current_hash = calculate_record_hash(
        prev_hash=prev_hash,
        user_id=user_id,
        document_id=actual_doc_id,
        action=action,
        decision=decision,
        reason_code=reason_code,
        details=clean_details,
        timestamp=timestamp
    )

    cursor = conn.execute(
        """
        INSERT INTO audit_logs (
            user_id, document_id, action, decision, reason_code, details,
            ip_address, prev_hash, current_hash, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            actual_doc_id,
            action,
            decision,
            reason_code,
            clean_details,
            ip_address,
            prev_hash,
            current_hash,
            timestamp
        )
    )

    log_id = cursor.lastrowid
    return {
        "id": log_id,
        "user_id": user_id,
        "document_id": actual_doc_id,
        "action": action,
        "decision": decision,
        "reason_code": reason_code,
        "details": clean_details,
        "ip_address": ip_address,
        "prev_hash": prev_hash,
        "current_hash": current_hash,
        "timestamp": timestamp
    }


def verify_audit_integrity(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Verifies cryptographic hash integrity across the entire audit log chain.
    Pinpoints any unauthorized tampering or row manipulation.
    """
    rows = conn.execute(
        """
        SELECT id, user_id, document_id, action, decision, reason_code,
               details, ip_address, prev_hash, current_hash, timestamp
        FROM audit_logs
        ORDER BY id ASC
        """
    ).fetchall()

    if not rows:
        return {
            "valid": True,
            "total_records": 0,
            "message": "Audit log is empty. Integrity intact."
        }

    expected_prev = GENESIS_HASH
    for index, row in enumerate(rows):
        # 1. Verify link to previous row
        if row["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "broken_at_id": row["id"],
                "index": index,
                "message": (
                    f"Integrity check failed at record ID {row['id']}: "
                    f"prev_hash mismatch. Expected '{expected_prev}', found '{row['prev_hash']}'."
                )
            }

        # 2. Re-compute current hash from contents
        computed_hash = calculate_record_hash(
            prev_hash=row["prev_hash"],
            user_id=row["user_id"],
            document_id=row["document_id"],
            action=row["action"],
            decision=row["decision"],
            reason_code=row["reason_code"],
            details=row["details"] or "",
            timestamp=row["timestamp"]
        )

        if computed_hash != row["current_hash"]:
            return {
                "valid": False,
                "broken_at_id": row["id"],
                "index": index,
                "message": (
                    f"Integrity check failed at record ID {row['id']}: "
                    f"Data alteration detected. Stored hash '{row['current_hash']}' does not match recomputed hash '{computed_hash}'."
                )
            }

        expected_prev = row["current_hash"]

    return {
        "valid": True,
        "total_records": len(rows),
        "latest_hash": expected_prev,
        "message": f"Cryptographic integrity verified. All {len(rows)} records are intact and untampered."
    }
