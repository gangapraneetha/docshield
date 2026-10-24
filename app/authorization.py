"""
DocShield Centralized Explainable Authorization Engine
Implements the core authorize_document() function that evaluates Zero-Trust
permissions, enforces ownership boundaries, and produces an auditable,
explainable decision trace for every document access request.
"""
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import sqlite3


@dataclass
class AuthorizationDecision:
    allowed: bool
    reason: str
    user_id: Optional[int]
    document_id: Optional[int]
    action: str
    message: str
    context: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def authorize_document(
    conn: sqlite3.Connection,
    user_id: Optional[int],
    document_id: Optional[int],
    action: str
) -> AuthorizationDecision:
    """
    Centralized Zero-Trust Authorization Evaluation Function.

    Evaluates:
    1. Authenticated user identity check.
    2. Document existence check (prevents enumeration / IDOR).
    3. Document ownership check (owners have full capabilities).
    4. Owner-only action check (delete, share, revoke require ownership).
    5. Explicit permissions check (view, download).
    6. Permission revocation check.

    Returns a structured, explainable AuthorizationDecision with reason codes.
    """
    action = action.lower().strip()
    
    # 1. Identity Verification
    if not user_id:
        return AuthorizationDecision(
            allowed=False,
            reason="user_not_authenticated",
            user_id=None,
            document_id=document_id,
            action=action,
            message="Access denied: The requesting user is not authenticated.",
            context={"user_id": None, "document_id": document_id, "action": action}
        )

    # 2. Document Existence Check
    doc_row = conn.execute(
        "SELECT id, title, owner_id FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()

    if not doc_row:
        return AuthorizationDecision(
            allowed=False,
            reason="document_not_found",
            user_id=user_id,
            document_id=document_id,
            action=action,
            message=f"Access denied: Document ID {document_id} does not exist or was deleted.",
            context={"user_id": user_id, "document_id": document_id, "action": action}
        )

    owner_id = doc_row["owner_id"]
    doc_title = doc_row["title"]

    # 3. Document Ownership Evaluation
    is_owner = (user_id == owner_id)
    if is_owner:
        return AuthorizationDecision(
            allowed=True,
            reason="owner_access",
            user_id=user_id,
            document_id=document_id,
            action=action,
            message=f"Access granted: User {user_id} is the verified owner of document '{doc_title}'.",
            context={
                "user_id": user_id,
                "document_id": document_id,
                "action": action,
                "is_owner": True
            }
        )

    # 4. Owner-Only Action Restriction
    # Non-owners are never allowed to delete documents, grant new shares, or revoke permissions
    if action in ("delete", "share", "revoke"):
        return AuthorizationDecision(
            allowed=False,
            reason="owner_only_action",
            user_id=user_id,
            document_id=document_id,
            action=action,
            message=f"Access denied: Action '{action}' is restricted exclusively to the document owner.",
            context={
                "user_id": user_id,
                "document_id": document_id,
                "action": action,
                "is_owner": False
            }
        )

    # 5. Check Explicit User Permissions
    # Fetch all permission records for this user & document
    perm_rows = conn.execute(
        """
        SELECT permission_type, is_revoked, granted_at, revoked_at
        FROM permissions
        WHERE document_id = ? AND user_id = ?
        """,
        (document_id, user_id)
    ).fetchall()

    if not perm_rows:
        return AuthorizationDecision(
            allowed=False,
            reason="no_matching_permission",
            user_id=user_id,
            document_id=document_id,
            action=action,
            message=f"Access denied: No permission record exists for user {user_id} on document '{doc_title}'.",
            context={"user_id": user_id, "document_id": document_id, "action": action}
        )

    # Map existing permission types and revocation state
    matching_perms = [p for p in perm_rows if p["permission_type"] == action]

    # If action is 'download' but user only has 'view', or vice-versa
    if not matching_perms:
        # Check if they have an active 'view' but asked to 'download' or vice versa
        active_other = [p["permission_type"] for p in perm_rows if p["is_revoked"] == 0]
        return AuthorizationDecision(
            allowed=False,
            reason="no_matching_permission",
            user_id=user_id,
            document_id=document_id,
            action=action,
            message=(
                f"Access denied: Requested action '{action}' is not granted to user {user_id}. "
                f"Active permissions: {active_other if active_other else 'None'}."
            ),
            context={
                "user_id": user_id,
                "document_id": document_id,
                "action": action,
                "available_permissions": active_other
            }
        )

    target_perm = matching_perms[0]

    # 6. Check Revocation Status
    if target_perm["is_revoked"] == 1:
        return AuthorizationDecision(
            allowed=False,
            reason="permission_revoked",
            user_id=user_id,
            document_id=document_id,
            action=action,
            message=f"Access denied: User {user_id}'s '{action}' permission on '{doc_title}' was explicitly revoked at {target_perm['revoked_at']}.",
            context={
                "user_id": user_id,
                "document_id": document_id,
                "action": action,
                "revoked_at": target_perm["revoked_at"]
            }
        )

    # 7. Explicit Granted Permission
    reason_code = f"explicit_{action}_permission"
    return AuthorizationDecision(
        allowed=True,
        reason=reason_code,
        user_id=user_id,
        document_id=document_id,
        action=action,
        message=f"Access granted: User {user_id} possesses active '{action}' permission on '{doc_title}'.",
        context={
            "user_id": user_id,
            "document_id": document_id,
            "action": action,
            "granted_at": target_perm["granted_at"]
        }
    )
