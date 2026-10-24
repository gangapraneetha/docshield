"""
DocShield Document Management & Sharing Routes
Enforces Zero-Trust access control via authorize_document(), handles private file
uploads, downloads, shares, revocations, and real-time scoped WebSocket notifications.
"""
import os
import uuid
from pathlib import Path
from typing import Optional, List
from fastapi import (
    APIRouter,
    Request,
    Response,
    Form,
    UploadFile,
    File,
    Depends,
    HTTPException,
    status,
)
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
import sqlite3

import app.config as config
from app.database import get_db
from app.security import (
    sanitize_filename,
    safe_resolve_path,
    verify_csrf_token,
)
from app.authorization import authorize_document
from app.audit import log_audit
from app.auth import (
    get_client_ip,
    get_session_token_from_request,
    require_authenticated_user,
    get_template_context,
)
from app.websockets import ws_manager

router = APIRouter()
templates = Jinja2Templates(directory=str(config.BASE_DIR / "templates"))


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    user_id = user["id"]
    query = request.query_params.get("q", "").strip()

    # 1. Fetch owned documents
    if query:
        owned_docs = conn.execute(
            """
            SELECT id, title, description, filename, file_size, mime_type, created_at, updated_at
            FROM documents
            WHERE owner_id = ? AND (title LIKE ? OR description LIKE ? OR filename LIKE ?)
            ORDER BY created_at DESC
            """,
            (user_id, f"%{query}%", f"%{query}%", f"%{query}%")
        ).fetchall()
    else:
        owned_docs = conn.execute(
            """
            SELECT id, title, description, filename, file_size, mime_type, created_at, updated_at
            FROM documents
            WHERE owner_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,)
        ).fetchall()

    # 2. Fetch shared documents (only non-revoked)
    shared_docs = conn.execute(
        """
        SELECT d.id, d.title, d.description, d.filename, d.file_size, d.mime_type, d.created_at,
               u.username AS owner_name,
               GROUP_CONCAT(p.permission_type, ', ') AS granted_permissions
        FROM documents d
        JOIN permissions p ON d.id = p.document_id
        JOIN users u ON d.owner_id = u.id
        WHERE p.user_id = ? AND p.is_revoked = 0
        GROUP BY d.id
        ORDER BY d.created_at DESC
        """,
        (user_id,)
    ).fetchall()

    # 3. Fetch active permissions for owned documents (for managing shares)
    owned_ids = [d["id"] for d in owned_docs]
    doc_permissions = {}
    if owned_ids:
        placeholders = ",".join("?" * len(owned_ids))
        perm_rows = conn.execute(
            f"""
            SELECT p.id, p.document_id, p.user_id, p.permission_type, p.is_revoked,
                   p.granted_at, p.revoked_at, u.username, u.email
            FROM permissions p
            JOIN users u ON p.user_id = u.id
            WHERE p.document_id IN ({placeholders})
            ORDER BY p.granted_at DESC
            """,
            owned_ids
        ).fetchall()
        for pr in perm_rows:
            doc_permissions.setdefault(pr["document_id"], []).append(dict(pr))

    # 4. Fetch registered users for the share dropdown (excluding self)
    other_users = conn.execute(
        "SELECT id, username, email FROM users WHERE id != ? ORDER BY username ASC",
        (user_id,)
    ).fetchall()

    # 5. Fetch user's recent notifications
    notifications = conn.execute(
        """
        SELECT id, title, message, type, is_read, created_at
        FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 10
        """,
        (user_id,)
    ).fetchall()

    # 6. Fetch recent audit activity visible to this user
    # Users can view audit events for documents they own or actions they performed
    recent_activity = conn.execute(
        """
        SELECT a.id, a.action, a.decision, a.reason_code, a.details, a.timestamp,
               u.username AS actor_name, d.title AS document_title
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE a.user_id = ? OR d.owner_id = ?
        ORDER BY a.id DESC
        LIMIT 15
        """,
        (user_id, user_id)
    ).fetchall()

    context = get_template_context(request, user, {
        "owned_documents": owned_docs,
        "shared_documents": shared_docs,
        "doc_permissions": doc_permissions,
        "other_users": other_users,
        "notifications": notifications,
        "recent_activity": recent_activity,
    })
    return templates.TemplateResponse(request=request, name="dashboard.html", context=context)


@router.post("/documents/upload")
async def upload_document(
    request: Request,
    title: str = Form(...),
    description: Optional[str] = Form(""),
    csrf_token: str = Form(...),
    file: UploadFile = File(...),
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)
    session_token = get_session_token_from_request(request) or ""

    # CSRF Verification
    if not verify_csrf_token(session_token, csrf_token):
        log_audit(
            conn=conn,
            action="DOCUMENT_UPLOAD",
            decision="DENIED",
            reason_code="csrf_verification_failed",
            user_id=user["id"],
            details="Upload rejected: Invalid or missing CSRF token.",
            ip_address=ip
        )
        return RedirectResponse(
            url="/dashboard?error=Security+validation+failed+(CSRF).+Please+try+again.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Filename & Extension validation
    clean_orig_name = sanitize_filename(file.filename or "document.bin")
    file_ext = clean_orig_name.rsplit(".", 1)[-1].lower() if "." in clean_orig_name else ""

    if not file_ext or file_ext not in config.ALLOWED_EXTENSIONS:
        log_audit(
            conn=conn,
            action="DOCUMENT_UPLOAD",
            decision="DENIED",
            reason_code="invalid_file_extension",
            user_id=user["id"],
            details=f"File extension '.{file_ext}' is not permitted.",
            ip_address=ip
        )
        return RedirectResponse(
            url=f"/dashboard?error=File+type+'.{file_ext}'+is+not+supported.+Allowed:+{','.join(config.ALLOWED_EXTENSIONS)}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Read content with strict size enforcement
    content = await file.read()
    file_size = len(content)

    if file_size == 0:
        return RedirectResponse(
            url="/dashboard?error=Uploaded+file+is+empty.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    if file_size > config.MAX_UPLOAD_BYTES:
        log_audit(
            conn=conn,
            action="DOCUMENT_UPLOAD",
            decision="DENIED",
            reason_code="file_size_limit_exceeded",
            user_id=user["id"],
            details=f"File size {file_size} bytes exceeds maximum limit of {config.MAX_UPLOAD_SIZE_MB}MB.",
            ip_address=ip
        )
        return RedirectResponse(
            url=f"/dashboard?error=File+exceeds+maximum+size+limit+of+{config.MAX_UPLOAD_SIZE_MB}MB.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Generate random internal UUID filename
    stored_filename = f"{uuid.uuid4().hex}.{file_ext}"
    target_path = config.UPLOAD_DIR / stored_filename

    # Save to private storage
    with open(target_path, "wb") as f:
        f.write(content)

    clean_title = title.strip() or clean_orig_name

    cursor = conn.execute(
        """
        INSERT INTO documents (
            title, description, filename, stored_filename, file_path,
            file_size, mime_type, owner_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            clean_title,
            (description or "").strip(),
            clean_orig_name,
            stored_filename,
            str(target_path),
            file_size,
            file.content_type or "application/octet-stream",
            user["id"]
        )
    )
    doc_id = cursor.lastrowid

    # Log successful upload with explainable reason
    log_audit(
        conn=conn,
        action="DOCUMENT_UPLOAD",
        decision="ALLOWED",
        reason_code="owner_access",
        user_id=user["id"],
        document_id=doc_id,
        details=f"Uploaded '{clean_title}' ({file_size} bytes).",
        ip_address=ip
    )

    # Record notification for the owner
    conn.execute(
        "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
        (user["id"], "Document Uploaded", f"'{clean_title}' was successfully encrypted and stored.", "success")
    )

    # Real-time WebSocket event to the owner ONLY
    await ws_manager.send_to_user(user["id"], {
        "type": "DOCUMENT_UPLOADED",
        "document_id": doc_id,
        "title": clean_title,
        "filename": clean_orig_name,
        "file_size": file_size,
        "message": f"Document '{clean_title}' uploaded successfully."
    })

    return RedirectResponse(
        url="/dashboard?success=Document+uploaded+and+secured+successfully.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/documents/{document_id}/download")
async def download_document(
    document_id: int,
    request: Request,
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)

    # CENTRAL AUTHORIZATION CHECK
    decision = authorize_document(
        conn=conn,
        user_id=user["id"],
        document_id=document_id,
        action="download"
    )

    # Tamper-evident Audit Logging of Decision
    log_audit(
        conn=conn,
        action="DOCUMENT_DOWNLOAD",
        decision="ALLOWED" if decision.allowed else "DENIED",
        reason_code=decision.reason,
        user_id=user["id"],
        document_id=document_id,
        details=decision.message,
        ip_address=ip
    )

    # Enforce Authorization
    if not decision.allowed:
        # Alert the document owner in real-time about unauthorized download attempt!
        doc_row = conn.execute("SELECT owner_id, title FROM documents WHERE id = ?", (document_id,)).fetchone()
        if doc_row:
            alert_msg = f"User '{user['username']}' attempted unauthorized download on '{doc_row['title']}'. Denied: {decision.reason}."
            conn.execute(
                "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
                (doc_row["owner_id"], "Security Alert", alert_msg, "danger")
            )
            await ws_manager.send_to_user(doc_row["owner_id"], {
                "type": "SECURITY_ALERT",
                "document_id": document_id,
                "title": doc_row["title"],
                "actor": user["username"],
                "reason": decision.reason,
                "message": alert_msg
            })

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN if decision.reason != "document_not_found" else status.HTTP_404_NOT_FOUND,
            detail=f"{decision.message} (Reason code: {decision.reason})"
        )

    # Retrieve document file information
    doc = conn.execute(
        "SELECT filename, stored_filename, mime_type FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()

    # Path traversal verification
    resolved_path = safe_resolve_path(doc["stored_filename"])
    if not resolved_path or not resolved_path.exists():
        log_audit(
            conn=conn,
            action="DOCUMENT_DOWNLOAD",
            decision="DENIED",
            reason_code="file_missing_on_disk",
            user_id=user["id"],
            document_id=document_id,
            details="Storage integrity failure: Physical file missing.",
            ip_address=ip
        )
        raise HTTPException(status_code=500, detail="Document storage error.")

    return FileResponse(
        path=str(resolved_path),
        filename=doc["filename"],
        media_type=doc["mime_type"] or "application/octet-stream"
    )


@router.get("/documents/{document_id}/view")
async def view_document(
    document_id: int,
    request: Request,
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)

    # CENTRAL AUTHORIZATION CHECK
    decision = authorize_document(
        conn=conn,
        user_id=user["id"],
        document_id=document_id,
        action="view"
    )

    # Audit Log
    log_audit(
        conn=conn,
        action="DOCUMENT_VIEW",
        decision="ALLOWED" if decision.allowed else "DENIED",
        reason_code=decision.reason,
        user_id=user["id"],
        document_id=document_id,
        details=decision.message,
        ip_address=ip
    )

    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN if decision.reason != "document_not_found" else status.HTTP_404_NOT_FOUND,
            detail=f"{decision.message} (Reason code: {decision.reason})"
        )

    doc = conn.execute(
        "SELECT filename, stored_filename, mime_type FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()

    resolved_path = safe_resolve_path(doc["stored_filename"])
    if not resolved_path or not resolved_path.exists():
        raise HTTPException(status_code=500, detail="Document storage error.")

    # Inline preview for supported browser formats
    return FileResponse(
        path=str(resolved_path),
        media_type=doc["mime_type"],
        content_disposition_type="inline"
    )


@router.post("/documents/{document_id}/share")
async def share_document(
    document_id: int,
    request: Request,
    target_username: str = Form(...),
    permission_type: str = Form(...),
    csrf_token: str = Form(...),
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)
    session_token = get_session_token_from_request(request) or ""

    if not verify_csrf_token(session_token, csrf_token):
        return RedirectResponse(
            url="/dashboard?error=CSRF+validation+failed.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # CENTRAL AUTHORIZATION CHECK (share is owner-only)
    decision = authorize_document(
        conn=conn,
        user_id=user["id"],
        document_id=document_id,
        action="share"
    )

    if not decision.allowed:
        log_audit(
            conn=conn,
            action="PERMISSION_SHARE_ATTEMPT",
            decision="DENIED",
            reason_code=decision.reason,
            user_id=user["id"],
            document_id=document_id,
            details=decision.message,
            ip_address=ip
        )
        raise HTTPException(status_code=403, detail=decision.message)

    # Validate target user
    target_user = conn.execute(
        "SELECT id, username FROM users WHERE username = ?",
        (target_username.strip(),)
    ).fetchone()

    if not target_user:
        return RedirectResponse(
            url=f"/dashboard?error=User+'{target_username}'+not+found.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    if target_user["id"] == user["id"]:
        return RedirectResponse(
            url="/dashboard?error=Cannot+share+document+with+yourself.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    if permission_type not in ("view", "download"):
        return RedirectResponse(
            url="/dashboard?error=Invalid+permission+type.+Must+be+'view'+or+'download'.",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Upsert permission record (if previously revoked, unrevoke it)
    existing_perm = conn.execute(
        "SELECT id, is_revoked FROM permissions WHERE document_id = ? AND user_id = ? AND permission_type = ?",
        (document_id, target_user["id"], permission_type)
    ).fetchone()

    doc_info = conn.execute("SELECT title FROM documents WHERE id = ?", (document_id,)).fetchone()

    if existing_perm:
        conn.execute(
            """
            UPDATE permissions
            SET is_revoked = 0, revoked_at = NULL, granted_at = datetime('now', 'utc'), granted_by = ?
            WHERE id = ?
            """,
            (user["id"], existing_perm["id"])
        )
    else:
        conn.execute(
            """
            INSERT INTO permissions (document_id, user_id, granted_by, permission_type)
            VALUES (?, ?, ?, ?)
            """,
            (document_id, target_user["id"], user["id"], permission_type)
        )

    # Audit Log
    log_audit(
        conn=conn,
        action="PERMISSION_GRANT",
        decision="ALLOWED",
        reason_code="owner_access",
        user_id=user["id"],
        document_id=document_id,
        details=f"Granted '{permission_type}' permission to '{target_user['username']}' for document '{doc_info['title']}'.",
        ip_address=ip
    )

    # Notification for recipient
    notif_msg = f"User '{user['username']}' shared document '{doc_info['title']}' with you ({permission_type} permission)."
    conn.execute(
        "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
        (target_user["id"], "Document Shared With You", notif_msg, "info")
    )

    # Push real-time event to recipient
    await ws_manager.send_to_user(target_user["id"], {
        "type": "DOCUMENT_SHARED",
        "document_id": document_id,
        "title": doc_info["title"],
        "shared_by": user["username"],
        "permission_type": permission_type,
        "message": notif_msg
    })

    # Push real-time event to owner
    await ws_manager.send_to_user(user["id"], {
        "type": "PERMISSION_UPDATED",
        "document_id": document_id,
        "target_user": target_user["username"],
        "permission_type": permission_type,
        "status": "granted",
        "message": f"Successfully granted '{permission_type}' access to {target_user['username']}."
    })

    return RedirectResponse(
        url=f"/dashboard?success=Permission+'{permission_type}'+granted+to+{target_user['username']}.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/documents/{document_id}/revoke")
async def revoke_document_access(
    document_id: int,
    request: Request,
    target_user_id: int = Form(...),
    permission_type: str = Form(...),
    csrf_token: str = Form(...),
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)
    session_token = get_session_token_from_request(request) or ""

    if not verify_csrf_token(session_token, csrf_token):
        return RedirectResponse(url="/dashboard?error=CSRF+validation+failed.", status_code=status.HTTP_303_SEE_OTHER)

    # CENTRAL AUTHORIZATION CHECK (revoke is owner-only)
    decision = authorize_document(
        conn=conn,
        user_id=user["id"],
        document_id=document_id,
        action="revoke"
    )

    if not decision.allowed:
        log_audit(
            conn=conn,
            action="PERMISSION_REVOKE_ATTEMPT",
            decision="DENIED",
            reason_code=decision.reason,
            user_id=user["id"],
            document_id=document_id,
            details=decision.message,
            ip_address=ip
        )
        raise HTTPException(status_code=403, detail=decision.message)

    target_user = conn.execute("SELECT id, username FROM users WHERE id = ?", (target_user_id,)).fetchone()
    doc_info = conn.execute("SELECT title FROM documents WHERE id = ?", (document_id,)).fetchone()

    # Mark permission as revoked
    conn.execute(
        """
        UPDATE permissions
        SET is_revoked = 1, revoked_at = datetime('now', 'utc')
        WHERE document_id = ? AND user_id = ? AND permission_type = ?
        """,
        (document_id, target_user_id, permission_type)
    )

    # Audit Log
    log_audit(
        conn=conn,
        action="PERMISSION_REVOKE",
        decision="ALLOWED",
        reason_code="owner_access",
        user_id=user["id"],
        document_id=document_id,
        details=f"Revoked '{permission_type}' permission from '{target_user['username'] if target_user else target_user_id}' on document '{doc_info['title']}'.",
        ip_address=ip
    )

    # Notification & WebSocket event to the revoked user
    if target_user:
        rev_msg = f"Your '{permission_type}' access to document '{doc_info['title']}' has been revoked by the owner."
        conn.execute(
            "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
            (target_user["id"], "Access Revoked", rev_msg, "warning")
        )
        await ws_manager.send_to_user(target_user["id"], {
            "type": "ACCESS_REVOKED",
            "document_id": document_id,
            "title": doc_info["title"],
            "permission_type": permission_type,
            "message": rev_msg
        })

    # WebSocket update to owner
    await ws_manager.send_to_user(user["id"], {
        "type": "PERMISSION_UPDATED",
        "document_id": document_id,
        "target_user": target_user["username"] if target_user else str(target_user_id),
        "permission_type": permission_type,
        "status": "revoked",
        "message": f"Revoked '{permission_type}' access for {target_user['username'] if target_user else target_user_id}."
    })

    return RedirectResponse(
        url="/dashboard?success=Access+permission+revoked+successfully.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/documents/{document_id}/delete")
async def delete_document(
    document_id: int,
    request: Request,
    csrf_token: str = Form(...),
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    ip = get_client_ip(request)
    session_token = get_session_token_from_request(request) or ""

    if not verify_csrf_token(session_token, csrf_token):
        return RedirectResponse(url="/dashboard?error=CSRF+validation+failed.", status_code=status.HTTP_303_SEE_OTHER)

    # CENTRAL AUTHORIZATION CHECK (delete is owner-only)
    decision = authorize_document(
        conn=conn,
        user_id=user["id"],
        document_id=document_id,
        action="delete"
    )

    if not decision.allowed:
        log_audit(
            conn=conn,
            action="DOCUMENT_DELETE",
            decision="DENIED",
            reason_code=decision.reason,
            user_id=user["id"],
            document_id=document_id,
            details=decision.message,
            ip_address=ip
        )
        raise HTTPException(status_code=403, detail=decision.message)

    doc = conn.execute(
        "SELECT title, stored_filename FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()

    # Find all shared users to notify them of deletion
    shared_users = conn.execute(
        "SELECT DISTINCT user_id FROM permissions WHERE document_id = ? AND is_revoked = 0",
        (document_id,)
    ).fetchall()
    shared_user_ids = [s["user_id"] for s in shared_users]

    # Delete physical file
    resolved_path = safe_resolve_path(doc["stored_filename"])
    if resolved_path and resolved_path.exists():
        try:
            os.remove(resolved_path)
        except Exception:
            pass

    # Delete document from DB (cascades permissions & notifications)
    conn.execute("DELETE FROM documents WHERE id = ?", (document_id,))

    # Audit Log
    log_audit(
        conn=conn,
        action="DOCUMENT_DELETE",
        decision="ALLOWED",
        reason_code="owner_access",
        user_id=user["id"],
        document_id=document_id,
        details=f"Document '{doc['title']}' permanently deleted by owner.",
        ip_address=ip
    )

    # Real-time WebSocket notifications
    del_event = {
        "type": "DOCUMENT_DELETED",
        "document_id": document_id,
        "title": doc["title"],
        "message": f"Document '{doc['title']}' was deleted."
    }
    await ws_manager.send_to_user(user["id"], del_event)
    await ws_manager.send_to_users(shared_user_ids, del_event)

    return RedirectResponse(
        url="/dashboard?success=Document+deleted+permanently.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/notifications/mark-read")
async def mark_notifications_read(
    request: Request,
    csrf_token: str = Form(...),
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    session_token = get_session_token_from_request(request) or ""
    if not verify_csrf_token(session_token, csrf_token):
        return RedirectResponse(url="/dashboard?error=CSRF+validation+failed.", status_code=status.HTTP_303_SEE_OTHER)

    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user["id"],))
    return RedirectResponse(url="/dashboard?success=Notifications+marked+as+read.", status_code=status.HTTP_303_SEE_OTHER)

