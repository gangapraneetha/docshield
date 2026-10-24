"""
DocShield Audit Trail & Cryptographic Verification Routes
Provides transparent viewing and cryptographic hash verification of all
authorization decisions and system actions for non-repudiation.
"""
from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import sqlite3

from app.config import BASE_DIR
from app.database import get_db
from app.auth import require_authenticated_user, get_template_context
from app.audit import verify_audit_integrity

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    action_filter = request.query_params.get("action", "").strip()
    decision_filter = request.query_params.get("decision", "").strip().upper()

    query = """
        SELECT a.id, a.user_id, a.document_id, a.action, a.decision, a.reason_code,
               a.details, a.ip_address, a.prev_hash, a.current_hash, a.timestamp,
               u.username AS actor_name, d.title AS document_title
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        LEFT JOIN documents d ON a.document_id = d.id
        WHERE 1=1
    """
    params = []

    if action_filter:
        query += " AND a.action = ?"
        params.append(action_filter)

    if decision_filter in ("ALLOWED", "DENIED"):
        query += " AND a.decision = ?"
        params.append(decision_filter)

    query += " ORDER BY a.id DESC LIMIT 100"

    logs = conn.execute(query, params).fetchall()

    # Perform full cryptographic chain verification
    integrity = verify_audit_integrity(conn)

    # Distinct actions for filter dropdown
    distinct_actions = [
        r["action"] for r in conn.execute(
            "SELECT DISTINCT action FROM audit_logs ORDER BY action ASC"
        ).fetchall()
    ]

    context = get_template_context(request, user, {
        "logs": logs,
        "integrity": integrity,
        "distinct_actions": distinct_actions,
        "selected_action": action_filter,
        "selected_decision": decision_filter,
    })
    return templates.TemplateResponse(request=request, name="audit.html", context=context)


@router.get("/api/audit/verify")
async def verify_audit_api(
    user: dict = Depends(require_authenticated_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    """API endpoint to cryptographically verify hash chain integrity on demand."""
    integrity = verify_audit_integrity(conn)
    return JSONResponse(content=integrity)
