"""
DocShield - Main Application Entrypoint
FastAPI web application implementing Zero-Trust explainable authorization,
private document vault, hash-chained audit trails, and scoped real-time WebSockets.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import BASE_DIR, APP_NAME, DEBUG
from app.database import init_db, db_context, get_db
from app.security import hash_password
from app.auth import get_current_user_optional, get_template_context
from app.routes.auth_routes import router as auth_router
from app.routes.doc_routes import router as doc_router
from app.routes.audit_routes import router as audit_router
from app.routes.ws_routes import router as ws_router


def seed_demo_data():
    """Seeds initial demonstration users if the database is brand new."""
    with db_context() as conn:
        count = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()["count"]
        if count == 0:
            demo_users = [
                ("alice", "alice@docshield.local", "Password123!"),
                ("bob", "bob@docshield.local", "Password123!"),
                ("charlie", "charlie@docshield.local", "Password123!")
            ]
            for username, email, pwd in demo_users:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, hash_password(pwd))
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    
    init_db()
    seed_demo_data()
    yield


app = FastAPI(
    title=APP_NAME,
    description="Zero-Trust Explainable Document Management System with Tamper-Evident Audit Trails",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if DEBUG else None,
    redoc_url=None
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(auth_router)
app.include_router(doc_router)
app.include_router(audit_router)
app.include_router(ws_router)

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root route: redirect to dashboard if authenticated, else login."""
    with db_context() as conn:
        user = get_current_user_optional(request, conn)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        with db_context() as conn:
            user = get_current_user_optional(request, conn)
        return templates.TemplateResponse(
            request=request,
            name="404.html",
            context=get_template_context(request, user, {"detail": str(exc.detail) if hasattr(exc, "detail") else "Resource Not Found"}),
            status_code=404
        )
    return JSONResponse(status_code=404, content={"error": "Not Found", "detail": str(exc.detail) if hasattr(exc, "detail") else "Not found"})


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc):
    accept = request.headers.get("accept", "")
    detail = str(exc.detail) if hasattr(exc, "detail") else "Access Denied by Policy Engine"
    if "text/html" in accept:
        with db_context() as conn:
            user = get_current_user_optional(request, conn)
        return templates.TemplateResponse(
            request=request,
            name="403.html",
            context=get_template_context(request, user, {"detail": detail}),
            status_code=403
        )
    return JSONResponse(status_code=403, content={"error": "Forbidden", "detail": detail})


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        return HTMLResponse(
            "<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;padding:50px;'>"
            "<h1>500 - Internal Server Error</h1>"
            "<p>An unexpected error occurred. It has been safely captured without leaking system details.</p>"
            "<a href='/dashboard'>Return to Dashboard</a>"
            "</body></html>",
            status_code=500
        )
    return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
