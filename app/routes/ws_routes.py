"""
DocShield WebSocket Connection Endpoint
Authenticates WebSocket connections using signed session cookies,
registers connections in the ScopedConnectionManager, and handles disconnects.
"""
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.config import COOKIE_NAME
from app.security import verify_session_token
from app.websockets import ws_manager

router = APIRouter()
logger = logging.getLogger("docshield.ws_routes")


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # 1. Authenticate via Session Cookie
    token = websocket.cookies.get(COOKIE_NAME)
    
    # Alternatively check query parameter for environments where cookies are restricted in WS handshake
    if not token:
        token = websocket.query_params.get("token")

    payload = verify_session_token(token) if token else None

    if not payload:
        logger.warning("Unauthenticated WebSocket connection attempt rejected.")
        await websocket.close(code=4401, reason="Unauthorized")
        return

    user_id = payload.get("user_id")
    await ws_manager.connect(user_id, websocket)

    try:
        # Keepalive loop: wait for messages or pings
        while True:
            data = await websocket.receive_text()
            # Client can send heartbeat pings: {"type": "ping"}
            if data == "ping" or '"ping"' in data:
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(user_id, websocket)
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        ws_manager.disconnect(user_id, websocket)
