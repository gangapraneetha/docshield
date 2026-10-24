"""
DocShield Authenticated & Scoped WebSocket Manager
Manages real-time WebSocket connections, guarantees strict recipient authorization,
and ensures confidential events or document metadata are never leaked.
"""
import json
import logging
from typing import Dict, Set, Optional, List, Any
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("docshield.websockets")


class ScopedConnectionManager:
    """
    Tracks active WebSocket connections segmented strictly by authenticated user ID.
    Zero global broadcasts of sensitive document events.
    """
    def __init__(self):
        # Maps user_id -> Set of active WebSockets for multi-tab support
        self.active_connections: Dict[int, Set[WebSocket]] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        """Accepts and registers an authenticated user's WebSocket connection."""
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        self.active_connections[user_id].add(websocket)
        logger.debug(f"User {user_id} connected via WebSocket. Active user count: {len(self.active_connections)}")

    def disconnect(self, user_id: int, websocket: WebSocket):
        """Removes a disconnected WebSocket cleanly."""
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
        logger.debug(f"User {user_id} disconnected from WebSocket.")

    async def send_to_user(self, user_id: int, payload: Dict[str, Any]):
        """
        Transmits a real-time event exclusively to the specified user's active sockets.
        Never leaks to other users.
        """
        sockets = self.active_connections.get(user_id, set()).copy()
        if not sockets:
            return

        message_str = json.dumps(payload)
        stale_sockets = []

        for ws in sockets:
            try:
                await ws.send_text(message_str)
            except Exception as e:
                logger.warning(f"Failed to send to user {user_id} socket: {e}")
                stale_sockets.append(ws)

        for stale in stale_sockets:
            self.disconnect(user_id, stale)

    async def send_to_users(self, user_ids: List[int], payload: Dict[str, Any]):
        """
        Sends an event to a strictly authorized list of user IDs.
        """
        for uid in set(user_ids):
            await self.send_to_user(uid, payload)


# Singleton manager instance
ws_manager = ScopedConnectionManager()
