"""
Tests for WebSocket Authentication and Event Recipient Authorization
"""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from app.websockets import ScopedConnectionManager
from app.security import create_session_token
import app.config as config
from main import app


def test_websocket_unauthenticated_connection_rejected():
    """Unauthenticated WebSocket connections must be closed immediately."""
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws"):
            pass
    assert exc_info.value.code == 4401


def test_websocket_authenticated_connection_accepted(seeded_users):
    """Authenticated WebSocket connection with valid session cookie connects successfully."""
    client = TestClient(app)
    alice_id = seeded_users["alice"]["id"]
    token = create_session_token(alice_id, "alice")
    client.cookies.set(config.COOKIE_NAME, token)

    with client.websocket_connect("/ws") as ws:
        # Send heartbeat ping
        ws.send_text('{"type": "ping"}')
        data = ws.receive_text()
        assert "pong" in data


@pytest.mark.asyncio
async def test_websocket_event_isolation_and_no_leakage():
    """
    CRITICAL REAL-TIME REQUIREMENT:
    Ensure confidential events sent to User Alice are NEVER delivered to User Bob.
    ScopedConnectionManager guarantees zero-leakage event distribution.
    """
    mgr = ScopedConnectionManager()

    class MockWebSocket:
        def __init__(self):
            self.messages = []
            self.accepted = False

        async def accept(self):
            self.accepted = True

        async def send_text(self, text):
            self.messages.append(text)

    ws_alice = MockWebSocket()
    ws_bob = MockWebSocket()

    # Register Alice (user_id=101) and Bob (user_id=102)
    await mgr.connect(user_id=101, websocket=ws_alice)
    await mgr.connect(user_id=102, websocket=ws_bob)

    # Transmit a confidential security event intended ONLY for Alice
    await mgr.send_to_user(101, {
        "type": "SECURITY_ALERT",
        "title": "Top Secret Financials",
        "message": "Confidential Event for Alice Only"
    })

    # Assert Alice received the message
    assert len(ws_alice.messages) == 1
    assert "Top Secret Financials" in ws_alice.messages[0]

    # Assert Bob received ZERO messages (absolute recipient isolation)
    assert len(ws_bob.messages) == 0

    # Test disconnection cleanup
    mgr.disconnect(101, ws_alice)
    assert 101 not in mgr.active_connections
