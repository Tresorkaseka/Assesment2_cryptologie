from __future__ import annotations

import json
import logging
from typing import Awaitable, Callable

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from shared.crypto import aes_decrypt
from server.app.session_store import SessionStore

logger = logging.getLogger("rsa_handshake")


class SessionEnvelopeMiddleware:
    def __init__(self, app: ASGIApp, session_store: SessionStore, exempt_paths: set[str] | None = None) -> None:
        self.app = app
        self.session_store = session_store
        self.exempt_paths = exempt_paths or {"/public-key", "/handshake", "/docs", "/openapi.json", "/redoc"}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        session_id = headers.get("x-session-id")
        if not session_id:
            logger.warning("Unauthenticated request rejected: missing X-Session-ID on %s", path)
            await self._reject(send, 401, "Missing X-Session-ID")
            return

        session = self.session_store.get(session_id)
        if session is None:
            logger.warning("Unauthenticated request rejected: invalid session %s on %s", session_id, path)
            await self._reject(send, 401, "Invalid or expired session")
            return

        body = await self._read_body(receive)
        if body:
            try:
                payload = json.loads(body.decode("utf-8"))
                plaintext = aes_decrypt(session.aes_key, payload, aad=session.session_id.encode("utf-8"))
            except Exception as exc:  # noqa: BLE001
                logger.warning("Encrypted body rejected for session %s on %s: %s", session_id, path, exc)
                await self._reject(send, 400, "Unable to decrypt message body")
                return
        else:
            plaintext = b""

        scope.setdefault("state", {})
        scope["state"]["session"] = session
        scope["state"]["decrypted_body"] = plaintext

        async def wrapped_receive() -> dict[str, object]:
            nonlocal plaintext
            if plaintext is not None:
                data = plaintext
                plaintext = None
                return {"type": "http.request", "body": data, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, wrapped_receive, send)

    async def _read_body(self, receive: Receive) -> bytes:
        chunks: list[bytes] = []
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                continue
            chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)
        return b"".join(chunks)

    async def _reject(self, send: Send, status_code: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        await send({"type": "http.response.start", "status": status_code, "headers": headers})
        await send({"type": "http.response.body", "body": body})

