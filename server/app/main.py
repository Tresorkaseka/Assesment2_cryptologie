from __future__ import annotations

from contextlib import asynccontextmanager
import json
import logging
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request

from shared.crypto import b64decode
from shared.schemas import HandshakeRequest, HandshakeResponse, MessageResponse, PublicKeyResponse
from server.app.config import ServerSettings, load_settings
from server.app.middleware import SessionEnvelopeMiddleware
from server.app.security import ServerKeyManager
from server.app.session_store import SessionStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("rsa_handshake")


def create_app(settings: ServerSettings | None = None) -> FastAPI:
    settings = settings or load_settings()
    key_manager = ServerKeyManager(settings.key_dir)
    session_store = SessionStore()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        keypair = key_manager.ensure_keypair()
        app.state.keypair = keypair
        logger.info("RSA keypair ready in %s", settings.key_dir)
        yield

    app = FastAPI(title="RSA Handshake Secure API", version="1.0.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.key_manager = key_manager
    app.state.session_store = session_store

    app.add_middleware(SessionEnvelopeMiddleware, session_store=session_store)

    @app.get("/public-key", response_model=PublicKeyResponse)
    def public_key(request: Request) -> PublicKeyResponse:
        keypair = _get_keypair(request)
        return PublicKeyResponse(
            algorithm="RSA",
            key_size=2048,
            public_key_pem=keypair.public_pem.decode("utf-8"),
        )

    @app.post("/handshake", response_model=HandshakeResponse)
    def handshake(request: Request, payload: HandshakeRequest) -> HandshakeResponse:
        keypair = _get_keypair(request)
        try:
            encrypted_session_key = b64decode(payload.encrypted_session_key)
            session_key = key_manager.decrypt_session_key(encrypted_session_key, keypair)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"Invalid encrypted session key: {exc}") from exc

        if len(session_key) != 32:
            raise HTTPException(status_code=400, detail="Session key must be 32 bytes for AES-256")

        session_id = str(uuid4())
        session_store.create(payload.client_id, session_id, session_key, settings.session_ttl_seconds)
        return HandshakeResponse(
            status="ok",
            client_id=payload.client_id,
            session_id=session_id,
            valid_for_seconds=settings.session_ttl_seconds,
        )

    @app.post("/message", response_model=MessageResponse)
    async def message(request: Request) -> MessageResponse:
        session = request.state.session
        body = await request.body()
        if not body:
            raise HTTPException(status_code=400, detail="Missing decrypted message body")
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Decrypted body is not valid JSON") from exc

        return MessageResponse(
            status="ok",
            session_id=session.session_id,
            client_id=session.client_id,
            received=data,
        )

    return app


def _get_keypair(request: Request):
    keypair = getattr(request.app.state, "keypair", None)
    if keypair is None:
        raise HTTPException(status_code=503, detail="Keypair not ready")
    return keypair


app = create_app()
