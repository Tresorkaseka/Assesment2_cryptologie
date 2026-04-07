from __future__ import annotations

from uuid import UUID
from typing import Any

from pydantic import BaseModel, Field


class AesEnvelope(BaseModel):
    iv: str = Field(..., description="Base64 encoded 12-byte IV")
    ciphertext: str = Field(..., description="Base64 encoded ciphertext")
    tag: str = Field(..., description="Base64 encoded GCM authentication tag")


class HandshakeRequest(BaseModel):
    client_id: UUID = Field(..., description="Unique client identifier")
    encrypted_session_key: str = Field(..., description="Base64 encoded RSA encrypted AES key")


class HandshakeResponse(BaseModel):
    status: str
    client_id: UUID
    session_id: str
    valid_for_seconds: int


class PublicKeyResponse(BaseModel):
    algorithm: str
    key_size: int
    public_key_pem: str


class MessageResponse(BaseModel):
    status: str
    session_id: str
    client_id: UUID
    received: Any


class ErrorResponse(BaseModel):
    detail: str
