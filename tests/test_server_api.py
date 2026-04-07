from fastapi.testclient import TestClient
from uuid import uuid4

from server.app.main import create_app
from shared.crypto import aes_encrypt, b64encode, generate_aes_key, rsa_encrypt
from shared.schemas import HandshakeRequest


def test_public_key_and_handshake_and_message(tmp_path) -> None:
    app = create_app()
    app.state.settings.key_dir = tmp_path
    app.state.key_manager.key_dir = tmp_path
    with TestClient(app) as client:
        public_key = client.get("/public-key")
        assert public_key.status_code == 200
        pem = public_key.json()["public_key_pem"]
        assert "BEGIN PUBLIC KEY" in pem

        from cryptography.hazmat.primitives import serialization

        public_obj = serialization.load_pem_public_key(pem.encode("utf-8"))
        aes_key = generate_aes_key()
        encrypted_session_key = rsa_encrypt(public_obj, aes_key)
        handshake = client.post(
            "/handshake",
            json=HandshakeRequest(client_id=uuid4(), encrypted_session_key=b64encode(encrypted_session_key)).model_dump(mode="json"),
        )
        assert handshake.status_code == 200
        session_id = handshake.json()["session_id"]

        envelope = aes_encrypt(aes_key, b'{"message":"hello"}', aad=session_id.encode("utf-8"))
        message = client.post("/message", headers={"X-Session-ID": session_id}, json=envelope)
        assert message.status_code == 200
        assert message.json()["received"]["message"] == "hello"


def test_message_requires_session() -> None:
    app = create_app()
    with TestClient(app) as client:
        response = client.post("/message", json={"iv": "a", "ciphertext": "b", "tag": "c"})
        assert response.status_code == 401


def test_tampered_payload_is_rejected(tmp_path) -> None:
    app = create_app()
    app.state.key_manager.key_dir = tmp_path
    with TestClient(app) as client:
        public_key = client.get("/public-key").json()["public_key_pem"]
        from cryptography.hazmat.primitives import serialization

        public_obj = serialization.load_pem_public_key(public_key.encode("utf-8"))
        aes_key = generate_aes_key()
        encrypted_session_key = rsa_encrypt(public_obj, aes_key)
        handshake = client.post(
            "/handshake",
            json=HandshakeRequest(client_id=uuid4(), encrypted_session_key=b64encode(encrypted_session_key)).model_dump(mode="json"),
        )
        session_id = handshake.json()["session_id"]
        envelope = aes_encrypt(aes_key, b'{"message":"hello"}', aad=session_id.encode("utf-8"))
        envelope["tag"] = envelope["tag"][:-4] + "AAAA"
        response = client.post("/message", headers={"X-Session-ID": session_id}, json=envelope)
        assert response.status_code == 400
