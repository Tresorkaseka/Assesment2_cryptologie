from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from uuid import uuid4

import httpx

from shared.crypto import aes_encrypt, b64encode, generate_aes_key, json_bytes
from shared.schemas import HandshakeRequest, HandshakeResponse, PublicKeyResponse


@dataclass(slots=True)
class SecureClient:
    server_url: str
    client_id: str = ""
    session_id: str = ""
    aes_key: bytes = b""
    public_key_pem: str = ""

    def initialize(self) -> HandshakeResponse:
        self.client_id = self.client_id or str(uuid4())
        public_key = self.fetch_public_key()
        self.public_key_pem = public_key.public_key_pem
        self.aes_key = generate_aes_key()

        encrypted_session_key = rsa_encrypt(
            public_key_obj=public_key,
            session_key=self.aes_key,
        )
        handshake = HandshakeRequest(
            client_id=self.client_id,
            encrypted_session_key=b64encode(encrypted_session_key),
        )
        response = httpx.post(f"{self.server_url}/handshake", json=handshake.model_dump(mode="json"), timeout=10.0)
        response.raise_for_status()
        data = HandshakeResponse.model_validate(response.json())
        self.session_id = data.session_id
        return data

    def fetch_public_key(self) -> PublicKeyResponse:
        response = httpx.get(f"{self.server_url}/public-key", timeout=10.0)
        response.raise_for_status()
        return PublicKeyResponse.model_validate(response.json())

    def send_message(self, message: str, tamper: bool = False) -> dict:
        if not self.session_id or not self.aes_key:
            raise RuntimeError("Client is not initialized")
        payload = {"message": message}
        envelope = aes_encrypt(self.aes_key, json_bytes(payload), aad=self.session_id.encode("utf-8"))
        if tamper:
            envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"
        response = httpx.post(
            f"{self.server_url}/message",
            headers={"X-Session-ID": self.session_id},
            json=envelope,
            timeout=10.0,
        )
        response.raise_for_status()
        return response.json()

    def tamper_attack(self) -> tuple[int, dict]:
        if not self.session_id or not self.aes_key:
            raise RuntimeError("Client is not initialized")
        envelope = aes_encrypt(
            self.aes_key,
            json_bytes({"message": "tampered"}),
            aad=self.session_id.encode("utf-8"),
        )
        envelope["tag"] = envelope["tag"][:-4] + "AAAA"
        response = httpx.post(
            f"{self.server_url}/message",
            headers={"X-Session-ID": self.session_id},
            json=envelope,
            timeout=10.0,
        )
        try:
            body = response.json()
        except json.JSONDecodeError:
            body = {"raw": response.text}
        return response.status_code, body


def rsa_encrypt(public_key_obj: PublicKeyResponse, session_key: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    public_key = serialization.load_pem_public_key(public_key_obj.public_key_pem.encode("utf-8"))
    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def interactive_loop(client: SecureClient) -> None:
    print(f"Connected as client_id={client.client_id}")
    print("Type a message and press Enter. Use /mitm to simulate a tampered attack. Use /quit to exit.")
    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            break
        if not line:
            continue
        if line in {"/quit", "quit", "exit"}:
            break
        if line == "/mitm":
            status, body = client.tamper_attack()
            print(f"attack status={status} body={body}")
            continue
        try:
            response = client.send_message(line)
            print(json.dumps(response, indent=2, ensure_ascii=False))
        except httpx.HTTPStatusError as exc:
            print(f"request failed: {exc.response.status_code} {exc.response.text}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RSA handshake demo client")
    parser.add_argument("--server-url", default="http://127.0.0.1:8000")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--message", default="")
    parser.add_argument("--attack", choices=["tamper"], default="")
    args = parser.parse_args(argv)

    client = SecureClient(server_url=args.server_url)
    handshake = client.initialize()
    print(json.dumps(handshake.model_dump(mode="json"), indent=2, ensure_ascii=False))

    if args.attack == "tamper":
        status, body = client.tamper_attack()
        print(f"attack status={status}")
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0

    if args.interactive:
        interactive_loop(client)
        return 0

    message = args.message or "Hello from the secure RSA/AES client"
    response = client.send_message(message)
    print(json.dumps(response, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
