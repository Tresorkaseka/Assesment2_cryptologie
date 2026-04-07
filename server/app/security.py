from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from shared.crypto import (
    RSAKeyPair,
    generate_rsa_keypair,
    load_rsa_keypair,
    rsa_decrypt,
    save_rsa_keypair,
)


@dataclass(slots=True)
class ServerKeyManager:
    key_dir: Path

    def ensure_keypair(self) -> RSAKeyPair:
        self.key_dir.mkdir(parents=True, exist_ok=True)
        private_path = self.key_dir / "rsa_private.pem"
        public_path = self.key_dir / "rsa_public.pem"
        if private_path.exists() and public_path.exists():
            return load_rsa_keypair(private_path, public_path)
        keypair = generate_rsa_keypair()
        save_rsa_keypair(private_path, public_path, keypair)
        return keypair

    def decrypt_session_key(self, encrypted_session_key: bytes, keypair: RSAKeyPair) -> bytes:
        return rsa_decrypt(keypair.private_key, encrypted_session_key)

