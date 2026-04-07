from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ServerSettings:
    key_dir: Path
    private_key_name: str = "rsa_private.pem"
    public_key_name: str = "rsa_public.pem"
    session_ttl_seconds: int = 3600

    @property
    def private_key_path(self) -> Path:
        return self.key_dir / self.private_key_name

    @property
    def public_key_path(self) -> Path:
        return self.key_dir / self.public_key_name


def load_settings() -> ServerSettings:
    key_dir = Path(os.getenv("RSA_KEY_DIR", "keys"))
    return ServerSettings(key_dir=key_dir)

