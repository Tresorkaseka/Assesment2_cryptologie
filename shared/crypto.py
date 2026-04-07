from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 32
GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16


@dataclass(slots=True)
class RSAKeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey

    @property
    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE) -> RSAKeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return RSAKeyPair(private_key=private_key, public_key=private_key.public_key())


def save_rsa_keypair(private_path: Path, public_path: Path, keypair: RSAKeyPair) -> None:
    private_path.write_bytes(keypair.private_pem)
    public_path.write_bytes(keypair.public_pem)


def load_rsa_private_key(path: Path) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_rsa_public_key(path: Path) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def load_rsa_keypair(private_path: Path, public_path: Path) -> RSAKeyPair:
    private_key = load_rsa_private_key(private_path)
    public_key = load_rsa_public_key(public_path)
    return RSAKeyPair(private_key=private_key, public_key=public_key)


def rsa_encrypt(public_key: rsa.RSAPublicKey, payload: bytes) -> bytes:
    return public_key.encrypt(
        payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key: rsa.RSAPrivateKey, payload: bytes) -> bytes:
    return private_key.decrypt(
        payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generate_aes_key() -> bytes:
    return os.urandom(AES_KEY_SIZE)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> dict[str, str]:
    iv = os.urandom(GCM_IV_SIZE)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(iv, plaintext, aad)
    ciphertext, tag = encrypted[:-GCM_TAG_SIZE], encrypted[-GCM_TAG_SIZE:]
    return {
        "iv": b64encode(iv),
        "ciphertext": b64encode(ciphertext),
        "tag": b64encode(tag),
    }


def aes_decrypt(key: bytes, envelope: dict[str, Any], aad: bytes | None = None) -> bytes:
    iv = b64decode(envelope["iv"])
    ciphertext = b64decode(envelope["ciphertext"])
    tag = b64decode(envelope["tag"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, aad)


def b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

