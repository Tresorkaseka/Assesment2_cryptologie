from shared.crypto import aes_decrypt, aes_encrypt, generate_aes_key, generate_rsa_keypair, rsa_decrypt, rsa_encrypt


def test_rsa_roundtrip() -> None:
    keypair = generate_rsa_keypair()
    payload = b"session-key"
    encrypted = rsa_encrypt(keypair.public_key, payload)
    assert rsa_decrypt(keypair.private_key, encrypted) == payload


def test_aes_roundtrip() -> None:
    key = generate_aes_key()
    plaintext = b'{"message":"hello"}'
    envelope = aes_encrypt(key, plaintext)
    assert aes_decrypt(key, envelope) == plaintext

