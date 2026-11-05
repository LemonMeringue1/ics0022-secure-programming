import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12


class DecryptionError(Exception):
    """Wrong password or corrupted/tampered vault."""


def encrypt(key: bytearray, pt: bytes, aad: bytes) -> tuple[bytes, bytes]: # -> tuple(nonce, ct)
    """Encrypt with AES-256-GCM. Returns tuple(nonce, ct_with_tag)."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    nonce = secrets.token_bytes(NONCE_LEN)

    ct = AESGCM(bytes(key)).encrypt(nonce, pt, aad)
    return nonce, ct


def decrypt(key: bytearray, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise DecryptionError("wrong password or corrupted/tampered vault")