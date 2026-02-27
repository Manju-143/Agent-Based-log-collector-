from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass(frozen=True)
class AeadResult:
    nonce_b64: str
    ciphertext_b64: str


def generate_key_256() -> bytes:
    return os.urandom(32)


def encrypt_aesgcm(key: bytes, plaintext: bytes, aad: bytes) -> AeadResult:
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return AeadResult(nonce_b64=b64e(nonce), ciphertext_b64=b64e(ct))


def decrypt_aesgcm(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: bytes) -> bytes:
    nonce = b64d(nonce_b64)
    ct = b64d(ciphertext_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)