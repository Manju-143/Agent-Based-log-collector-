from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass
class SigningKeypair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey


def generate_ed25519_keypair() -> SigningKeypair:
    priv = Ed25519PrivateKey.generate()
    return SigningKeypair(private=priv, public=priv.public_key())


def save_private_key_pem(path: str, key: Ed25519PrivateKey) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_key_pem(path: str, key: Ed25519PublicKey) -> None:
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key_pem(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Not an Ed25519 private key")
    return key


def load_public_key_pem(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        data = f.read()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("Not an Ed25519 public key")
    return key


def sign_bytes(priv: Ed25519PrivateKey, msg: bytes) -> str:
    sig = priv.sign(msg)
    return b64e(sig)


def verify_bytes(pub: Ed25519PublicKey, msg: bytes, sig_b64: str) -> bool:
    try:
        pub.verify(b64d(sig_b64), msg)
        return True
    except Exception:
        return False