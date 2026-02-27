from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass(frozen=True)
class X25519Keypair:
    private: X25519PrivateKey
    public: X25519PublicKey


def generate_x25519_keypair() -> X25519Keypair:
    priv = X25519PrivateKey.generate()
    return X25519Keypair(private=priv, public=priv.public_key())


def save_x25519_private_raw(path: str, key: X25519PrivateKey) -> None:
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(raw)


def save_x25519_public_raw(path: str, key: X25519PublicKey) -> None:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    with open(path, "wb") as f:
        f.write(raw)


def load_x25519_private_raw(path: str) -> X25519PrivateKey:
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) != 32:
        raise ValueError("X25519 private key must be 32 bytes (raw)")
    return X25519PrivateKey.from_private_bytes(raw)


def load_x25519_public_raw(path: str) -> X25519PublicKey:
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) != 32:
        raise ValueError("X25519 public key must be 32 bytes (raw)")
    return X25519PublicKey.from_public_bytes(raw)