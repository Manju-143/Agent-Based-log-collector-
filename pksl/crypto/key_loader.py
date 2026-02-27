from __future__ import annotations

import base64
import os


def load_aes_key() -> bytes:
    """
    Load AES-256 key from environment variable PKSL_AES_KEY.
    Key must be base64 encoded.
    """
    k = os.getenv("PKSL_AES_KEY")
    if not k:
        raise ValueError("Missing PKSL_AES_KEY environment variable")

    key = base64.b64decode(k.encode("ascii"))

    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes (256-bit)")

    return key