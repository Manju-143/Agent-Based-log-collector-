from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class LogRecord(BaseModel):
    timestamp: str
    event_type: str
    severity: str
    message: str
    extra: Dict[str, Any] = Field(default_factory=dict)


class Envelope(BaseModel):
    version: int = 1
    agent_id: str
    seq: int

    # Session binding (Noise transcript hash, base64)
    session_id: Optional[str] = None

    # When encryption is enabled, we will send ciphertext+nonce and set record=None.
    record: Optional[LogRecord] = None

    # Hash chain (integrity)
    prev_hash: Optional[str] = None
    hash: Optional[str] = None

    # Signature (authenticity)
    sig_alg: Optional[str] = None
    key_id: Optional[str] = None
    signature: Optional[str] = None

    # Encryption (confidentiality)
    enc_alg: Optional[str] = None          # e.g., "aes-256-gcm"
    nonce: Optional[str] = None            # base64
    ciphertext: Optional[str] = None       # base64