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
    record: LogRecord

    # Future crypto fields (we’ll fill later)
    prev_hash: Optional[str] = None
    hash: Optional[str] = None
    signature: Optional[str] = None
    ciphertext: Optional[str] = None
    nonce: Optional[str] = None