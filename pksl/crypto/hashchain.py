from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional


GENESIS = "0" * 64  # 64 hex chars


def canonical_json(obj: Dict[str, Any]) -> bytes:
    # stable serialization
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_log_hash(
    *,
    agent_id: str,
    seq: int,
    prev_hash: str,
    record_dict: Dict[str, Any],
    version: int = 1,
) -> str:
    # Bind chain to agent + seq + record content
    payload = {
        "v": version,
        "agent_id": agent_id,
        "seq": seq,
        "prev_hash": prev_hash,
        "record": record_dict,
    }
    return sha256_hex(canonical_json(payload))


def genesis_prev_hash(prev_hash: Optional[str]) -> str:
    return prev_hash or GENESIS