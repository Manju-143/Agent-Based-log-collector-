from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Dict


@dataclass
class ServerState:
    # Per-agent monotonic counters (replay defense)
    last_seq: Dict[str, int]
    # Per-agent last hash (hash-chain continuity)
    last_hash: Dict[str, str]


def load_server_state(path: str) -> ServerState:
    """
    Loads server replay/hash-chain state from JSON.
    - Safe on missing/empty/corrupt files
    - Coerces types
    """
    if not path or not os.path.exists(path):
        return ServerState(last_seq={}, last_hash={})

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            return ServerState(last_seq={}, last_hash={})
        data = json.loads(raw)
    except Exception:
        # If corrupt, fail safe (fresh state). You may optionally log a warning.
        return ServerState(last_seq={}, last_hash={})

    last_seq_raw = data.get("last_seq") or {}
    last_hash_raw = data.get("last_hash") or {}

    # Coerce to expected types
    last_seq = {}
    for k, v in last_seq_raw.items():
        try:
            last_seq[str(k)] = int(v)
        except Exception:
            # Skip bad values rather than crash
            continue

    last_hash = {}
    for k, v in last_hash_raw.items():
        try:
            last_hash[str(k)] = str(v)
        except Exception:
            continue

    return ServerState(last_seq=last_seq, last_hash=last_hash)


def save_server_state(path: str, state: ServerState) -> None:
    """
    Atomic save to reduce risk of partial writes (power loss/crash).
    """
    dirpath = os.path.dirname(path) or "."
    os.makedirs(dirpath, exist_ok=True)

    payload = {"last_seq": state.last_seq, "last_hash": state.last_hash}

    # Write to a temp file in the same directory then replace atomically
    fd, tmppath = tempfile.mkstemp(prefix=".server_state_", suffix=".json", dir=dirpath)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmppath, path)  # atomic on Windows + POSIX
    finally:
        # If something failed before replace, best-effort cleanup
        try:
            if os.path.exists(tmppath):
                os.remove(tmppath)
        except Exception:
            pass