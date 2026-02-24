from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict


@dataclass
class ServerState:
    last_seq: Dict[str, int]
    last_hash: Dict[str, str]


def load_server_state(path: str) -> ServerState:
    if not os.path.exists(path):
        return ServerState(last_seq={}, last_hash={})

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            if not raw:
                return ServerState(last_seq={}, last_hash={})
            data = json.loads(raw)
    except Exception:
        return ServerState(last_seq={}, last_hash={})

    return ServerState(
        last_seq={k: int(v) for k, v in (data.get("last_seq") or {}).items()},
        last_hash={k: str(v) for k, v in (data.get("last_hash") or {}).items()},
    )


def save_server_state(path: str, state: ServerState) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {"last_seq": state.last_seq, "last_hash": state.last_hash},
            f,
            ensure_ascii=False,
            indent=2,
        )