from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class AgentState:
    seq: int
    prev_hash: Optional[str]


def load_state(path: str) -> AgentState:
    if not os.path.exists(path):
        return AgentState(seq=0, prev_hash=None)

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
            if not raw:
                # empty file (e.g., interrupted write)
                return AgentState(seq=0, prev_hash=None)
            data = json.loads(raw)
    except Exception:
        # corrupted json or partial write
        return AgentState(seq=0, prev_hash=None)

    return AgentState(
        seq=int(data.get("seq", 0)),
        prev_hash=data.get("prev_hash"),
    )


def save_state(path: str, state: AgentState) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"seq": state.seq, "prev_hash": state.prev_hash}, f, ensure_ascii=False, indent=2)