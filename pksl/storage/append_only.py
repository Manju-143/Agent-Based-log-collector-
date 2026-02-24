from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def append_jsonl(storage_dir: str, filename: str, obj: Dict[str, Any]) -> str:
    ensure_dir(storage_dir)
    full_path = os.path.join(storage_dir, filename)
    line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    with open(full_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return full_path


def utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"