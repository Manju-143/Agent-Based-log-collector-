from __future__ import annotations

import argparse
import json
import os
from typing import Dict, Tuple

from pksl.crypto.hashchain import compute_log_hash, GENESIS, canonical_json
from pksl.crypto.signing import load_public_key_pem, verify_bytes


def public_key_path_for(keys_dir: str, agent_id: str) -> str:
    return os.path.join(keys_dir, f"{agent_id}_ed25519_public.pem")


def signing_message_with_record_fields(
    *,
    version: int,
    agent_id: str,
    seq: int,
    prev_hash: str,
    hash_hex: str,
    record_dict: dict,
) -> bytes:
    to_sign = {
        "v": version,
        "agent_id": agent_id,
        "seq": seq,
        "prev_hash": prev_hash,
        "hash": hash_hex,
        "record": record_dict,
    }
    return canonical_json(to_sign)


def verify_file(path: str, keys_dir: str) -> Tuple[bool, str]:
    last_hash: Dict[str, str] = {}
    last_seq: Dict[str, int] = {}

    if not os.path.exists(path):
        return False, f"file not found: {path}"

    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except Exception as e:
                return False, f"line {line_no}: invalid json ({e})"

            agent_id = obj.get("agent_id")
            seq = obj.get("seq")
            version = obj.get("version", 1)

            prev_hash = obj.get("prev_hash")
            hash_hex = obj.get("hash")
            record = obj.get("record")

            sig_alg = obj.get("sig_alg")
            key_id = obj.get("key_id")
            signature = obj.get("signature")

            if not agent_id or not isinstance(agent_id, str):
                return False, f"line {line_no}: missing/invalid agent_id"
            if not isinstance(seq, int):
                return False, f"line {line_no}: missing/invalid seq"
            if not isinstance(record, dict):
                return False, f"line {line_no}: missing/invalid record (expected dict)"
            if not prev_hash or not hash_hex:
                return False, f"line {line_no}: missing prev_hash/hash"
            if sig_alg != "ed25519":
                return False, f"line {line_no}: unsupported sig_alg={sig_alg}"
            if not key_id or not signature:
                return False, f"line {line_no}: missing key_id/signature"

            # Replay / monotonic check (offline)
            prev_seen_seq = last_seq.get(agent_id, 0)
            if seq <= prev_seen_seq:
                return False, f"line {line_no}: replay/non-monotonic seq (seq={seq} last={prev_seen_seq})"

            # Hash chain check
            expected_prev = last_hash.get(agent_id, GENESIS)
            if prev_hash != expected_prev:
                return False, (
                    f"line {line_no}: hash chain break for {agent_id} "
                    f"(expected_prev={expected_prev} got_prev={prev_hash})"
                )

            expected_hash = compute_log_hash(
                agent_id=agent_id,
                seq=seq,
                prev_hash=prev_hash,
                record_dict=record,
                version=version,
            )
            if hash_hex != expected_hash:
                return False, f"line {line_no}: hash mismatch for {agent_id} seq={seq}"

            # Signature check
            pub_path = public_key_path_for(keys_dir, key_id)
            if not os.path.exists(pub_path):
                return False, f"line {line_no}: missing public key file: {pub_path}"

            pub = load_public_key_pem(pub_path)
            msg = signing_message_with_record_fields(
                version=version,
                agent_id=agent_id,
                seq=seq,
                prev_hash=prev_hash,
                hash_hex=hash_hex,
                record_dict=record,
            )
            if not verify_bytes(pub, msg, signature):
                return False, f"line {line_no}: invalid signature for {agent_id} seq={seq}"

            # Update trackers
            last_seq[agent_id] = seq
            last_hash[agent_id] = hash_hex

    return True, f"OK: verified {path} (agents={len(last_seq)})"


def main() -> None:
    ap = argparse.ArgumentParser(description="Verify append-only log file: hash chain + signatures.")
    ap.add_argument("--file", default="./data/verified_logs.jsonl", help="Path to JSONL log file")
    ap.add_argument("--keys", default="./keys", help="Directory containing *_ed25519_public.pem")
    args = ap.parse_args()

    ok, msg = verify_file(args.file, args.keys)
    if ok:
        print(msg)
        raise SystemExit(0)
    else:
        print("FAIL:", msg)
        raise SystemExit(2)


if __name__ == "__main__":
    main()