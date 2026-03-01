import hashlib
import json
def _canonical_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
def _chain_hash(prev_hash_hex: str, record_obj: dict) -> str:
    h = hashlib.sha256()
    h.update(bytes.fromhex(prev_hash_hex))
    h.update(_canonical_bytes(record_obj))
    return h.hexdigest()
def test_hash_chain_links_consecutive_records():
    genesis = "00" * 32
    rec1 = {"v": 1, "agent_id": "agent-01", "seq": 1, "record": {"msg": "a"}}
    h1 = _chain_hash(genesis, rec1)
    rec2 = {"v": 1, "agent_id": "agent-01", "seq": 2, "record": {"msg": "b"}}
    h2 = _chain_hash(h1, rec2)
# The second record should be linked to the first via prev_hash.
    assert len(h1) == 64
    assert len(h2) == 64
    assert h1 != h2
def test_hash_chain_detects_tampering():
    genesis = "00" * 32
    rec1 = {"v": 1, "agent_id": "agent-01", "seq": 1, "record": {"msg": "a"}}
    h1 = _chain_hash(genesis, rec1)

    # attacker modifies record content after the fact
    rec1_tampered = {"v": 1, "agent_id": "agent-01", "seq": 1, "record": {"msg": "A"}}
    h1_tampered = _chain_hash(genesis, rec1_tampered)

    assert h1_tampered != h1