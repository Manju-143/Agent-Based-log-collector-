import asyncio
import base64
import json
import os
from typing import Dict, Any

from pksl.config import AgentConfig
from pksl.models import Envelope, LogRecord
from pksl.storage.append_only import utc_now_iso
from pksl.transport.framing import send_frame, recv_frame
from pksl.transport.tcp_async import open_tcp_connection

from pksl.transport.noise_xx import (
    noise_xx_handshake_initiator,
    noise_encrypt,
    noise_decrypt,
)

from pksl.crypto.hashchain import compute_log_hash, genesis_prev_hash, canonical_json
from pksl.crypto.signing import load_private_key_pem, sign_bytes
from pksl.crypto.key_loader import load_aes_key
from pksl.crypto.aead import encrypt_aesgcm

from pksl.crypto.pki import load_cert  # must exist in your pksl/crypto/pki.py
from cryptography.hazmat.primitives import serialization

from agent.state_store import load_state, save_state, AgentState


# -----------------------------
# Demo log generator
# -----------------------------
def make_record(i: int) -> LogRecord:
    return LogRecord(
        timestamp=utc_now_iso(),
        event_type="heartbeat",
        severity="INFO",
        message=f"agent heartbeat #{i}",
        extra={"counter": i},
    )


# -----------------------------
# Paths / helpers
# -----------------------------
def state_path_for(agent_id: str) -> str:
    os.makedirs("./data", exist_ok=True)
    return os.path.join("./data", f"agent_state_{agent_id}.json")


def private_key_path_for(agent_id: str) -> str:
    return os.path.join("keys", f"{agent_id}_ed25519_private.pem")


def noise_static_private_path_for(agent_id: str) -> str:
    return os.path.join("keys", f"{agent_id}_noise_private.key")


def load_agent_cert_b64() -> str:
    """
    Loads agent X.509 certificate (PEM) and base64 encodes it so it can be sent
    in the session_hello. Server can validate chain + CRL.
    """
    cert_path = os.getenv("PKSL_AGENT_CERT", "pki/issued/agent-01_cert.pem")
    cert = load_cert(cert_path)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return base64.b64encode(pem).decode("ascii")


def signing_message_with_record_fields(
    *,
    version: int,
    agent_id: str,
    seq: int,
    prev_hash: str,
    hash_hex: str,
    session_id: str,
    record_dict: Dict[str, Any],
) -> bytes:
    # Channel binding: session_id is included in signed material.
    to_sign = {
        "v": version,
        "agent_id": agent_id,
        "seq": seq,
        "prev_hash": prev_hash,
        "hash": hash_hex,
        "session_id": session_id,
        "record": record_dict,
    }
    return canonical_json(to_sign)


# -----------------------------
# Main
# -----------------------------
async def main() -> None:
    cfg = AgentConfig.from_env()

    # Load persisted state
    spath = state_path_for(cfg.agent_id)
    state = load_state(spath)
    seq = state.seq
    prev_hash = state.prev_hash

    # Load Ed25519 signing key
    priv_path = private_key_path_for(cfg.agent_id)
    if not os.path.exists(priv_path):
        raise FileNotFoundError(
            f"Missing private key: {priv_path}. Generate it with: python -m tools.gen_keys"
        )
    priv = load_private_key_pem(priv_path)

    # Load AES key for payload encryption
    aes_key = load_aes_key()

    # Load agent cert (for PKI identity)
    agent_cert_b64 = load_agent_cert_b64()

    i = 0
    print(
        f"[agent] id={cfg.agent_id} -> {cfg.target_host}:{cfg.target_port} | "
        f"state={spath} | start_seq={seq} | enc=aes-256-gcm | transport=Noise_XX(auth+bound+pki)"
    )

    while True:
        try:
            reader, writer = await open_tcp_connection(cfg.target_host, cfg.target_port)

            # Noise handshake (initiator) with static key (auth transport)
            noise = await noise_xx_handshake_initiator(
                reader,
                writer,
                static_private_key_path=noise_static_private_path_for(cfg.agent_id),
            )

            # Per-connection session_id (channel binding)
            session_nonce = os.urandom(32)
            session_id = base64.b64encode(session_nonce).decode("ascii")

            # Send session hello: includes session_id and agent certificate (base64 PEM)
            hello_obj = {
                "type": "session_hello",
                "session_id": session_id,
                "agent_id": cfg.agent_id,
                "agent_cert_b64": agent_cert_b64,
            }
            hello = json.dumps(hello_obj).encode("utf-8")
            await send_frame(writer, noise_encrypt(noise, hello))
            print("[agent] noise handshake finished | session_hello sent (with cert)")

            while True:
                seq += 1
                i += 1

                record = make_record(i)
                record_dict = record.model_dump()

                # Hash chain over plaintext record content
                ph = genesis_prev_hash(prev_hash)
                h = compute_log_hash(
                    agent_id=cfg.agent_id,
                    seq=seq,
                    prev_hash=ph,
                    record_dict=record_dict,
                    version=1,
                )

                # AES-GCM encrypt the record (record stays confidential)
                plaintext = canonical_json(record_dict)
                aad = canonical_json(
                    {"agent_id": cfg.agent_id, "seq": seq, "prev_hash": ph, "hash": h, "v": 1}
                )
                enc = encrypt_aesgcm(aes_key, plaintext, aad)

                # Envelope carries ciphertext + chain metadata (no plaintext record)
                env = Envelope(
                    agent_id=cfg.agent_id,
                    seq=seq,
                    session_id=session_id,
                    record=None,
                    prev_hash=ph,
                    hash=h,
                )
                env.enc_alg = "aes-256-gcm"
                env.nonce = enc.nonce_b64
                env.ciphertext = enc.ciphertext_b64

                # Signature binds record semantics + session_id (prevents replay across sessions)
                env.sig_alg = "ed25519"
                env.key_id = cfg.agent_id
                env.signature = sign_bytes(
                    priv,
                    signing_message_with_record_fields(
                        version=env.version,
                        agent_id=env.agent_id,
                        seq=env.seq,
                        prev_hash=env.prev_hash or "",
                        hash_hex=env.hash or "",
                        session_id=session_id,
                        record_dict=record_dict,
                    ),
                )

                # Serialize and send (Noise encrypt full envelope)
                payload = env.model_dump_json().encode("utf-8")
                wire = noise_encrypt(noise, payload)
                await send_frame(writer, wire)

                # Receive Noise-encrypted ack
                ack_wire = await recv_frame(reader)
                ack_plain = noise_decrypt(noise, ack_wire)
                ack = json.loads(ack_plain.decode("utf-8"))

                print(f"[agent] sent seq={seq} ack={ack}")

                # Persist state only when server accepted
                if ack.get("ok") is True:
                    prev_hash = h
                    save_state(spath, AgentState(seq=seq, prev_hash=prev_hash))

                await asyncio.sleep(cfg.send_interval_sec)

        except Exception as e:
            print(f"[agent] connection error: {e} (retrying in 2s)")
            await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())