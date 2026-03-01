import asyncio
import json
import os

from pksl.config import ServerConfig
from pksl.models import Envelope, LogRecord
from pksl.storage.append_only import append_jsonl, utc_now_iso
from pksl.transport.framing import recv_frame, send_frame
from pksl.transport.tcp_async import start_tcp_server
from pksl.crypto.hashchain import compute_log_hash, GENESIS, canonical_json

from pksl.crypto.signing import load_public_key_pem, verify_bytes
from pksl.crypto.key_loader import load_aes_key
from pksl.crypto.aead import decrypt_aesgcm

from pksl.transport.noise_xx import (
    noise_xx_handshake_responder,
    noise_encrypt,
    noise_decrypt,
)

from pksl.crypto.pki import (
    load_cert_from_b64_pem,
    validate_cert,
    cert_fingerprint_hex,
    cert_subject_cn,
)

from server.state_store import ServerState, load_server_state, save_server_state


def state_path() -> str:
    os.makedirs("./data", exist_ok=True)
    return os.path.join("./data", "server_state.json")


def public_key_path_for(agent_id: str) -> str:
    return os.path.join("keys", f"{agent_id}_ed25519_public.pem")


def server_noise_static_private_path() -> str:
    return os.path.join("keys", "server_noise_private.key")


def signing_message_with_record_fields(
    *,
    version: int,
    agent_id: str,
    seq: int,
    prev_hash: str,
    hash_hex: str,
    session_id: str,
    record_dict: dict,
) -> bytes:
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


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: ServerConfig,
    state: ServerState,
    state_file: str,
    aes_key: bytes,
) -> None:
    peer = writer.get_extra_info("peername")
    noise = None  # important: avoid NameError if handshake fails

    try:
        # Noise handshake (responder) with static key (auth transport)
        noise = await noise_xx_handshake_responder(
            reader,
            writer,
            static_private_key_path=server_noise_static_private_path(),
        )

        # Channel binding: receive session_hello as FIRST encrypted frame
        hello_wire = await recv_frame(reader)
        hello_plain = noise_decrypt(noise, hello_wire)
        hello = json.loads(hello_plain.decode("utf-8"))

        if hello.get("type") != "session_hello" or not hello.get("session_id"):
            raise ValueError("Missing/invalid session_hello for channel binding")

        expected_session_id = str(hello["session_id"])

        # --- PKI: validate agent certificate from hello ---
        agent_id_from_hello = str(hello.get("agent_id", ""))
        agent_cert_b64 = str(hello.get("agent_cert_b64", ""))

        if not agent_id_from_hello:
            raise ValueError("session_hello missing agent_id")
        if not agent_cert_b64:
            raise ValueError("session_hello missing agent_cert_b64")

        agent_cert = load_cert_from_b64_pem(agent_cert_b64)
        validate_cert(agent_cert)

        # Bind identity: require CN == agent_id (recommended for coursework clarity)
        cn = cert_subject_cn(agent_cert)
        if cn and cn != agent_id_from_hello:
            raise ValueError(f"Certificate CN mismatch: cert_cn={cn} agent_id={agent_id_from_hello}")

        agent_cert_fp = cert_fingerprint_hex(agent_cert)

        while True:
            # Receive Noise-encrypted envelope
            wire = await recv_frame(reader)
            plain = noise_decrypt(noise, wire)

            obj = json.loads(plain.decode("utf-8"))
            env = Envelope.model_validate(obj)

            # ---- session binding check ----
            if not env.session_id:
                raise ValueError("Missing session_id (required for channel binding)")
            if env.session_id != expected_session_id:
                raise ValueError("Session binding mismatch")

            # Optional: make sure agent_id matches hello identity
            if env.agent_id != agent_id_from_hello:
                raise ValueError("Agent identity mismatch (env.agent_id != session_hello agent_id)")

            # ---- replay protection (DO THIS EARLY) ----
            prev_seen_seq = state.last_seq.get(env.agent_id, 0)
            if env.seq <= prev_seen_seq:
                raise ValueError(
                    f"Replay detected: agent={env.agent_id} seq={env.seq} last_seq={prev_seen_seq}"
                )

            # ---- hash chain fields present ----
            if not env.hash or not env.prev_hash:
                raise ValueError("Missing hash chain fields (hash/prev_hash)")

            # ---- hash chain continuity check (also early) ----
            expected_prev = state.last_hash.get(env.agent_id, GENESIS)
            if env.prev_hash != expected_prev:
                raise ValueError(
                    f"Hash chain break: agent={env.agent_id} expected_prev={expected_prev} got_prev={env.prev_hash}"
                )

            # ---- decrypt record payload (AES-GCM) ----
            if env.enc_alg != "aes-256-gcm":
                raise ValueError("Unsupported or missing enc_alg (expected aes-256-gcm)")
            if not env.nonce or not env.ciphertext:
                raise ValueError("Missing nonce/ciphertext for encrypted payload")

            aad = canonical_json(
                {
                    "agent_id": env.agent_id,
                    "seq": env.seq,
                    "prev_hash": env.prev_hash,
                    "hash": env.hash,
                    "v": env.version,
                }
            )
            plaintext = decrypt_aesgcm(aes_key, env.nonce, env.ciphertext, aad)
            record_dict = json.loads(plaintext.decode("utf-8"))
            record = LogRecord.model_validate(record_dict)

            # ---- hash correctness check ----
            expected_hash = compute_log_hash(
                agent_id=env.agent_id,
                seq=env.seq,
                prev_hash=env.prev_hash,
                record_dict=record.model_dump(),
                version=env.version,
            )
            if env.hash != expected_hash:
                raise ValueError(f"Hash mismatch: agent={env.agent_id} seq={env.seq}")

            # ---- signature verification ----
            if env.sig_alg != "ed25519":
                raise ValueError("Unsupported or missing sig_alg (expected ed25519)")
            if not env.signature or not env.key_id:
                raise ValueError("Missing signature or key_id")

            pub_path = public_key_path_for(env.key_id)
            if not os.path.exists(pub_path):
                raise FileNotFoundError(f"Missing public key for agent '{env.key_id}': {pub_path}")

            pub = load_public_key_pem(pub_path)
            ok = verify_bytes(
                pub,
                signing_message_with_record_fields(
                    version=env.version,
                    agent_id=env.agent_id,
                    seq=env.seq,
                    prev_hash=env.prev_hash,
                    hash_hex=env.hash,
                    session_id=env.session_id,
                    record_dict=record.model_dump(),
                ),
                env.signature,
            )
            if not ok:
                raise ValueError(f"Invalid signature: agent={env.agent_id} key_id={env.key_id} seq={env.seq}")

            # ---- update & persist server state (ONLY after accept) ----
            state.last_seq[env.agent_id] = env.seq
            state.last_hash[env.agent_id] = env.hash
            save_server_state(state_file, state)

            # ---- store verified log ----
            stored_obj = env.model_dump()
            stored_obj["record"] = record.model_dump()
            stored_obj["server_received_at"] = utc_now_iso()
            stored_obj["integrity_status"] = "verified_pki_noise_xx_bound_hash_sig_aesgcm"
            stored_obj["agent_cert_fp"] = agent_cert_fp

            path = append_jsonl(cfg.storage_dir, cfg.log_file, stored_obj)

            # Non-authoritative indexing (optional)
            if not hasattr(handle_client, "_os_indexer"):
                from pksl.indexing.opensearch_indexer import OpenSearchIndexer
                handle_client._os_indexer = OpenSearchIndexer()  # type: ignore[attr-defined]
                handle_client._os_indexer.ensure_index()         # type: ignore[attr-defined]

            handle_client._os_indexer.index_log(stored_obj)      # type: ignore[attr-defined]

            ack = {
                "ok": True,
                "stored_to": path,
                "seq": env.seq,
                "agent_id": env.agent_id,
                "integrity_status": "verified_pki_noise_xx_bound_hash_sig_aesgcm",
            }

            ack_plain = json.dumps(ack).encode("utf-8")
            ack_wire = noise_encrypt(noise, ack_plain)
            await send_frame(writer, ack_wire)

    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        err = {"ok": False, "error": str(e), "peer": str(peer)}
        try:
            err_plain = json.dumps(err).encode("utf-8")
            if noise is not None:
                err_wire = noise_encrypt(noise, err_plain)
                await send_frame(writer, err_wire)
            else:
                # handshake failed; best-effort plain error
                await send_frame(writer, err_plain)
        except Exception:
            pass
    finally:
        writer.close()
        await writer.wait_closed()


async def main() -> None:
    cfg = ServerConfig.from_env()
    spath = state_path()
    state = load_server_state(spath)
    aes_key = load_aes_key()

    print(
        f"[server] state={spath} | agents_tracked={len(state.last_seq)} | "
        f"storage={cfg.storage_dir}/{cfg.log_file} | transport=Noise_XX(auth+bound+pki) | enc=aes-256-gcm"
    )

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await handle_client(r, w, cfg, state, spath, aes_key)

    server = await start_tcp_server(cfg.host, cfg.port, _handler)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"[server] listening on {addrs}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())