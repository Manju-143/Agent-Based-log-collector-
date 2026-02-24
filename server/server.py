from __future__ import annotations

import asyncio
import json
import os

from pksl.config import ServerConfig
from pksl.models import Envelope
from pksl.storage.append_only import append_jsonl, utc_now_iso
from pksl.transport.framing import recv_frame, send_frame
from pksl.transport.tcp_async import start_tcp_server
from pksl.crypto.hashchain import compute_log_hash, GENESIS

from server.state_store import ServerState, load_server_state, save_server_state


def state_path() -> str:
    # Store under ./data so Docker/K8s can mount a volume there
    os.makedirs("./data", exist_ok=True)
    return os.path.join("./data", "server_state.json")


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: ServerConfig,
    state: ServerState,
    state_file: str,
) -> None:
    peer = writer.get_extra_info("peername")
    try:
        while True:
            data = await recv_frame(reader)
            obj = json.loads(data.decode("utf-8"))
            env = Envelope.model_validate(obj)

            # ---- replay protection: sequence must strictly increase ----
            prev_seen_seq = state.last_seq.get(env.agent_id, 0)
            if env.seq <= prev_seen_seq:
                raise ValueError(
                    f"Replay detected: agent={env.agent_id} seq={env.seq} last_seq={prev_seen_seq}"
                )

            # ---- hash chain validation ----
            if not env.hash or not env.prev_hash:
                raise ValueError("Missing hash chain fields (hash/prev_hash)")

            expected_prev = state.last_hash.get(env.agent_id, GENESIS)
            if env.prev_hash != expected_prev:
                raise ValueError(
                    f"Hash chain break: agent={env.agent_id} expected_prev={expected_prev} got_prev={env.prev_hash}"
                )

            expected_hash = compute_log_hash(
                agent_id=env.agent_id,
                seq=env.seq,
                prev_hash=env.prev_hash,
                record_dict=env.record.model_dump(),
                version=env.version,
            )
            if env.hash != expected_hash:
                raise ValueError(f"Hash mismatch: agent={env.agent_id} seq={env.seq}")

            # Update state only after validation
            state.last_seq[env.agent_id] = env.seq
            state.last_hash[env.agent_id] = env.hash

            # Persist state so server restarts won't break chain
            save_server_state(state_file, state)

            stored_obj = env.model_dump()
            stored_obj["server_received_at"] = utc_now_iso()
            stored_obj["integrity_status"] = "verified_hashchain"

            path = append_jsonl(cfg.storage_dir, cfg.log_file, stored_obj)

            ack = {
                "ok": True,
                "stored_to": path,
                "seq": env.seq,
                "agent_id": env.agent_id,
                "integrity_status": "verified_hashchain",
            }
            await send_frame(writer, json.dumps(ack).encode("utf-8"))

    except asyncio.IncompleteReadError:
        pass
    except Exception as e:
        err = {"ok": False, "error": str(e), "peer": str(peer)}
        try:
            await send_frame(writer, json.dumps(err).encode("utf-8"))
        except Exception:
            pass
    finally:
        writer.close()
        await writer.wait_closed()


async def main() -> None:
    cfg = ServerConfig.from_env()

    spath = state_path()
    state = load_server_state(spath)

    print(
        f"[server] state={spath} | agents_tracked={len(state.last_seq)} | "
        f"storage={cfg.storage_dir}/{cfg.log_file}"
    )

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await handle_client(r, w, cfg, state, spath)

    server = await start_tcp_server(cfg.host, cfg.port, _handler)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"[server] listening on {addrs}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())