from __future__ import annotations

import asyncio
import json
import os

from pksl.config import AgentConfig
from pksl.models import Envelope, LogRecord
from pksl.storage.append_only import utc_now_iso
from pksl.transport.framing import send_frame, recv_frame
from pksl.transport.tcp_async import open_tcp_connection

from pksl.crypto.hashchain import compute_log_hash, genesis_prev_hash
from agent.state_store import load_state, save_state, AgentState


def make_record(i: int) -> LogRecord:
    return LogRecord(
        timestamp=utc_now_iso(),
        event_type="heartbeat",
        severity="INFO",
        message=f"agent heartbeat #{i}",
        extra={"counter": i},
    )


def state_path_for(agent_id: str) -> str:
    # Store under ./data so Docker/K8s can mount a volume there
    os.makedirs("./data", exist_ok=True)
    return os.path.join("./data", f"agent_state_{agent_id}.json")


async def main() -> None:
    cfg = AgentConfig.from_env()

    # NEW: load persisted agent state
    spath = state_path_for(cfg.agent_id)
    state = load_state(spath)

    seq = state.seq
    prev_hash = state.prev_hash

    i = 0  # just local counter for message text

    print(f"[agent] id={cfg.agent_id} -> {cfg.target_host}:{cfg.target_port} | state={spath} | start_seq={seq}")

    while True:
        try:
            reader, writer = await open_tcp_connection(cfg.target_host, cfg.target_port)

            while True:
                seq += 1
                i += 1

                record = make_record(i)

                ph = genesis_prev_hash(prev_hash)
                h = compute_log_hash(
                    agent_id=cfg.agent_id,
                    seq=seq,
                    prev_hash=ph,
                    record_dict=record.model_dump(),
                    version=1,
                )

                env = Envelope(
                    agent_id=cfg.agent_id,
                    seq=seq,
                    record=record,
                    prev_hash=ph,
                    hash=h,
                )

                payload = env.model_dump_json().encode("utf-8")
                await send_frame(writer, payload)

                ack_bytes = await recv_frame(reader)
                ack = json.loads(ack_bytes.decode("utf-8"))
                print(f"[agent] sent seq={seq} ack={ack}")

                # NEW: persist state after successful send/ack
                prev_hash = h
                save_state(spath, AgentState(seq=seq, prev_hash=prev_hash))

                await asyncio.sleep(cfg.send_interval_sec)

        except Exception as e:
            print(f"[agent] connection error: {e} (retrying in 2s)")
            await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())