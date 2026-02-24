from __future__ import annotations

import asyncio
import json

from pksl.config import AgentConfig
from pksl.models import Envelope, LogRecord
from pksl.storage.append_only import utc_now_iso
from pksl.transport.framing import send_frame, recv_frame
from pksl.transport.tcp_async import open_tcp_connection


def make_record(i: int) -> LogRecord:
    return LogRecord(
        timestamp=utc_now_iso(),
        event_type="heartbeat",
        severity="INFO",
        message=f"agent heartbeat #{i}",
        extra={"counter": i},
    )


async def main() -> None:
    cfg = AgentConfig.from_env()
    seq = 0
    i = 0

    print(f"[agent] id={cfg.agent_id} -> {cfg.target_host}:{cfg.target_port}")

    while True:
        try:
            reader, writer = await open_tcp_connection(cfg.target_host, cfg.target_port)

            while True:
                seq += 1
                i += 1

                env = Envelope(agent_id=cfg.agent_id, seq=seq, record=make_record(i))
                payload = env.model_dump_json().encode("utf-8")

                await send_frame(writer, payload)

                ack_bytes = await recv_frame(reader)
                ack = json.loads(ack_bytes.decode("utf-8"))
                print(f"[agent] sent seq={seq} ack={ack}")

                await asyncio.sleep(cfg.send_interval_sec)

        except Exception as e:
            print(f"[agent] connection error: {e} (retrying in 2s)")
            await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())