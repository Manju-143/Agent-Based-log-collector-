from __future__ import annotations

import asyncio
import json

from pksl.config import ServerConfig
from pksl.models import Envelope
from pksl.storage.append_only import append_jsonl, utc_now_iso
from pksl.transport.framing import recv_frame, send_frame
from pksl.transport.tcp_async import start_tcp_server


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: ServerConfig) -> None:
    peer = writer.get_extra_info("peername")
    try:
        while True:
            data = await recv_frame(reader)
            obj = json.loads(data.decode("utf-8"))

            env = Envelope.model_validate(obj)

            stored_obj = env.model_dump()
            stored_obj["server_received_at"] = utc_now_iso()
            stored_obj["integrity_status"] = "accepted_unverified"

            path = append_jsonl(cfg.storage_dir, cfg.log_file, stored_obj)

            ack = {"ok": True, "stored_to": path, "seq": env.seq, "agent_id": env.agent_id}
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

    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await handle_client(r, w, cfg)

    server = await start_tcp_server(cfg.host, cfg.port, _handler)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"[server] listening on {addrs} | storage={cfg.storage_dir}/{cfg.log_file}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())