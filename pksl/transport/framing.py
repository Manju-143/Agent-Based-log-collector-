from __future__ import annotations

import asyncio
import struct

_MAX_FRAME = 10 * 1024 * 1024  # 10MB cap


async def send_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    header = struct.pack("!I", len(payload))
    writer.write(header + payload)
    await writer.drain()


async def recv_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > _MAX_FRAME:
        raise ValueError(f"Invalid frame length: {length}")
    return await reader.readexactly(length)