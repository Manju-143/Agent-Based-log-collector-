from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

ClientHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def start_tcp_server(host: str, port: int, handler: ClientHandler) -> asyncio.AbstractServer:
    return await asyncio.start_server(handler, host, port)


async def open_tcp_connection(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection(host, port)