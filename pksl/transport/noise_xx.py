from __future__ import annotations

import asyncio
from noise.connection import NoiseConnection, Keypair

from pksl.transport.framing import send_frame, recv_frame

# Authenticated pattern (requires static keypair 's' on both sides)
NOISE_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"


async def noise_xx_handshake_initiator(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    static_private_key_path: str,
) -> NoiseConnection:
    """
    Initiator (agent) side of XX:
      -> e
      <- e, ee, s, es
      -> s, se
    Requires local static keypair 's' to be configured.
    """
    noise = NoiseConnection.from_name(NOISE_NAME)
    noise.set_as_initiator()
    noise.set_keypair_from_private_path(Keypair.STATIC, static_private_key_path)
    noise.start_handshake()

    msg1 = noise.write_message()
    await send_frame(writer, msg1)

    msg2 = await recv_frame(reader)
    noise.read_message(msg2)

    msg3 = noise.write_message()
    await send_frame(writer, msg3)

    if not noise.handshake_finished:
        raise RuntimeError("Noise XX handshake did not finish (initiator)")

    return noise


async def noise_xx_handshake_responder(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    static_private_key_path: str,
) -> NoiseConnection:
    """
    Responder (server) side of XX.
    Requires local static keypair 's' to be configured.
    """
    noise = NoiseConnection.from_name(NOISE_NAME)
    noise.set_as_responder()
    noise.set_keypair_from_private_path(Keypair.STATIC, static_private_key_path)
    noise.start_handshake()

    msg1 = await recv_frame(reader)
    noise.read_message(msg1)

    msg2 = noise.write_message()
    await send_frame(writer, msg2)

    msg3 = await recv_frame(reader)
    noise.read_message(msg3)

    if not noise.handshake_finished:
        raise RuntimeError("Noise XX handshake did not finish (responder)")

    return noise


def noise_encrypt(noise: NoiseConnection, plaintext: bytes) -> bytes:
    return noise.encrypt(plaintext)


def noise_decrypt(noise: NoiseConnection, ciphertext: bytes) -> bytes:
    return noise.decrypt(ciphertext)