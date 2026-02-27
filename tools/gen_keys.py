from __future__ import annotations

import os

from pksl.crypto.signing import (
    generate_ed25519_keypair,
    save_private_key_pem,
    save_public_key_pem,
)

from pksl.crypto.noise_static import (
    generate_x25519_keypair,
    save_x25519_private_raw,
    save_x25519_public_raw,
)


KEYS_DIR = "./keys"


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def gen_ed25519(agent_id: str) -> None:
    kp = generate_ed25519_keypair()

    priv = os.path.join(KEYS_DIR, f"{agent_id}_ed25519_private.pem")
    pub = os.path.join(KEYS_DIR, f"{agent_id}_ed25519_public.pem")

    save_private_key_pem(priv, kp.private)
    save_public_key_pem(pub, kp.public)

    print(f"[OK] Ed25519 keys generated for {agent_id}")


def gen_noise_static(agent_id: str) -> None:
    kp = generate_x25519_keypair()

    priv = os.path.join(KEYS_DIR, f"{agent_id}_noise_private.key")
    pub = os.path.join(KEYS_DIR, f"{agent_id}_noise_public.key")

    save_x25519_private_raw(priv, kp.private)
    save_x25519_public_raw(pub, kp.public)

    print(f"[OK] Noise static keys generated for {agent_id}")


def main() -> None:
    ensure_dir(KEYS_DIR)

    # agent identity
    gen_ed25519("agent-01")
    gen_noise_static("agent-01")

    # server transport identity (Noise static)
    gen_noise_static("server")


if __name__ == "__main__":
    main()