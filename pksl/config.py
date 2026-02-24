from __future__ import annotations

import os
from dataclasses import dataclass


def _get_env(name: str, default: str | None = None) -> str:
    v = os.getenv(name, default)
    if v is None:
        raise RuntimeError(f"Missing required env var: {name}")
    return v


def _get_env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as e:
        raise RuntimeError(f"Invalid int for {name}: {raw}") from e


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int
    storage_dir: str
    log_file: str

    @staticmethod
    def from_env() -> "ServerConfig":
        return ServerConfig(
            host=_get_env("PKSL_SERVER_HOST", "0.0.0.0"),
            port=_get_env_int("PKSL_SERVER_PORT", 9000),
            storage_dir=_get_env("PKSL_STORAGE_DIR", "./data"),
            log_file=_get_env("PKSL_LOG_FILE", "verified_logs.jsonl"),
        )


@dataclass(frozen=True)
class AgentConfig:
    agent_id: str
    target_host: str
    target_port: int
    send_interval_sec: int

    @staticmethod
    def from_env() -> "AgentConfig":
        return AgentConfig(
            agent_id=_get_env("PKSL_AGENT_ID", "agent-01"),
            target_host=_get_env("PKSL_TARGET_HOST", "127.0.0.1"),
            target_port=_get_env_int("PKSL_TARGET_PORT", 9000),
            send_interval_sec=_get_env_int("PKSL_SEND_INTERVAL_SEC", 2),
        )