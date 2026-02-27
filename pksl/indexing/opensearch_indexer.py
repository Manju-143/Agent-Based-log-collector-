from __future__ import annotations

import os
from typing import Any, Dict, Optional

from opensearchpy import OpenSearch


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


class OpenSearchIndexer:
    """
    Non-authoritative indexing. Failure must NOT break log ingestion.
    """

    def __init__(self) -> None:
        self.enabled = _env("PKSL_OS_ENABLED", "0") == "1"
        self.host = _env("PKSL_OS_HOST", "localhost")
        self.port = int(_env("PKSL_OS_PORT", "9200"))
        self.index = _env("PKSL_OS_INDEX", "pksl-verified-logs")

        # OpenSearch security (docker default)
        self.username = _env("PKSL_OS_USER", "admin")
        self.password = _env("PKSL_OS_PASS", "")
        self.use_ssl = _env("PKSL_OS_SSL", "1") == "1"
        self.verify_certs = _env("PKSL_OS_VERIFY_CERTS", "0") == "1"

        self.client: Optional[OpenSearch] = None
        if self.enabled:
            self.client = OpenSearch(
                hosts=[{"host": self.host, "port": self.port}],
                http_auth=(self.username, self.password) if self.password else None,
                use_ssl=self.use_ssl,
                verify_certs=self.verify_certs,
                ssl_show_warn=False,
                http_compress=True,
            )

    def ensure_index(self) -> None:
        if not self.enabled or not self.client:
            return
        try:
            if self.client.indices.exists(self.index):
                return

            mapping = {
                "mappings": {
                    "properties": {
                        "agent_id": {"type": "keyword"},
                        "seq": {"type": "long"},
                        "session_id": {"type": "keyword"},
                        "server_received_at": {"type": "date"},
                        "integrity_status": {"type": "keyword"},
                        "record.timestamp": {"type": "date"},
                        "record.event_type": {"type": "keyword"},
                        "record.severity": {"type": "keyword"},
                        "record.message": {"type": "text"},
                    }
                }
            }
            self.client.indices.create(index=self.index, body=mapping)
        except Exception:
            return

    def index_log(self, doc: Dict[str, Any]) -> None:
        if not self.enabled or not self.client:
            return
        try:
            doc_id = f"{doc.get('agent_id')}:{doc.get('seq')}"
            self.client.index(index=self.index, id=doc_id, body=doc, refresh=False)
        except Exception:
            return