from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional


@dataclass(slots=True)
class SessionRecord:
    client_id: str
    session_id: str
    aes_key: bytes
    expires_at: datetime

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now >= self.expires_at


class SessionStore:
    def __init__(self) -> None:
        self._records: dict[str, SessionRecord] = {}
        self._lock = threading.Lock()

    def create(self, client_id: str, session_id: str, aes_key: bytes, ttl_seconds: int) -> SessionRecord:
        record = SessionRecord(
            client_id=client_id,
            session_id=session_id,
            aes_key=aes_key,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._records[session_id] = record
        return record

    def get(self, session_id: str) -> Optional[SessionRecord]:
        now = datetime.now(timezone.utc)
        with self._lock:
            record = self._records.get(session_id)
            if record is None:
                return None
            if record.is_expired(now):
                self._records.pop(session_id, None)
                return None
            return record

    def purge_expired(self) -> int:
        now = datetime.now(timezone.utc)
        removed = 0
        with self._lock:
            for session_id, record in list(self._records.items()):
                if record.is_expired(now):
                    self._records.pop(session_id, None)
                    removed += 1
        return removed

