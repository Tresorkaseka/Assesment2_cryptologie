from datetime import datetime, timedelta, timezone

from server.app.session_store import SessionStore


def test_session_expiry() -> None:
    store = SessionStore()
    record = store.create("client", "session", b"0" * 32, ttl_seconds=3600)
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert store.get("session") is None

