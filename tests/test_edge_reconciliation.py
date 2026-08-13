"""Edge heartbeat freshness and descriptive state reconciliation."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from azazel_deception.runtime.compose import DockerComposeAdapter
from azazel_deception.runtime.transport import heartbeat_is_fresh

COMPOSE = Path("runtime/compose/reference-linux.compose.yaml")


# --------------------------------------------------------------------------- #
# Heartbeat freshness
# --------------------------------------------------------------------------- #

def test_fresh_heartbeat_accepted():
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)
    issued = now - timedelta(seconds=10)
    assert heartbeat_is_fresh(issued.isoformat(), 30, now=now) is True


def test_stale_heartbeat_rejected():
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)
    issued = now - timedelta(seconds=120)
    assert heartbeat_is_fresh(issued.isoformat(), 30, now=now) is False


def test_future_heartbeat_beyond_skew_rejected():
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)
    issued = now + timedelta(seconds=60)
    assert heartbeat_is_fresh(issued, 30, now=now) is False


def test_small_future_skew_tolerated():
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)
    issued = now + timedelta(seconds=2)
    assert heartbeat_is_fresh(issued, 30, now=now) is True


def test_unparsable_heartbeat_fails_closed():
    assert heartbeat_is_fresh("not-a-timestamp", 30) is False


def test_naive_timestamp_treated_as_utc():
    now = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)
    assert heartbeat_is_fresh("2026-08-14T11:59:50", 30, now=now) is True


# --------------------------------------------------------------------------- #
# State reconciliation
# --------------------------------------------------------------------------- #

def _adapter(tmp_path):
    return DockerComposeAdapter(COMPOSE, tmp_path, live_enabled=False)


def _write_state(adapter, env_id, state):
    adapter.state.write(env_id, {"environment_id": env_id, "state": state})


def test_reconcile_consistent():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        adapter = _adapter(d)
        _write_state(adapter, "env-1", "active")
        report = adapter.reconcile_with_edge(["env-1"])
        assert report["consistent"] is True
        assert report["authority"] == "descriptive_only"
        assert report["local_only_active"] == []
        assert report["edge_only_active"] == []


def test_reconcile_flags_local_only_active():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        adapter = _adapter(d)
        _write_state(adapter, "env-1", "active")  # running locally
        _write_state(adapter, "env-2", "terminated")
        report = adapter.reconcile_with_edge([])  # Edge authorizes nothing active
        assert report["consistent"] is False
        assert report["local_only_active"] == ["env-1"]
        assert report["edge_only_active"] == []


def test_reconcile_flags_edge_only_active():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        adapter = _adapter(d)
        _write_state(adapter, "env-1", "active")
        report = adapter.reconcile_with_edge(["env-1", "env-missing"])
        assert report["consistent"] is False
        assert report["edge_only_active"] == ["env-missing"]
        assert report["local_only_active"] == []
