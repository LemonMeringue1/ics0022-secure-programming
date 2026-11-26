import logging
import threading
from types import SimpleNamespace

import pytest

import timeout
from timeout import Timeout


# --- test doubles -------------------------------------------------------------

class FakeTimer:
    """Stands in for threading.Timer so nothing runs in the background."""
    created = []

    def __init__(self, interval, function):
        self.interval, self.function = interval, function
        self.started = self.cancelled = False
        FakeTimer.created.append(self)

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True


@pytest.fixture(autouse=True)
def no_real_exit(monkeypatch):
    """NEVER remove: do_expire calls os._exit, which would kill pytest."""
    exits = []
    monkeypatch.setattr(timeout, "os", SimpleNamespace(_exit=exits.append))
    return exits


@pytest.fixture
def fake_timer(monkeypatch):
    FakeTimer.created.clear()
    monkeypatch.setattr(timeout, "threading", SimpleNamespace(Timer=FakeTimer))
    return FakeTimer


# --- start / stop / refresh logic (deterministic) -------------------------------

def test_default_timeout_is_three_minutes():
    assert Timeout().timeout == 180


def test_start_creates_and_starts_one_timer(fake_timer):
    t = Timeout(30)
    t.start()
    assert len(fake_timer.created) == 1
    timer = fake_timer.created[0]
    assert timer.started and timer.interval == 30
    assert timer.function == t._expire


def test_start_twice_does_not_create_second_timer(fake_timer):
    t = Timeout(30)
    t.start()
    t.start()
    assert len(fake_timer.created) == 1


def test_stop_cancels_timer(fake_timer):
    t = Timeout(30)
    t.start()
    t.stop()
    assert fake_timer.created[0].cancelled


def test_stop_is_safe_when_not_started_or_called_twice(fake_timer):
    t = Timeout(30)
    t.stop()                       # never started
    t.start()
    t.stop()
    t.stop()                       # already stopped
    assert len(fake_timer.created) == 1


def test_start_after_stop_creates_fresh_timer(fake_timer):
    t = Timeout(30)
    t.start()
    t.stop()
    t.start()
    assert len(fake_timer.created) == 2
    assert fake_timer.created[1].started


def test_refresh_replaces_running_timer(fake_timer):
    t = Timeout(30)
    t.start()
    t.refresh()
    old, new = fake_timer.created
    assert old.cancelled
    assert new.started and not new.cancelled


def test_refresh_does_nothing_when_not_running(fake_timer):
    Timeout(30).refresh()
    assert fake_timer.created == []


def test_refresh_after_stop_does_not_restart(fake_timer):
    t = Timeout(30)
    t.start()
    t.stop()
    t.refresh()
    assert len(fake_timer.created) == 1


# --- what happens on expiry ---------------------------------------------------------

def test_expire_runs_cleanup_before_exit(monkeypatch, capsys, caplog):
    events = []
    monkeypatch.setattr(timeout, "os", SimpleNamespace(_exit=lambda c: events.append(("exit", c))))
    with caplog.at_level(logging.INFO):
        Timeout(30, on_expire=lambda: events.append("cleanup"))._expire()
    assert events == ["cleanup", ("exit", 1)]
    assert "timed out" in capsys.readouterr().out
    assert "session_timed_out" in caplog.text


def test_expire_still_exits_if_cleanup_raises(no_real_exit):
    def bad():
        raise RuntimeError("boom hunter2")
    Timeout(30, on_expire=bad)._expire()
    assert no_real_exit == [1]


def test_expire_without_callback_exits(no_real_exit):
    Timeout(30)._expire()
    assert no_real_exit == [1]


# --- real timers (short intervals, Event-based so they are not flaky) ------------------

class Probe(Timeout):
    """Records expiry instead of signalling anything."""

    def __init__(self, timeout):
        super().__init__(timeout)
        self.expired = threading.Event()

    def do_expire(self):
        self.expired.set()


def test_real_timer_fires_after_interval():
    t = Probe(0.05)
    t.start()
    try:
        assert t.expired.wait(timeout=2)
    finally:
        t.stop()


def test_stop_prevents_expiry():
    t = Probe(0.1)
    t.start()
    t.stop()
    assert not t.expired.wait(timeout=0.4)


def test_refresh_postpones_expiry():
    t = Probe(0.4)
    t.start()
    try:
        assert not t.expired.wait(timeout=0.25)   # not yet
        t.refresh()                                # restart the 0.4 s window
        assert not t.expired.wait(timeout=0.25)   # 0.5 s since start, but only 0.25 since refresh
        assert t.expired.wait(timeout=2)           # does fire eventually
    finally:
        t.stop()


def test_timer_thread_is_daemon():
    t = Timeout(30)
    t.start()
    try:
        assert t._t.daemon is True
    finally:
        t.stop()