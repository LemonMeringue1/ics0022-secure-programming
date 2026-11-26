# tests/test_shell.py
import builtins
import logging
from types import SimpleNamespace

import pytest

import shell
from cipher import DecryptionError
from errors import EntryError, VaultLockedError
from vault_file import VaultFormatError

MASTER = "correct horse battery staple"
ENTRY = {"username": "alice", "password": "s3cret-pass", "notes": "my notes"}


# --- test doubles -------------------------------------------------------------

class UnscriptedPrompt(BaseException):
    """Raised when the code asks for input the test did not script.
    BaseException so run_shell's `except Exception` can't swallow it."""


class Feed:
    """Scripted input() and getpass.getpass(). Exceptions in the script are raised."""

    def __init__(self, inputs, passwords):
        self._inputs, self._passwords = iter(inputs), iter(passwords)
        self.password_prompts = []

    @staticmethod
    def _emit(item):
        if isinstance(item, BaseException) or (
            isinstance(item, type) and issubclass(item, BaseException)
        ):
            raise item
        return item

    def input(self, prompt=""):
        try:
            return self._emit(next(self._inputs))
        except StopIteration:
            raise EOFError from None            # like Ctrl+D

    def getpass(self, prompt="Password: "):
        self.password_prompts.append(prompt)
        try:
            return self._emit(next(self._passwords))
        except StopIteration:
            raise UnscriptedPrompt(prompt) from None


def feed(monkeypatch, inputs=(), passwords=()):
    f = Feed(inputs, passwords)
    monkeypatch.setattr(builtins, "input", f.input)
    monkeypatch.setattr(shell.getpass, "getpass", f.getpass)
    return f


class FakeVault:
    def __init__(self, entries=None):
        self.entries = {k: dict(v) for k, v in (entries or {}).items()}
        self.locked = False
        self.edit_calls = []

    def lock(self):
        self.locked = True

    def list_name(self):
        return sorted(self.entries)

    def get(self, name):
        if name not in self.entries:
            raise EntryError("no such entry")
        return dict(self.entries[name])

    def add(self, name, username, password, notes=""):
        self.entries[name] = {"username": username, "password": password, "notes": notes}

    def edit(self, name, **fields):
        self.edit_calls.append((name, fields))
        self.entries[name].update(fields)

    def delete(self, name):
        del self.entries[name]


class FakeTimeout:
    instances = []

    def __init__(self, *a, **kw):
        self.events = []
        FakeTimeout.instances.append(self)

    def start(self):
        self.events.append("start")

    def stop(self):
        self.events.append("stop")

    def refresh(self):
        self.events.append("refresh")


# --- fixtures -------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fake_timeout(monkeypatch):
    """NEVER remove: the real Timeout SIGKILLs the whole process (pytest included)."""
    FakeTimeout.instances.clear()
    monkeypatch.setattr(shell, "Timeout", FakeTimeout)


@pytest.fixture(autouse=True)
def clipboard(monkeypatch):
    history = []
    monkeypatch.setattr(shell.pyperclip, "copy", history.append)
    return history


def existing(tmp_path):
    p = tmp_path / "vault.json"
    p.write_text("{}")
    return str(p)


@pytest.fixture
def session(monkeypatch, tmp_path, capsys):
    """Run run_shell with a FakeVault. Returns (return_code, vault, stdout)."""
    def go(inputs, *, vault=None, passwords=()):
        vault = vault if vault is not None else FakeVault({"github": ENTRY})
        monkeypatch.setattr(shell, "_unlock", lambda p: vault)
        monkeypatch.setattr(shell, "_create", lambda p: vault)
        feed(monkeypatch, inputs, passwords)
        rc = shell.run_shell(existing(tmp_path))
        return rc, vault, capsys.readouterr().out
    return go


def raiser(exc):
    def boom(*a, **kw):
        raise exc
    return boom


# --- passwords are never printed ------------------------------------------------

def test_show_masks_password():
    out = shell.cmd_show(FakeVault({"github": ENTRY}), ["github"])
    assert "Password: ********" in out
    assert "s3cret-pass" not in out


def test_list_shows_names_only():
    out = shell.cmd_list(FakeVault({"zeta": ENTRY, "alpha": ENTRY}), [])
    assert out == "alpha\nzeta"
    assert "s3cret-pass" not in out and "alice" not in out


def test_passwords_are_read_without_echo(monkeypatch):
    f = feed(monkeypatch, inputs=["alice", "notes"], passwords=["s3cret-pass"])
    shell.cmd_add(FakeVault(), ["github"])
    assert f.password_prompts == ["Password: "]


def test_copy_hides_password_and_clears_clipboard(monkeypatch, clipboard):
    started, sleeps = [], []

    class FakeThread:
        def __init__(self, target=None, daemon=None, **kw):
            self.target, self.daemon = target, daemon

        def start(self):
            started.append(self)

    monkeypatch.setattr(shell, "threading", SimpleNamespace(Thread=FakeThread))
    monkeypatch.setattr(shell, "time", SimpleNamespace(sleep=sleeps.append))

    msg = shell.cmd_copy(FakeVault({"github": ENTRY}), ["github"])
    assert "s3cret-pass" not in msg
    assert clipboard == ["s3cret-pass"]

    assert started[0].daemon is True
    started[0].target()                         # run the clearing thread now
    assert sleeps == [15]
    assert clipboard == ["s3cret-pass", ""]


# --- commands ---------------------------------------------------------------------

def test_add_stores_entry(monkeypatch):
    v = FakeVault()
    feed(monkeypatch, inputs=["alice", "my notes"], passwords=["s3cret-pass"])
    assert shell.cmd_add(v, ["github"]) == "Added 'github'."
    assert v.entries["github"] == ENTRY


def test_edit_only_changes_given_fields(monkeypatch):
    v = FakeVault({"github": ENTRY})
    feed(monkeypatch, inputs=["", "new notes"], passwords=[""])
    shell.cmd_edit(v, ["github"])
    assert v.edit_calls == [("github", {"notes": "new notes"})]
    assert v.entries["github"]["password"] == "s3cret-pass"


def test_edit_with_all_fields_empty_changes_nothing(monkeypatch):
    v = FakeVault({"github": ENTRY})
    feed(monkeypatch, inputs=["", ""], passwords=[""])
    assert shell.cmd_edit(v, ["github"]) == "No changes."
    assert v.edit_calls == []


# --- run_shell: session lifecycle ---------------------------------------------------

@pytest.mark.parametrize(
    "inputs",
    [["quit"], [], [KeyboardInterrupt], ["add site", KeyboardInterrupt]],
    ids=["quit", "eof", "ctrl-c-at-prompt", "ctrl-c-mid-command"],
)
def test_every_exit_path_locks_vault_and_stops_timer(session, inputs):
    rc, vault, _ = session(inputs)
    assert rc == 0
    assert vault.locked
    assert FakeTimeout.instances[0].events[-1] == "stop"


def test_timer_refreshed_before_each_prompt(session):
    session(["list", "list", "quit"])
    events = FakeTimeout.instances[0].events
    assert events[0] == "start"
    assert events.count("refresh") == 3


@pytest.mark.parametrize("exc,shown", [
    (EntryError("no such entry"), "no such entry"),
    (VaultLockedError("vault is locked"), "vault is locked"),
    (DecryptionError("detail hunter2"), "Vault error."),
    (VaultFormatError("detail hunter2"), "Vault error."),
    (RuntimeError("detail hunter2"), "Unexpected error."),
])
def test_errors_become_safe_messages_and_shell_survives(session, exc, shown):
    vault = FakeVault()
    vault.list_name = raiser(exc)
    rc, vault, out = session(["list", "help", "quit"], vault=vault)
    assert shown in out
    assert "hunter2" not in out                 # no internal detail leaks
    assert out.count("Commands:") == 2          # still running after the error
    assert rc == 0 and vault.locked


def test_lock_command_locks_old_vault_and_switches_to_new(monkeypatch, tmp_path, capsys):
    v1, v2 = FakeVault({"alpha": ENTRY}), FakeVault({"beta": ENTRY})
    vaults = iter([v1, v2])
    monkeypatch.setattr(shell, "_unlock", lambda p: next(vaults))
    feed(monkeypatch, ["lock", "list", "quit"])
    assert shell.run_shell(existing(tmp_path)) == 0
    out = capsys.readouterr().out
    assert v1.locked and v2.locked
    assert "beta" in out and "alpha" not in out


def test_create_retries_on_password_mismatch(monkeypatch):
    vault = object()
    monkeypatch.setattr(shell, "Vault", SimpleNamespace(create=lambda p, pw: vault))
    feed(monkeypatch, passwords=["aaa", "bbb", MASTER, MASTER])
    assert shell._create("/v") is vault


def test_no_secrets_in_logs_on_error(session, caplog):
    vault = FakeVault()
    vault.list_name = raiser(RuntimeError("detail hunter2"))
    with caplog.at_level(logging.DEBUG):
        session(["list", "quit"], vault=vault)
    assert "hunter2" not in caplog.text


def test_wrong_master_password_exits_cleanly(monkeypatch, tmp_path):
    monkeypatch.setattr(shell, "Vault", SimpleNamespace(open=raiser(DecryptionError("x"))))
    f = feed(monkeypatch, passwords=["bad"] * 10)
    assert shell.run_shell(existing(tmp_path)) == 1
    assert len(f.password_prompts) == shell.MAX_ATTEMPTS


def test_unlock_retries_after_wrong_password(monkeypatch):
    vault = object()

    def open_(path, pw):
        if pw != MASTER:
            raise DecryptionError("x")
        return vault

    monkeypatch.setattr(shell, "Vault", SimpleNamespace(open=open_))
    feed(monkeypatch, passwords=["wrong", MASTER])
    assert shell._unlock("/v") is vault


def test_timer_paused_while_reprompting_after_lock(monkeypatch, tmp_path):
    vaults = iter([FakeVault(), FakeVault()])
    states = []

    def unlock(path):
        states.append(FakeTimeout.instances[-1].events[-1] if FakeTimeout.instances else None)
        return next(vaults)

    monkeypatch.setattr(shell, "_unlock", unlock)
    feed(monkeypatch, ["lock", "quit"])
    shell.run_shell(existing(tmp_path))
    assert states[1] == "stop"


# --- one integration test with the real Vault -----------------------------------------

def test_session_persists_across_runs(monkeypatch, tmp_path, capsys):
    import vault as vault_module
    from kdf import KdfParams

    real = vault_module.derive_key
    fast = KdfParams(time_cost=1, memory_cost=64, parallelism=1)
    monkeypatch.setattr(vault_module, "derive_key", lambda pw, salt, params: real(pw, salt, fast))
    path = str(tmp_path / "vault.json")

    feed(monkeypatch, ["add github", "alice", "my notes", "quit"], [MASTER, MASTER, "s3cret-pass"])
    assert shell.run_shell(path) == 0
    out1 = capsys.readouterr().out

    feed(monkeypatch, ["list", "show github", "quit"], [MASTER])
    assert shell.run_shell(path) == 0
    out2 = capsys.readouterr().out

    assert "github" in out2 and "alice" in out2
    assert "s3cret-pass" not in out1 + out2
    assert MASTER not in out1 + out2