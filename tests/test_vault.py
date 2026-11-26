import base64
import json
import logging

import pytest

import vault as vault_module
from cipher import DecryptionError
from errors import EntryError, VaultLockedError
from kdf import KdfParams
from vault import Vault

FAST = KdfParams(time_cost=1, memory_cost=64, parallelism=1)
MASTER = "correct horse battery"
SECRET = "s3cret-pass"


@pytest.fixture
def path(tmp_path):
    return str(tmp_path / "vault.json")


@pytest.fixture
def v(path):
    vault = Vault.create(path, MASTER, FAST)
    yield vault
    vault.lock()


def is_zeroed(key) -> bool:
    return all(b == 0 for b in key)


# --- create / open ---------------------------------------------------------

def test_entries_persist_across_lock_and_reopen(path, v):
    v.add("github", "alice", SECRET, "notes")
    v.lock()
    v2 = Vault.open(path, MASTER)
    assert v2.get("github") == {"username": "alice", "password": SECRET, "notes": "notes"}
    v2.lock()


@pytest.mark.parametrize("pw", ["short", "x" * 1025])
def test_create_rejects_bad_master_password_length(path, pw):
    with pytest.raises(ValueError):
        Vault.create(path, pw, FAST)


def test_wrong_password_rejected(path, v):
    v.lock()
    with pytest.raises(DecryptionError):
        Vault.open(path, "wrong password!!")


def test_tampered_ciphertext_rejected(path, v):
    v.add("github", "alice", SECRET)
    v.lock()
    with open(path) as f:
        data = json.load(f)
    ct = bytearray(base64.b64decode(data["ct"]))
    ct[0] ^= 0x01
    data["ct"] = base64.b64encode(bytes(ct)).decode()
    with open(path, "w") as f:
        json.dump(data, f)
    with pytest.raises(DecryptionError):
        Vault.open(path, MASTER)


def test_file_on_disk_contains_no_plaintext(path, v):
    v.add("github", "alice", SECRET, "my notes")
    with open(path, "rb") as f:
        raw = f.read()
    for secret in (SECRET.encode(), b"alice", b"my notes", MASTER.encode()):
        assert secret not in raw


# --- memory handling -----------------------------------------------------------

def test_lock_zeroizes_key_and_blocks_operations(v):
    key = v._key
    v.add("github", "alice", SECRET)
    v.lock()
    assert is_zeroed(key)
    assert v.is_locked
    for call in (v.list_name, lambda: v.get("github"), lambda: v.add("x", "u", "p")):
        with pytest.raises(VaultLockedError):
            call()


def test_lock_twice_is_safe(v):
    v.lock()
    v.lock()
    assert v.is_locked


def test_key_wiped_after_wrong_password(path, v, monkeypatch):
    v.lock()
    keys = []
    real = vault_module.derive_key
    monkeypatch.setattr(vault_module, "derive_key",
                        lambda *a, **k: keys.append(real(*a, **k)) or keys[-1])
    with pytest.raises(DecryptionError):
        Vault.open(path, "wrong password!!")
    assert is_zeroed(keys[0])


def test_key_wiped_after_unexpected_error_in_open(path, v, monkeypatch):
    v.lock()
    keys = []
    real = vault_module.derive_key
    monkeypatch.setattr(vault_module, "derive_key",
                        lambda *a, **k: keys.append(real(*a, **k)) or keys[-1])

    def boom(*a, **k):
        raise KeyError("x")

    monkeypatch.setattr(vault_module, "decrypt", boom)
    with pytest.raises(KeyError):
        Vault.open(path, MASTER)
    assert is_zeroed(keys[0])


# --- entry operations ---------------------------------------------------------------

def test_list_is_sorted(v):
    v.add("zeta", "u", "p")
    v.add("alpha", "u", "p")
    assert v.list_name() == ["alpha", "zeta"]


def test_edit_changes_only_given_fields(path, v):
    v.add("github", "alice", SECRET, "notes")
    v.edit("github", notes="new")
    assert v.get("github") == {"username": "alice", "password": SECRET, "notes": "new"}


def test_delete_removes_entry(v):
    v.add("github", "alice", SECRET)
    v.delete("github")
    assert v.list_name() == []


def test_get_returns_a_copy(v):
    v.add("github", "alice", SECRET)
    v.get("github")["password"] = "changed"
    assert v.get("github")["password"] == SECRET


def test_duplicate_and_missing_entries_rejected(v):
    v.add("github", "alice", SECRET)
    with pytest.raises(EntryError):
        v.add("github", "bob", "p")
    for call in (lambda: v.get("nope"), lambda: v.delete("nope"), lambda: v.edit("nope", notes="x")):
        with pytest.raises(EntryError):
            call()


# --- validation wiring (rules themselves are tested in test_validation.py) --------------

def test_invalid_input_rejected_and_vault_unchanged(path, v):
    v.add("github", "alice", SECRET)
    with open(path, "rb") as f:
        before = f.read()
    with pytest.raises(EntryError):
        v.add("bad\x1bname", "u", "p")
    with pytest.raises(EntryError):
        v.edit("github", password="")
    with pytest.raises(EntryError):
        v.edit("github", unknown="x")
    with pytest.raises(EntryError):
        v.edit("github")
    assert v.list_name() == ["github"]
    with open(path, "rb") as f:
        assert f.read() == before


def test_failed_write_leaves_memory_state_unchanged(v, monkeypatch):
    monkeypatch.setattr(vault_module, "save_vault", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        v.add("github", "alice", SECRET)
    assert v.list_name() == []


# --- logging ----------------------------------------------------------------------------

def test_no_secrets_in_logs(path, v, caplog):
    with caplog.at_level(logging.DEBUG):
        v.add("github", "alice", SECRET, "my notes")
        v.edit("github", password="new-secret-pass")
        v.delete("github")
        v.lock()
        with pytest.raises(DecryptionError):
            Vault.open(path, "wrong password!!")
    for secret in (SECRET, "new-secret-pass", "alice", "my notes", MASTER, "wrong password!!"):
        assert secret not in caplog.text
    assert "unlock_failed" in caplog.text