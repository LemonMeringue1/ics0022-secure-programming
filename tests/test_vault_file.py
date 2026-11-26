import base64
import copy
import json
import os

import pytest

import vault_file
from vault_file import VaultFormatError, load_vault, save_vault


def b64(n: int) -> str:
    return base64.b64encode(bytes(n)).decode()


VALID = {
    "version": 1,
    "kdf": {
        "name": "argon2id",
        "salt": b64(16),
        "time_cost": 1,
        "memory_cost": 64,
        "parallelism": 1,
    },
    "nonce": b64(12),
    "ct": b64(40),
}


def variant(**changes):
    """VALID with top-level changes, e.g. variant(version=2)."""
    d = copy.deepcopy(VALID)
    d.update(changes)
    return d


def kdf_variant(**changes):
    d = copy.deepcopy(VALID)
    d["kdf"].update(changes)
    return d


@pytest.fixture
def path(tmp_path):
    return str(tmp_path / "vault.json")


# --- save / load --------------------------------------------------------------

def test_round_trip(path):
    save_vault(path, VALID)
    assert load_vault(path) == VALID


def test_save_overwrites_existing_file(path):
    save_vault(path, VALID)
    newer = variant(ct=b64(80))
    save_vault(path, newer)
    assert load_vault(path) == newer


def test_must_not_exist_refuses_to_overwrite(path, tmp_path):
    save_vault(path, VALID)
    with pytest.raises(FileExistsError):
        save_vault(path, variant(ct=b64(80)), must_not_exist=True)
    assert load_vault(path) == VALID                       # original untouched
    assert os.listdir(tmp_path) == ["vault.json"]          # no temp file left behind


def test_must_not_exist_creates_new_file(path):
    save_vault(path, VALID, must_not_exist=True)
    assert load_vault(path) == VALID


def test_no_temp_files_left_after_normal_save(path, tmp_path):
    save_vault(path, VALID)
    save_vault(path, VALID)
    assert os.listdir(tmp_path) == ["vault.json"]


def test_save_validates_before_touching_disk(path, tmp_path):
    with pytest.raises(VaultFormatError):
        save_vault(path, variant(version=99))
    assert os.listdir(tmp_path) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_vault_file_is_owner_only(path):
    save_vault(path, VALID)
    assert os.stat(path).st_mode & 0o777 == 0o600


# --- load: hostile or damaged files ----------------------------------------------

@pytest.mark.parametrize("content", [
    b"",                      # empty
    b"not json at all",
    b"\xff\xfe\x00bad utf8",  # invalid UTF-8
    b"[1, 2, 3]",             # valid JSON, wrong shape
    b'"just a string"',
    b"null",
])
def test_garbage_files_rejected(path, content):
    with open(path, "wb") as f:
        f.write(content)
    with pytest.raises(VaultFormatError):
        load_vault(path)


def test_oversized_file_rejected(path, monkeypatch):
    monkeypatch.setattr(vault_file, "MAX_FILE_SIZE", 100)
    with open(path, "w") as f:
        f.write(json.dumps(VALID))                          # larger than 100 bytes
    with pytest.raises(VaultFormatError):
        load_vault(path)


# --- structure validation -----------------------------------------------------------

@pytest.mark.parametrize("bad", [
    variant(version=2),
    variant(version="1"),
    {k: v for k, v in VALID.items() if k != "nonce"},
    {k: v for k, v in VALID.items() if k != "ct"},
    {k: v for k, v in VALID.items() if k != "kdf"},
    variant(kdf="argon2id"),                          # kdf not a dict
    variant(nonce="!!!not-base64!!!"),
    variant(ct="!!!not-base64!!!"),
    variant(nonce=b64(11)),                           # wrong nonce length
    variant(nonce=b64(13)),
    kdf_variant(name="pbkdf2"),
    kdf_variant(salt=b64(15)),                        # salt too short
    kdf_variant(salt="!!!"),
    kdf_variant(salt=None),
], ids=lambda d: "")
def test_malformed_structure_rejected(path, bad):
    with pytest.raises(VaultFormatError):
        save_vault(path, bad)


@pytest.mark.parametrize("change", [
    {"time_cost": 0}, {"time_cost": 21},
    {"parallelism": 0}, {"parallelism": 17},
    {"memory_cost": 7},                  # below 8 * parallelism
    {"memory_cost": 1_048_577},          # above the cap (DoS guard)
    {"time_cost": "1"}, {"time_cost": 1.5}, {"time_cost": True}, {"memory_cost": None},
], ids=str)
def test_unsafe_kdf_parameters_rejected(path, change):
    with pytest.raises(VaultFormatError):
        save_vault(path, kdf_variant(**change))


@pytest.mark.parametrize("change", [
    {"time_cost": 1, "memory_cost": 8, "parallelism": 1},                # lower bounds
    {"time_cost": 20, "memory_cost": 1_048_576, "parallelism": 16},      # upper bounds
])
def test_boundary_kdf_parameters_accepted(path, change):
    save_vault(path, kdf_variant(**change))
    assert load_vault(path)["kdf"]["time_cost"] == change["time_cost"]


def test_validation_applies_on_load_too(path):
    """A file edited by hand to carry huge KDF params is rejected before any Argon2 work."""
    with open(path, "w") as f:
        json.dump(kdf_variant(memory_cost=1_048_577), f)
    with pytest.raises(VaultFormatError):
        load_vault(path)
