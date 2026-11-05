import base64
import json
from typing import Dict

from cipher import DecryptionError, decrypt, encrypt
from kdf import KdfParams, derive_key, new_salt
from vault_file import load_vault, save_vault

VERSION = 1
MIN_PASSWORD_LENGTH = 12


class VaultLockedError(Exception):
    """Vault is locked."""


class EntryError(Exception):
    """Entry already exists, doesn't exist or should be non-empty"""


def _b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64decode(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _aad(header: dict) -> bytes:
    return json.dumps(
        {"version": header["version"], "kdf": header["kdf"]},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def _wipe(key: bytearray) -> None:
    for i in range(len(key)):
        key[i] = 0


class Vault:
    def __init__(self, path: str, header: dict, key: bytearray, entries: dict):
        self._path = path
        self._header = header
        self._key: bytearray | None = key
        self._entries = entries # {name: {"username", "password", "notes"}}

    @classmethod
    def create(cls, path: str, master_password: str, params: KdfParams = KdfParams()) -> "Vault":
        if len(master_password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"master password must be at least {MIN_PASSWORD_LENGTH} characters")

        salt = new_salt()
        header = {
            "version": VERSION,
            "kdf": {
                "name": "argon2id",
                "salt": _b64encode(salt),
                "time_cost": params.time_cost,
                "memory_cost": params.memory_cost,
                "parallelism": params.parallelism,
            },
        }
        key = derive_key(master_password, salt, params)
        vault = cls(path, header, key, {})

        try:
            vault._write({}, must_not_exist=True)
        except BaseException:
            _wipe(key)
            raise
        return vault

    @classmethod
    def open(cls, path: str, master_password: str) -> "Vault":
        data = load_vault(path)
        kdf = data["kdf"]
        header = {"version": VERSION, "kdf": kdf}

        key = derive_key(
            master_password,
            _b64decode(kdf["salt"]),
            KdfParams(kdf["time_cost"], kdf["memory_cost"], kdf["parallelism"])
        )

        try:
            plaintext = decrypt(
                key,
                _b64decode(data["nonce"]),
                _b64decode(data["ct"]),
                _aad(header)
            )
            entries = json.loads(plaintext)

            if not isinstance(entries, Dict):
                raise DecryptionError("wrong password or corrupted/tampered vault")
        except (DecryptionError, ValueError):
            _wipe(key)
            raise DecryptionError("wrong password or corrupted/tampered vault")
        return cls(path, header, key, entries)

    def lock(self):
        if self._key is not None:
            _wipe(self._key)
            self._key = None
        self._entries = {}

    @property
    def is_locked(self) -> bool:
        return self._key is None

    def list_name(self) -> list[str]:
        self._require_unlocked()
        return sorted(self._entries)

    def get(self, name: str) -> dict:
        self._require_unlocked()
        try:
            return dict(self._entries[name])
        except KeyError:
            raise EntryError("no such entry")

    def add(self, name: str, username: str, password: str, notes: str = "") -> None:
        self._require_unlocked()
        if not name:
            raise EntryError("entry name must be non-empty")
        if name in self._entries:
            raise EntryError("entry already exists")
        self._commit(
            {**self._entries,
             name: {"username": username, "password": password, "notes": notes}}
        )

    def edit(self, name:str, **fields) -> None:
        self._require_unlocked()
        if name not in self._entries:
            raise EntryError("no such entry")
        allowed = {"username", "password", "notes"}
        if not fields or not set(fields) <= allowed:
            raise EntryError("invalid fields")
        self._commit({**self._entries, name: {**self._entries[name], **fields}})

    def delete(self, name: str) -> None:
        self._require_unlocked()
        if name not in self._entries:
            raise EntryError("no such entry")
        self._commit({k: v for k, v in self._entries.items() if k != name})

    def _require_unlocked(self) -> None:
        if self._key is None:
            raise VaultLockedError("vault is locked")

    def _commit(self, new_entries: dict) -> None:
        self._write(new_entries)
        self._entries = new_entries

    def _write(self, entries: dict, *, must_not_exist: bool = False) -> None:
        nonce, ct = encrypt(
            self._key,
            json.dumps(entries).encode("utf-8"),
            _aad(self._header)
        )
        data = {**self._header, "nonce": _b64encode(nonce), "ct": _b64encode(ct)}
        save_vault(self._path, data, must_not_exist=must_not_exist)
