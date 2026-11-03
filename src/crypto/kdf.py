import secrets
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

SALT_LEN = 16
KEY_LEN = 32


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 6
    memory_cost: int = 131072
    parallelism: int = 4


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_LEN)


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytearray:
    """Derive a 32-byte vault key from the master password using Argon2id."""
    if len(salt) < SALT_LEN:
        raise ValueError("salt too short")

    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID
    )
    return bytearray(raw)
