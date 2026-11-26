import dataclasses

import pytest
from argon2.low_level import Type, hash_secret_raw

from kdf import KEY_LEN, SALT_LEN, KdfParams, derive_key, new_salt

# Cheap parameters so the suite stays fast. Argon2 requires
# memory_cost >= 8 * parallelism.
FAST = KdfParams(time_cost=1, memory_cost=64, parallelism=1)
SALT = bytes(range(SALT_LEN))
PASSWORD = "correct horse battery staple"


# --- new_salt -------------------------------------------------------------

def test_new_salt_length():
    assert len(new_salt()) == SALT_LEN == 16


def test_new_salt_is_bytes():
    assert isinstance(new_salt(), bytes)


def test_new_salt_is_unique():
    salts = {new_salt() for _ in range(200)}
    assert len(salts) == 200


# --- derive_key: output shape ---------------------------------------------

def test_key_length():
    assert len(derive_key(PASSWORD, SALT, FAST)) == KEY_LEN == 32


def test_key_is_bytearray():
    # bytearray (not bytes) so the vault can zeroize it after use
    assert isinstance(derive_key(PASSWORD, SALT, FAST), bytearray)


def test_key_is_mutable_and_wipeable():
    key = derive_key(PASSWORD, SALT, FAST)
    for i in range(len(key)):
        key[i] = 0
    assert key == bytearray(KEY_LEN)


def test_each_call_returns_independent_object():
    k1 = derive_key(PASSWORD, SALT, FAST)
    k2 = derive_key(PASSWORD, SALT, FAST)
    assert k1 is not k2
    k1[0] ^= 0xFF
    assert k1 != k2          # wiping one must not affect the other


# --- derive_key: determinism and sensitivity --------------------------------

def test_deterministic():
    assert derive_key(PASSWORD, SALT, FAST) == derive_key(PASSWORD, SALT, FAST)


def test_different_password_gives_different_key():
    assert derive_key("password-one-xx", SALT, FAST) != derive_key("password-two-xx", SALT, FAST)


def test_different_salt_gives_different_key():
    other = bytearray(SALT)
    other[0] ^= 0x01
    assert derive_key(PASSWORD, SALT, FAST) != derive_key(PASSWORD, bytes(other), FAST)


@pytest.mark.parametrize("changed", [
    KdfParams(time_cost=2, memory_cost=64, parallelism=1),
    KdfParams(time_cost=1, memory_cost=128, parallelism=1),
    KdfParams(time_cost=1, memory_cost=64, parallelism=2),
])
def test_each_parameter_affects_key(changed):
    assert derive_key(PASSWORD, SALT, FAST) != derive_key(PASSWORD, SALT, changed)


def test_password_is_case_sensitive():
    assert derive_key("Password-123456", SALT, FAST) != derive_key("password-123456", SALT, FAST)


# --- derive_key: input handling ---------------------------------------------

@pytest.mark.parametrize("pw", ["", "a", "x" * 1000, "pässwörd-日本語-🔑"])
def test_various_passwords_accepted(pw):
    assert len(derive_key(pw, SALT, FAST)) == KEY_LEN


def test_unicode_is_encoded_as_utf8():
    pw = "pässwörd-日本語"
    expected = hash_secret_raw(
        secret=pw.encode("utf-8"), salt=SALT,
        time_cost=1, memory_cost=64, parallelism=1,
        hash_len=32, type=Type.ID,
    )
    assert derive_key(pw, SALT, FAST) == bytearray(expected)


@pytest.mark.parametrize("size", [0, 1, SALT_LEN - 1])
def test_short_salt_rejected(size):
    with pytest.raises(ValueError):
        derive_key(PASSWORD, bytes(size), FAST)


def test_salt_of_exact_minimum_length_accepted():
    assert len(derive_key(PASSWORD, bytes(SALT_LEN), FAST)) == KEY_LEN


def test_longer_salt_accepted():
    assert len(derive_key(PASSWORD, bytes(32), FAST)) == KEY_LEN


# --- algorithm check ----------------------------------------------------------

def test_uses_argon2id_with_32_byte_output():
    """Guards against silently switching variant (argon2i/argon2d) or length."""
    expected = hash_secret_raw(
        secret=PASSWORD.encode("utf-8"), salt=SALT,
        time_cost=1, memory_cost=64, parallelism=1,
        hash_len=32, type=Type.ID,
    )
    assert derive_key(PASSWORD, SALT, FAST) == bytearray(expected)


def test_not_argon2i_or_argon2d():
    for variant in (Type.I, Type.D):
        other = hash_secret_raw(
            secret=PASSWORD.encode("utf-8"), salt=SALT,
            time_cost=1, memory_cost=64, parallelism=1,
            hash_len=32, type=variant,
        )
        assert derive_key(PASSWORD, SALT, FAST) != bytearray(other)


# --- KdfParams ---------------------------------------------------------------

def test_default_params():
    p = KdfParams()
    assert (p.time_cost, p.memory_cost, p.parallelism) == (6, 131072, 4)


def test_default_params_meet_minimum_recommendation():
    # OWASP minimum for Argon2id is e.g. m=19 MiB, t=2, p=1;
    # memory_cost is in KiB.
    p = KdfParams()
    assert p.memory_cost >= 19 * 1024
    assert p.time_cost >= 2
    assert p.parallelism >= 1


def test_params_are_frozen():
    p = KdfParams()
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.time_cost = 1


def test_params_equality_and_positional_construction():
    # Vault.open builds KdfParams(time, memory, parallelism) positionally
    assert KdfParams(1, 64, 1) == FAST


# --- slow test: real parameters -------------------------------------------------

@pytest.mark.slow
def test_default_params_work_end_to_end():
    key = derive_key(PASSWORD, SALT, KdfParams())
    assert len(key) == KEY_LEN