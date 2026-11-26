import pytest

from cipher import NONCE_LEN, DecryptionError, decrypt, encrypt

AAD = b"header-v1"
PT = b"super secret vault contents"


@pytest.fixture
def key() -> bytearray:
    return bytearray(range(32))


def flip_bit(data: bytes, index: int = 0) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


# --- round trip ---------------------------------------------------------

def test_round_trip(key):
    nonce, ct = encrypt(key, PT, AAD)
    assert decrypt(key, nonce, ct, AAD) == PT


@pytest.mark.parametrize("pt", [b"", b"a", b"x" * 10_000])
def test_round_trip_various_sizes(key, pt):
    nonce, ct = encrypt(key, pt, AAD)
    assert decrypt(key, nonce, ct, AAD) == pt


def test_round_trip_empty_aad(key):
    nonce, ct = encrypt(key, PT, b"")
    assert decrypt(key, nonce, ct, b"") == PT


def test_accepts_bytearray_and_bytes_key(key):
    nonce, ct = encrypt(key, PT, AAD)
    assert decrypt(bytes(key), nonce, ct, AAD) == PT


# --- output shape -------------------------------------------------------

def test_nonce_length(key):
    nonce, _ = encrypt(key, PT, AAD)
    assert len(nonce) == NONCE_LEN == 12


def test_ciphertext_is_plaintext_plus_16_byte_tag(key):
    _, ct = encrypt(key, PT, AAD)
    assert len(ct) == len(PT) + 16


def test_ciphertext_does_not_contain_plaintext(key):
    _, ct = encrypt(key, PT, AAD)
    assert PT not in ct


def test_nonce_is_fresh_each_call(key):
    nonces = {encrypt(key, PT, AAD)[0] for _ in range(200)}
    assert len(nonces) == 200


def test_same_plaintext_gives_different_ciphertext(key):
    _, ct1 = encrypt(key, PT, AAD)
    _, ct2 = encrypt(key, PT, AAD)
    assert ct1 != ct2


# --- authentication / tamper detection -----------------------------------

def test_wrong_key_rejected(key):
    nonce, ct = encrypt(key, PT, AAD)
    other = bytearray(key)
    other[0] ^= 0xFF
    with pytest.raises(DecryptionError):
        decrypt(other, nonce, ct, AAD)


@pytest.mark.parametrize("index", [0, 5, -1])   # first, middle, last (tag) byte
def test_tampered_ciphertext_rejected(key, index):
    nonce, ct = encrypt(key, PT, AAD)
    with pytest.raises(DecryptionError):
        decrypt(key, nonce, flip_bit(ct, index), AAD)


def test_tampered_nonce_rejected(key):
    nonce, ct = encrypt(key, PT, AAD)
    with pytest.raises(DecryptionError):
        decrypt(key, flip_bit(nonce), ct, AAD)


def test_tampered_aad_rejected(key):
    nonce, ct = encrypt(key, PT, AAD)
    with pytest.raises(DecryptionError):
        decrypt(key, nonce, ct, b"header-v2")


def test_truncated_ciphertext_rejected(key):
    nonce, ct = encrypt(key, PT, AAD)
    with pytest.raises(DecryptionError):
        decrypt(key, nonce, ct[:-1], AAD)


def test_appended_data_rejected(key):
    nonce, ct = encrypt(key, PT, AAD)
    with pytest.raises(DecryptionError):
        decrypt(key, nonce, ct + b"\x00", AAD)


def test_decryption_error_message_is_generic(key):
    nonce, ct = encrypt(key, PT, AAD)
    with pytest.raises(DecryptionError) as exc:
        decrypt(key, nonce, flip_bit(ct), AAD)
    msg = str(exc.value)
    assert PT.decode() not in msg
    assert exc.value.__cause__ is None      # `from None` suppresses InvalidTag chaining


# --- key length validation ------------------------------------------------

@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_encrypt_rejects_bad_key_length(size):
    with pytest.raises(ValueError):
        encrypt(bytearray(size), PT, AAD)


@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_decrypt_rejects_bad_key_length(key, size):
    nonce, ct = encrypt(key, PT, AAD)
    with pytest.raises(ValueError):
        decrypt(bytearray(size), nonce, ct, AAD)


# --- known-answer test ----------------------------------------------------

def test_known_answer_decrypts():
    """Guards against accidentally changing the algorithm or parameters.

    Ciphertext is generated once with the standard library to be independent
    of the code under test.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    k = bytes(32)
    n = bytes(12)
    expected_ct = AESGCM(k).encrypt(n, b"hello", b"aad")
    assert decrypt(bytearray(k), n, expected_ct, b"aad") == b"hello"