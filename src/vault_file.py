import base64
import json
import os
import stat
import tempfile

SUPPORTED_VERSION = 1
MAX_FILE_SIZE = 10 * 1024 * 1024


class VaultFormatError(Exception):
    """Vault file is missing fields, malformed or has incorrect parameters."""


def load_vault(path: str) -> dict:
    real = os.path.realpath(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(real, flags)

    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_SIZE:
            raise VaultFormatError("invalid vault file")
        raw = f.read(MAX_FILE_SIZE + 1)

    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise VaultFormatError("invalid vault file") from None

    _validate(data)
    return data


def save_vault(path: str, data: dict, *, must_not_exist: bool = False) -> None:
    _validate(data)
    real = os.path.realpath(path)
    directory = os.path.dirname(real)
    payload = json.dumps(data, indent=2).encode("utf-8")

    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".vault", suffix=".tmp")

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())

        if must_not_exist:
            os.link(tmp, real)
            os.unlink(tmp)
        else:
            os.replace(tmp, real)
        _fsync_dir(directory)


    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _fsync_dir(directory: str) -> None:
    if not hasattr(os, "O_DIRECTORY"):          # not available on windows
        return
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _validate(data: object) -> None:
    if not isinstance(data, dict):
        raise VaultFormatError("invalid vault file")
    if data.get("version") != SUPPORTED_VERSION:
        raise VaultFormatError("unsupported vault version")

    kdf = data.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != "argon2id":
        raise VaultFormatError("invalid vault file")

    try:
        t, m, p = kdf["time_cost"], kdf["memory_cost"], kdf["parallelism"]
        salt = base64.b64decode(kdf["salt"], validate=True)
        nonce = base64.b64decode(data["nonce"], validate=True)
        base64.b64decode(data["ct"], validate=True)
    except (KeyError, TypeError, ValueError):
        raise VaultFormatError("invalid vault file") from None

    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (t, m, p)):
        raise VaultFormatError("invalid vault file")
    if not (1 <= t <= 20 and 1 <= p <= 16 and 8 * p <= m <= 1_048_576):
        raise VaultFormatError("unsafe KDF parameters")
    if len(salt) < 16 or len(nonce) != 12:
        raise VaultFormatError("invalid vault file")