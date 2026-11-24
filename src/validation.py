import unicodedata

from errors import EntryError

MAX_NAME = 64
MAX_USERNAME = 128
MAX_PASSWORD = 256
MAX_NOTES = 1024

_LIMITS = {
    "username": MAX_USERNAME,
    "password": MAX_PASSWORD,
    "notes": MAX_NOTES,
}


def _has_control_chars(s: str, allow_newline: bool = False) -> bool:
    for ch in s:
        if allow_newline and ch in "\n\t":
            continue
        if unicodedata.category(ch).startswith("C"):   # Cc, Cf, Cs, Co, Cn
            return True
    return False


def validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise EntryError("invalid entry name")

    name = unicodedata.normalize("NFC", name).strip()
    if not name or len(name) > MAX_NAME or _has_control_chars(name):
        raise EntryError("invalid entry name")
    return name


def validate_field(field: str, value: str) -> str:
    if field not in _LIMITS:
        raise EntryError("invalid fields")
    if not isinstance(value, str):
        raise EntryError(f"invalid {field}")
    if len(value) > _LIMITS[field]:
        raise EntryError(f"{field} is too long")
    if _has_control_chars(value, allow_newline=(field == "notes")):
        raise EntryError(f"{field} contains invalid characters")
    if field == "password" and not value:
        raise EntryError("password must not be empty")
    return value