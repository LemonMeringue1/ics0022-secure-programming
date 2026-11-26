# tests/test_validation.py
import pytest

from errors import EntryError
from validation import (
    MAX_NAME, MAX_NOTES, MAX_PASSWORD, MAX_USERNAME,
    validate_field, validate_name,
)


# --- validate_name ----------------------------------------------------------

@pytest.mark.parametrize("name", ["github", "my site", "bank-xyz_2", "päss-日本語", "a", "\u2401"])
def test_valid_names_accepted(name):
    assert validate_name(name) == name


@pytest.mark.parametrize("bad", [
    "",                 # empty
    "   ",              # whitespace only
    "x\x1b[31m",        # ANSI escape (terminal injection)
    "a\nb",             # newline (log-line forgery)
    "a\rb",
    "a\x00b",           # NUL
    "a\u200bb",         # zero-width space (Cf)
    "a\u202eb",         # right-to-left override (Cf)
    "a\ud800b",         # lone surrogate (Cs)
])
def test_bad_names_rejected(bad):
    with pytest.raises(EntryError):
        validate_name(bad)


@pytest.mark.parametrize("bad", [None, 123, b"bytes", ["a"]])
def test_non_string_name_rejected(bad):
    with pytest.raises(EntryError):
        validate_name(bad)


def test_name_length_boundary():
    assert validate_name("a" * MAX_NAME) == "a" * MAX_NAME
    with pytest.raises(EntryError):
        validate_name("a" * (MAX_NAME + 1))


def test_name_is_stripped():
    assert validate_name("  github  ") == "github"


def test_name_is_nfc_normalized():
    assert validate_name("cafe\u0301") == "caf\u00e9"      # decomposed -> precomposed
    assert validate_name("cafe\u0301") == validate_name("caf\u00e9")


def test_length_checked_after_strip():
    assert validate_name(" " + "a" * MAX_NAME + " ") == "a" * MAX_NAME


def test_name_error_does_not_echo_input():
    with pytest.raises(EntryError) as e:
        validate_name("secret\x1b-name")
    assert "secret" not in str(e.value)


# --- validate_field: accepted values -------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("username", "alice"),
    ("username", ""),                       # empty username allowed
    ("password", "p@ss w0rd!§日本語🔑"),     # any printable characters
    ("notes", ""),
    ("notes", "line1\nline2\tindented"),    # newline/tab allowed in notes only
])
def test_valid_fields_accepted(field, value):
    assert validate_field(field, value) == value


@pytest.mark.parametrize("field,limit", [
    ("username", MAX_USERNAME), ("password", MAX_PASSWORD), ("notes", MAX_NOTES),
])
def test_field_length_boundary(field, limit):
    assert validate_field(field, "x" * limit) == "x" * limit
    with pytest.raises(EntryError):
        validate_field(field, "x" * (limit + 1))


# --- validate_field: rejected values ----------------------------------------------

@pytest.mark.parametrize("field", ["username", "password", "notes"])
@pytest.mark.parametrize("bad", ["a\x00b", "a\x1bb", "a\u200bb", "a\u202eb"])
def test_control_characters_rejected_in_all_fields(field, bad):
    with pytest.raises(EntryError):
        validate_field(field, bad)


@pytest.mark.parametrize("field", ["username", "password"])
@pytest.mark.parametrize("bad", ["a\nb", "a\tb", "a\rb"])
def test_newline_and_tab_rejected_outside_notes(field, bad):
    with pytest.raises(EntryError):
        validate_field(field, bad)


def test_carriage_return_rejected_even_in_notes():
    with pytest.raises(EntryError):
        validate_field("notes", "a\rb")


def test_empty_password_rejected():
    with pytest.raises(EntryError):
        validate_field("password", "")


@pytest.mark.parametrize("field", ["username", "password", "notes"])
@pytest.mark.parametrize("bad", [None, 123, b"bytes"])
def test_non_string_value_rejected(field, bad):
    with pytest.raises(EntryError):
        validate_field(field, bad)


@pytest.mark.parametrize("field", ["name", "id", "", "USERNAME", None])
def test_unknown_field_rejected(field):
    with pytest.raises(EntryError):
        validate_field(field, "value")


def test_field_error_does_not_echo_value():
    with pytest.raises(EntryError) as e:
        validate_field("password", "hunter2\x00")
    assert "hunter2" not in str(e.value)


def test_password_not_stripped_or_altered():
    assert validate_field("password", "  spaced  ") == "  spaced  "