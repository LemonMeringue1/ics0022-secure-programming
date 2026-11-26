import logging
import os
import re

import pytest

from setup_logging import setup_logging


@pytest.fixture
def root_logger():
    """Isolate the root logger: restore level and handlers after each test.

    setup_logging mutates global state, so without this, handlers pile up
    across tests and pytest's own caplog handler could be disturbed.
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    yield root
    for h in root.handlers[:]:
        if h not in saved_handlers:
            root.removeHandler(h)
            h.close()
    root.setLevel(saved_level)


@pytest.fixture
def log_path(tmp_path):
    return str(tmp_path / "log.log")


def _file_handlers(root, path):
    return [
        h for h in root.handlers
        if isinstance(h, logging.FileHandler)
        and os.path.realpath(h.baseFilename) == os.path.realpath(path)
    ]


def _flush(root):
    for h in root.handlers:
        h.flush()


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# --- file creation ----------------------------------------------------------

def test_log_file_created(root_logger, log_path):
    assert not os.path.exists(log_path)
    setup_logging(log_path)
    assert os.path.isfile(log_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_log_file_created_owner_only(root_logger, log_path):
    setup_logging(log_path)
    assert os.stat(log_path).st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_permissions_applied_before_handler_opens_file(root_logger, log_path, monkeypatch):
    """The file must already be 0o600 when logging.FileHandler opens it."""
    seen = {}
    real_init = logging.FileHandler.__init__

    def spy(self, filename, *a, **kw):
        seen["mode"] = os.stat(filename).st_mode & 0o777
        real_init(self, filename, *a, **kw)

    monkeypatch.setattr(logging.FileHandler, "__init__", spy)
    setup_logging(log_path)
    assert seen["mode"] == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_existing_file_permissions_not_loosened(root_logger, log_path):
    with open(log_path, "w") as f:
        f.write("old\n")
    os.chmod(log_path, 0o600)
    setup_logging(log_path)
    assert os.stat(log_path).st_mode & 0o777 == 0o600


def test_existing_content_is_preserved(root_logger, log_path):
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("previous line\n")
    setup_logging(log_path)
    logging.getLogger("t").info("new")
    _flush(root_logger)
    content = _read(log_path)
    assert content.startswith("previous line\n")
    assert "event=new" in content


def test_missing_directory_raises(root_logger, tmp_path):
    with pytest.raises(OSError):
        setup_logging(str(tmp_path / "nope" / "log.log"))


def test_failure_leaves_no_handler_installed(root_logger, tmp_path):
    before = root_logger.handlers[:]
    with pytest.raises(OSError):
        setup_logging(str(tmp_path / "nope" / "log.log"))
    assert root_logger.handlers == before


# --- handler and level --------------------------------------------------------

def test_adds_one_file_handler(root_logger, log_path):
    setup_logging(log_path)
    assert len(_file_handlers(root_logger, log_path)) == 1


def test_handler_uses_utf8(root_logger, log_path):
    setup_logging(log_path)
    assert _file_handlers(root_logger, log_path)[0].encoding == "utf-8"


def test_default_level_is_info(root_logger, log_path):
    setup_logging(log_path)
    assert root_logger.level == logging.INFO


def test_custom_level_applied(root_logger, log_path):
    setup_logging(log_path, level=logging.DEBUG)
    assert root_logger.level == logging.DEBUG


def test_debug_suppressed_at_info(root_logger, log_path):
    setup_logging(log_path)
    log = logging.getLogger("t")
    log.debug("hidden_event")
    log.info("shown_event")
    _flush(root_logger)
    content = _read(log_path)
    assert "hidden_event" not in content
    assert "shown_event" in content


def test_debug_written_at_debug_level(root_logger, log_path):
    setup_logging(log_path, level=logging.DEBUG)
    logging.getLogger("t").debug("dbg_event")
    _flush(root_logger)
    assert "dbg_event" in _read(log_path)


# --- format --------------------------------------------------------------------

LINE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (?P<level>[A-Z]+) (?P<name>\S+) event=(?P<msg>.*)$"
)


def test_line_format(root_logger, log_path):
    setup_logging(log_path)
    logging.getLogger("auth.vault").info("unlock_success")
    _flush(root_logger)
    m = LINE.match(_read(log_path).strip())
    assert m, "line does not match 'timestamp LEVEL name event=message'"
    assert m["level"] == "INFO"
    assert m["name"] == "auth.vault"
    assert m["msg"] == "unlock_success"


@pytest.mark.parametrize("method,level", [
    ("info", "INFO"), ("warning", "WARNING"), ("error", "ERROR"),
])
def test_level_names_in_output(root_logger, log_path, method, level):
    setup_logging(log_path)
    getattr(logging.getLogger("t"), method)("evt")
    _flush(root_logger)
    assert f" {level} t event=evt" in _read(log_path)


def test_lazy_args_formatted(root_logger, log_path):
    setup_logging(log_path)
    logging.getLogger("t").info("entry_added name=%s", "github")
    _flush(root_logger)
    assert "event=entry_added name=github" in _read(log_path)


def test_unicode_message_written(root_logger, log_path):
    setup_logging(log_path)
    logging.getLogger("t").info("entry_added name=%s", "päss-日本語")
    _flush(root_logger)
    assert "päss-日本語" in _read(log_path)


def test_one_line_per_record(root_logger, log_path):
    setup_logging(log_path)
    log = logging.getLogger("t")
    for i in range(5):
        log.info("evt%d", i)
    _flush(root_logger)
    assert len(_read(log_path).splitlines()) == 5


# --- known limitation -------------------------------------------------------------

@pytest.mark.xfail(reason="setup_logging does not guard against being called twice", strict=True)
def test_calling_twice_does_not_duplicate_handlers(root_logger, log_path):
    setup_logging(log_path)
    setup_logging(log_path)
    assert len(_file_handlers(root_logger, log_path)) == 1