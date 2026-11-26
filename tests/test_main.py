import os
import sys

import pytest

from main import safe_path, BASE_DIR
import main


def test_path_outside_base_rejected():
    with pytest.raises(ValueError):
        safe_path("/etc/passwd")
    with pytest.raises(ValueError):
        safe_path(os.path.join(BASE_DIR, "..", "elsewhere.json"))


def test_sibling_prefix_rejected():
    with pytest.raises(ValueError):
        safe_path(BASE_DIR + "-evil/vault.json")


def test_inside_base_accepted():
    assert safe_path(os.path.join(BASE_DIR, "vault.json")).startswith(BASE_DIR)


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Redirect main's base directory to tmp_path and stub out side effects."""
    base = os.path.realpath(tmp_path / ".pwmanager")
    monkeypatch.setattr(main, "BASE_DIR", base)
    monkeypatch.setattr(main, "DEFAULT_VAULT", os.path.join(base, "vault.json"))
    monkeypatch.setattr(main, "LOGGING_PATH", os.path.join(base, "log.log"))

    calls = {"shell": [], "logging": [], "order": []}

    def fake_shell(path):
        calls["order"].append("shell")
        calls["shell"].append(path)
        return calls.get("rc", 0)

    def fake_logging(path):
        calls["order"].append("logging")
        calls["logging"].append(path)

    monkeypatch.setattr(main, "run_shell", fake_shell)
    monkeypatch.setattr(main, "setup_logging", fake_logging)

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["main.py", *argv])
        with pytest.raises(SystemExit) as exc:
            main.main()
        return exc.value.code

    calls["run"] = run
    calls["base"] = base
    return calls


# --- normal startup ---------------------------------------------------------

def test_default_vault_used_when_no_argument(app):
    assert app["run"]() == 0
    assert app["shell"] == [os.path.join(app["base"], "vault.json")]


def test_custom_vault_inside_base_is_used(app):
    custom = os.path.join(app["base"], "other.json")
    assert app["run"]("--vault", custom) == 0
    assert app["shell"] == [custom]


def test_shell_receives_resolved_path(app):
    messy = os.path.join(app["base"], "sub", "..", "vault.json")
    app["run"]("--vault", messy)
    assert app["shell"] == [os.path.join(app["base"], "vault.json")]


def test_exit_code_comes_from_run_shell(app):
    app["rc"] = 1
    assert app["run"]() == 1


# --- setup ------------------------------------------------------------------

def test_base_dir_created(app):
    assert not os.path.exists(app["base"])
    app["run"]()
    assert os.path.isdir(app["base"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_base_dir_created_owner_only(app):
    app["run"]()
    assert os.stat(app["base"]).st_mode & 0o777 == 0o700


def test_existing_base_dir_is_fine(app):
    os.makedirs(app["base"])
    assert app["run"]() == 0


def test_logging_configured_with_log_path_before_shell(app):
    app["run"]()
    assert app["logging"] == [os.path.join(app["base"], "log.log")]
    assert app["order"] == ["logging", "shell"]


# --- rejection of bad paths (no side effects) -------------------------------

@pytest.mark.parametrize("bad", ["/etc/passwd", "../elsewhere.json"])
def test_path_outside_base_exits_with_usage_error(app, bad, capsys):
    assert app["run"]("--vault", bad) == 2
    assert "outside allowed directory" in capsys.readouterr().err


def test_rejected_path_has_no_side_effects(app):
    app["run"]("--vault", "/etc/passwd")
    assert app["shell"] == []
    assert app["logging"] == []
    assert not os.path.exists(app["base"])      # nothing created before validation


def test_directory_as_vault_rejected(app, capsys):
    os.makedirs(os.path.join(app["base"], "adir"))
    assert app["run"]("--vault", os.path.join(app["base"], "adir")) == 2
    assert "must be a file" in capsys.readouterr().err
    assert app["shell"] == []


def test_sibling_directory_with_same_prefix_rejected(app):
    assert app["run"]("--vault", app["base"] + "-evil/vault.json") == 2
    assert app["shell"] == []


@pytest.mark.skipif(os.name != "posix", reason="symlinks need POSIX")
def test_symlink_escaping_base_rejected(app, tmp_path):
    os.makedirs(app["base"])
    target = tmp_path / "outside.json"
    target.write_text("{}")
    link = os.path.join(app["base"], "link.json")
    os.symlink(target, link)
    assert app["run"]("--vault", link) == 2
    assert app["shell"] == []


def test_error_message_does_not_echo_path(app, capsys):
    app["run"]("--vault", "/etc/secret-looking-name")
    assert "secret-looking-name" not in capsys.readouterr().err


# --- argparse behavior ------------------------------------------------------

def test_help_exits_zero(app, capsys):
    assert app["run"]("--help") == 0
    assert "--vault" in capsys.readouterr().out


def test_unknown_argument_exits_with_usage_error(app):
    assert app["run"]("--bogus") == 2
    assert app["shell"] == []


def test_vault_option_requires_value(app):
    assert app["run"]("--vault") == 2