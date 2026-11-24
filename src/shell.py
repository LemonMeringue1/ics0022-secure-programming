import getpass
import os
import shlex
import signal
import threading
import time
import logging

from cipher import DecryptionError
from vault_file import VaultFormatError
from vault import Vault
from errors import EntryError, VaultLockedError
from timeout import Timeout

import pyperclip

MAX_ATTEMPTS = 3
PROMPT = "pm> "
HELP = """Commands:
    add <name>      add an entry
    delete <name>   delete an entry
    copy <name>     copy password of entry to clipboard for 15 seconds
    edit <name>     edit entry fields
    list            list all entries
    show            show an entry
    lock            lock the vault
    help            show this help output
    quit | exit     lock and quit"""
logger = logging.getLogger(__name__)


def _create(path: str) -> Vault | None:
    print("No vault found. Creating a new one.")
    for _ in range(MAX_ATTEMPTS):
        pw = getpass.getpass("Choose master password: ")

        if getpass.getpass("Repeat master password: ") != pw:
            print("Passwords do not match.")
            continue
        try:
            return Vault.create(path, pw)
        except ValueError as e:
            print(e)
    return None


def _unlock(path: str) -> Vault | None:
    for _ in range(MAX_ATTEMPTS):
        try:
            pw = getpass.getpass("Master password: ")
        except KeyboardInterrupt:
            break
        try:
            return Vault.open(path, pw)
        except DecryptionError:
            raise DecryptionError("Wrong password or corrupted/tampered vault.") from None
        except VaultFormatError:
            raise VaultFormatError("invalid vault file") from None
            return None
    return None


def cmd_add(vault: Vault, args: list[str]) -> str:
    if len(args) != 1:
        return "usage: add <name>"
    name = args[0]
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    notes = input("Notes: ")
    vault.add(name, username, password, notes)
    return f"Added '{name}'."


def cmd_edit(vault: Vault, args: list[str]) -> str:
    if len(args) != 1:
        return "usage: edit <name>"
    name = args[0]

    print("Leave a field empty to keep its current value.")
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    notes = input("Notes: ")

    fields = {}
    if username:
        fields["username"] = username
    if password:
        fields["password"] = password
    if notes:
        fields["notes"] = notes

    if not fields:
        return "No changes."

    vault.edit(name, **fields)
    return f"Updated '{name}'."


def cmd_list(vault: Vault, args: list[str]) -> str:
    names = vault.list_name()
    return "\n".join(names) if names else "(no entries)"


def cmd_show(vault: Vault, args: list[str]) -> str:
    if len(args) != 1:
        return "usage: show <name>"
    e = vault.get(args[0])
    return f"Username: {e['username']}\nPassword: ********\nNotes:    {e['notes']}"


def cmd_delete(vault: Vault, args: list[str]) -> str:
    if len(args) != 1:
        return "usage: delete <name>"
    name = args[0]
    vault.delete(name)
    return f"Deleted '{name}'."


def _copy_with_timeout(text: str, timeout: int) -> None:
    pyperclip.copy(text)

    def clear_clipboard():
        time.sleep(timeout)
        pyperclip.copy("")

    thread = threading.Thread(target=clear_clipboard, daemon=True)
    thread.start()


def cmd_copy(vault: Vault, args: list[str]) -> str:
    if len(args) != 1:
        return "usage: copy <name>"
    e = vault.get(args[0])
    _copy_with_timeout(e["password"], 15)
    return "Password copied to clipboard (for 15 seconds)."


COMMANDS = {"add": cmd_add, "edit": cmd_edit, "list": cmd_list, "show": cmd_show, "delete": cmd_delete, "copy": cmd_copy}


def run_shell(path: str) -> int:
    vault = _unlock(path) if os.path.exists(path) else _create(path)
    if vault is None:
        return 1
    timeout = Timeout()
    timeout.start()

    try:
        print(HELP)
        while True:
            timeout.refresh()
            try:
                line = input(PROMPT)
            except EOFError:               # Ctrl+D / Ctrl+Z
                print()
                break
            try:
                parts = shlex.split(line)
            except ValueError:
                print("invalid input")
                continue
            if not parts:
                continue
            cmd, args = parts[0], parts[1:]

            if cmd in ("quit", "exit"):
                break
            if cmd == "help":
                print(HELP)
                continue
            if cmd == "lock":
                vault.lock()
                vault = _unlock(path)
                if vault is None:
                    return 1
                continue

            handler = COMMANDS.get(cmd)
            if handler is None:
                print("unknown command. use 'help'")
                continue

            try:
                print(handler(vault, args))
            except (EntryError, VaultLockedError) as e:
                print(e)
            except (DecryptionError, VaultFormatError):
                print("Vault error.")
            except Exception:
                print("Unexpected error.")
    except KeyboardInterrupt:              # Ctrl+C
        print()
    finally:
        if vault is not None:
            vault.lock()
        timeout.stop()
    return 0
