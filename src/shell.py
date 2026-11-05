import getpass
import os
import shlex
import traceback

from cipher import DecryptionError
from vault_file import VaultFormatError
from vault import Vault, EntryError, VaultLockedError

MAX_ATTEMPTS = 3
PROMPT = "pm> "
HELP = """Commands:
    add <name>      add an entry; will initialize a vault if one doesn't exist yet
    list            list all entries
    show            show an entry
    lock            lock the vault
    help            show this help output
    quit            lock and quit"""


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
        pw = getpass.getpass("Master password: ")
        try:
            return Vault.open(path, pw)
        except DecryptionError:
            raise DecryptionError("Wrong password or corrupted vault.")
        except VaultFormatError:
            raise VaultFormatError("Vault file is invalid.")
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


def cmd_list(vault: Vault, args: list[str]) -> str:
    names = vault.list_name()
    return "\n".join(names) if names else "(no entries)"


def cmd_show(vault: Vault, args: list[str]) -> str:
    if len(args) != 1:
        return "usage: show <name>"
    e = vault.get(args[0])
    return f"Username: {e['username']}\nPassword: ********\nNotes:    {e['notes']}"


COMMANDS = {"add": cmd_add, "list": cmd_list, "show": cmd_show}


def run_shell(path: str) -> int:
    vault = _unlock(path) if os.path.exists(path) else _create(path)
    if vault is None:
        return 1

    try:
        print(HELP)
        while True:
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
    return 0