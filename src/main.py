import argparse
import os
import sys

from shell import run_shell
from setup_logging import setup_logging

BASE_DIR = os.path.realpath(os.path.join(os.path.expanduser("~"), ".pwmanager"))
DEFAULT_VAULT = os.path.join(BASE_DIR, "vault.json")
LOGGING_PATH = os.path.join(BASE_DIR, "log.log")


def safe_path(path):
    resolved = os.path.realpath(path)
    if resolved != BASE_DIR and not resolved.startswith(BASE_DIR + os.sep):
        raise ValueError("vault path is outside allowed directory")
    if os.path.isdir(resolved):
        raise ValueError("vault path must be a file, not directory")
    return resolved


def main() -> None:
    ap = argparse.ArgumentParser(description="Local password manager")
    ap.add_argument("--vault", default=DEFAULT_VAULT, help="path to the vault file")
    args = ap.parse_args()

    try:
        vault_path = safe_path(args.vault)
    except ValueError as e:
        ap.error(str(e))

    os.makedirs(BASE_DIR, mode=0o700, exist_ok=True)
    setup_logging(LOGGING_PATH)
    sys.exit(run_shell(vault_path))


if __name__ == "__main__":
    main()