import argparse
import os
import sys

from shell import run_shell
from setup_logging import setup_logging

DEFAULT_VAULT = os.path.join(os.path.expanduser("~"), ".pwmanager", "vault.json")
LOGGING_PATH = os.path.join(os.path.expanduser("~"), ".pwmanager", "log.log")


def main() -> None:
    ap = argparse.ArgumentParser(description="Local password manager")
    ap.add_argument("--vault", default=DEFAULT_VAULT, help="path to the vault file")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.vault)), mode=0o700, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(LOGGING_PATH)), exist_ok=True)
    setup_logging(LOGGING_PATH)
    sys.exit(run_shell(args.vault))


if __name__ == "__main__":
    main()