# src/main.py
import argparse
import os
import sys

from shell import run_shell

DEFAULT_VAULT = os.path.join(os.path.expanduser("~"), ".pwmanager", "vault.json")


def main() -> None:
    ap = argparse.ArgumentParser(description="Local password manager")
    ap.add_argument("--vault", default=DEFAULT_VAULT, help="path to the vault file")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.vault)), mode=0o700, exist_ok=True)
    sys.exit(run_shell(args.vault))


if __name__ == "__main__":
    main()