import cryptography
import argon2
import sys

def init():
    ...

def unlock():
    ...

def add():
    ...

def list_entries():
    ...

def show():
    ...

def edit():
    ...

def delete():
    ...

def lock():
    ...

def main():
    command_list = ["init", "unlock", "add", "list", "show", "edit", "delete", "lock"]
    if len(sys.argv) < 2 or sys.argv[1] not in command_list:
        print("Usage: python main.py [command]\n"
              "\n"
              "commands:\n"
              "init     - Create a new vault\n"
              "unlock   - Unlock the vault\n"
              "add      - Add an entry\n"
              "list     - List all entries\n"
              "show     - Show all entries\n"
              "edit     - Edit an entry\n"
              "delete   - Delete an entry\n"
              "lock     - Lock the vault\n")
        sys.exit(1)

if __name__ == "__main__":
    main()