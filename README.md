# Password Manager

Current progress: Checkpoint 3

A local, offline password manager.

## Scope

This project is a local, single-user command-line password manager. It stores
vault entries (e.g. site name, username, password, notes) encrypted at rest in a local vault
file, protected by a master password.

**In scope:**

* Creating a new vault, protected by a master password
* Unlocking an existing vault
* Adding, viewing, editing, and deleting entries within an unlocked session
* Locking the vault (manually, and automatically after inactivity)

**Out of scope** (for this project):

* Any form of network sync, cloud backup, or multi-device support
* Password sharing between users
* Browser integration / autofill
* Recovery of a forgotten master password

## Commands

| Command        | Description                                           |
|----------------|-------------------------------------------------------|
| python main.py | Create vault if doesn't exist, otherwise unlock       |
| add \<name>    | Add a new entry (name, username, password, notes)     |
| delete \<name> | Delete an entry                                       |
| copy \<name>   | Copy password of entry                                |
| edit \<name>   | Edit an existing entry                                |
| list           | List entry names                                      |
| show \<name>   | Display an entry's details (no password in plaintext) |
| lock           | Manually lock the vault and clear the key from memory |
| help           | Show help output                                      |
| quit \| exit   | Lock and quit                                         |

## Build and run

**Requirements:** Python 3.11+, and a virtual environment.

```bash
# clone and enter the repo
git clone https://github.com/LemonMeringue1/ics0022-secure-programming
cd ics0022-secure-programming

# create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# install dependencies
pip install -r requirements.txt

# optionally, run tests
python -m pytest tests/ -v

# run program
cd src
python main.py
```

## Repository structure

| Path                 | Description                          |
|----------------------|--------------------------------------|
| src/cipher.py        | Encryption and decryption module     |
| src/kdf.py           | Key derivation module                |
| src/main.py          | Main module                          |
| src/setup_logging.py | Logging module                       |
| src/shell.py         | Interactive shell module             |
| src/timeout.py       | User inactivity timeout module       |
| src/validation.py    | Input validation module              |
| src/vault.py         | Vault module, containing Vault class |
| src/vault_file.py    | Vault saving and loading module      |
| /tests/              | Tests module                         |
