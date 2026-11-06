# Password Manager

Current progress: Checkpoint 2

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

## Planned commands

|Command|Description|
|-|-|
|python main.py init|Create a new vault, prompting for a master password|
|python main.py unlock|Unlock the vault for the current session|
|python main.py add|Add a new entry (site, username, password, notes)|
|python main.py list|List entry names (no secrets shown) in the unlocked vault|
|python main.py show <name>|Display a specific entry's details|
|python main.py edit <name>|Edit an existing entry|
|python main.py delete <name>|Delete an entry|
|python main.py lock|Manually lock the vault and clear the key from memory|

## Build and run

**Requirements:** Python 3.11+, and a virtual
environment.

```bash
# clone and enter the repo
git clone https://github.com/LemonMeringue1/ics0022-secure-programming
cd ics0022-secure-programming

# create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# install dependencies
pip install -r requirements.txt

# run
cd src
python main.py --help
```

## Repository structure



```
.
├── README.md
├── requirements.txt
└── src/
    ├── cipher.py
    ├── kdf.py
    ├── main.py
    ├── shell.py
    ├── vault.py
    └── vault_file.py
```

