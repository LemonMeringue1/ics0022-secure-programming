## Checkpoint 2 Progress

**Encryption module:**

* Implemented (kdf.py and cipher.py)
* Encryption, decryption and key derivation
* Encryption with AES-256-GCM via cryptography package
* Key derivation with Argon2id via argon2-cffi
* AES-256-GCM as per OWASP recommendations for cryptographic storage
* Argon2id as per OWASP recommendation for password storage
* Argon2id params at least recommended minimum: time_cost = 6, memory_cost = 131072, parallelism = 4
* Unique nonce on each encryption

**Storage layer:**

* Implemented (vault_file.py)
* Vault saving, vault loading and vault format validation
* Open vault with file descriptor, not path name
* Write to temporary vault file, then save to real vault file
* Validation against incorrect format, unsafe/incorrect values, non-existent vault version
* os module for secure file operations

**User management module:**

* Implemented (shell.py and main.py)
* Interactive shell
* Current commands: `add <name>`, `list`, `show`, `lock`, `help`, `quit`
* Usage: `python main.py`; prompts for master password; creates vault if non-existent, opens vault if exists
* By default, vault stored at and read/wrote from ~/.pwmanager/vault.json
* Specify vault path with `python main.py --vault <path>`
* `add <name>` - add an entry
* `list` - list all entries
* `show` - show an entry
* `lock` - lock the vault
* `help` - show help message
* `quit` - lock and quit
* Ctrl+C and Ctrl+Z handled

**Vault implementation:**

* Implemented (vault.py)
* Vault format is .json
* Vault handled as class with methods:
  * `create()`
  * `open()`
  * `lock()`
  * `list_name()`
  * `get()`
  * `add()`
  * `edit()`
  * `delete()`
* Create new vault instance on each create and open