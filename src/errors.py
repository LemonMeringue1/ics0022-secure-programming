class VaultLockedError(Exception):
    """Vault is locked."""


class EntryError(Exception):
    """Entry already exists, doesn't exist or should be non-empty"""