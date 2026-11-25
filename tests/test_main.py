import os

import pytest

from main import safe_path, BASE_DIR


def test_path_outside_base_rejected():
    with pytest.raises(ValueError):
        safe_path("/etc/passwd")
    with pytest.raises(ValueError):
        safe_path(os.path.join(BASE_DIR, "..", "elsewhere.json"))

def test_sibling_prefix_rejected():
    with pytest.raises(ValueError):
        safe_path(BASE_DIR + "-evil/vault.json")

def test_inside_base_accepted():
    assert safe_path(os.path.join(BASE_DIR, "vault.json")).startswith(BASE_DIR)