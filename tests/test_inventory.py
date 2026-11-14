from pathlib import Path

import pytest
import yaml

from riskpatch.inventory import load_inventory

EXAMPLE = Path("inventory/stack.example.yaml")


def test_example_valid():
    inventory = load_inventory(EXAMPLE)
    assert inventory.meta.name == "example-php"
    assert len(inventory.components) == 2


def test_generic_requires_identity(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "meta": {"name": "x", "environment": "dev"},
                "components": [
                    {
                        "id": "a",
                        "name": "A",
                        "version": "1",
                        "ecosystem": "generic",
                        "role": "runtime",
                        "exposure": "internal",
                        "auth_boundary": "admin",
                        "used_at_runtime": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_inventory(path)


def test_rejects_path_id(tmp_path: Path):
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    raw["components"][0]["id"] = "../etc/passwd"
    path = tmp_path / "bad-id.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        load_inventory(path)


def test_unknown_exposure_is_internet():
    component = load_inventory(EXAMPLE).components[0]
    component.exposure = component.exposure.__class__.unknown
    assert component.effective_exposure.value == "internet"
