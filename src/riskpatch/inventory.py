from __future__ import annotations

from enum import Enum
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class Environment(str, Enum):
    production = "production"
    staging = "staging"
    dev = "dev"


class Ecosystem(str, Enum):
    generic = "generic"
    packagist = "Packagist"
    debian = "Debian"
    ubuntu = "Ubuntu"
    pypi = "PyPI"
    npm = "npm"
    go = "Go"
    crates = "crates.io"


class Role(str, Enum):
    runtime = "runtime"
    os = "os"
    webserver = "webserver"
    library = "library"
    dev = "dev"


class Exposure(str, Enum):
    internet = "internet"
    internal = "internal"
    vpn = "vpn"
    localhost = "localhost"
    unknown = "unknown"


class AuthBoundary(str, Enum):
    unauthenticated = "unauthenticated"
    authenticated = "authenticated"
    admin = "admin"
    unknown = "unknown"


class Meta(BaseModel):
    name: str
    environment: Environment


class Component(BaseModel):
    id: str
    name: str
    version: str
    ecosystem: Ecosystem
    vendor: str = ""
    product: str = ""
    cpe: str = ""
    role: Role
    exposure: Exposure
    auth_boundary: AuthBoundary
    used_at_runtime: bool
    mitigations: list[str] = Field(default_factory=list)
    distro_package: str = ""
    notes: str = ""

    @field_validator("id")
    @classmethod
    def safe_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value) or ".." in value:
            raise ValueError("id must contain only letters, numbers, dots, underscores, or hyphens")
        return value

    @field_validator("version")
    @classmethod
    def version_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("version is required")
        return value.strip()

    @field_validator("cpe")
    @classmethod
    def cpe_shape(cls, value: str) -> str:
        if value and not value.startswith("cpe:2.3:"):
            raise ValueError("cpe must start with cpe:2.3:")
        return value

    @model_validator(mode="after")
    def generic_identity(self) -> Component:
        if self.ecosystem == Ecosystem.generic and not self.cpe and not (self.vendor and self.product):
            raise ValueError("generic component must have cpe or vendor+product")
        if self.ecosystem != Ecosystem.generic and not self.product and not self.name:
            raise ValueError("package name is required")
        return self

    @property
    def effective_exposure(self) -> Exposure:
        if self.exposure == Exposure.unknown:
            return Exposure.internet
        return self.exposure

    @property
    def package_name(self) -> str:
        return self.product or self.name


class Inventory(BaseModel):
    meta: Meta
    components: list[Component]

    @model_validator(mode="after")
    def unique_ids(self) -> Inventory:
        ids = [item.id for item in self.components]
        if len(ids) != len(set(ids)):
            raise ValueError("component IDs must be unique")
        if not self.components:
            raise ValueError("at least one component required")
        return self


def load_inventory(path: Path) -> Inventory:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("inventory must be a YAML mapping")
    return Inventory.model_validate(raw)
