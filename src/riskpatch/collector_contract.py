"""Versioned payload contract shared with the Go collector (collector/internal/collect)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator

SUPPORTED_MAJOR = "1"
ASSET_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
Short = Field(max_length=256)


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore")


class OsFacts(_Base):
    name: str = Field("", max_length=128)
    version: str = Field("", max_length=64)
    id_like: str = Field("", max_length=128)
    kernel: str = Field("", max_length=128)
    arch: str = Field("", max_length=32)


class Runtime(_Base):
    name: str = Field(max_length=64)
    version: str = Field(max_length=128)
    sapi: str = Field("", max_length=32)
    path: str = Field("", max_length=256)
    compile_flags: list[str] = Field(default_factory=list, max_length=200)


class Package(_Base):
    name: str = Field(max_length=200)
    version: str = Field(max_length=200)
    arch: str = Field("", max_length=32)
    manager: str = Field("", max_length=16)


class Service(_Base):
    name: str = Field(max_length=200)
    status: str = Field("", max_length=32)


class Listener(_Base):
    proto: str = Field("tcp", max_length=8)
    address: str = Field("", max_length=64)
    port: int = Field(ge=0, le=65535)
    process: str = Field("", max_length=64)


class ConfigFact(_Base):
    source: str = Field(max_length=256)
    key: str = Field(max_length=200)
    value: str = Field("", max_length=1024)


class Application(_Base):
    ecosystem: str = Field(max_length=32)
    name: str = Field(max_length=200)
    version: str = Field(max_length=128)
    direct: bool | None = None
    manifest: str = Field("", max_length=256)


class Exposure(_Base):
    exposure: str = Field("unknown", pattern="^(internet|internal|vpn|localhost|unknown)$")
    environment: str = Field("unknown", max_length=32)
    auth_boundary: str = Field("unknown", pattern="^(unauthenticated|authenticated|admin|unknown)$")
    mitigations: list[str] = Field(default_factory=list, max_length=50)
    labels: dict[str, str] = Field(default_factory=dict)


class Facts(_Base):
    os: OsFacts = Field(default_factory=OsFacts)
    hostname: str = Field("", max_length=253)
    runtimes: list[Runtime] = Field(default_factory=list, max_length=500)
    packages: list[Package] = Field(default_factory=list, max_length=30000)
    services: list[Service] = Field(default_factory=list, max_length=2000)
    listening_ports: list[Listener] = Field(default_factory=list, max_length=2000)
    modules: list[str] = Field(default_factory=list, max_length=2000)
    config_facts: list[ConfigFact] = Field(default_factory=list, max_length=5000)
    applications: list[Application] = Field(default_factory=list, max_length=20000)
    exposure: Exposure = Field(default_factory=Exposure)


class SnapshotIn(_Base):
    schema_version: str = Field(max_length=16)
    asset_id: str
    collected_at: datetime
    collector_version: str = Field(max_length=64)
    facts: Facts
    errors: list[str] = Field(default_factory=list, max_length=200)

    @field_validator("schema_version")
    @classmethod
    def major(cls, value: str) -> str:
        if value.split(".")[0] != SUPPORTED_MAJOR:
            raise ValueError(f"schema_version {value} unsupported, need {SUPPORTED_MAJOR}.x")
        return value

    @field_validator("asset_id")
    @classmethod
    def asset(cls, value: str) -> str:
        if not ASSET_ID.fullmatch(value) or ".." in value:
            raise ValueError("asset_id only letters, digits, dot, underscore, or hyphen")
        return value

    @field_validator("collected_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("collected_at must use timezone")
        return value.astimezone(timezone.utc)


class IngestResult(BaseModel):
    snapshot_id: int
    status: str
    duplicate: bool = False
    asset_id: str
