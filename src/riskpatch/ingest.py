from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import zlib
from datetime import datetime, timedelta, timezone

from riskpatch.collector_contract import Facts, SnapshotIn
from riskpatch.db import audit, index_text, now_iso, tx
from riskpatch.redact import REDACTED, SECRET_KEY, redact

# runtime/package name -> (vendor, product) for CPE style matching
CPE_MAP: dict[str, tuple[str, str]] = {
    "php": ("php", "php"),
    "python": ("python", "python"),
    "node": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    "go": ("golang", "go"),
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "apache2": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "openssl": ("openssl", "openssl"),
    "openssh-server": ("openbsd", "openssh"),
    "openssh": ("openbsd", "openssh"),
    "linux": ("linux", "linux_kernel"),
}
WEBSERVERS = {"nginx", "apache", "apache2", "httpd"}
RUNTIME_PACKAGE = {
    "php": re.compile(r"^php[0-9.]*-(cli|fpm|common|cgi)$"),
    "python": re.compile(r"^python3[0-9.]*(-minimal)?$"),
    "node": re.compile(r"^nodejs$"),
    "nginx": re.compile(r"^nginx(-core|-full|-light)?$"),
    "apache2": re.compile(r"^apache2$"),
    "go": re.compile(r"^golang(-[0-9.]+)?-go$"),
}
ECOSYSTEMS = {"packagist": "Packagist", "pypi": "PyPI", "npm": "npm", "go": "Go", "crates.io": "crates.io", "crates": "crates.io"}
UPSTREAM = re.compile(r"^(?:\d+:)?(\d+(?:\.\d+)*[a-z]?)")


class IngestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def bounded_decompress(data: bytes, limit: int) -> bytes:
    """gzip bodies are inflated with a hard cap to defuse decompression bombs."""
    inflater = zlib.decompressobj(wbits=31)
    out = inflater.decompress(data, limit + 1)
    if len(out) > limit or inflater.unconsumed_tail:
        raise IngestError(413, "payload too large after decompression")
    return out


def payload_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def upstream_version(version: str) -> str:
    match = UPSTREAM.match(version.strip())
    return match.group(1) if match else version.strip()


def match_key_for(ecosystem: str, vendor: str, product: str, name: str) -> str:
    if ecosystem == "generic":
        return f"generic:{vendor}:{product}"
    return f"{ecosystem}:{name}"


def normalize_components(facts: Facts, os_name: str) -> list[dict]:
    """Facts -> identified components. Anything without a trustworthy identity is skipped, not guessed."""
    comps: list[dict] = []
    seen: set[str] = set()
    packages = {pkg.name: pkg for pkg in facts.packages}

    def distro_for(runtime: str) -> str:
        pattern = RUNTIME_PACKAGE.get(runtime)
        if not pattern:
            return ""
        for pkg in facts.packages:
            if pattern.match(pkg.name):
                return f"{pkg.name} {pkg.version}"
        return ""

    def add(**kw) -> None:
        kw.setdefault("distro_package", "")
        kw.setdefault("used_at_runtime", True)
        kw.setdefault("direct_dependency", None)
        key = (kw["match_key"], kw["version"])
        marker = f"{key[0]}@{key[1]}"
        if marker in seen:
            return
        seen.add(marker)
        comps.append(kw)

    for runtime in facts.runtimes:
        ident = CPE_MAP.get(runtime.name.lower())
        if ident is None:
            continue
        vendor, product = ident
        role = "webserver" if runtime.name.lower() in WEBSERVERS else "runtime"
        add(kind="runtime", name=runtime.name + (f"-{runtime.sapi}" if runtime.sapi else ""), version=upstream_version(runtime.version),
            ecosystem="generic", vendor=vendor, product=product, match_key=match_key_for("generic", vendor, product, runtime.name),
            role=role, distro_package=distro_for(runtime.name.lower()))
    have_products = {c["match_key"] for c in comps}
    for name, pkg in packages.items():
        ident = CPE_MAP.get(name)
        if ident is None:
            continue
        key = match_key_for("generic", ident[0], ident[1], name)
        if key in have_products:
            continue
        role = "webserver" if name in WEBSERVERS else "library"
        add(kind="package", name=name, version=upstream_version(pkg.version), ecosystem="generic", vendor=ident[0], product=ident[1],
            match_key=key, role=role, distro_package=f"{name} {pkg.version}")
    for app in facts.applications:
        eco = ECOSYSTEMS.get(app.ecosystem.lower())
        if eco is None or not app.version.strip():
            continue
        add(kind="application", name=app.name, version=app.version.strip().lstrip("v"), ecosystem=eco, vendor="", product="",
            match_key=match_key_for(eco, "", "", app.name), role="library", direct_dependency=app.direct)
    return comps


def redact_facts(payload: dict) -> dict:
    cleaned = redact(payload)
    for item in cleaned.get("facts", {}).get("config_facts", []) or []:
        if isinstance(item, dict) and SECRET_KEY.search(str(item.get("key", ""))):
            item["value"] = REDACTED
    return cleaned


def ingest_snapshot(conn: sqlite3.Connection, raw: bytes, principal, max_age_seconds: int) -> tuple[int, str, bool]:
    try:
        parsed = SnapshotIn.model_validate_json(raw)
    except ValueError as exc:
        raise IngestError(422, f"invalid payload: {str(exc)[:500]}") from exc
    now = datetime.now(timezone.utc)
    if parsed.collected_at < now - timedelta(seconds=max_age_seconds):
        raise IngestError(422, "collected_at too old (replay protection)")
    if parsed.collected_at > now + timedelta(minutes=10):
        raise IngestError(422, "collected_at in the future")
    original = json.loads(raw)
    digest = payload_hash(original)
    collected = parsed.collected_at.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    idem = f"{principal.workspace_id}|{parsed.asset_id}|{collected}|{digest}"
    existing = conn.execute("SELECT id FROM snapshots WHERE idempotency_key=?", (idem,)).fetchone()
    if existing:
        return existing["id"], parsed.asset_id, True

    stored = redact_facts(original)
    facts = parsed.facts
    exposure = facts.exposure
    ts = now_iso()
    comps = normalize_components(facts, facts.os.name)
    os_id = facts.os.id_like or ""
    kernel_version = facts.os.kernel or ""
    with tx(conn):
            row = conn.execute("SELECT id FROM assets WHERE workspace_id=? AND asset_id=?", (principal.workspace_id, parsed.asset_id)).fetchone()
            if row is None:
                cur = conn.execute(
                    "INSERT INTO assets (workspace_id, asset_id, first_seen, last_seen, updated_at) VALUES (?,?,?,?,?)",
                    (principal.workspace_id, parsed.asset_id, ts, ts, ts),
                )
                asset_pk = cur.lastrowid
            else:
                asset_pk = row["id"]
            cur = conn.execute(
                """INSERT INTO snapshots (workspace_id, asset_pk, asset_id, collected_at, received_at, collector_version, schema_version,
                   payload_hash, idempotency_key, error_count, token_id, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (principal.workspace_id, asset_pk, parsed.asset_id, collected, ts, parsed.collector_version, parsed.schema_version,
                 digest, idem, len(parsed.errors), principal.token_id, ts),
            )
            snapshot_id = cur.lastrowid
            conn.execute("INSERT INTO snapshot_facts (snapshot_id, payload_json) VALUES (?,?)", (snapshot_id, json.dumps(stored)))
            for c in comps:
                conn.execute(
                    """INSERT INTO components (snapshot_id, asset_pk, kind, name, version, ecosystem, vendor, product, match_key, role,
                       used_at_runtime, distro_package, direct_dependency) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (snapshot_id, asset_pk, c["kind"], c["name"], c["version"], c["ecosystem"], c["vendor"], c["product"], c["match_key"],
                     c["role"], int(c["used_at_runtime"]), c["distro_package"], c["direct_dependency"]),
                )
            # Only the newest collection updates the asset's current view; late arrivals stay as history.
            latest = conn.execute("SELECT s.collected_at FROM assets a JOIN snapshots s ON s.id=a.latest_snapshot_id WHERE a.id=?", (asset_pk,)).fetchone()
            if latest is None or latest["collected_at"] <= collected:
                conn.execute(
                    """UPDATE assets SET hostname=?, environment=?, exposure=?, auth_boundary=?, mitigations=?, collector_version=?,
                       os_name=?, os_version=?, os_id=?, kernel=?, latest_snapshot_id=?, last_seen=?, updated_at=? WHERE id=?""",
                    (facts.hostname or parsed.asset_id, exposure.environment, exposure.exposure, exposure.auth_boundary,
                     json.dumps(exposure.mitigations), parsed.collector_version, facts.os.name, facts.os.version, os_id, kernel_version,
                     snapshot_id, ts, ts, asset_pk),
                )
            names = " ".join(sorted({p.name for p in facts.packages})[:5000])
            runtimes = " ".join(f"{r.name} {r.version}" for r in facts.runtimes)
            index_text(conn, "asset", parsed.asset_id, f"{parsed.asset_id} {facts.hostname}", f"{runtimes} {facts.os.name} {facts.os.version} {names}")
            audit(conn, principal.actor, "ingest.snapshot", str(snapshot_id), {"asset_id": parsed.asset_id, "hash": digest[:16]}, principal.workspace_id)

    return snapshot_id, parsed.asset_id, False


def snapshot_diff(old: dict | None, new: dict) -> dict:
    """Package/runtime/app/config differences between two stored payloads."""
    def index(payload: dict | None) -> dict[str, str]:
        out: dict[str, str] = {}
        facts = (payload or {}).get("facts", {})
        for r in facts.get("runtimes", []):
            out[f"runtime:{r.get('name')}:{r.get('sapi', '')}"] = r.get("version", "")
        for p in facts.get("packages", []):
            out[f"package:{p.get('name')}"] = p.get("version", "")
        for a in facts.get("applications", []):
            out[f"app:{a.get('ecosystem')}:{a.get('name')}"] = a.get("version", "")
        for c in facts.get("config_facts", []):
            out[f"config:{c.get('source')}:{c.get('key')}"] = c.get("value", "")
        return out

    a, b = index(old), index(new)
    return {
        "added": sorted(k for k in b if k not in a),
        "removed": sorted(k for k in a if k not in b),
        "changed": [{"item": k, "from": a[k], "to": b[k]} for k in sorted(b) if k in a and a[k] != b[k]],
    }
