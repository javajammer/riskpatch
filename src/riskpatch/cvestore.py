from __future__ import annotations

import hashlib
import json
import sqlite3

from riskpatch.db import index_text, now_iso
from riskpatch.facts import VersionBound, VulnFact
from riskpatch.providers import CveRecord


def _hash(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def _normalized(conn: sqlite3.Connection, cve_id: str) -> dict:
    row = conn.execute("SELECT summary, cvss_score, cvss_severity, attack_vector, cwe, kev, refs, patched_versions FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
    data = dict(row)
    data["affected"] = [list(r) for r in conn.execute("SELECT match_key, source, ranges_json FROM cve_affected WHERE cve_id=? ORDER BY 1,2", (cve_id,))]
    return data


def _union(old_json: str, new: list[str]) -> str:
    merged = list(dict.fromkeys(json.loads(old_json) + [x for x in new if x]))
    return json.dumps(sorted(merged))


def upsert_record(conn: sqlite3.Connection, rec: CveRecord, keep_raw: bool = True) -> str:
    """Merge one provider record into the CVE store. Returns created/updated/unchanged. Caller owns the transaction."""
    fact = rec.fact
    if fact.cve_id == "UNKNOWN":
        return "unchanged"
    ts = now_iso()
    row = conn.execute("SELECT * FROM cves WHERE cve_id=?", (fact.cve_id,)).fetchone()
    if row is None:
        conn.execute(
            """INSERT INTO cves (cve_id, summary, cvss_score, cvss_severity, attack_vector, cwe, kev, refs, patched_versions,
               primary_source, content_hash, revision, first_seen, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,'',0,?,?)""",
            (fact.cve_id, fact.summary, fact.cvss_score, fact.cvss_severity, fact.attack_vector, json.dumps(sorted(set(fact.cwe))),
             int(fact.kev), json.dumps(sorted(set(fact.references))), json.dumps(sorted(set(fact.patched_versions))), rec.source, ts, ts),
        )
    else:
        take_new = rec.source == "nvd"
        incoming = fact.summary or ""
        stored = row["summary"] or ""
        if incoming and (not stored or len(incoming) > len(stored) or (take_new and len(incoming) >= len(stored))):
            summary = incoming
        else:
            summary = stored
        score, sev, vec = row["cvss_score"], row["cvss_severity"], row["attack_vector"]
        if fact.cvss_score is not None and (score is None or take_new):
            score, sev, vec = fact.cvss_score, fact.cvss_severity, fact.attack_vector
        conn.execute(
            "UPDATE cves SET summary=?, cvss_score=?, cvss_severity=?, attack_vector=?, cwe=?, kev=?, refs=?, patched_versions=? WHERE cve_id=?",
            (summary, score, sev, vec, _union(row["cwe"], fact.cwe), int(bool(row["kev"]) or fact.kev),
             _union(row["refs"], fact.references), _union(row["patched_versions"], fact.patched_versions), fact.cve_id),
        )
    for key, ranges in rec.affected.items():
        conn.execute(
            "INSERT INTO cve_affected (cve_id, match_key, source, ranges_json) VALUES (?,?,?,?) "
            "ON CONFLICT(cve_id, match_key, source) DO UPDATE SET ranges_json=excluded.ranges_json",
            (fact.cve_id, key, rec.source, json.dumps([r.model_dump(exclude_none=True) for r in ranges], sort_keys=True)),
        )
    raw_json = json.dumps(rec.raw, default=str) if keep_raw and rec.raw is not None else None
    conn.execute(
        "INSERT INTO cve_sources (cve_id, source, url, fetched_at, content_hash, raw_json) VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(cve_id, source) DO UPDATE SET url=excluded.url, fetched_at=excluded.fetched_at, "
        "content_hash=excluded.content_hash, raw_json=excluded.raw_json",
        (fact.cve_id, rec.source, rec.url, ts, _hash(rec.raw) if rec.raw is not None else "", raw_json),
    )
    return _finalize(conn, fact.cve_id, rec.source, row is None)


def _finalize(conn: sqlite3.Connection, cve_id: str, source: str, created: bool) -> str:
    normalized = _normalized(conn, cve_id)
    digest = _hash(normalized)
    current = conn.execute("SELECT content_hash, revision, summary FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
    if digest == current["content_hash"]:
        return "unchanged"
    revision = current["revision"] + 1
    ts = now_iso()
    conn.execute("UPDATE cves SET content_hash=?, revision=?, updated_at=? WHERE cve_id=?", (digest, revision, ts, cve_id))
    conn.execute(
        "INSERT INTO cve_revisions (cve_id, revision, source, content_hash, normalized_json, created_at) VALUES (?,?,?,?,?,?)",
        (cve_id, revision, source, digest, json.dumps(normalized, default=str), ts),
    )
    index_text(conn, "cve", cve_id, cve_id, current["summary"])
    return "created" if created else "updated"


def mark_kev(conn: sqlite3.Connection, ids: set[str]) -> int:
    changed = 0
    for cve_id in sorted(ids):
        row = conn.execute("SELECT kev FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
        if row is None:
            fact = VulnFact(cve_id=cve_id, kev=True, source="kev")
            upsert_record(conn, CveRecord(fact=fact, source="kev", url="cisa-kev"), keep_raw=False)
            changed += 1
        elif not row["kev"]:
            conn.execute("UPDATE cves SET kev=1 WHERE cve_id=?", (cve_id,))
            _finalize(conn, cve_id, "kev", False)
            changed += 1
    return changed


def facts_for(conn: sqlite3.Connection, match_key: str) -> list[VulnFact]:
    """One VulnFact per CVE for a component identity. affected stays None so rules.judge evaluates the ranges."""
    out: dict[str, VulnFact] = {}
    rows = conn.execute(
        """SELECT c.*, a.ranges_json, a.source AS range_source FROM cve_affected a JOIN cves c ON c.cve_id=a.cve_id
           WHERE a.match_key=? ORDER BY c.cve_id""",
        (match_key,),
    ).fetchall()
    for row in rows:
        ranges = [VersionBound.model_validate(r) for r in json.loads(row["ranges_json"])]
        fact = out.get(row["cve_id"])
        if fact is None:
            out[row["cve_id"]] = VulnFact(
                cve_id=row["cve_id"], summary=row["summary"], cvss_score=row["cvss_score"], cvss_severity=row["cvss_severity"],
                attack_vector=row["attack_vector"], cwe=json.loads(row["cwe"]), kev=bool(row["kev"]), references=json.loads(row["refs"]),
                patched_versions=json.loads(row["patched_versions"]), ranges=ranges, source=row["primary_source"],
                match_note=f"ranges from {row['range_source']}",
            )
        else:
            fact.ranges.extend(ranges)
            fact.match_note += f", {row['range_source']}"
    return list(out.values())
