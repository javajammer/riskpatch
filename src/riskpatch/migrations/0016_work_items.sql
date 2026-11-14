-- fixed_version: the recommended safe version, copied out of verdict_json so findings can be grouped by it.
-- NULL = not extracted yet (a one-time backfill at worker start fills it), '' = no fixed version known.
ALTER TABLE findings ADD COLUMN fixed_version TEXT;

-- A work item is a decision about one CVE on one package version (with one recommended fix) across all servers.
-- Rows exist only once a person acts on a group; the Work queue itself is computed live from open findings.
CREATE TABLE IF NOT EXISTS work_items (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    cve_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    component_name TEXT NOT NULL,
    component_version TEXT NOT NULL,
    fixed_version TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'new' CHECK (state IN ('new','needs_validation','accepted','scheduled','mitigated','verified','deferred','not_applicable')),
    applicability TEXT NOT NULL DEFAULT 'unknown' CHECK (applicability IN ('confirmed','potential','not_applicable','unknown')),
    assignee TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE (workspace_id, cve_id, ecosystem, component_name, component_version, fixed_version)
);
CREATE INDEX IF NOT EXISTS idx_work_items_state ON work_items (workspace_id, state);

-- Append-only history: who decided what, when, for how many servers, from which snapshots.
CREATE TABLE IF NOT EXISTS work_events (
    id INTEGER PRIMARY KEY,
    work_item_id INTEGER NOT NULL REFERENCES work_items(id),
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    applicability TEXT NOT NULL,
    assignee TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    server_count INTEGER NOT NULL DEFAULT 0,
    snapshot_ids TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_work_events_item ON work_events (work_item_id, id);
