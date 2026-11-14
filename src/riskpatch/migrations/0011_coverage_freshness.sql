CREATE TABLE IF NOT EXISTS cache_layers (
    key TEXT PRIMARY KEY,
    ttl_seconds INTEGER CHECK (ttl_seconds IS NULL OR ttl_seconds > 0),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cache_entries (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    layer_key TEXT NOT NULL REFERENCES cache_layers(key),
    scope_type TEXT NOT NULL CHECK (scope_type IN ('global', 'source', 'asset')),
    scope_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'running', 'success', 'stale', 'failed')),
    refreshed_at TEXT,
    ttl_seconds INTEGER,
    input_fingerprint TEXT NOT NULL DEFAULT '',
    record_count INTEGER NOT NULL DEFAULT 0,
    last_job_id INTEGER,
    last_error TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, layer_key, scope_type, scope_id)
);

CREATE TABLE IF NOT EXISTS cache_state_events (
    id INTEGER PRIMARY KEY,
    entry_id INTEGER NOT NULL REFERENCES cache_entries(id),
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    job_id INTEGER,
    at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_events_entry ON cache_state_events(entry_id, id);

CREATE TABLE IF NOT EXISTS refresh_jobs (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    layer_key TEXT NOT NULL REFERENCES cache_layers(key),
    target TEXT NOT NULL,
    trigger_source TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'success', 'retry_wait', 'failed')),
    progress_done INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    retries INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    next_attempt_at TEXT,
    error TEXT,
    dead_lettered INTEGER NOT NULL DEFAULT 0,
    job_id INTEGER REFERENCES jobs(id),
    queued_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_jobs_target ON refresh_jobs(workspace_id, layer_key, target, state);

CREATE TABLE IF NOT EXISTS inventory_snapshots (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    asset_pk INTEGER NOT NULL REFERENCES assets(id),
    asset_id TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    collector_version TEXT NOT NULL DEFAULT '',
    package_hash TEXT NOT NULL,
    packages_json TEXT NOT NULL DEFAULT '[]',
    os_name TEXT,
    os_version TEXT,
    kernel TEXT,
    arch TEXT,
    UNIQUE (workspace_id, asset_id, package_hash, collected_at)
);

ALTER TABLE assets ADD COLUMN agent_id TEXT;
ALTER TABLE assets ADD COLUMN agent_version TEXT;
ALTER TABLE assets ADD COLUMN last_heartbeat_at TEXT;
ALTER TABLE assets ADD COLUMN inventory_collected_at TEXT;
ALTER TABLE assets ADD COLUMN inventory_hash TEXT;
ALTER TABLE assets ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'silent', 'decommissioned'));
