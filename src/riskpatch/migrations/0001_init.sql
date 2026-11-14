CREATE TABLE workspaces (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
INSERT INTO workspaces (id, name, created_at) VALUES (1, 'default', strftime('%Y-%m-%dT%H:%M:%SZ','now'));

CREATE TABLE api_tokens (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  last_used_at TEXT
);

CREATE TABLE assets (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
  asset_id TEXT NOT NULL,
  hostname TEXT,
  environment TEXT NOT NULL DEFAULT 'unknown',
  exposure TEXT NOT NULL DEFAULT 'unknown',
  auth_boundary TEXT NOT NULL DEFAULT 'unknown',
  mitigations TEXT NOT NULL DEFAULT '[]',
  metadata_override TEXT NOT NULL DEFAULT '{}',
  collector_version TEXT,
  os_name TEXT,
  os_version TEXT,
  os_id TEXT,
  kernel TEXT,
  latest_snapshot_id INTEGER,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (workspace_id, asset_id)
);

CREATE TABLE snapshots (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
  asset_pk INTEGER NOT NULL REFERENCES assets(id),
  asset_id TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  collector_version TEXT,
  schema_version TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  analysis_status TEXT NOT NULL DEFAULT 'pending',
  analyzed_at TEXT,
  error_count INTEGER NOT NULL DEFAULT 0,
  token_id INTEGER,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_snapshots_asset ON snapshots(asset_pk, collected_at);
CREATE INDEX idx_snapshots_status ON snapshots(analysis_status);

CREATE TABLE snapshot_facts (
  snapshot_id INTEGER PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
  payload_json TEXT
);

CREATE TABLE components (
  id INTEGER PRIMARY KEY,
  snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  asset_pk INTEGER NOT NULL REFERENCES assets(id),
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  vendor TEXT NOT NULL DEFAULT '',
  product TEXT NOT NULL DEFAULT '',
  match_key TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'library',
  used_at_runtime INTEGER NOT NULL DEFAULT 1,
  distro_package TEXT NOT NULL DEFAULT '',
  direct_dependency INTEGER
);
CREATE INDEX idx_components_snapshot ON components(snapshot_id);
CREATE INDEX idx_components_key ON components(match_key);

CREATE TABLE cves (
  cve_id TEXT PRIMARY KEY,
  summary TEXT NOT NULL DEFAULT '',
  cvss_score REAL,
  cvss_severity TEXT,
  attack_vector TEXT,
  cwe TEXT NOT NULL DEFAULT '[]',
  kev INTEGER NOT NULL DEFAULT 0,
  refs TEXT NOT NULL DEFAULT '[]',
  patched_versions TEXT NOT NULL DEFAULT '[]',
  primary_source TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 1,
  first_seen TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_cves_updated ON cves(updated_at);
CREATE INDEX idx_cves_kev ON cves(kev);

CREATE TABLE cve_affected (
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  match_key TEXT NOT NULL,
  source TEXT NOT NULL,
  ranges_json TEXT NOT NULL,
  PRIMARY KEY (cve_id, match_key, source)
);
CREATE INDEX idx_cve_affected_key ON cve_affected(match_key);

CREATE TABLE cve_sources (
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  url TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  raw_json TEXT,
  UNIQUE (cve_id, source)
);

CREATE TABLE cve_revisions (
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  source TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  normalized_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_cve_revisions_cve ON cve_revisions(cve_id);

CREATE TABLE provider_status (
  provider TEXT PRIMARY KEY,
  last_attempt_at TEXT,
  last_success_at TEXT,
  last_error TEXT,
  stale INTEGER NOT NULL DEFAULT 0,
  cursor_json TEXT NOT NULL DEFAULT '{}',
  records_last_run INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE provider_queries (
  provider TEXT NOT NULL,
  query_key TEXT NOT NULL,
  queried_at TEXT NOT NULL,
  PRIMARY KEY (provider, query_key)
);

CREATE TABLE jobs (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
  type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  trigger_source TEXT NOT NULL,
  scope_json TEXT NOT NULL DEFAULT '{}',
  dedupe_key TEXT UNIQUE,
  queued_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  counts_json TEXT NOT NULL DEFAULT '{}',
  error TEXT,
  provider_status_json TEXT NOT NULL DEFAULT '{}',
  attempts INTEGER NOT NULL DEFAULT 0,
  lease_owner TEXT,
  lease_expires_at TEXT,
  app_version TEXT,
  ruleset_version TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_jobs_status ON jobs(status, queued_at);

CREATE TABLE job_events (
  id INTEGER PRIMARY KEY,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  at TEXT NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE INDEX idx_job_events_job ON job_events(job_id);

CREATE TABLE analysis_runs (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
  job_id INTEGER REFERENCES jobs(id),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  ruleset_version TEXT NOT NULL,
  assets_processed INTEGER NOT NULL DEFAULT 0,
  findings_created INTEGER NOT NULL DEFAULT 0,
  findings_updated INTEGER NOT NULL DEFAULT 0,
  findings_resolved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE findings (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
  asset_pk INTEGER NOT NULL REFERENCES assets(id),
  asset_id TEXT NOT NULL,
  snapshot_id INTEGER REFERENCES snapshots(id),
  component_key TEXT NOT NULL,
  component_name TEXT NOT NULL,
  component_version TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  level TEXT NOT NULL,
  level_rank INTEGER NOT NULL,
  previous_level TEXT,
  action TEXT NOT NULL,
  confidence TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  cvss_score REAL,
  kev INTEGER NOT NULL DEFAULT 0,
  exposure TEXT NOT NULL,
  exposure_assumed INTEGER NOT NULL DEFAULT 0,
  reachability TEXT NOT NULL,
  one_line TEXT NOT NULL,
  verdict_json TEXT NOT NULL,
  ruleset_version TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  level_changed_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (workspace_id, asset_pk, component_key, cve_id)
);
CREATE INDEX idx_findings_level ON findings(level_rank DESC);
CREATE INDEX idx_findings_cve ON findings(cve_id);
CREATE INDEX idx_findings_updated ON findings(updated_at);

CREATE TABLE finding_evidence (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_evidence_finding ON finding_evidence(finding_id);

CREATE TABLE reports (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
  analysis_run_id INTEGER REFERENCES analysis_runs(id),
  asset_pk INTEGER REFERENCES assets(id),
  asset_id TEXT,
  snapshot_id INTEGER,
  generated_at TEXT NOT NULL,
  highest TEXT NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0,
  content_json TEXT NOT NULL,
  content_md TEXT NOT NULL
);
CREATE INDEX idx_reports_asset ON reports(asset_pk, generated_at);

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
  asset_id TEXT,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL,
  acknowledged_at TEXT,
  acknowledged_by TEXT
);
CREATE INDEX idx_alerts_ack ON alerts(acknowledged_at);

CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY,
  workspace_id INTEGER NOT NULL DEFAULT 1,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT NOT NULL DEFAULT '{}'
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE VIRTUAL TABLE search_index USING fts5(kind UNINDEXED, ref UNINDEXED, title, body);
