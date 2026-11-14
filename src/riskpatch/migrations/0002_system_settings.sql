CREATE TABLE IF NOT EXISTS system_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Default scheduler config (can be overridden via UI at /ui/system)
INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('worker_enabled', '1', strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('cve_sync_interval_seconds', '3600', strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('analysis_interval_seconds', '10800', strftime('%Y-%m-%dT%H:%M:%SZ','now'));
