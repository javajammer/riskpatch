CREATE TABLE IF NOT EXISTS job_schedules (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  job_type TEXT NOT NULL,
  interval_seconds INTEGER NOT NULL DEFAULT 3600,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Default schedules (mirip perilaku worker lama)
INSERT OR IGNORE INTO job_schedules (name, job_type, interval_seconds, enabled, created_at, updated_at)
VALUES ('CVE sync', 'cve_sync', 3600, 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'));

INSERT OR IGNORE INTO job_schedules (name, job_type, interval_seconds, enabled, created_at, updated_at)
VALUES ('Analysis', 'analysis', 10800, 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'), strftime('%Y-%m-%dT%H:%M:%SZ','now'));
