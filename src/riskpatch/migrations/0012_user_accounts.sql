CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    disabled_at TEXT,
    last_login_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

ALTER TABLE api_tokens ADD COLUMN owner_user_id INTEGER REFERENCES users(id);
ALTER TABLE api_tokens ADD COLUMN purpose TEXT NOT NULL DEFAULT '';
