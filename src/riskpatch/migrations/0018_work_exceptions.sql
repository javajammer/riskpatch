-- A deferral is an exception to fixing something: it needs a reason, an owner, an expiry date and (ideally) a compensating control.
-- When it expires the work item reopens; the SLA clock is not reset, so it is overdue at once if the target already passed.
CREATE TABLE IF NOT EXISTS work_exceptions (
    id INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id),
    work_item_id INTEGER NOT NULL REFERENCES work_items(id),
    reason TEXT NOT NULL,
    compensating_control TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_on TEXT NOT NULL,
    server_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'superseded')),
    closed_at TEXT,
    closed_by TEXT NOT NULL DEFAULT '',
    closed_note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_work_exceptions_status ON work_exceptions (workspace_id, status, expires_on);
CREATE INDEX IF NOT EXISTS idx_work_exceptions_item ON work_exceptions (work_item_id, status);
