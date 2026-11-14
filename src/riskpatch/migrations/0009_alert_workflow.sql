ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'closed'));
ALTER TABLE alerts ADD COLUMN closed_at TEXT;
ALTER TABLE alerts ADD COLUMN closed_by TEXT;
ALTER TABLE alerts ADD COLUMN resolution_note TEXT NOT NULL DEFAULT '';

UPDATE alerts
SET status='closed', closed_at=acknowledged_at, closed_by=acknowledged_by
WHERE acknowledged_at IS NOT NULL;

CREATE INDEX idx_alerts_status ON alerts(workspace_id, status, created_at);
