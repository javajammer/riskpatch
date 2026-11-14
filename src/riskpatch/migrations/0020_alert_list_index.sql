-- Alert list views filter by workspace and status and sort by id; without this the planner sorts every open alert to show 100.
CREATE INDEX IF NOT EXISTS idx_alerts_ws_status_id ON alerts (workspace_id, status, id);
