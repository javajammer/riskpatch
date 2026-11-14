-- Covering indexes for the pages that count or group open findings/alerts. Without them every overview, assets,
-- findings, alerts and coverage request scanned the whole (wide) findings table, so page time grew with open findings.
CREATE INDEX IF NOT EXISTS idx_findings_ws_status_level ON findings (workspace_id, status, level, kev);
CREATE INDEX IF NOT EXISTS idx_findings_ws_status_asset ON findings (workspace_id, status, asset_pk, level_rank, level, kev);
CREATE INDEX IF NOT EXISTS idx_findings_asset_status ON findings (asset_pk, status, level_rank, level);
CREATE INDEX IF NOT EXISTS idx_findings_list_order ON findings (workspace_id, status, level_rank DESC, cvss_score DESC, id);
CREATE INDEX IF NOT EXISTS idx_alerts_ws_asset ON alerts (workspace_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ws_closed ON alerts (workspace_id, status, closed_at);
CREATE INDEX IF NOT EXISTS idx_findings_ws_status_seen ON findings (workspace_id, status, first_seen);
