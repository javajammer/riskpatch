ALTER TABLE alerts ADD COLUMN finding_id INTEGER REFERENCES findings(id);
CREATE UNIQUE INDEX idx_alerts_finding ON alerts(finding_id) WHERE finding_id IS NOT NULL;
