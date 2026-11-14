-- Who owns a server and how important it is. Set by people (never overwritten by collector ingest, unlike environment).
ALTER TABLE assets ADD COLUMN owner TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN business_tier TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN service TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN maintenance_window TEXT NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN ownership_updated_at TEXT;
ALTER TABLE assets ADD COLUMN ownership_updated_by TEXT NOT NULL DEFAULT '';
