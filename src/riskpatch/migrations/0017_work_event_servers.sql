-- Which servers a decision covered, so a mitigation can later be verified against exactly those servers.
ALTER TABLE work_events ADD COLUMN servers TEXT NOT NULL DEFAULT '[]';
