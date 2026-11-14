-- search_index.kind/ref are UNINDEXED, so DELETE ... WHERE kind=? AND ref=? scans the whole FTS table.
-- Analysis re-indexes every finding inside one write transaction; that held the database lock for minutes
-- and made ingest fail with "database is locked". This map lets index_text delete by rowid instead.
CREATE TABLE IF NOT EXISTS search_map (
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    rid INTEGER NOT NULL,
    PRIMARY KEY (kind, ref)
) WITHOUT ROWID;
INSERT OR REPLACE INTO search_map (kind, ref, rid) SELECT kind, ref, rowid FROM search_index;
