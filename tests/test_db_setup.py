from riskpatch import db


def test_a_fresh_migrated_database_has_every_hot_index(tmp_path):
    conn = db.connect(tmp_path / "fresh.sqlite3")
    db.migrate(conn)
    assert db.missing_indexes(conn) == []


def test_a_dropped_index_is_reported(tmp_path):
    conn = db.connect(tmp_path / "dropped.sqlite3")
    db.migrate(conn)
    conn.execute("DROP INDEX idx_alerts_ws_status_id")
    conn.commit()
    assert db.missing_indexes(conn) == ["idx_alerts_ws_status_id"]


def test_analyze_collects_statistics(tmp_path):
    conn = db.connect(tmp_path / "stats.sqlite3")
    db.migrate(conn)
    seconds = db.analyze(conn)
    assert seconds >= 0
    assert conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='sqlite_stat1'").fetchone()[0] == 1
