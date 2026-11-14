from riskpatch.db import connect, index_text, migrate, tx


def _conn(tmp_path):
    conn = connect(tmp_path / "t.db")
    migrate(conn)
    return conn


def test_reindexing_replaces_the_entry_instead_of_duplicating_it(tmp_path):
    conn = _conn(tmp_path)
    with tx(conn):
        index_text(conn, "finding", "7", "CVE-1 openssl", "first body")
        index_text(conn, "finding", "7", "CVE-1 openssl", "second body")
        index_text(conn, "finding", "8", "CVE-2 nginx", "other")
    rows = conn.execute("SELECT ref, body FROM search_index WHERE kind='finding' ORDER BY ref").fetchall()
    assert [(r["ref"], r["body"]) for r in rows] == [("7", "second body"), ("8", "other")]
    assert conn.execute("SELECT COUNT(*) FROM search_index WHERE search_index MATCH 'first'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM search_map").fetchone()[0] == 2


def test_stale_map_entry_never_deletes_another_row(tmp_path):
    conn = _conn(tmp_path)
    with tx(conn):
        index_text(conn, "finding", "1", "a", "alpha")
        rid = conn.execute("SELECT rid FROM search_map WHERE ref='1'").fetchone()[0]
        conn.execute("DELETE FROM search_index WHERE rowid=?", (rid,))  # removed behind the map's back
        index_text(conn, "cve", "CVE-9", "b", "beta")  # may reuse the freed rowid
        index_text(conn, "finding", "1", "a", "alpha again")
    assert conn.execute("SELECT COUNT(*) FROM search_index WHERE kind='cve' AND ref='CVE-9'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM search_index WHERE kind='finding' AND ref='1'").fetchone()[0] == 1
