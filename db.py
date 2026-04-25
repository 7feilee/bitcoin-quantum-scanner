import sqlite3
import contextlib
from config import DB_PATH

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS scan_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type   TEXT    NOT NULL,
    started_at  TEXT    NOT NULL,
    completed_at TEXT,
    status      TEXT    NOT NULL DEFAULT 'running',
    block_height INTEGER,
    block_hash  TEXT,
    records_found INTEGER DEFAULT 0,
    error_msg   TEXT
);

CREATE TABLE IF NOT EXISTS quantum_utxos (
    txid            TEXT NOT NULL,
    vout            INTEGER NOT NULL,
    address         TEXT,
    script_hex      TEXT NOT NULL,
    script_type     TEXT NOT NULL,
    pubkey_hex      TEXT,
    value_sat       INTEGER NOT NULL,
    block_height    INTEGER,
    risk_level      TEXT NOT NULL,
    risk_reason     TEXT,
    scan_run_id     INTEGER REFERENCES scan_runs(id),
    PRIMARY KEY (txid, vout)
);

CREATE TABLE IF NOT EXISTS address_distribution (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id     INTEGER REFERENCES scan_runs(id),
    script_type     TEXT NOT NULL,
    utxo_count      INTEGER NOT NULL DEFAULT 0,
    total_value_sat INTEGER NOT NULL DEFAULT 0,
    quantum_risk    TEXT NOT NULL,
    pct_of_utxos    REAL,
    pct_of_value    REAL
);

CREATE TABLE IF NOT EXISTS timelock_utxos (
    txid                    TEXT NOT NULL,
    vout                    INTEGER NOT NULL,
    address                 TEXT,
    script_hex              TEXT NOT NULL,
    lock_type               TEXT NOT NULL,
    lock_value              INTEGER,
    estimated_unlock_height INTEGER,
    value_sat               INTEGER NOT NULL,
    block_height            INTEGER,
    is_inheritance_pattern  INTEGER NOT NULL DEFAULT 0,
    extra_json              TEXT,
    scan_run_id             INTEGER REFERENCES scan_runs(id),
    PRIMARY KEY (txid, vout)
);

CREATE TABLE IF NOT EXISTS address_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    address     TEXT NOT NULL,
    queried_at  TEXT NOT NULL DEFAULT (datetime('now')),
    ip_hash     TEXT,
    result_risk TEXT,
    result_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_quantum_address   ON quantum_utxos(address);
CREATE INDEX IF NOT EXISTS idx_quantum_type      ON quantum_utxos(script_type);
CREATE INDEX IF NOT EXISTS idx_quantum_risk      ON quantum_utxos(risk_level);
CREATE INDEX IF NOT EXISTS idx_quantum_run       ON quantum_utxos(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_quantum_satoshi   ON quantum_utxos(script_type, block_height);
CREATE INDEX IF NOT EXISTS idx_quantum_overview  ON quantum_utxos(scan_run_id, script_type, value_sat);
CREATE INDEX IF NOT EXISTS idx_timelock_type     ON timelock_utxos(lock_type);
CREATE INDEX IF NOT EXISTS idx_timelock_inherit  ON timelock_utxos(is_inheritance_pattern);
CREATE INDEX IF NOT EXISTS idx_queries_address   ON address_queries(address);
CREATE INDEX IF NOT EXISTS idx_queries_time      ON address_queries(queried_at);
CREATE INDEX IF NOT EXISTS idx_dist_run          ON address_distribution(scan_run_id);

CREATE TABLE IF NOT EXISTS migration_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_date       DATE    NOT NULL UNIQUE,
    block_height    INTEGER,
    total_utxos     INTEGER,
    total_value_sat INTEGER,
    vuln_utxos      INTEGER,
    vuln_value_sat  INTEGER,
    p2pk_utxos      INTEGER DEFAULT 0,
    p2pk_value      INTEGER DEFAULT 0,
    p2tr_utxos      INTEGER DEFAULT 0,
    p2tr_value      INTEGER DEFAULT 0,
    p2ms_utxos      INTEGER DEFAULT 0,
    p2ms_value      INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_snap_date ON migration_snapshots(scan_date);

CREATE TABLE IF NOT EXISTS quantum_analytics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    computed_at TEXT    NOT NULL DEFAULT (datetime('now')),
    scan_run_id INTEGER REFERENCES scan_runs(id),
    metric      TEXT    NOT NULL,
    label       TEXT    NOT NULL,
    utxo_count  INTEGER NOT NULL DEFAULT 0,
    value_sat   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_analytics_metric ON quantum_analytics(metric);

CREATE TABLE IF NOT EXISTS reused_addresses (
    address          TEXT NOT NULL PRIMARY KEY,
    pubkey_hex       TEXT NOT NULL,
    first_seen_txid  TEXT NOT NULL,
    first_seen_block INTEGER NOT NULL,
    scan_run_id      INTEGER REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS wallet_top100 (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    computed_at TEXT    NOT NULL DEFAULT (datetime('now')),
    rank        INTEGER NOT NULL,
    address     TEXT    NOT NULL,
    script_type TEXT    NOT NULL,
    utxo_count  INTEGER NOT NULL DEFAULT 0,
    value_sat   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_wallet_top100_rank ON wallet_top100(rank);
"""


@contextlib.contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def start_scan_run(scan_type: str, block_height: int = None, block_hash: str = None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scan_runs (scan_type, started_at, block_height, block_hash) "
            "VALUES (?, datetime('now'), ?, ?)",
            (scan_type, block_height, block_hash),
        )
        return cur.lastrowid


def finish_scan_run(run_id: int, records: int, error: str = None):
    status = "failed" if error else "complete"
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_runs SET completed_at=datetime('now'), status=?, "
            "records_found=?, error_msg=? WHERE id=?",
            (status, records, error, run_id),
        )


def get_latest_analytics(metric: str) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT label, utxo_count, value_sat FROM quantum_analytics "
            "WHERE metric=? ORDER BY id DESC LIMIT 500",
            (metric,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_latest_scan(scan_type: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_runs WHERE scan_type=? AND status='complete' "
            "ORDER BY id DESC LIMIT 1",
            (scan_type,),
        ).fetchone()
        return dict(row) if row else None


def export_csvs():
    """Generate CSV exports from the latest scan data."""
    import csv, os
    from config import CSV_DIR

    quantum_csv = os.path.join(CSV_DIR, "quantum_utxos.csv")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT q.txid, q.vout, q.address, q.script_type, q.pubkey_hex, "
            "q.value_sat, q.block_height, q.risk_level, q.risk_reason "
            "FROM quantum_utxos q "
            "JOIN scan_runs s ON q.scan_run_id = s.id "
            "WHERE s.id = (SELECT MAX(id) FROM scan_runs WHERE scan_type='quantum' AND status='complete')"
        ).fetchall()
    with open(quantum_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["txid", "vout", "address", "script_type", "pubkey_hex",
                         "value_sat", "block_height", "risk_level", "risk_reason"])
        for row in rows:
            writer.writerow(list(row))

    timelock_csv = os.path.join(CSV_DIR, "timelock_utxos.csv")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT t.txid, t.vout, t.address, t.lock_type, t.lock_value, "
            "t.estimated_unlock_height, t.value_sat, t.block_height, t.is_inheritance_pattern "
            "FROM timelock_utxos t "
            "JOIN scan_runs s ON t.scan_run_id = s.id "
            "WHERE s.id = (SELECT MAX(id) FROM scan_runs WHERE scan_type='timelocks' AND status='complete')"
        ).fetchall()
    with open(timelock_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["txid", "vout", "address", "lock_type", "lock_value",
                         "estimated_unlock_height", "value_sat", "block_height", "is_inheritance_pattern"])
        for row in rows:
            writer.writerow(list(row))


def write_migration_snapshot():
    """Write daily aggregate stats for migration trend tracking.
    Call from cron after quantum + distribution scans complete."""
    with get_conn() as conn:
        q_run = conn.execute(
            "SELECT id, block_height FROM scan_runs "
            "WHERE scan_type='quantum' AND status='complete' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not q_run:
            return

        rows = conn.execute(
            "SELECT script_type, COUNT(*) AS cnt, SUM(value_sat) AS val "
            "FROM quantum_utxos WHERE scan_run_id=? GROUP BY script_type",
            (q_run["id"],),
        ).fetchall()

        dist = conn.execute(
            "SELECT SUM(utxo_count) AS tu, SUM(total_value_sat) AS tv "
            "FROM address_distribution WHERE scan_run_id = "
            "(SELECT MAX(id) FROM scan_runs WHERE scan_type='distribution' AND status='complete')"
        ).fetchone()

        bd = {r["script_type"]: (r["cnt"], r["val"]) for r in rows}
        vuln_utxos = sum(r["cnt"] for r in rows)
        vuln_value = sum(r["val"] for r in rows)

        conn.execute(
            "INSERT OR REPLACE INTO migration_snapshots "
            "(scan_date, block_height, total_utxos, total_value_sat, "
            " vuln_utxos, vuln_value_sat, "
            " p2pk_utxos, p2pk_value, p2tr_utxos, p2tr_value, p2ms_utxos, p2ms_value) "
            "VALUES (date('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                q_run["block_height"],
                dist["tu"] if dist else None,
                dist["tv"] if dist else None,
                vuln_utxos, vuln_value,
                *bd.get("P2PK", (0, 0)),
                *bd.get("P2TR", (0, 0)),
                *bd.get("P2MS", (0, 0)),
            ),
        )


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
