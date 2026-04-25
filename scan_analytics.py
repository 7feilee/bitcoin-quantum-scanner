"""
Analytics scanner — runs after the daily quantum + distribution scan.

Computes pre-aggregated metrics from existing DB tables and stores them in
quantum_analytics so API endpoints can serve them in <1 ms.

Metrics computed:
  dormancy          — vulnerable UTXOs bucketed by Bitcoin halving epoch
  value_concentration — top 100 addresses by total BTC held
  satoshi_era       — P2PK UTXOs in blocks 0-100000 broken into four eras
  p2sh_multisig     — exposed multisig scripts found in timelock_utxos
  entity_tag        — cross-reference against data/known_entities.json
  lightning         — Lightning channel estimate from CSV timelock patterns

P2TR growth (Feature 4) requires no computation here; the API reads
migration_snapshots directly.

Runtime: ~2-10 minutes (SQL on indexed 57M-row table).
"""

import json
import logging
import os
import sys

from db import get_conn, get_latest_analytics, init_db  # noqa: F401 (get_latest_analytics imported for callers)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [analytics] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "logs", "scan_analytics.log")),
    ],
)
log = logging.getLogger(__name__)

_ENTITIES_PATH = os.path.join(os.path.dirname(__file__), "data", "known_entities.json")


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_latest_quantum_run_id(conn) -> int | None:
    row = conn.execute(
        "SELECT id FROM scan_runs WHERE scan_type='quantum' AND status='complete' "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["id"] if row else None


def _write_metric(conn, metric: str, rows: list[dict], run_id: int | None):
    conn.execute("DELETE FROM quantum_analytics WHERE metric=?", (metric,))
    conn.executemany(
        "INSERT INTO quantum_analytics (scan_run_id, metric, label, utxo_count, value_sat) "
        "VALUES (?,?,?,?,?)",
        [(run_id, metric, r["label"], r["utxo_count"], r["value_sat"]) for r in rows],
    )
    log.info("metric %-22s  %d rows", metric, len(rows))


# ── Feature 1: Dormancy distribution ─────────────────────────────────────────

def compute_dormancy(run_id: int, conn):
    rows = conn.execute(
        """
        SELECT
            CASE
                WHEN block_height < 210000 THEN 'genesis'
                WHEN block_height < 420000 THEN 'halving1'
                WHEN block_height < 630000 THEN 'halving2'
                WHEN block_height < 840000 THEN 'halving3'
                ELSE                            'halving4_plus'
            END AS epoch,
            COUNT(*)       AS utxo_count,
            SUM(value_sat) AS value_sat
        FROM quantum_utxos
        WHERE scan_run_id = ?
        GROUP BY epoch
        """,
        (run_id,),
    ).fetchall()

    _write_metric(conn, "dormancy", [dict(r) | {"label": r["epoch"]} for r in rows], run_id)


# ── Feature 2: Value concentration (top 100 addresses) ───────────────────────

def compute_value_concentration(run_id: int, conn):
    rows = conn.execute(
        """
        SELECT address, COUNT(*) AS utxo_count, SUM(value_sat) AS value_sat
        FROM quantum_utxos
        WHERE scan_run_id = ? AND address IS NOT NULL
        GROUP BY address
        ORDER BY value_sat DESC
        LIMIT 100
        """,
        (run_id,),
    ).fetchall()

    _write_metric(conn, "value_concentration",
                  [{"label": r["address"], "utxo_count": r["utxo_count"], "value_sat": r["value_sat"]}
                   for r in rows], run_id)


# ── Feature 3: Satoshi-era P2PK breakdown ────────────────────────────────────

def compute_satoshi_era(run_id: int, conn):
    rows = conn.execute(
        """
        SELECT
            CASE
                WHEN block_height <= 1000  THEN 'genesis'
                WHEN block_height <= 10000 THEN 'early'
                WHEN block_height <= 50000 THEN 'satoshi_era'
                ELSE                            'post_satoshi'
            END AS era,
            COUNT(*)       AS utxo_count,
            SUM(value_sat) AS value_sat
        FROM quantum_utxos
        WHERE scan_run_id = ? AND script_type = 'P2PK' AND block_height <= 100000
        GROUP BY era
        """,
        (run_id,),
    ).fetchall()

    _write_metric(conn, "satoshi_era",
                  [{"label": r["era"], "utxo_count": r["utxo_count"], "value_sat": r["value_sat"]}
                   for r in rows], run_id)


# ── Feature 6: P2SH/P2WSH multisig resolution ────────────────────────────────

def compute_p2sh_multisig(conn):
    # Use indexed COUNT queries — no fetchall on the large timelock_utxos table.
    # idx_timelock_type covers lock_type; no index on extra_json so we count by
    # lock_type pattern as a fast proxy for source type.
    p2sh = conn.execute(
        "SELECT COUNT(*) FROM timelock_utxos WHERE lock_type != 'CSV' AND lock_type != 'CLTV_CSV'"
        " AND extra_json IS NOT NULL"
    ).fetchone()[0]

    witness = conn.execute(
        "SELECT COUNT(*) FROM timelock_utxos WHERE lock_type IN ('CLTV','CSV','CLTV_CSV')"
        " AND extra_json IS NOT NULL"
    ).fetchone()[0]

    _write_metric(conn, "p2sh_multisig", [
        {"label": "exposed_multisig", "utxo_count": p2sh,    "value_sat": 0},
        {"label": "other_p2sh",       "utxo_count": witness, "value_sat": 0},
    ], None)


# ── Feature 7: Exchange / entity tagging ─────────────────────────────────────

def compute_entity_tags(run_id: int, conn):
    if not os.path.exists(_ENTITIES_PATH):
        log.warning("known_entities.json not found at %s; skipping", _ENTITIES_PATH)
        return

    with open(_ENTITIES_PATH) as f:
        entities = json.load(f)

    out: list[dict] = []
    for e in entities:
        name = e["entity"]
        pubkey = e.get("pubkey_hex")
        address = e.get("address")

        row = None
        if pubkey:
            # Try exact match first; also try compressed form of uncompressed key
            row = conn.execute(
                "SELECT COUNT(*) AS cnt, COALESCE(SUM(value_sat),0) AS val "
                "FROM quantum_utxos WHERE pubkey_hex = ?",
                (pubkey,),
            ).fetchone()
            if not row or not row["cnt"]:
                # Uncompressed → compressed: take X coordinate (bytes 1-33) with 02/03 prefix
                if len(pubkey) == 130 and pubkey.startswith("04"):
                    try:
                        x = int(pubkey[2:66], 16)
                        y = int(pubkey[66:], 16)
                        prefix = "02" if y % 2 == 0 else "03"
                        compressed = prefix + pubkey[2:66]
                        row = conn.execute(
                            "SELECT COUNT(*) AS cnt, COALESCE(SUM(value_sat),0) AS val "
                            "FROM quantum_utxos WHERE pubkey_hex = ?",
                            (compressed,),
                        ).fetchone()
                    except ValueError:
                        pass
        elif address:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt, COALESCE(SUM(value_sat),0) AS val "
                "FROM quantum_utxos WHERE address = ?",
                (address,),
            ).fetchone()

        if row and row["cnt"]:
            out.append({"label": name, "utxo_count": row["cnt"], "value_sat": row["val"]})

    _write_metric(conn, "entity_tag", out, run_id)


# ── Feature 8: Lightning channel estimate ─────────────────────────────────────

def compute_lightning(conn):
    csv_row = conn.execute(
        "SELECT COUNT(*) AS cnt, COALESCE(SUM(value_sat),0) AS val "
        "FROM timelock_utxos WHERE lock_type='CSV'"
    ).fetchone()

    p2wsh_row = conn.execute(
        "SELECT utxo_count FROM address_distribution "
        "WHERE scan_run_id = ("
        "  SELECT MAX(id) FROM scan_runs WHERE scan_type='distribution' AND status='complete'"
        ") AND script_type='P2WSH'"
    ).fetchone()

    _write_metric(conn, "lightning", [
        {"label": "csv_utxo_count",        "utxo_count": csv_row["cnt"] if csv_row else 0, "value_sat": csv_row["val"] if csv_row else 0},
        {"label": "p2wsh_utxo_upper_bound","utxo_count": p2wsh_row["utxo_count"] if p2wsh_row else 0, "value_sat": 0},
    ], None)


# ── Wallet tier distribution ─────────────────────────────────────────────────

# Satoshi thresholds for each tier
_TIERS = [
    ("whale_10k_plus",  1_000_000_000_000, None),                          # ≥ 10 000 BTC
    ("whale_5k_10k",      500_000_000_000, 1_000_000_000_000),             # 5 000–10 000
    ("whale_1k_5k",       100_000_000_000,   500_000_000_000),             # 1 000–5 000
    ("large_100_1k",       10_000_000_000,   100_000_000_000),             # 100–1 000
    ("medium_10_100",       1_000_000_000,    10_000_000_000),             # 10–100
    ("small_under10",                   0,     1_000_000_000),             # < 10
]

def compute_wallet_tiers(run_id: int, conn):
    # Per-address totals (same subquery as value_concentration — reuses query cache).
    rows = conn.execute(
        """
        SELECT
            CASE
                WHEN total_sat >= 1000000000000 THEN 'whale_10k_plus'
                WHEN total_sat >=  500000000000 THEN 'whale_5k_10k'
                WHEN total_sat >=  100000000000 THEN 'whale_1k_5k'
                WHEN total_sat >=   10000000000 THEN 'large_100_1k'
                WHEN total_sat >=    1000000000 THEN 'medium_10_100'
                ELSE                                 'small_under10'
            END AS tier,
            COUNT(*)        AS wallet_count,
            SUM(total_sat)  AS value_sat
        FROM (
            SELECT address, SUM(value_sat) AS total_sat
            FROM quantum_utxos
            WHERE scan_run_id = ? AND address IS NOT NULL
            GROUP BY address
        )
        GROUP BY tier
        """,
        (run_id,),
    ).fetchall()

    _write_metric(conn, "wallet_tiers",
                  [{"label": r["tier"], "utxo_count": r["wallet_count"], "value_sat": r["value_sat"]}
                   for r in rows], run_id)


# ── main ──────────────────────────────────────────────────────────────────────

def _run(name: str, fn):
    try:
        fn()
    except Exception as e:
        log.error("metric %s failed: %s", name, e)


def main():
    init_db()

    with get_conn() as conn:
        run_id = _get_latest_quantum_run_id(conn)
    if not run_id:
        log.error("No completed quantum scan found — run scan_quantum.py first")
        sys.exit(1)

    log.info("Computing analytics for quantum scan run #%d", run_id)

    _run("dormancy",            lambda: _with_conn(compute_dormancy,            run_id))
    _run("value_concentration", lambda: _with_conn(compute_value_concentration, run_id))
    _run("wallet_tiers",        lambda: _with_conn(compute_wallet_tiers,        run_id))
    _run("satoshi_era",         lambda: _with_conn(compute_satoshi_era,         run_id))
    _run("p2sh_multisig",       lambda: _with_conn(compute_p2sh_multisig))
    _run("entity_tags",         lambda: _with_conn(compute_entity_tags,         run_id))
    _run("lightning",           lambda: _with_conn(compute_lightning))

    log.info("Analytics complete")


def _with_conn(fn, *args):
    with get_conn() as conn:
        fn(*args, conn)


if __name__ == "__main__":
    main()
