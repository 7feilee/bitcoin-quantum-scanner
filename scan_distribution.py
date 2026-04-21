"""
Address-type distribution scanner.

Iterates the full UTXO snapshot and buckets each entry by script type,
then writes aggregate statistics to address_distribution.

Quantum-risk ratings by script type:
  CRITICAL  P2PK, P2TR           – pubkey directly exposed
  HIGH      P2MS                  – multiple pubkeys exposed
  MEDIUM    P2SH, P2WSH           – script unknown until spend
  LOW       P2PKH, P2WPKH         – only hash exposed (assuming no reuse)
  NONE      OP_RETURN             – provably unspendable
  UNKNOWN   everything else

Typical runtime: 15-25 minutes.
"""

import logging
import os
import sys
import time
from collections import defaultdict

from config import (BITCOIN_RPC_HOST, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_PORT,
                    BITCOIN_RPC_USER, SNAPSHOT_PATH)
from chainstate_reader import iter_utxo_snapshot
from db import finish_scan_run, get_conn, init_db, start_scan_run

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [distribution] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "logs", "scan_distribution.log")),
    ],
)
log = logging.getLogger(__name__)

QUANTUM_RISK = {
    "P2PK":      "CRITICAL",
    "P2TR":      "CRITICAL",
    "P2MS":      "HIGH",
    "P2SH":      "MEDIUM",
    "P2WSH":     "MEDIUM",
    "P2PKH":     "LOW",
    "P2WPKH":    "LOW",
    "OP_RETURN": "NONE",
    "UNKNOWN":   "UNKNOWN",
}

LOG_INTERVAL = 5_000_000


def rpc(method, *params):
    from bitcoinrpc.authproxy import AuthServiceProxy
    url = (f"http://{BITCOIN_RPC_USER}:{BITCOIN_RPC_PASSWORD}"
           f"@{BITCOIN_RPC_HOST}:{BITCOIN_RPC_PORT}")
    proxy = AuthServiceProxy(url)
    return getattr(proxy, method)(*params)


def get_or_create_snapshot(path: str) -> tuple[int, str]:
    if os.path.exists(path):
        log.info("Reusing existing snapshot at %s", path)
        return None, None
    log.info("Creating UTXO snapshot…")
    info = rpc("dumptxoutset", path)
    return info.get("base_height", 0), info.get("base_hash", "")


def scan(snapshot_path: str, run_id: int) -> int:
    counts: dict[str, int] = defaultdict(int)
    values: dict[str, int] = defaultdict(int)
    processed = 0

    for utxo in iter_utxo_snapshot(snapshot_path):
        st = utxo["script_type"]
        counts[st] += 1
        values[st] += utxo["value_sat"]
        processed += 1
        if processed % LOG_INTERVAL == 0:
            log.info("Processed %d UTXOs…", processed)

    total_utxos = sum(counts.values())
    total_value = sum(values.values())

    with get_conn() as conn:
        # Clear previous distribution for this run type
        conn.execute(
            "DELETE FROM address_distribution WHERE scan_run_id IN "
            "(SELECT id FROM scan_runs WHERE scan_type='distribution')"
        )
        for st, cnt in sorted(counts.items(), key=lambda x: -x[1]):
            risk = QUANTUM_RISK.get(st, "UNKNOWN")
            pct_u = cnt / total_utxos * 100 if total_utxos else 0
            pct_v = values[st] / total_value * 100 if total_value else 0
            conn.execute(
                "INSERT INTO address_distribution "
                "(scan_run_id, script_type, utxo_count, total_value_sat, "
                " quantum_risk, pct_of_utxos, pct_of_value) "
                "VALUES (?,?,?,?,?,?,?)",
                (run_id, st, cnt, values[st], risk,
                 round(pct_u, 4), round(pct_v, 4)),
            )

    return processed


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bitcoin address-type distribution scanner")
    parser.add_argument("--snapshot", default=SNAPSHOT_PATH)
    parser.add_argument("--no-create-snapshot", action="store_true")
    args = parser.parse_args()

    init_db()

    if args.no_create_snapshot:
        block_height, block_hash = None, None
    else:
        block_height, block_hash = get_or_create_snapshot(args.snapshot)

    run_id = start_scan_run("distribution", block_height, block_hash)
    log.info("Started distribution scan run #%d", run_id)

    t0 = time.time()
    try:
        total = scan(args.snapshot, run_id)
        finish_scan_run(run_id, total)
        log.info("Distribution scan complete: %d UTXOs in %.1f s", total, time.time() - t0)
    except Exception as e:
        finish_scan_run(run_id, 0, str(e))
        log.exception("Scan failed")
        sys.exit(1)

    # Print summary
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT script_type, utxo_count, total_value_sat, quantum_risk, "
            "pct_of_utxos, pct_of_value FROM address_distribution "
            "WHERE scan_run_id=? ORDER BY utxo_count DESC", (run_id,)
        ).fetchall()
    log.info("%-12s %12s %20s %10s %8s %8s",
             "type", "count", "value_sat", "risk", "pct_n", "pct_v")
    for r in rows:
        log.info("%-12s %12d %20d %10s %7.2f%% %7.2f%%",
                 r[0], r[1], r[2], r[3], r[4], r[5])


if __name__ == "__main__":
    main()
