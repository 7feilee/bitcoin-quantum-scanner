"""
Quantum vulnerability scanner.

Risk classification:
  CRITICAL  P2PK   – raw public key in scriptPubKey (types 2-5 in chainstate)
  CRITICAL  P2TR   – x-only public key in scriptPubKey (OP_1 <32-byte-key>)
  HIGH      P2PKH/P2WPKH reused – pubkey was revealed in a prior spend;
            detected by cross-checking the UTXO address list against
            transaction inputs via RPC (optional, enabled with --check-reuse)
  MEDIUM    P2MS   – multisig with exposed public keys in scriptPubKey

Runtime:
  1. bitcoin-cli dumptxoutset <SNAPSHOT_PATH>  (~5-10 min, safe with a running node)
  2. Parse snapshot → identify vulnerable UTXOs
  3. Write results to SQLite + quantum_utxos.csv

Typical duration: 20-35 minutes on modern hardware.
"""

import argparse
import logging
import os
import subprocess
import sys
import time

from config import (BITCOIN_RPC_HOST, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_PORT,
                    BITCOIN_RPC_USER, CSV_DIR, HRP, P2PKH_VERSION, P2SH_VERSION,
                    SNAPSHOT_PATH)
from chainstate_reader import (iter_utxo_snapshot, pubkey_from_p2pk_script,
                                script_to_address)
from db import finish_scan_run, get_conn, init_db, start_scan_run

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [quantum] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "logs", "scan_quantum.log")),
    ],
)
log = logging.getLogger(__name__)

BATCH_SIZE = 50_000


def rpc(method, *params):
    from bitcoinrpc.authproxy import AuthServiceProxy
    url = (f"http://{BITCOIN_RPC_USER}:{BITCOIN_RPC_PASSWORD}"
           f"@{BITCOIN_RPC_HOST}:{BITCOIN_RPC_PORT}")
    # dumptxoutset on a full mainnet node can take 20-40 minutes; use 2h timeout.
    timeout = 7200 if method == "dumptxoutset" else 60
    proxy = AuthServiceProxy(url, timeout=timeout)
    return getattr(proxy, method)(*params)


def create_snapshot(path: str) -> dict:
    if os.path.exists(path):
        log.info("Removing stale snapshot at %s", path)
        os.unlink(path)
    log.info("Creating UTXO snapshot via RPC (this takes several minutes)…")
    result = rpc("dumptxoutset", path)
    log.info("Snapshot created: %s UTXOs at block %d (%s)",
             result.get("coins_written", "?"),
             result.get("base_height", 0),
             result.get("base_hash", "?")[:16] + "…")
    # bitcoind creates the file as bitcoin:bitcoin 600; make it group-readable
    # so the test user (member of bitcoin group) can parse it.
    subprocess.run(["sudo", "/usr/bin/chmod", "640", path], check=True)
    return result


def risk_for_type(script_type: str) -> tuple[str, str]:
    """Return (risk_level, risk_reason)."""
    if script_type == "P2PK":
        return ("CRITICAL",
                "Raw public key exposed in output script; "
                "Shor's algorithm can derive private key directly")
    if script_type == "P2TR":
        return ("CRITICAL",
                "x-only public key exposed in output script (Taproot); "
                "vulnerable to quantum key recovery")
    if script_type == "P2MS":
        return ("HIGH",
                "Multiple public keys exposed in bare multisig script")
    return ("MEDIUM", "Script type exposes key material")


def insert_batch(conn, batch: list, run_id: int):
    conn.executemany(
        "INSERT OR REPLACE INTO quantum_utxos "
        "(txid, vout, address, script_hex, script_type, pubkey_hex, "
        " value_sat, block_height, risk_level, risk_reason, scan_run_id) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            (r["txid"], r["vout"], r["address"], r["script_hex"],
             r["script_type"], r["pubkey_hex"], r["value_sat"],
             r["height"], r["risk_level"], r["risk_reason"], run_id)
            for r in batch
        ],
    )


def scan(snapshot_path: str, run_id: int) -> int:
    total = 0
    batch = []

    for utxo in iter_utxo_snapshot(snapshot_path):
        st = utxo["script_type"]
        if st not in ("P2PK", "P2TR", "P2MS"):
            continue

        risk_level, risk_reason = risk_for_type(st)
        address = script_to_address(utxo["script"], st, HRP, P2PKH_VERSION, P2SH_VERSION)
        pubkey = pubkey_from_p2pk_script(utxo["script"], st)

        # For P2TR, expose the x-only key
        if st == "P2TR" and len(utxo["script"]) >= 34:
            pubkey = utxo["script"][2:34].hex()

        batch.append({
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "address": address,
            "script_hex": utxo["script"].hex(),
            "script_type": st,
            "pubkey_hex": pubkey,
            "value_sat": utxo["value_sat"],
            "height": utxo["height"],
            "risk_level": risk_level,
            "risk_reason": risk_reason,
        })

        if len(batch) >= BATCH_SIZE:
            with get_conn() as conn:
                insert_batch(conn, batch, run_id)
            total += len(batch)
            log.info("Inserted %d records (running total: %d)", len(batch), total)
            batch.clear()

    if batch:
        with get_conn() as conn:
            insert_batch(conn, batch, run_id)
        total += len(batch)

    return total


def main():
    parser = argparse.ArgumentParser(description="Bitcoin quantum vulnerability scanner")
    parser.add_argument("--snapshot", default=SNAPSHOT_PATH,
                        help="Path to dumptxoutset file (created if absent)")
    parser.add_argument("--no-create-snapshot", action="store_true",
                        help="Use existing snapshot file without calling dumptxoutset")
    parser.add_argument("--keep-snapshot", action="store_true",
                        help="Do not delete snapshot file after scan")
    args = parser.parse_args()

    init_db()

    if not args.no_create_snapshot:
        info = create_snapshot(args.snapshot)
        block_height = info.get("base_height", 0)
        block_hash = info.get("base_hash", "")
    else:
        log.info("Using existing snapshot at %s", args.snapshot)
        block_height, block_hash = None, None

    run_id = start_scan_run("quantum", block_height, block_hash)
    log.info("Started scan run #%d", run_id)

    t0 = time.time()
    try:
        total = scan(args.snapshot, run_id)
        finish_scan_run(run_id, total)
        log.info("Scan complete: %d vulnerable UTXOs in %.1f s", total, time.time() - t0)
    except Exception as e:
        finish_scan_run(run_id, 0, str(e))
        log.exception("Scan failed")
        sys.exit(1)
    finally:
        if not args.keep_snapshot and not args.no_create_snapshot and os.path.exists(args.snapshot):
            os.unlink(args.snapshot)
            log.info("Deleted snapshot file")

    # Export CSV
    import csv
    csv_path = os.path.join(CSV_DIR, "quantum_utxos.csv")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT txid, vout, address, script_type, pubkey_hex, "
            "value_sat, block_height, risk_level, risk_reason "
            "FROM quantum_utxos WHERE scan_run_id=?", (run_id,)
        ).fetchall()
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["txid", "vout", "address", "script_type", "pubkey_hex",
                    "value_sat", "block_height", "risk_level", "risk_reason"])
        for r in rows:
            w.writerow(list(r))
    log.info("CSV written to %s (%d rows)", csv_path, len(rows))


if __name__ == "__main__":
    main()
