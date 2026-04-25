"""
All-wallet statistics scanner.

Reads the full UTXO snapshot (~165M outputs) to compute per-address BTC holdings
across the entire Bitcoin UTXO set — not just quantum-vulnerable addresses.

Writes three metrics to the DB:
  all_wallet_tiers   → tier distribution (wallet count + sat per tier)
  all_wallet_summary → total addresses, mean balance, total BTC
  wallet_top100      → top 100 addresses by total BTC held

Runtime: ~20-30 minutes (same pass as scan_quantum.py).
Must run BEFORE the cron removes the snapshot (added before rm -f in cron.sh).

Note: P2PK and bare-multisig UTXOs have no standard address and are counted
in all_wallet_summary totals but excluded from tier/top-100 tables (those
are covered by the quantum-vulnerable wallet_tiers metric).
"""

import heapq
import logging
import os
import sys
import time

from config import HRP, P2PKH_VERSION, P2SH_VERSION, SNAPSHOT_PATH
from chainstate_reader import iter_utxo_snapshot, script_to_address
from db import get_conn, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [allwallets] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "logs", "scan_allwallets.log")),
    ],
)
log = logging.getLogger(__name__)

# BTC tier boundaries in satoshis (lower bound inclusive)
_TIERS = [
    ("whale_10k_plus",  1_000_000_000_000),   # ≥ 10 000 BTC
    ("whale_5k_10k",      500_000_000_000),   # 5 000–10 000
    ("whale_1k_5k",       100_000_000_000),   # 1 000–5 000
    ("large_100_1k",       10_000_000_000),   # 100–1 000
    ("medium_10_100",       1_000_000_000),   # 10–100
    ("small_1_10",            100_000_000),   # 1–10
    ("dust_under1",                     0),   # < 1
]


def _tier(sat: int) -> str:
    for name, threshold in _TIERS:
        if sat >= threshold:
            return name
    return "dust_under1"


def _infer_type(addr: str) -> str:
    if not addr:
        return "UNKNOWN"
    low = addr.lower()
    if low.startswith("bc1p"):
        return "P2TR"
    if low.startswith("bc1q"):
        return "P2WPKH" if len(addr) <= 42 else "P2WSH"
    if addr[0] == "1":
        return "P2PKH"
    if addr[0] == "3":
        return "P2SH"
    return "UNKNOWN"


def scan(snapshot_path: str):
    if not os.path.exists(snapshot_path):
        log.error("Snapshot not found at %s — run scan_quantum.py first", snapshot_path)
        sys.exit(1)

    log.info("Reading UTXO snapshot: %s", snapshot_path)
    t0 = time.time()

    # address → [total_sat, utxo_count]
    addr_data: dict = {}
    total_utxos  = 0
    no_addr_sats = 0   # P2PK / bare-multisig / OP_RETURN

    for utxo in iter_utxo_snapshot(snapshot_path):
        script      = utxo["script"]
        script_type = utxo["script_type"]
        value_sat   = utxo["value_sat"]
        total_utxos += 1

        addr = script_to_address(script, script_type, hrp=HRP,
                                  p2pkh_ver=P2PKH_VERSION, p2sh_ver=P2SH_VERSION)
        if not addr:
            no_addr_sats += value_sat
            continue

        entry = addr_data.get(addr)
        if entry is None:
            addr_data[addr] = [value_sat, 1]
        else:
            entry[0] += value_sat
            entry[1] += 1

        if total_utxos % 10_000_000 == 0:
            elapsed = time.time() - t0
            log.info("  %dM UTXOs processed — %d unique addresses (%.0fs)",
                     total_utxos // 1_000_000, len(addr_data), elapsed)

    elapsed = time.time() - t0
    log.info("Snapshot read: %d UTXOs, %d unique addresses in %.0fs",
             total_utxos, len(addr_data), elapsed)

    # ── compute tier distribution ──────────────────────────────────────────────
    tier_wallets: dict = {}
    tier_sats:    dict = {}
    total_addressable_sat = 0

    for sat, _ in addr_data.values():
        t = _tier(sat)
        tier_wallets[t] = tier_wallets.get(t, 0) + 1
        tier_sats[t]    = tier_sats.get(t, 0) + sat
        total_addressable_sat += sat

    total_wallets = len(addr_data)
    mean_sat = total_addressable_sat // total_wallets if total_wallets else 0

    # ── top 100 by total BTC held ──────────────────────────────────────────────
    top100 = heapq.nlargest(100, addr_data.items(), key=lambda kv: kv[1][0])

    # ── write to DB ───────────────────────────────────────────────────────────
    with get_conn() as conn:
        # Tier distribution
        conn.execute("DELETE FROM quantum_analytics WHERE metric='all_wallet_tiers'")
        conn.executemany(
            "INSERT INTO quantum_analytics (metric, label, utxo_count, value_sat) "
            "VALUES (?,?,?,?)",
            [("all_wallet_tiers", name, tier_wallets.get(name, 0), tier_sats.get(name, 0))
             for name, _ in _TIERS],
        )

        # Summary
        conn.execute("DELETE FROM quantum_analytics WHERE metric='all_wallet_summary'")
        conn.executemany(
            "INSERT INTO quantum_analytics (metric, label, utxo_count, value_sat) "
            "VALUES (?,?,?,?)",
            [
                ("all_wallet_summary", "total_addresses", total_wallets, 0),
                ("all_wallet_summary", "mean_balance_sat", 0, mean_sat),
                ("all_wallet_summary", "total_btc_sat",    0, total_addressable_sat),
                ("all_wallet_summary", "no_addr_sat",      0, no_addr_sats),
            ],
        )

        # Top 100
        conn.execute("DELETE FROM wallet_top100")
        conn.executemany(
            "INSERT INTO wallet_top100 (rank, address, script_type, utxo_count, value_sat) "
            "VALUES (?,?,?,?,?)",
            [(i + 1, addr, _infer_type(addr), data[1], data[0])
             for i, (addr, data) in enumerate(top100)],
        )

    log.info("Written: %d tiers, summary, top-100. Total time %.0fs",
             len(tier_wallets), time.time() - t0)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="All-wallet UTXO statistics scanner")
    parser.add_argument("--snapshot", default=SNAPSHOT_PATH)
    args = parser.parse_args()
    init_db()
    scan(args.snapshot)


if __name__ == "__main__":
    main()
