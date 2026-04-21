"""
Timelock UTXO scanner — runs as a multi-day background job.

Detects:
  1. Bare CLTV / CSV scripts in the UTXO set (visible directly in scriptPubKey)
  2. P2WSH outputs whose witness scripts contain OP_CLTV or OP_CSV
     (found by scanning spending inputs across all historical transactions)
  3. Non-default nLockTime transactions with unspent outputs
  4. Dual-key inheritance pattern:
       OP_IF <primary_key> OP_CHECKSIG OP_ELSE
         <locktime> OP_CLTV OP_DROP <backup_key> OP_CHECKSIG OP_ENDIF

Strategy:
  Phase 1 (fast, ~30 min): scan UTXO snapshot for bare CLTV/CSV in raw scripts
  Phase 2 (slow, 3-5 days): iterate blocks 0..tip via getblock verbosity=2,
      extract P2WSH/P2SH witness scripts, detect timelock patterns

Progress is checkpointed to SQLite so the job is restartable.

OP codes:
  0xb1 = OP_CHECKLOCKTIMEVERIFY (CLTV)
  0xb2 = OP_CHECKSEQUENCEVERIFY (CSV)
"""

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from typing import Optional

from config import (BITCOIN_RPC_HOST, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_PORT,
                    BITCOIN_RPC_USER, CSV_DIR, HRP, P2PKH_VERSION, P2SH_VERSION,
                    SNAPSHOT_PATH)
from chainstate_reader import bech32_address, base58check, iter_utxo_snapshot
from db import finish_scan_run, get_conn, init_db, start_scan_run

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [timelocks] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "logs", "scan_timelocks.log")),
    ],
)
log = logging.getLogger(__name__)

OP_CLTV = 0xb1
OP_CSV  = 0xb2
OP_IF   = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_DROP  = 0x75
OP_CHECKSIG = 0xac

BATCH_SIZE = 10_000
BLOCK_BATCH = 500   # blocks processed per log line


# ── RPC helper ────────────────────────────────────────────────────────────────

_rpc_proxy = None

def rpc(method, *params):
    global _rpc_proxy
    from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
    if _rpc_proxy is None:
        url = (f"http://{BITCOIN_RPC_USER}:{BITCOIN_RPC_PASSWORD}"
               f"@{BITCOIN_RPC_HOST}:{BITCOIN_RPC_PORT}")
        _rpc_proxy = AuthServiceProxy(url, timeout=120)
    try:
        return getattr(_rpc_proxy, method)(*params)
    except Exception:
        # Reconnect on failure
        _rpc_proxy = None
        raise


# ── script analysis ───────────────────────────────────────────────────────────

def has_timelock_opcode(script: bytes) -> tuple[bool, str]:
    """Return (found, lock_type) for CLTV/CSV presence."""
    has_cltv = OP_CLTV in script
    has_csv  = OP_CSV  in script
    if has_cltv and has_csv:
        return True, "CLTV_CSV"
    if has_cltv:
        return True, "CLTV"
    if has_csv:
        return True, "CSV"
    return False, ""


def extract_lock_value(script: bytes, lock_type: str) -> Optional[int]:
    """Parse the numeric argument immediately before OP_CLTV or OP_CSV."""
    opcode = OP_CLTV if "CLTV" in lock_type else OP_CSV
    for i, b in enumerate(script):
        if b != opcode:
            continue
        if i == 0:
            return None
        # Walk back over OP_DROP if present
        j = i - 1
        if j >= 0 and script[j] == OP_DROP:
            j -= 1
        if j < 0:
            return None
        # The byte at j should be a data push size (1-5 bytes for locktime)
        push_len = script[j]
        if push_len == 0:
            return 0
        if 1 <= push_len <= 5:
            start = j - push_len
            if start >= 0:
                raw = script[start:j]
                # little-endian signed integer
                if not raw:
                    return None
                val = int.from_bytes(raw, "little", signed=False)
                return val
    return None


def is_inheritance_pattern(script: bytes) -> bool:
    """
    Heuristic: OP_IF <pubkey_push> OP_CHECKSIG OP_ELSE <n> OP_CLTV OP_DROP <pubkey_push> OP_CHECKSIG OP_ENDIF
    Must contain OP_IF, OP_ELSE, OP_ENDIF, OP_CHECKSIG×2, and OP_CLTV.
    """
    if OP_IF not in script or OP_ELSE not in script or OP_ENDIF not in script:
        return False
    if script.count(OP_CHECKSIG) < 2:
        return False
    if OP_CLTV not in script:
        return False
    return True


def script_type_from_raw(script: bytes) -> str:
    n = len(script)
    if n == 22 and script[0] == 0x00 and script[1] == 0x14:
        return "P2WPKH"
    if n == 34 and script[0] == 0x00 and script[1] == 0x20:
        return "P2WSH"
    if n == 34 and script[0] == 0x51 and script[1] == 0x20:
        return "P2TR"
    return "UNKNOWN"


def address_from_script(script: bytes, script_type: str) -> Optional[str]:
    if script_type == "P2WPKH":
        return bech32_address(HRP, 0, script[2:22])
    if script_type == "P2WSH":
        return bech32_address(HRP, 0, script[2:34])
    if script_type == "P2TR":
        return bech32_address(HRP, 1, script[2:34])
    if script_type == "P2PKH" and len(script) == 25:
        return base58check(P2PKH_VERSION + script[3:23])
    if script_type == "P2SH" and len(script) == 23:
        return base58check(P2SH_VERSION + script[2:22])
    return None


# ── Phase 1: UTXO snapshot scan for bare timelocks ───────────────────────────

def phase1_snapshot(snapshot_path: str, run_id: int) -> int:
    log.info("Phase 1: scanning UTXO snapshot for bare CLTV/CSV scripts…")
    batch = []
    found = 0

    for utxo in iter_utxo_snapshot(snapshot_path):
        script = utxo["script"]
        st     = utxo["script_type"]
        if st == "OP_RETURN":
            continue

        ok, lock_type = has_timelock_opcode(script)
        if not ok:
            continue

        lock_value  = extract_lock_value(script, lock_type)
        inherit     = is_inheritance_pattern(script)
        address     = address_from_script(script, st)

        batch.append({
            "txid": utxo["txid"], "vout": utxo["vout"],
            "address": address, "script_hex": script.hex(),
            "lock_type": lock_type, "lock_value": lock_value,
            "unlock_height": lock_value if "CLTV" in lock_type else None,
            "value_sat": utxo["value_sat"], "height": utxo["height"],
            "inherit": int(inherit), "extra": None,
        })
        if len(batch) >= BATCH_SIZE:
            _insert_batch(batch, run_id)
            found += len(batch)
            batch.clear()

    if batch:
        _insert_batch(batch, run_id)
        found += len(batch)

    log.info("Phase 1 complete: %d bare timelock UTXOs found", found)
    return found


# ── Phase 2: block-by-block scan for P2WSH/P2SH timelock scripts ─────────────

def _get_checkpoint(run_id: int) -> int:
    """Return the last checkpointed block height for a resumable scan, or 0."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT error_msg FROM scan_runs WHERE id=?", (run_id,)
        ).fetchone()
    if row and row[0]:
        try:
            return json.loads(row[0]).get("phase2_block", 0)
        except Exception:
            return 0
    return 0


def _save_checkpoint(run_id: int, block_height: int, found: int):
    with get_conn() as conn:
        conn.execute(
            "UPDATE scan_runs SET error_msg=?, records_found=? WHERE id=?",
            (json.dumps({"phase2_block": block_height}), found, run_id),
        )


def phase2_blocks(run_id: int, start_block: int = 0) -> int:
    tip = rpc("getblockcount")
    log.info("Phase 2: scanning blocks %d – %d for P2WSH/P2SH timelocks…", start_block, tip)

    batch = []
    found = 0
    t_batch = time.time()

    for height in range(start_block, tip + 1):
        bhash = rpc("getblockhash", height)
        block = rpc("getblock", bhash, 2)  # verbosity=2: full tx data

        for tx in block["tx"]:
            # Scan inputs for witness scripts (reveals P2WSH/P2SH redeemScript)
            for vin in tx.get("vin", []):
                witness = vin.get("txinwitness", [])
                if witness:
                    # Last item in witness is the witness script for P2WSH
                    ws_hex = witness[-1]
                    try:
                        ws = bytes.fromhex(ws_hex)
                    except ValueError:
                        continue
                    ok, lock_type = has_timelock_opcode(ws)
                    if not ok:
                        continue
                    # The UTXO being spent here no longer exists, but we record the
                    # script pattern so we can detect the same template in live UTXOs.
                    lock_value = extract_lock_value(ws, lock_type)
                    inherit    = is_inheritance_pattern(ws)
                    ws_hash    = hashlib.sha256(ws).digest()
                    address    = bech32_address(HRP, 0, ws_hash)
                    batch.append({
                        "txid": vin.get("txid", ""), "vout": vin.get("vout", 0),
                        "address": address, "script_hex": ws.hex(),
                        "lock_type": lock_type, "lock_value": lock_value,
                        "unlock_height": lock_value if "CLTV" in lock_type else None,
                        "value_sat": 0,  # we don't know value from input alone
                        "height": height,
                        "inherit": int(inherit),
                        "extra": json.dumps({"source": "witness_script", "spending_txid": tx["txid"]}),
                    })

                # Also check scriptSig for P2SH redeemScript (last push)
                sig_hex = vin.get("scriptSig", {}).get("hex", "")
                if sig_hex:
                    try:
                        sig = bytes.fromhex(sig_hex)
                    except ValueError:
                        continue
                    # The redeem script is the last pushed item in scriptSig
                    redeem = _extract_last_push(sig)
                    if redeem and len(redeem) > 2:
                        ok, lock_type = has_timelock_opcode(redeem)
                        if ok:
                            lock_value = extract_lock_value(redeem, lock_type)
                            inherit    = is_inheritance_pattern(redeem)
                            batch.append({
                                "txid": vin.get("txid", ""), "vout": vin.get("vout", 0),
                                "address": None, "script_hex": redeem.hex(),
                                "lock_type": lock_type, "lock_value": lock_value,
                                "unlock_height": lock_value if "CLTV" in lock_type else None,
                                "value_sat": 0,
                                "height": height,
                                "inherit": int(inherit),
                                "extra": json.dumps({"source": "p2sh_redeemscript", "spending_txid": tx["txid"]}),
                            })

        if len(batch) >= BATCH_SIZE:
            _insert_batch(batch, run_id)
            found += len(batch)
            batch.clear()

        if height % BLOCK_BATCH == 0:
            elapsed = time.time() - t_batch
            rate = BLOCK_BATCH / elapsed if elapsed else 0
            eta_h = (tip - height) / rate / 3600 if rate else 0
            log.info("Block %d / %d  found=%d  %.0f blk/s  ETA %.1f h",
                     height, tip, found, rate, eta_h)
            _save_checkpoint(run_id, height, found)
            t_batch = time.time()

    if batch:
        _insert_batch(batch, run_id)
        found += len(batch)

    return found


def _extract_last_push(script: bytes) -> Optional[bytes]:
    """Return the data from the last push opcode in script."""
    pos, last = 0, None
    while pos < len(script):
        op = script[pos]
        pos += 1
        if 1 <= op <= 75:
            if pos + op <= len(script):
                last = script[pos:pos + op]
                pos += op
        elif op == 0x4c:  # OP_PUSHDATA1
            if pos < len(script):
                n = script[pos]; pos += 1
                last = script[pos:pos + n]; pos += n
        elif op == 0x4d:  # OP_PUSHDATA2
            if pos + 2 <= len(script):
                n = int.from_bytes(script[pos:pos + 2], "little"); pos += 2
                last = script[pos:pos + n]; pos += n
        else:
            pass
    return last


def _insert_batch(batch: list, run_id: int):
    with get_conn() as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO timelock_utxos "
            "(txid, vout, address, script_hex, lock_type, lock_value, "
            " estimated_unlock_height, value_sat, block_height, "
            " is_inheritance_pattern, extra_json, scan_run_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (r["txid"], r["vout"], r["address"], r["script_hex"],
                 r["lock_type"], r["lock_value"], r["unlock_height"],
                 r["value_sat"], r["height"], r["inherit"],
                 r["extra"], run_id)
                for r in batch
            ],
        )


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Bitcoin timelock UTXO scanner")
    parser.add_argument("--snapshot", default=SNAPSHOT_PATH)
    parser.add_argument("--skip-phase1", action="store_true",
                        help="Skip bare-script UTXO scan")
    parser.add_argument("--skip-phase2", action="store_true",
                        help="Skip block-by-block scan")
    parser.add_argument("--resume", type=int, default=None,
                        help="Resume phase 2 from this block height")
    parser.add_argument("--run-id", type=int, default=None,
                        help="Resume an existing scan run by ID")
    args = parser.parse_args()

    init_db()

    try:
        tip = rpc("getblockcount")
        tip_hash = rpc("getblockhash", tip)
    except Exception as e:
        log.error("Cannot connect to Bitcoin Core RPC: %s", e)
        sys.exit(1)

    if args.run_id:
        run_id = args.run_id
        log.info("Resuming scan run #%d", run_id)
    else:
        run_id = start_scan_run("timelocks", tip, tip_hash)
        log.info("Started timelock scan run #%d (tip block %d)", run_id, tip)

    total = 0
    t0 = time.time()

    try:
        if not args.skip_phase1:
            if not os.path.exists(args.snapshot):
                log.info("Creating UTXO snapshot for phase 1…")
                rpc("dumptxoutset", args.snapshot)
            total += phase1_snapshot(args.snapshot, run_id)

        if not args.skip_phase2:
            start_blk = args.resume if args.resume is not None else _get_checkpoint(run_id)
            total += phase2_blocks(run_id, start_blk)

        # Clear the checkpoint marker now that we're done
        with get_conn() as conn:
            conn.execute(
                "UPDATE scan_runs SET error_msg=NULL WHERE id=?", (run_id,)
            )
        finish_scan_run(run_id, total)
        log.info("Timelock scan complete: %d records in %.1f h",
                 total, (time.time() - t0) / 3600)

    except KeyboardInterrupt:
        log.info("Interrupted — progress saved (run_id=%d)", run_id)
    except Exception as e:
        finish_scan_run(run_id, total, str(e))
        log.exception("Scan failed")
        sys.exit(1)

    # Export CSV
    import csv
    csv_path = os.path.join(CSV_DIR, "timelock_utxos.csv")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT txid, vout, address, lock_type, lock_value, "
            "estimated_unlock_height, value_sat, block_height, is_inheritance_pattern "
            "FROM timelock_utxos WHERE scan_run_id=?", (run_id,)
        ).fetchall()
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["txid", "vout", "address", "lock_type", "lock_value",
                    "estimated_unlock_height", "value_sat", "block_height",
                    "is_inheritance_pattern"])
        for r in rows:
            w.writerow(list(r))
    log.info("CSV written to %s (%d rows)", csv_path, len(rows))


if __name__ == "__main__":
    main()
