"""
Address reuse scanner — one-time multi-day background job (similar to scan_timelocks.py).

Scans every block input to find public keys that have been revealed on-chain:
  • P2PKH spends:  pubkey is the last push in scriptSig
  • P2WPKH spends: pubkey is witness[1] (33-byte compressed key)

Revealed pubkeys are hashed to their address and stored in reused_addresses.
The address-check endpoint uses this table to upgrade LOW → HIGH risk for
P2PKH/P2WPKH addresses whose pubkey is already known to an attacker.

Runtime: 3-7 days (full block history, same order as scan_timelocks.py Phase 2).
Progress is checkpointed so the job is safely resumable.

Usage:
  nohup python scan_reuse.py >> logs/reuse.log 2>&1 &
  python scan_reuse.py --resume 500000   # resume from block 500000
  python scan_reuse.py --run-id 5        # resume existing scan run
"""

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from config import (BITCOIN_RPC_HOST, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_PORT,
                    BITCOIN_RPC_USER, DB_PATH, HRP, P2PKH_VERSION)
from chainstate_reader import bech32_address, base58check
from db import finish_scan_run, get_conn, init_db, start_scan_run

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [reuse] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "logs", "scan_reuse.log")),
    ],
)
log = logging.getLogger(__name__)

BATCH_SIZE    = 10_000
BLOCK_BATCH   = 500
REUSE_WORKERS = 4
PREFETCH      = 8


# ── RPC helpers (same pattern as scan_timelocks.py) ───────────────────────────

_rpc_proxy = None

def rpc(method, *params):
    global _rpc_proxy
    from bitcoinrpc.authproxy import AuthServiceProxy
    for attempt in range(2):
        if _rpc_proxy is None:
            url = (f"http://{BITCOIN_RPC_USER}:{BITCOIN_RPC_PASSWORD}"
                   f"@{BITCOIN_RPC_HOST}:{BITCOIN_RPC_PORT}")
            _rpc_proxy = AuthServiceProxy(url, timeout=120)
        try:
            return getattr(_rpc_proxy, method)(*params)
        except (BrokenPipeError, ConnectionResetError, OSError):
            _rpc_proxy = None
            if attempt:
                raise
        except Exception:
            _rpc_proxy = None
            raise


_tl = threading.local()

def _thread_rpc():
    from bitcoinrpc.authproxy import AuthServiceProxy
    if getattr(_tl, "proxy", None) is None:
        url = (f"http://{BITCOIN_RPC_USER}:{BITCOIN_RPC_PASSWORD}"
               f"@{BITCOIN_RPC_HOST}:{BITCOIN_RPC_PORT}")
        _tl.proxy = AuthServiceProxy(url, timeout=120)
    return _tl.proxy

def _fetch_block_task(height: int, bhash: str):
    for attempt in range(2):
        try:
            return height, _thread_rpc().getblock(bhash, 2)
        except (BrokenPipeError, ConnectionResetError, OSError):
            _tl.proxy = None
            if attempt:
                raise
        except Exception:
            _tl.proxy = None
            raise


# ── Pubkey extraction ─────────────────────────────────────────────────────────

def _extract_last_push(script: bytes) -> Optional[bytes]:
    """Return the data from the last push opcode in script (reused from scan_timelocks)."""
    pos, last = 0, None
    while pos < len(script):
        op = script[pos]; pos += 1
        if 1 <= op <= 75:
            if pos + op <= len(script):
                last = script[pos:pos + op]; pos += op
        elif op == 0x4c:
            if pos < len(script):
                n = script[pos]; pos += 1
                last = script[pos:pos + n]; pos += n
        elif op == 0x4d:
            if pos + 2 <= len(script):
                n = int.from_bytes(script[pos:pos + 2], "little"); pos += 2
                last = script[pos:pos + n]; pos += n
    return last


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _extract_pubkey_p2pkh(scriptsig_hex: str) -> Optional[bytes]:
    """Extract the public key from a P2PKH scriptSig (last push, 33 or 65 bytes)."""
    if not scriptsig_hex:
        return None
    try:
        sig = bytes.fromhex(scriptsig_hex)
    except ValueError:
        return None
    pk = _extract_last_push(sig)
    if pk and len(pk) in (33, 65):
        return pk
    return None


def _extract_pubkey_p2wpkh(witness: list) -> Optional[bytes]:
    """Extract the public key from a P2WPKH witness stack (witness[1], 33 bytes)."""
    if len(witness) == 2:
        try:
            pk = bytes.fromhex(witness[1])
            if len(pk) == 33:
                return pk
        except ValueError:
            pass
    return None


def _pubkey_to_address(pubkey: bytes) -> tuple[str, str]:
    """Return (p2pkh_address, p2wpkh_address) for a pubkey."""
    h = _hash160(pubkey)
    p2pkh  = base58check(P2PKH_VERSION + h)
    p2wpkh = bech32_address(HRP, 0, h)
    return p2pkh, p2wpkh


# ── Checkpoint ────────────────────────────────────────────────────────────────

def _get_checkpoint(run_id: int) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT error_msg FROM scan_runs WHERE id=?", (run_id,)
        ).fetchone()
    if row and row[0]:
        try:
            return json.loads(row[0]).get("reuse_block", 0)
        except Exception:
            return 0
    return 0


# ── Main scan loop ────────────────────────────────────────────────────────────

def scan_reuse(run_id: int, start_block: int = 0) -> int:
    tip = rpc("getblockcount")
    log.info("Scanning blocks %d – %d for revealed pubkeys…", start_block, tip)

    _INSERT_SQL = (
        "INSERT OR IGNORE INTO reused_addresses "
        "(address, pubkey_hex, first_seen_txid, first_seen_block, scan_run_id) "
        "VALUES (?,?,?,?,?)"
    )

    db = sqlite3.connect(DB_PATH, timeout=60)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")

    batch: list = []
    found = 0
    t_batch = time.time()

    def _flush():
        nonlocal found
        db.executemany(_INSERT_SQL, batch)
        db.commit()
        found += len(batch)
        batch.clear()

    def _ckpt(h: int):
        db.execute(
            "UPDATE scan_runs SET error_msg=?, records_found=? WHERE id=?",
            (json.dumps({"reuse_block": h}), found, run_id),
        )
        db.commit()

    try:
        with ThreadPoolExecutor(max_workers=REUSE_WORKERS) as pool:
            pending: list = []
            next_h = start_block

            def _fill():
                nonlocal next_h
                while len(pending) < PREFETCH and next_h <= tip:
                    bhash = rpc("getblockhash", next_h)
                    pending.append((next_h, pool.submit(_fetch_block_task, next_h, bhash)))
                    next_h += 1

            _fill()

            while pending:
                height, fut = pending.pop(0)
                _, block = fut.result()
                _fill()

                for tx in block["tx"]:
                    for vin in tx.get("vin", []):
                        pubkey = None

                        # P2PKH
                        pk = _extract_pubkey_p2pkh(vin.get("scriptSig", {}).get("hex", ""))
                        if pk:
                            pubkey = pk

                        # P2WPKH (overrides P2PKH if both present, though that can't happen)
                        pk = _extract_pubkey_p2wpkh(vin.get("txinwitness", []))
                        if pk:
                            pubkey = pk

                        if pubkey:
                            p2pkh, p2wpkh = _pubkey_to_address(pubkey)
                            txid = tx["txid"]
                            pk_hex = pubkey.hex()
                            batch.append((p2pkh,  pk_hex, txid, height, run_id))
                            batch.append((p2wpkh, pk_hex, txid, height, run_id))

                if len(batch) >= BATCH_SIZE:
                    _flush()

                if height % BLOCK_BATCH == 0:
                    elapsed = time.time() - t_batch
                    rate = BLOCK_BATCH / elapsed if elapsed else 0
                    eta_h = (tip - height) / rate / 3600 if rate else 0
                    log.info("Block %d / %d  found=%d  %.0f blk/s  ETA %.1f h",
                             height, tip, found, rate, eta_h)
                    _ckpt(height)
                    t_batch = time.time()

        if batch:
            _flush()

    finally:
        db.close()

    return found


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Bitcoin address reuse scanner")
    parser.add_argument("--resume", type=int, default=None,
                        help="Resume phase from this block height")
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
        run_id = start_scan_run("reuse", tip, tip_hash)
        log.info("Started reuse scan run #%d (tip block %d)", run_id, tip)

    start_blk = args.resume if args.resume is not None else _get_checkpoint(run_id)

    try:
        total = scan_reuse(run_id, start_blk)
        with get_conn() as conn:
            conn.execute("UPDATE scan_runs SET error_msg=NULL WHERE id=?", (run_id,))
        finish_scan_run(run_id, total)
        log.info("Reuse scan complete: %d address/pubkey pairs", total)
    except KeyboardInterrupt:
        log.info("Interrupted — progress saved (run_id=%d)", run_id)
    except Exception as e:
        finish_scan_run(run_id, total if "total" in dir() else 0, str(e))
        log.exception("Scan failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
