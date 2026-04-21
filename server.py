"""
FastAPI server — Bitcoin Quantum Scanner public API.

Endpoints:
  GET /api/v1/address/{address}        Address quantum risk check
  GET /api/v1/scan/quantum/status      Latest quantum scan summary
  GET /api/v1/scan/quantum/download    Download quantum_utxos.csv
  GET /api/v1/scan/distribution        Address type distribution stats
  GET /api/v1/scan/timelocks/status    Timelock scan status
  GET /api/v1/scan/timelocks/download  Download timelock_utxos.csv
  GET /api/v1/stats                    Overall stats
  GET /healthz                         Health check

Run:
  uvicorn server:app --host 0.0.0.0 --port 8000
"""

import hashlib
import json
import math
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from config import CSV_DIR
from db import get_conn, init_db

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Bitcoin Quantum Scanner",
    description="Public API for Bitcoin quantum vulnerability analysis",
    version="1.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    # allow_origins=["*"] is intentional: this is a fully public, read-only API
    # with no authentication or user-specific data exposed. Restricting origins
    # would only break legitimate third-party dashboards without any security gain.
    allow_origins=["*"],
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
)

# ── address format helpers ────────────────────────────────────────────────────

_P2PKH_RE  = re.compile(r'^[13][1-9A-HJ-NP-Za-km-z]{25,34}$')
_BECH32_RE = re.compile(r'^(bc|tb)1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,87}$', re.I)

# Base58 alphabet (no 0, O, I, l)
_BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _base58check_decode(address: str) -> bool:
    """Return True if address has a valid base58check checksum."""
    try:
        n = 0
        for char in address.encode():
            n = n * 58 + _BASE58_ALPHABET.index(char)
        # Reconstruct bytes via divmod — preserves all bytes including internal zeros.
        # n.to_bytes(25) would silently drop leading zero bytes encoded by leading '1' chars.
        out: list[int] = []
        while n:
            n, rem = divmod(n, 256)
            out.append(rem)
        out.reverse()
        leading = len(address) - len(address.lstrip('1'))
        decoded = b'\x00' * leading + bytes(out)
        if len(decoded) != 25:
            return False
        digest = hashlib.sha256(hashlib.sha256(decoded[:-4]).digest()).digest()
        return digest[:4] == decoded[-4:]
    except (ValueError, OverflowError):
        return False

_BECH32_CHARSET = frozenset('qpzry9x8gf2tvdw0s3jn54khce6mua7l')

RISK_MATRIX = {
    "P2PK":   ("CRITICAL", 5, "Raw public key exposed in output script"),
    "P2TR":   ("CRITICAL", 5, "x-only public key exposed in Taproot output"),
    "P2MS":   ("HIGH",     4, "Multiple public keys exposed in bare multisig"),
    "P2SH":   ("MEDIUM",   3, "Redeem script unknown; risk depends on script contents"),
    "P2WSH":  ("MEDIUM",   3, "Witness script unknown; risk depends on script contents"),
    "P2PKH":  ("LOW",      2, "Only public key hash exposed; safe while unspent and unreused"),
    "P2WPKH": ("LOW",      2, "Only public key hash exposed; safe while unspent and unreused"),
}


def classify_address(address: str) -> Optional[str]:
    """Return script type from address format, or None."""
    if address.startswith("1"):
        return "P2PKH"
    if address.startswith("3"):
        return "P2SH"
    low = address.lower()
    if low.startswith("bc1p") or low.startswith("tb1p"):
        return "P2TR"
    if low.startswith("bc1q") or low.startswith("tb1q"):
        # Length distinguishes P2WPKH (42 chars) from P2WSH (62 chars)
        return "P2WPKH" if len(address) <= 42 else "P2WSH"
    return None


def ip_hash(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


# ── startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    init_db()


# ── health ────────────────────────────────────────────────────────────────────

@app.get("/healthz")
@limiter.limit("120/minute")
def health(request: Request):
    return {"status": "ok", "ts": datetime.utcnow().isoformat()}


# ── overview (single call for Tab 1) ─────────────────────────────────────────

# Quantum clock constants — sourced from Google 2024/2025 estimates
_QUBITS_CURRENT = 1_500
_QUBITS_NEEDED  = 500_000
_GROWTH_PER_YEAR = 2.0
_CURRENT_YEAR   = 2026

_YEARS_TO_QDAY = math.log2(_QUBITS_NEEDED / _QUBITS_CURRENT)  # ≈ 8.4


@app.get("/api/v1/overview")
@limiter.limit("120/minute")
def overview(request: Request):
    with get_conn() as conn:
        q_run = conn.execute(
            "SELECT id, block_height, block_hash, completed_at FROM scan_runs "
            "WHERE scan_type='quantum' AND status='complete' ORDER BY id DESC LIMIT 1"
        ).fetchone()

        breakdown_rows = (
            conn.execute(
                "SELECT script_type, COUNT(*) AS cnt, SUM(value_sat) AS val "
                "FROM quantum_utxos WHERE scan_run_id=? GROUP BY script_type",
                (q_run["id"],),
            ).fetchall()
            if q_run else []
        )

        dist = conn.execute(
            "SELECT SUM(utxo_count) AS tu, SUM(total_value_sat) AS tv "
            "FROM address_distribution WHERE scan_run_id = "
            "(SELECT MAX(id) FROM scan_runs WHERE scan_type='distribution' AND status='complete')"
        ).fetchone()

        snapshots = conn.execute(
            "SELECT scan_date, block_height, total_utxos, total_value_sat, "
            "vuln_utxos, vuln_value_sat, p2pk_value, p2tr_value, p2ms_value "
            "FROM migration_snapshots ORDER BY scan_date ASC LIMIT 90"
        ).fetchall()

        # Satoshi coins: P2PK outputs exactly 50 BTC mined before block 50 000
        satoshi = conn.execute(
            "SELECT COUNT(*) AS cnt, SUM(value_sat) AS val "
            "FROM quantum_utxos "
            "WHERE script_type='P2PK' AND block_height <= 50000 AND value_sat = 5000000000"
        ).fetchone()

    bd: dict = {}
    for r in breakdown_rows:
        bd[r["script_type"]] = {"utxos": r["cnt"], "value_sat": r["val"]}

    vuln_value = sum(r["val"] for r in breakdown_rows)
    total_value = dist["tv"] if dist and dist["tv"] else None
    total_utxos = dist["tu"] if dist and dist["tu"] else None

    # 30-day migration delta (most recent vs 30 days ago)
    migration_delta = None
    if len(snapshots) >= 2:
        old = snapshots[max(0, len(snapshots) - 30)]
        new = snapshots[-1]
        if old["vuln_value_sat"] and new["vuln_value_sat"]:
            delta_sat = new["vuln_value_sat"] - old["vuln_value_sat"]
            migration_delta = {
                "btc_change": delta_sat / 1e8,
                "pct_change": delta_sat / old["vuln_value_sat"] * 100,
            }

    return {
        "block_height": q_run["block_height"] if q_run else None,
        "block_hash": q_run["block_hash"] if q_run else None,
        "last_scan_at": q_run["completed_at"] if q_run else None,
        "total_utxos": total_utxos,
        "total_value_sat": total_value,
        "vuln_value_sat": vuln_value or None,
        "safe_value_sat": (total_value - vuln_value) if total_value else None,
        "vuln_pct": round(vuln_value / total_value * 100, 4) if total_value else None,
        "breakdown": {
            st: {"utxos": v["utxos"], "value_sat": v["value_sat"],
                 "value_btc": v["value_sat"] / 1e8}
            for st, v in bd.items()
        },
        "satoshi": {
            "address_count": satoshi["cnt"] if satoshi else 0,
            "total_value_sat": satoshi["val"] if satoshi and satoshi["val"] else 0,
            "total_value_btc": satoshi["val"] / 1e8 if satoshi and satoshi["val"] else 0,
        },
        "quantum_clock": {
            "qubits_current": _QUBITS_CURRENT,
            "qubits_needed":  _QUBITS_NEEDED,
            "threat_pct": round(_QUBITS_CURRENT / _QUBITS_NEEDED * 100, 3),
            "years_to_qday": round(_YEARS_TO_QDAY, 1),
            "estimated_year": _CURRENT_YEAR + round(_YEARS_TO_QDAY),
            "growth_rate_per_year": _GROWTH_PER_YEAR,
        },
        "migration_trend": [
            {
                "date": r["scan_date"],
                "vuln_value_sat": r["vuln_value_sat"],
                "vuln_utxos": r["vuln_utxos"],
                "p2pk_btc": (r["p2pk_value"] or 0) / 1e8,
                "p2tr_btc": (r["p2tr_value"] or 0) / 1e8,
            }
            for r in snapshots
        ],
        "migration_30d": migration_delta,
    }


# ── address check ─────────────────────────────────────────────────────────────

@app.get("/api/v1/address/{address}")
@limiter.limit("30/minute")
def check_address(address: str, request: Request):
    address = address.strip()
    if len(address) < 25 or len(address) > 90:
        raise HTTPException(400, "Invalid address length")

    script_type = classify_address(address)
    if script_type is None:
        raise HTTPException(400, "Unrecognised address format")

    # Validate checksum / charset to reject obviously bad inputs early
    if address.startswith(("1", "3")):
        # P2PKH and P2SH: full base58check validation
        if not _P2PKH_RE.match(address):
            raise HTTPException(400, "Invalid base58 address format")
        if not _base58check_decode(address):
            raise HTTPException(400, "Invalid base58check checksum")
    else:
        # bech32 / bech32m: verify charset and length (basic sanity)
        lower = address.lower()
        if not _BECH32_RE.match(lower):
            raise HTTPException(400, "Invalid bech32 address format")
        # Check all characters after the separator are in the bech32 charset
        sep_idx = lower.index("1", 2)  # 'bc1...' or 'tb1...' — '1' is the separator
        data_part = lower[sep_idx + 1:]
        if not all(c in _BECH32_CHARSET for c in data_part):
            raise HTTPException(400, "Invalid bech32 character in address")

    # Look up in latest quantum scan
    with get_conn() as conn:
        utxo_rows = conn.execute(
            "SELECT txid, vout, script_type, pubkey_hex, value_sat, "
            "block_height, risk_level, risk_reason "
            "FROM quantum_utxos WHERE address=? LIMIT 100",
            (address,),
        ).fetchall()

    # Also check scan metadata
    with get_conn() as conn:
        scan_row = conn.execute(
            "SELECT completed_at, block_height FROM scan_runs "
            "WHERE scan_type='quantum' AND status='complete' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()

    if utxo_rows:
        risk_level   = utxo_rows[0]["risk_level"]
        risk_score   = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1}.get(risk_level, 0)
        risk_reason  = utxo_rows[0]["risk_reason"]
        utxos_found  = True
    else:
        risk_level, risk_score, risk_reason = RISK_MATRIX.get(
            script_type, ("UNKNOWN", 0, "Script type not recognized"))
        utxos_found = False

    # Override LOW to HIGH for P2PKH/P2WPKH reuse warning if needed
    # (full reuse detection requires a separate pass; add a note)
    reuse_warning = (
        script_type in ("P2PKH", "P2WPKH") and not utxos_found
        and risk_level == "LOW"
    )

    result = {
        "address": address,
        "address_type": script_type,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_details": {
            "reason": risk_reason,
            "reuse_warning": (
                "If this address has ever been used to send funds, the public key "
                "was revealed and quantum risk increases to HIGH."
            ) if reuse_warning else None,
            "quantum_explanation": _quantum_explanation(script_type),
            "recommendation": _recommendation(script_type),
        },
        "utxo_data": {
            "found_in_scan": utxos_found,
            "utxo_count": len(utxo_rows),
            "total_value_sat": sum(r["value_sat"] for r in utxo_rows),
            "utxos": [
                {
                    "txid": r["txid"], "vout": r["vout"],
                    "value_sat": r["value_sat"],
                    "pubkey_hex": r["pubkey_hex"],
                }
                for r in utxo_rows[:10]
            ] if utxo_rows else [],
            "last_scan_at": scan_row["completed_at"] if scan_row else None,
            "scan_block_height": scan_row["block_height"] if scan_row else None,
        },
    }

    # Log query — store SHA-256 hash of address (not the raw address) to avoid
    # building a linkable query log that ties IP hashes to specific addresses.
    address_hash = hashlib.sha256(address.encode()).hexdigest()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO address_queries (address, ip_hash, result_risk, result_json) "
            "VALUES (?,?,?,?)",
            (address_hash, ip_hash(request), risk_level,
             json.dumps({"risk_level": risk_level, "script_type": script_type})),
        )

    return result


def _quantum_explanation(st: str) -> str:
    explanations = {
        "P2PK":   "The raw ECDSA public key is embedded in the scriptPubKey. A sufficiently powerful quantum computer running Shor's algorithm could derive the private key in hours.",
        "P2TR":   "Taproot outputs include the x-only public key directly in scriptPubKey. The quantum threat is identical to P2PK.",
        "P2MS":   "All public keys in a bare multisig output are permanently visible on-chain.",
        "P2SH":   "The redeem script is hidden until spent. If the underlying script exposes keys (e.g. multisig), risk rises upon spending.",
        "P2WSH":  "The witness script is hidden until spent. Risk depends on what is inside the witness script.",
        "P2PKH":  "Only the RIPEMD-160(SHA-256(pubkey)) hash is on-chain. Hash functions provide ~80-bit security against Grover's algorithm, which is currently considered safe.",
        "P2WPKH": "Same as P2PKH — only the key hash is on-chain. Safe as long as the address has never sent funds.",
    }
    return explanations.get(st, "Unknown script type.")


def _recommendation(st: str) -> str:
    if st in ("P2PK", "P2TR"):
        return "Move funds to a new P2PKH or P2WPKH address immediately. Do not reuse the destination address."
    if st == "P2MS":
        return "Migrate to P2WSH multisig where script is not directly exposed."
    if st in ("P2PKH", "P2WPKH"):
        return "Never reuse this address after spending. Consider migrating to a fresh address if you have spent from it."
    return "Evaluate the underlying script and consider migrating if keys are exposed."


# ── quantum scan status ───────────────────────────────────────────────────────

@app.get("/api/v1/scan/quantum/status")
@limiter.limit("120/minute")
def quantum_status(request: Request):
    with get_conn() as conn:
        run = conn.execute(
            "SELECT * FROM scan_runs WHERE scan_type='quantum' AND status='complete' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not run:
            return {"status": "no_scan", "message": "No completed quantum scan found"}

        summary = conn.execute(
            "SELECT script_type, COUNT(*) AS cnt, SUM(value_sat) AS val "
            "FROM quantum_utxos WHERE scan_run_id=? GROUP BY script_type",
            (run["id"],),
        ).fetchall()

    return {
        "status": "complete",
        "scan_run_id": run["id"],
        "completed_at": run["completed_at"],
        "block_height": run["block_height"],
        "block_hash": run["block_hash"],
        "total_vulnerable_utxos": run["records_found"],
        "breakdown": [
            {"script_type": r[0], "utxo_count": r[1], "total_value_sat": r[2]}
            for r in summary
        ],
    }


# ── quantum CSV download ──────────────────────────────────────────────────────

@app.get("/api/v1/scan/quantum/download")
@limiter.limit("10/minute")
def quantum_download(request: Request):
    path = Path(CSV_DIR) / "quantum_utxos.csv"
    if not path.exists():
        raise HTTPException(404, "CSV not yet generated — run scan_quantum.py first")
    return FileResponse(
        str(path),
        media_type="text/csv",
        filename="quantum_utxos.csv",
    )


# ── distribution ──────────────────────────────────────────────────────────────

@app.get("/api/v1/scan/distribution")
@limiter.limit("120/minute")
def distribution(request: Request):
    with get_conn() as conn:
        run = conn.execute(
            "SELECT * FROM scan_runs WHERE scan_type='distribution' AND status='complete' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not run:
            return {"status": "no_scan", "message": "No completed distribution scan found"}

        rows = conn.execute(
            "SELECT script_type, utxo_count, total_value_sat, quantum_risk, "
            "pct_of_utxos, pct_of_value "
            "FROM address_distribution WHERE scan_run_id=? ORDER BY utxo_count DESC",
            (run["id"],),
        ).fetchall()

    total_utxos = sum(r["utxo_count"] for r in rows)
    total_value = sum(r["total_value_sat"] for r in rows)

    return {
        "status": "complete",
        "scan_run_id": run["id"],
        "completed_at": run["completed_at"],
        "block_height": run["block_height"],
        "total_utxos": total_utxos,
        "total_value_sat": total_value,
        "distribution": [
            {
                "script_type": r["script_type"],
                "utxo_count": r["utxo_count"],
                "total_value_sat": r["total_value_sat"],
                "quantum_risk": r["quantum_risk"],
                "pct_of_utxos": r["pct_of_utxos"],
                "pct_of_value": r["pct_of_value"],
            }
            for r in rows
        ],
    }


# ── timelocks status ──────────────────────────────────────────────────────────

@app.get("/api/v1/scan/timelocks/status")
@limiter.limit("120/minute")
def timelocks_status(request: Request):
    with get_conn() as conn:
        run = conn.execute(
            "SELECT * FROM scan_runs WHERE scan_type='timelocks' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not run:
            return {"status": "no_scan", "message": "No timelock scan found"}

        summary = conn.execute(
            "SELECT lock_type, COUNT(*) AS cnt, SUM(value_sat) AS val, "
            "SUM(is_inheritance_pattern) AS inherit_cnt "
            "FROM timelock_utxos WHERE scan_run_id=? GROUP BY lock_type",
            (run["id"],),
        ).fetchall()

    return {
        "status": run["status"],
        "scan_run_id": run["id"],
        "started_at": run["started_at"],
        "completed_at": run["completed_at"],
        "block_height": run["block_height"],
        "records_found": run["records_found"],
        "breakdown": [
            {
                "lock_type": r[0],
                "utxo_count": r[1],
                "total_value_sat": r[2],
                "inheritance_patterns": r[3],
            }
            for r in summary
        ],
    }


# ── timelocks CSV download ────────────────────────────────────────────────────

@app.get("/api/v1/scan/timelocks/download")
@limiter.limit("10/minute")
def timelocks_download(request: Request):
    path = Path(CSV_DIR) / "timelock_utxos.csv"
    if not path.exists():
        raise HTTPException(404, "CSV not yet generated — run scan_timelocks.py first")
    return FileResponse(
        str(path),
        media_type="text/csv",
        filename="timelock_utxos.csv",
    )


# ── overall stats ─────────────────────────────────────────────────────────────

@app.get("/api/v1/stats")
@limiter.limit("120/minute")
def stats(request: Request):
    with get_conn() as conn:
        scans = conn.execute(
            "SELECT scan_type, MAX(completed_at) AS last_run, "
            "MAX(records_found) AS records "
            "FROM scan_runs WHERE status='complete' GROUP BY scan_type"
        ).fetchall()

        query_count = conn.execute(
            "SELECT COUNT(*) FROM address_queries"
        ).fetchone()[0]

        dist_row = conn.execute(
            "SELECT SUM(utxo_count), SUM(total_value_sat) "
            "FROM address_distribution WHERE scan_run_id = ("
            "  SELECT MAX(id) FROM scan_runs WHERE scan_type='distribution' AND status='complete'"
            ")"
        ).fetchone()

    return {
        "scans": {r[0]: {"last_run": r[1], "records": r[2]} for r in scans},
        "total_queries": query_count,
        "utxo_set": {
            "total_utxos": dist_row[0] if dist_row and dist_row[0] else None,
            "total_value_sat": dist_row[1] if dist_row and dist_row[1] else None,
        },
    }
