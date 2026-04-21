# Bitcoin Quantum Scanner

Live dashboard: **https://btc.mayfly.wiki**

Identifies Bitcoin UTXOs whose public keys are exposed on-chain and therefore
vulnerable to a cryptographically-relevant quantum computer running Shor's
algorithm. Data is derived directly from a Bitcoin Core full node — no
third-party APIs, no estimated figures.

## What it detects

| Script type | Quantum risk | Reason |
|-------------|-------------|--------|
| P2PK | **CRITICAL** | Raw public key in `scriptPubKey` |
| P2TR (Taproot) | **CRITICAL** | x-only public key in `scriptPubKey` |
| P2MS (bare multisig) | **HIGH** | All public keys in `scriptPubKey` |
| P2SH / P2WSH | MEDIUM | Script unknown until spend |
| P2PKH / P2WPKH | LOW | Only key hash on-chain (safe while unreused) |

## Features

- **Address risk checker** — paste any Bitcoin address, get an instant risk rating
- **Vulnerable UTXO scan** — full P2PK / P2TR / P2MS enumeration with CSV export
- **Address type distribution** — every UTXO in the set bucketed by script type
- **Timelock UTXO analysis** — CLTV / CSV locks and dual-key inheritance patterns
- **Migration trend** — daily snapshots track whether the community is moving funds

## Architecture

```
Bitcoin Core (full node, txindex=1)
    ↓  dumptxoutset  (atomic snapshot, safe on running node)
scan_quantum.py / scan_distribution.py / scan_timelocks.py
    ↓  batch inserts
SQLite  (data/quantum.db)
    ↓
FastAPI  (server.py, port 8000)
    ↓  nginx reverse proxy
https://btc.mayfly.wiki  (static frontend)
```

Scans run daily at 03:00 via cron. The timelock scan is a one-time background
job (3–5 days) that iterates every historical block.

## Requirements

- Bitcoin Core ≥ 22.0 with `txindex=1`
- Python 3.12+
- 11 TB disk (full blockchain), 126 GB RAM recommended (`dbcache=100000`)

## Setup

```bash
# 1. Configure Bitcoin Core
cp bitcoin.conf.example /path/to/bitcoin/datadir/bitcoin.conf
# Edit rpcpassword and paths, then start: sudo systemctl start bitcoind

# 2. Python environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit BITCOIN_RPC_PASSWORD, BITCOIN_DATADIR, DB_PATH

# 4. Initialise database
python db.py

# 5. Wait for IBD, then scan
python scan_quantum.py
python scan_distribution.py

# 6. Start API
uvicorn server:app --host 127.0.0.1 --port 8000
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/overview` | All summary stats for the dashboard |
| GET | `/api/v1/address/{address}` | Quantum risk for a specific address |
| GET | `/api/v1/scan/quantum/status` | Latest quantum scan summary |
| GET | `/api/v1/scan/quantum/download` | Download `quantum_utxos.csv` |
| GET | `/api/v1/scan/distribution` | UTXO set breakdown by script type |
| GET | `/api/v1/scan/timelocks/status` | Timelock scan progress |
| GET | `/api/v1/scan/timelocks/download` | Download `timelock_utxos.csv` |
| GET | `/api/v1/stats` | Query counts and scan metadata |
| GET | `/healthz` | Health check |

Rate limits: 30 req/min on the address endpoint, 10 req/min on CSV downloads,
120 req/min on all other endpoints.

## Quantum clock methodology

Estimated years to Q-Day based on Google's 2024/2025 research:

```
Qubits needed to break secp256k1:  ~500,000
Current best (Google Willow, 2024): ~1,500
Assumed growth rate:                 2× per year
Years remaining: log₂(500,000 / 1,500) ≈ 8.4 years → ~2034
```

This is an estimate. The true timeline depends on error correction advances,
qubit quality, and engineering progress — not just raw qubit count.

## Limitations

- **Address reuse** (P2PKH/P2WPKH addresses that have sent funds, revealing their
  public key) is not yet included in the vulnerable count. This is a planned
  addition that will increase the reported risk figure.
- The quantum clock is a rough estimate, not a precise forecast.
- Timelock values for P2SH/P2WSH outputs are only visible when those outputs are
  spent, so the timelock scanner records historical patterns rather than a live
  count of locked UTXOs.

## License

MIT
