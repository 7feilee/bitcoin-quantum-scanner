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
| P2PKH / P2WPKH (reused) | **HIGH** | Public key revealed in prior spend (via `scan_reuse.py`) |
| P2SH / P2WSH | MEDIUM | Script unknown until spend |
| P2PKH / P2WPKH | LOW | Only key hash on-chain (safe while unreused) |

## Features

- **Overview** — total vulnerable BTC, quantum countdown clock, migration trend sparkline, Satoshi coin analysis
- **Address risk checker** — instant CRITICAL/HIGH/MEDIUM/LOW rating with reuse detection
- **UTXO distribution** — every UTXO in the set bucketed by script type with supply share
- **Timelock analysis** — CLTV/CSV locks and dual-key inheritance patterns
- **Analytics tab**
  - Dormancy distribution by Bitcoin halving epoch
  - Wallet tier distribution (quantum-vulnerable and full UTXO set)
  - Top 100 richest vulnerable addresses
  - Top 100 richest addresses across all ~165M UTXOs
  - Satoshi-era P2PK breakdown (blocks 0–100k)
  - P2TR growth trend
  - Lightning channel estimate from CSV timelock patterns
  - Exchange/entity tagging via `data/known_entities.json`

## Architecture

```
Bitcoin Core (full node, txindex=1)
    ↓  dumptxoutset  (atomic snapshot, safe on running node)
scan_quantum.py      — P2PK / P2TR / P2MS vulnerable UTXOs         (~30 min)
scan_distribution.py — UTXO set aggregate stats by script type     (~20 min)
scan_analytics.py    — pre-compute analytics metrics from DB        (~5 min)
scan_allwallets.py   — per-address BTC totals across full UTXO set (~25 min)
    ↓  batch inserts
SQLite  (data/quantum.db, WAL mode)
    ↓
FastAPI  (server.py, port 8000)  ← in-process cache, 5-min TTL
    ↓  nginx reverse proxy
https://btc.mayfly.wiki  (static frontend)
```

**One-time long-running jobs** (run manually, resumable):
- `scan_timelocks.py` — block-by-block CLTV/CSV scan (3–5 days)
- `scan_reuse.py` — reveals P2PKH/P2WPKH addresses with known pubkeys (3–7 days)

Daily cron at 03:00 runs: quantum → distribution → migration snapshot → analytics → allwallets.

## Requirements

- Bitcoin Core ≥ 22.0 with `txindex=1`
- Python 3.12+
- ~11 TB disk (full blockchain), ≥16 GB RAM (`dbcache` scaled to available RAM)

## Setup

```bash
# 1. Clone and create environment
git clone https://github.com/7feilee/bitcoin-quantum-scanner
cd bitcoin-quantum-scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit: BITCOIN_RPC_PASSWORD, BITCOIN_DATADIR, DB_PATH, SNAPSHOT_PATH

# 3. Initialise database
python db.py

# 4. Run initial scans (Bitcoin Core must be fully synced)
python scan_quantum.py          # ~30 min — creates snapshot automatically
python scan_distribution.py --no-create-snapshot
python scan_analytics.py
python scan_allwallets.py       # ~25 min — run before cron deletes snapshot

# 5. Start API
uvicorn server:app --host 127.0.0.1 --port 8000

# 6. (Optional) Long-running one-time scans
nohup python scan_timelocks.py >> logs/timelocks.log 2>&1 &
nohup python scan_reuse.py     >> logs/reuse.log     2>&1 &
```

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
BITCOIN_DATADIR=/data/bitcoin
BITCOIN_RPC_USER=bitcoin
BITCOIN_RPC_PASSWORD=your_rpc_password_here
BITCOIN_RPC_HOST=127.0.0.1
BITCOIN_RPC_PORT=8332
BITCOIN_NETWORK=mainnet

DB_PATH=/path/to/data/quantum.db
SNAPSHOT_PATH=/path/to/data/utxo-snapshot.dat
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
| GET | `/api/v1/analytics/dormancy` | Vulnerable UTXOs by halving epoch |
| GET | `/api/v1/analytics/concentration` | Top 100 vulnerable addresses by BTC |
| GET | `/api/v1/analytics/wallet_tiers` | Vulnerable wallet tier distribution |
| GET | `/api/v1/analytics/satoshi_era` | P2PK exposure in blocks 0–100k |
| GET | `/api/v1/analytics/p2tr_growth` | Daily Taproot exposure trend |
| GET | `/api/v1/analytics/entities` | Known entity holdings |
| GET | `/api/v1/analytics/lightning` | Lightning channel estimate |
| GET | `/api/v1/analytics/all_wallet_tiers` | Full UTXO set wallet tier distribution |
| GET | `/api/v1/analytics/all_wallet_top100` | Top 100 richest Bitcoin addresses |
| GET | `/api/v1/analytics/all_wallet_summary` | Total addresses, mean balance |
| GET | `/api/v1/stats` | Query counts and scan metadata |
| GET | `/healthz` | Health check |

Rate limits: 30 req/min on the address endpoint, 10 req/min on CSV downloads,
60–120 req/min on all other endpoints.

## Quantum clock methodology

Based on Google's 2024/2025 Willow research:

```
Qubits needed to break secp256k1:  ~500,000
Current best (Google Willow, 2024): ~1,500
Assumed growth rate:                 2× per year
Years remaining: log₂(500,000 / 1,500) ≈ 8.4 years → ~2034
```

This is an estimate. The true timeline depends on error correction advances,
qubit quality, and engineering progress — not just raw qubit count.

## Extending entity tagging

Edit `data/known_entities.json` to add known addresses or public keys:

```json
[
  {
    "pubkey_hex": "04678afdb0...",
    "entity": "Satoshi Nakamoto",
    "category": "miner",
    "note": "Genesis block coinbase pubkey"
  },
  {
    "address": "1ExchangeAddressHere",
    "entity": "Exchange Name",
    "category": "exchange"
  }
]
```

Run `python scan_analytics.py` after editing to refresh the dashboard.

## License

MIT
