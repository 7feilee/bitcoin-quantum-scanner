# Bitcoin Quantum Scanner — Project Context

## What this is
A self-hosted Bitcoin UTXO scanner that identifies quantum-vulnerable addresses and publishes the results at https://btc.mayfly.wiki. Data is sourced directly from a local Bitcoin Core full node.

## Server
- i7-13700K / 126 GB RAM / 11 TB disk
- Bitcoin Core v28.1.0, datadir `/data/bitcoin`, txindex=1, dbcache=100 GB
- Working directory: `/home/test/btc/`
- Python 3.12, virtualenv at `venv/`

## Services
- `bitcoind.service` — Bitcoin Core full node (auto-start)
- `btc-api.service` — FastAPI on `127.0.0.1:8000` (auto-start)
- nginx `btc.mayfly.wiki` → static frontend + `/api/` proxy to FastAPI
- Cron at 03:00 runs `cron.sh` (quantum + distribution scans)

## Scan pipeline
1. `scan_quantum.py`      — P2PK / P2TR / P2MS vulnerable UTXOs (~30 min)
2. `scan_distribution.py` — aggregate UTXO set stats by script type (~20 min)
3. `scan_timelocks.py`    — CLTV/CSV timelocks + inheritance patterns (3-5 days, one-time)
All three use `dumptxoutset` as the data source (safe to call on a running node).

## Database
SQLite at `data/quantum.db`. Tables: `scan_runs`, `quantum_utxos`, `address_distribution`,
`timelock_utxos`, `address_queries`, `migration_snapshots`.

## API
FastAPI with slowapi rate limiting (30/min on address endpoint).
All SQL queries use parameterised statements; no raw string interpolation.
Addresses are SHA-256 hashed before being written to the query log.

## Key files
- `chainstate_reader.py` — parses `dumptxoutset` binary format; implements bech32m and base58check inline (no external crypto deps)
- `server.py`            — FastAPI endpoints; also handles address format validation with checksum verification
- `config.py`            — loads `.env` automatically via python-dotenv

## Security notes
- `.env` and `bitcoin.conf` are `chmod 600`
- `data/quantum.db` is `chmod 600`
- UTXO snapshot is stored in `data/`, not `/tmp/`
- Shell scripts write RPC credentials to a `mktemp`/`chmod 600` temp file instead of passing them as CLI args

## Known gaps (planned)
- Address reuse detection: P2PKH/P2WPKH addresses that have been spent from (pubkey revealed in scriptSig/witness) are not yet flagged as HIGH risk
- Migration trend requires multiple daily scans to become meaningful
