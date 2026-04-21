#!/usr/bin/env bash
# Polls IBD progress; launches full scan suite the moment sync completes.
# Run once: nohup bash wait_and_scan.sh &
# Check:    tail -f logs/wait_and_scan.log

set -euo pipefail
cd "$(dirname "$0")"

LOG="logs/wait_and_scan.log"
LOCK="logs/wait_and_scan.lock"
DONE_FLAG="logs/first_scan.done"

exec >> "$LOG" 2>&1

if [ -f "$DONE_FLAG" ]; then
  echo "$(date '+%H:%M:%S') First scan already completed. Exiting."
  exit 0
fi

if [ -f "$LOCK" ]; then
  echo "$(date '+%H:%M:%S') Another instance is running (lockfile exists). Exiting."
  exit 1
fi
echo $$ > "$LOCK"
trap 'rm -f "$LOCK"' EXIT

source .env 2>/dev/null
source venv/bin/activate

BTCCONF=$(mktemp /tmp/btcrpc-XXXXXX.conf)
chmod 600 "$BTCCONF"
printf 'rpcuser=%s\nrpcpassword=%s\n' "$BITCOIN_RPC_USER" "$BITCOIN_RPC_PASSWORD" > "$BTCCONF"
trap 'rm -f "$BTCCONF"; rm -f "$LOCK"' EXIT
CLI="bitcoin-cli -datadir=/data/bitcoin -conf=$BTCCONF"

echo "$(date '+%Y-%m-%d %H:%M:%S') wait_and_scan started — polling every 5 min"

while true; do
  if ! info=$($CLI getblockchaininfo 2>/dev/null); then
    echo "$(date '+%H:%M:%S') RPC unavailable, retry in 60s"
    sleep 60
    continue
  fi

  progress=$(echo "$info" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['verificationprogress'])")
  ibd=$(echo "$info"      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['initialblockdownload'])")
  blocks=$(echo "$info"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['blocks'])")
  headers=$(echo "$info"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['headers'])")
  pct=$(python3 -c "print(f'{float('$progress')*100:.2f}')")

  echo "$(date '+%H:%M:%S') IBD=$ibd  blocks=$blocks/$headers  progress=$pct%"

  # IBD complete when verificationprogress > 99.99% and flag is False
  if [ "$ibd" = "False" ] && python3 -c "exit(0 if float('$progress') > 0.9999 else 1)"; then
    echo "$(date '+%H:%M:%S') ─────────────────────────────────────────"
    echo "$(date '+%H:%M:%S') IBD COMPLETE. Launching scan suite."
    echo "$(date '+%H:%M:%S') ─────────────────────────────────────────"

    echo "$(date '+%H:%M:%S') [1/3] Starting quantum scan (~30 min)…"
    python scan_quantum.py --keep-snapshot
    echo "$(date '+%H:%M:%S') [1/3] Quantum scan done."

    echo "$(date '+%H:%M:%S') [2/3] Starting distribution scan (~20 min)…"
    python scan_distribution.py --no-create-snapshot
    echo "$(date '+%H:%M:%S') [2/3] Distribution scan done."

    # Clean up snapshot now
    rm -f "${SNAPSHOT_PATH:-/tmp/utxo-snapshot.dat}"

    echo "$(date '+%H:%M:%S') [3/3] Writing migration snapshot…"
    python -c "from db import write_migration_snapshot; write_migration_snapshot()"
    echo "$(date '+%H:%M:%S') [3/3] Done."

    touch "$DONE_FLAG"
    echo "$(date '+%H:%M:%S') ─────────────────────────────────────────"
    echo "$(date '+%H:%M:%S') ALL SCANS COMPLETE. Dashboard is live."
    echo "$(date '+%H:%M:%S') ─────────────────────────────────────────"

    # Start timelock scan in background (3-5 days)
    echo "$(date '+%H:%M:%S') Launching timelock scan in background…"
    nohup python scan_timelocks.py --skip-phase1 >> logs/timelocks.log 2>&1 &
    echo "$(date '+%H:%M:%S') Timelock scan PID: $!"

    break
  fi

  sleep 300  # poll every 5 minutes
done
