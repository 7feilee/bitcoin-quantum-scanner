#!/usr/bin/env bash
# Quick status check for Bitcoin node + scan state.
# Run: ./status.sh
# Watch continuously: watch -n 30 ./status.sh

cd "$(dirname "$0")"
source .env 2>/dev/null

BTCCONF=$(mktemp /tmp/btcrpc-XXXXXX.conf)
chmod 600 "$BTCCONF"
printf 'rpcuser=%s\nrpcpassword=%s\n' "$BITCOIN_RPC_USER" "$BITCOIN_RPC_PASSWORD" > "$BTCCONF"
trap 'rm -f "$BTCCONF"' EXIT
CLI="bitcoin-cli -datadir=/data/bitcoin -conf=$BTCCONF"

echo "════════════════════════════════════════"
echo "  BTC QUANTUM MONITOR — STATUS"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "════════════════════════════════════════"

# ── Bitcoin Core ──────────────────────────
if ! info=$($CLI getblockchaininfo 2>/dev/null); then
  echo "  bitcoind:    ✗ NOT RUNNING"
  echo ""
  echo "  Start with:  sudo systemctl start bitcoind"
  exit 1
fi

blocks=$(echo "$info" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['blocks'])")
headers=$(echo "$info" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['headers'])")
pct=$(echo "$info" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f\"{d['verificationprogress']*100:.2f}\")")
ibd=$(echo "$info" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['initialblockdownload'])")
disk=$(du -sh /data/bitcoin/blocks 2>/dev/null | cut -f1 || echo "?")

echo ""
echo "  Bitcoin Core:  ✓ running"
echo "  Chain:         mainnet"
echo "  Blocks:        $blocks / $headers"
echo "  IBD progress:  $pct%"
echo "  Disk (blocks): $disk"
if [ "$ibd" = "True" ]; then
  echo "  Status:        ⏳ SYNCING — scans unavailable until 100%"
  echo ""
  eta_blocks=$((headers - blocks))
  echo "  Remaining:     ~$eta_blocks blocks"
  echo "  ETA:           IBD typically completes in 6-10 hours"
  echo "                 (dbcache=100GB greatly accelerates sync)"
else
  echo "  Status:        ✓ FULLY SYNCED — ready to scan"
fi

# ── Scan DB ───────────────────────────────
echo ""
if [ -f "data/quantum.db" ]; then
  python3 - << 'PYEOF'
from db import get_conn
with get_conn() as c:
    runs = c.execute("SELECT scan_type, status, completed_at, records_found FROM scan_runs ORDER BY id DESC LIMIT 6").fetchall()
    snaps = c.execute("SELECT COUNT(*), MIN(scan_date), MAX(scan_date) FROM migration_snapshots").fetchone()

if runs:
    print("  Scan runs:")
    for r in runs:
        print(f"    {r[0]:<14} {r[1]:<10} {r[2] or '—':<20} {r[3] or 0:>10} records")
else:
    print("  Scan runs:     none yet")

if snaps and snaps[0]:
    print(f"  Trend data:    {snaps[0]} snapshots ({snaps[1]} → {snaps[2]})")
else:
    print("  Trend data:    none yet")
PYEOF
else
  echo "  DB:            not initialized (run: python db.py)"
fi

echo ""
