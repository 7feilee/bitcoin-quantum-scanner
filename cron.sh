#!/usr/bin/env bash
# Daily cron — runs at 02:00, completes before ~06:00
# crontab entry:  0 2 * * * /home/test/btc/cron.sh >> /home/test/btc/logs/cron.log 2>&1
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/logs/cron.log"
VENV="$SCRIPT_DIR/venv"
DOTENV="$SCRIPT_DIR/.env"

echo "========================================"
echo "$(date '+%Y-%m-%d %H:%M:%S') cron start"
echo "========================================"

# Load environment
if [[ -f "$DOTENV" ]]; then
    set -a
    source "$DOTENV"
    set +a
fi

# Activate virtualenv
source "$VENV/bin/activate"

cd "$SCRIPT_DIR"

# Initialise DB if needed
python -c "from db import init_db; init_db()"

# ── Quantum scan (~25-35 min) ─────────────────────────────────────────────────
echo "$(date '+%H:%M:%S') starting quantum scan"
python scan_quantum.py --keep-snapshot
echo "$(date '+%H:%M:%S') quantum scan done"

# ── Distribution scan (~15-25 min, reuses snapshot) ──────────────────────────
echo "$(date '+%H:%M:%S') starting distribution scan"
python scan_distribution.py --no-create-snapshot
echo "$(date '+%H:%M:%S') distribution scan done"

# Clean up snapshot
rm -f "${SNAPSHOT_PATH:-/tmp/utxo-snapshot.dat}"

# ── Write migration snapshot (for trend tracking) ─────────────────────────────
echo "$(date '+%H:%M:%S') writing migration snapshot"
python -c "from db import write_migration_snapshot; write_migration_snapshot()"

echo "$(date '+%H:%M:%S') cron complete"

# NOTE: scan_timelocks.py is a separate long-running job (3-5 days).
# Launch it manually once:
#   nohup python scan_timelocks.py --skip-phase1 >> logs/timelocks.log 2>&1 &
# Then resume with --resume <last_block> if interrupted.
