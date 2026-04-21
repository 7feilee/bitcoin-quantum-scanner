import os
from pathlib import Path

# Auto-load .env from the project directory (python-dotenv)
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_env_file, override=False)
    except ImportError:
        pass

BITCOIN_DATADIR = os.getenv("BITCOIN_DATADIR", str(Path.home() / ".bitcoin"))
BITCOIN_RPC_USER = os.getenv("BITCOIN_RPC_USER", "bitcoin")
BITCOIN_RPC_PASSWORD = os.getenv("BITCOIN_RPC_PASSWORD", "")
BITCOIN_RPC_HOST = os.getenv("BITCOIN_RPC_HOST", "127.0.0.1")
BITCOIN_RPC_PORT = int(os.getenv("BITCOIN_RPC_PORT", "8332"))

_base = Path(__file__).parent
DB_PATH = os.getenv("DB_PATH", str(_base / "data" / "quantum.db"))
CSV_DIR = str(_base / "data")
LOG_DIR = str(_base / "logs")

CHAINSTATE_PATH = os.path.join(BITCOIN_DATADIR, "chainstate")
SNAPSHOT_PATH = os.getenv("SNAPSHOT_PATH", str(_base / "data" / "utxo-snapshot.dat"))

# Bitcoin mainnet address prefixes
NETWORK = os.getenv("BITCOIN_NETWORK", "mainnet")  # mainnet | testnet
HRP = "bc" if NETWORK == "mainnet" else "tb"
P2PKH_VERSION = b'\x00' if NETWORK == "mainnet" else b'\x6f'
P2SH_VERSION = b'\x05' if NETWORK == "mainnet" else b'\xc4'
