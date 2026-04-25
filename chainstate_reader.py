"""
Parses Bitcoin Core's UTXO snapshot produced by `bitcoin-cli dumptxoutset`.

File format (Bitcoin Core 28+):
  magic        : 5 bytes   ("utxo\xff")
  version      : uint16 LE
  net_magic    : 4 bytes   (e.g. f9beb4d9 for mainnet)
  block_hash   : 32 bytes  (internal byte order, reversed for display)
  utxo_count   : uint64 LE
  per UTXO: (same as legacy)

File format (Bitcoin Core 22.x – 27.x, no magic prefix):
  block_hash   : 32 bytes  (internal byte order, reversed for display)
  utxo_count   : uint64 LE
  per UTXO:
    txid        : 32 bytes (internal byte order)
    vout        : uint32 LE
    code        : chainstate VarInt  (height<<1 | coinbase)
    amount      : chainstate VarInt  (compressed satoshis)
    script      : compressed script  (type VarInt + data bytes)

Chainstate VarInt differs from network CompactSize:
  n = 0
  while b = read_byte():
    n = (n << 7) | (b & 0x7f)
    if b & 0x80: n += 1
    else: return n

Script compression types:
  0   → P2PKH    : 20-byte hash160 follows
  1   → P2SH     : 20-byte hash160 follows
  2,3 → P2PK     : compressed pubkey (prefix + 32-byte X)
  4,5 → P2PK     : uncompressed pubkey stored as (parity_prefix + 32-byte X)
  ≥6  → raw      : (type - 6) bytes of raw scriptPubKey follow
"""

import hashlib
import struct
from typing import Iterator, Tuple


# ── varint / amount helpers ───────────────────────────────────────────────────

def _read_compactsize(f) -> int:
    """Network CompactSize (used for vout in v28+ grouped snapshot format)."""
    b = f.read(1)
    if not b:
        raise EOFError("unexpected end of snapshot")
    b = b[0]
    if b < 0xfd:
        return b
    if b == 0xfd:
        return struct.unpack('<H', f.read(2))[0]
    if b == 0xfe:
        return struct.unpack('<I', f.read(4))[0]
    return struct.unpack('<Q', f.read(8))[0]


def _read_varint(f) -> int:
    n = 0
    while True:
        b = f.read(1)
        if not b:
            raise EOFError("unexpected end of snapshot")
        b = b[0]
        n = (n << 7) | (b & 0x7f)
        if b & 0x80:
            n += 1
        else:
            return n


def _decompress_amount(x: int) -> int:
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e:
        n *= 10
        e -= 1
    return n


# ── script decoding ───────────────────────────────────────────────────────────

def _classify_raw(script: bytes) -> str:
    n = len(script)
    if n == 22 and script[0] == 0x00 and script[1] == 0x14:
        return "P2WPKH"
    if n == 34 and script[0] == 0x00 and script[1] == 0x20:
        return "P2WSH"
    if n == 34 and script[0] == 0x51 and script[1] == 0x20:
        return "P2TR"
    if n >= 1 and script[0] == 0x6a:
        return "OP_RETURN"
    if n >= 3 and script[-1] == 0xae:
        return "P2MS"
    return "UNKNOWN"


def _read_script(f) -> Tuple[bytes, str]:
    """Return (raw_script_bytes, script_type_string)."""
    code = _read_varint(f)

    if code == 0:
        h = f.read(20)
        return b'\x76\xa9\x14' + h + b'\x88\xac', "P2PKH"

    if code == 1:
        h = f.read(20)
        return b'\xa9\x14' + h + b'\x87', "P2SH"

    if code in (2, 3):
        x = f.read(32)
        pubkey = bytes([code]) + x          # 02/03 + X
        script = bytes([0x21]) + pubkey + bytes([0xac])
        return script, "P2PK"

    if code in (4, 5):
        x = f.read(32)
        # parity stored in code: 4=even-Y, 5=odd-Y
        # reconstruct compressed form for storage: parity 4→02, 5→03
        compressed_prefix = 0x02 if code == 4 else 0x03
        pubkey_compressed = bytes([compressed_prefix]) + x
        # Original script used uncompressed 65-byte key; flag accordingly
        return pubkey_compressed, "P2PK"

    raw_len = code - 6
    raw = f.read(raw_len)
    return raw, _classify_raw(raw)


# ── address encoding ──────────────────────────────────────────────────────────

_BASE58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _b58encode(v: bytes) -> str:
    n = int.from_bytes(v, "big")
    result = []
    while n:
        n, r = divmod(n, 58)
        result.append(_BASE58[r])
    result.extend(_BASE58[0] for _ in v[: len(v) - len(v.lstrip(b'\x00'))])
    return bytes(reversed(result)).decode()


def base58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _b58encode(payload + chk)


def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if (b >> i) & 1 else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & ((1 << (frombits + tobits - 1)) - 1)
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_address(hrp: str, witver: int, witprog: bytes) -> str:
    const = _BECH32M_CONST if witver else _BECH32_CONST
    data = [witver] + _convertbits(list(witprog), 8, 5)
    chk = _bech32_polymod(_bech32_hrp_expand(hrp) + data + [0] * 6) ^ const
    checksum = [(chk >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def script_to_address(script: bytes, script_type: str, hrp: str = "bc",
                       p2pkh_ver: bytes = b'\x00', p2sh_ver: bytes = b'\x05') -> str | None:
    if script_type == "P2PKH":
        return base58check(p2pkh_ver + script[3:23])
    if script_type == "P2SH":
        return base58check(p2sh_ver + script[2:22])
    if script_type == "P2WPKH":
        return bech32_address(hrp, 0, script[2:22])
    if script_type == "P2WSH":
        return bech32_address(hrp, 0, script[2:34])
    if script_type == "P2TR":
        return bech32_address(hrp, 1, script[2:34])
    return None


def pubkey_from_p2pk_script(script: bytes, script_type: str) -> str | None:
    """Return compressed pubkey hex from a P2PK script entry."""
    if script_type != "P2PK":
        return None
    # script is either: 0x21 + 33-byte-compressed-pubkey + 0xac (compressed)
    # or the raw 33-byte compressed form stored from type 2/3/4/5
    if len(script) == 35 and script[0] == 0x21 and script[-1] == 0xac:
        return script[1:34].hex()
    if len(script) == 33:
        return script.hex()
    return script.hex()


# ── snapshot iterator ─────────────────────────────────────────────────────────

_SNAPSHOT_MAGIC = b'utxo\xff'


def iter_utxo_snapshot(path: str) -> Iterator[dict]:
    """
    Yield dicts with keys:
      txid, vout, height, is_coinbase, value_sat, script, script_type
    where script is raw bytes and txid is the hex display form.

    Supports both formats:
      - v28+ (magic present): grouped by txid — one txid + output_count,
        then N × (vout, code, amount, script) records.
      - legacy (no magic): one record per UTXO — txid + uint32 vout + coin data.
    """
    with open(path, "rb") as f:
        prefix = f.read(5)
        if prefix == _SNAPSHOT_MAGIC:
            version = struct.unpack("<H", f.read(2))[0]
            f.read(4)  # network magic
            block_hash = f.read(32)[::-1].hex()
            utxo_count = struct.unpack("<Q", f.read(8))[0]

            if version >= 2:
                # Grouped format: txid → n_outputs → [(vout, code, amount, script)…]
                # n_outputs and vout use CompactSize; code, amount, script type use CVarInt.
                yielded = 0
                while yielded < utxo_count:
                    txid_raw = f.read(32)
                    if len(txid_raw) < 32:
                        break
                    txid = txid_raw[::-1].hex()
                    n_outputs = _read_compactsize(f)
                    for _ in range(n_outputs):
                        vout = _read_compactsize(f)
                        code = _read_varint(f)
                        height = code >> 1
                        is_coinbase = bool(code & 1)
                        value_sat = _decompress_amount(_read_varint(f))
                        script, script_type = _read_script(f)
                        yield {
                            "txid": txid,
                            "vout": vout,
                            "height": height,
                            "is_coinbase": is_coinbase,
                            "value_sat": value_sat,
                            "script": script,
                            "script_type": script_type,
                            "block_hash": block_hash,
                        }
                        yielded += 1
            else:
                # v1 magic format: still per-UTXO with CVarInt vout
                for _ in range(utxo_count):
                    txid = f.read(32)[::-1].hex()
                    vout = _read_varint(f)
                    code = _read_varint(f)
                    height = code >> 1
                    is_coinbase = bool(code & 1)
                    value_sat = _decompress_amount(_read_varint(f))
                    script, script_type = _read_script(f)
                    yield {
                        "txid": txid,
                        "vout": vout,
                        "height": height,
                        "is_coinbase": is_coinbase,
                        "value_sat": value_sat,
                        "script": script,
                        "script_type": script_type,
                        "block_hash": block_hash,
                    }
        else:
            # Legacy format (v22–v27): per-UTXO with uint32 vout
            block_hash = (prefix + f.read(27))[::-1].hex()
            utxo_count = struct.unpack("<Q", f.read(8))[0]
            for _ in range(utxo_count):
                txid = f.read(32)[::-1].hex()
                vout = struct.unpack("<I", f.read(4))[0]
                code = _read_varint(f)
                height = code >> 1
                is_coinbase = bool(code & 1)
                value_sat = _decompress_amount(_read_varint(f))
                script, script_type = _read_script(f)
                yield {
                    "txid": txid,
                    "vout": vout,
                    "height": height,
                    "is_coinbase": is_coinbase,
                    "value_sat": value_sat,
                    "script": script,
                    "script_type": script_type,
                    "block_hash": block_hash,
                }
