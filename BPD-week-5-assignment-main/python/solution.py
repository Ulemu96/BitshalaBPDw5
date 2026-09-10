#!/usr/bin/env python3
"""
Bitcoin Protocol Development - Week 5
Parsing a Descriptor and Calculating Wallet Balance
"""

import hashlib
import hmac
import struct
import requests
from Crypto.Hash import RIPEMD160
from typing import List, Dict, Tuple

# ---- Configuration ----
ESPLORA_API = "http://localhost:3002"
DESCRIPTOR = "wpkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/*)#adv567t2"
GAP_LIMIT = 10
NETWORK_HRP = "bcrt"

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s):
    n = 0
    for char in s:
        n = n * 58 + B58_ALPHABET.index(char)
    h = hex(n)[2:]
    if len(h) % 2:
        h = '0' + h
    data = bytes.fromhex(h)
    pad = 0
    for char in s:
        if char == '1':
            pad += 1
        else:
            break
    return b'\x00' * pad + data

def b58check_decode(s):
    raw = b58decode(s)
    payload, checksum = raw[:-4], raw[-4:]
    calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if calc != checksum:
        raise ValueError("Base58 checksum mismatch")
    return payload

def parse_extended_key(key_str):
    payload = b58check_decode(key_str)
    if len(payload) != 78:
        raise ValueError(f"Invalid extended key length: {len(payload)}")
    return {
        "depth": payload[4],
        "child_num": struct.unpack(">I", payload[9:13])[0],
        "chain_code": payload[13:45],
        "pubkey": payload[45:78],
    }

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def _scalar_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result

def _decompress_pubkey(pubkey):
    prefix = pubkey[0]
    x = int.from_bytes(pubkey[1:33], "big")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y % 2 == 0) != (prefix == 0x02):
        y = P - y
    return (x, y)

def _compress_point(point):
    x, y = point
    prefix = 0x02 if y % 2 == 0 else 0x03
    return bytes([prefix]) + x.to_bytes(32, "big")

def derive_child_pubkey(parent_pubkey, parent_chaincode, index):
    data = parent_pubkey + struct.pack(">I", index)
    I = hmac.new(parent_chaincode, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    parent_point = _decompress_pubkey(parent_pubkey)
    tweak_point = _scalar_mul(int.from_bytes(IL, "big"), (Gx, Gy))
    child_point = _point_add(tweak_point, parent_point)
    return _compress_point(child_point), IR

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _bech32_encode(hrp, data):
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in combined])

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def pubkey_to_p2wpkh(pubkey):
    sha = hashlib.sha256(pubkey).digest()
    h160 = RIPEMD160.new(sha).digest()
    data = [0] + _convertbits(h160, 8, 5)
    return _bech32_encode(NETWORK_HRP, data)

def extract_tpub(descriptor):
    base = descriptor.split("#")[0] if "#" in descriptor else descriptor
    if not base.startswith("wpkh(") or not base.endswith("/*)"):
        raise ValueError(f"Invalid descriptor format: {descriptor}")
    return base[len("wpkh("):-len("/*)")]

def derive_address(account_key, index):
    chain0_pub, chain0_cc = derive_child_pubkey(
        account_key["pubkey"], account_key["chain_code"], 0
    )
    child_pub, _ = derive_child_pubkey(chain0_pub, chain0_cc, index)
    return pubkey_to_p2wpkh(child_pub)

def get_address_info(address):
    try:
        r = requests.get(f"{ESPLORA_API}/address/{address}", timeout=5)
        if r.status_code != 200:
            return {"tx_count": 0, "balance": 0}
        data = r.json()
        chain = data.get("chain_stats", {})
        mempool = data.get("mempool_stats", {})
        tx_count = chain.get("tx_count", 0) + mempool.get("tx_count", 0)
        balance = (chain.get("funded_txo_sum", 0) - chain.get("spent_txo_sum", 0))
        balance += (mempool.get("funded_txo_sum", 0) - mempool.get("spent_txo_sum", 0))
        return {"tx_count": tx_count, "balance": balance}
    except Exception as e:
        print(f"  [WARN] Esplora error for {address}: {e}")
        return {"tx_count": 0, "balance": 0}

def main():
    print("=" * 60)
    print(" Exercise 5: Descriptor -> Addresses -> Balance")
    print("=" * 60)
    print(f"Esplora URL: {ESPLORA_API}")
    print(f"Gap limit  : {GAP_LIMIT}")

    tpub = extract_tpub(DESCRIPTOR)
    account_key = parse_extended_key(tpub)
    print(f"Parsed tpub (depth={account_key['depth']})")

    print("\nStarting address scan...\n")
    addresses, balances, tx_counts = [], [], []
    consecutive_unused = 0
    index = 0

    while consecutive_unused < GAP_LIMIT:
        addr = derive_address(account_key, index)
        info = get_address_info(addr)

        addresses.append(addr)
        balances.append(info["balance"])
        tx_counts.append(info["tx_count"])

        if info["tx_count"] > 0:
            print(f"  [{index:>4}] {addr}  {info['balance']:>15} sats  {info['tx_count']} tx  USED")
            consecutive_unused = 0
        else:
            print(f"  [{index:>4}] {addr}               0 sats  unused")
            consecutive_unused += 1

        index += 1

    total_sat = sum(balances)
    total_btc = total_sat / 100_000_000

    print(f"\nScanned {index} addresses")
    print(f"Total balance: {total_sat} sats = {total_btc} BTC")

    with open("out.txt", "w") as f:
        f.write(f"{total_btc}\n")

    print("\nResults written to out.txt")

if __name__ == "__main__":
    main()
