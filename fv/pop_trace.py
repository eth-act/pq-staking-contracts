"""Bytecode-level check of the registration proof-of-possession binding.

For random (chain id, registration contract address, stake id, pubkey, signature) it traces a
request to the compiled PQValidatorRegistration runtime and checks, from EVM memory:
  1. the first KECCAK256 preimage is exactly
     K("leanXMSS-K registration proof of possession v1") ‖ chain_id (32 BE) ‖ address (20)
       ‖ stake_id (8 BE) ‖ pubkey (32)          (124 bytes)
  2. the second KECCAK256 preimage is the bottom-layer message digest input
     P ‖ T(3, layer 1, tree 0xFFFF, leaf 0xFFFF) ‖ rho_bottom ‖ M   (slot 2^32-1), M = hash 1;
  3. stake_id > 2^40-1 or a length != 2440 reverts before any KECCAK256 and any SSTORE;
  4. no SSTORE happens unless the call succeeds (a random signature never verifies).

usage: python3 pop_trace.py RPC_URL N
"""

import json
import random
import subprocess
import sys
import urllib.request

from Crypto.Hash import keccak  # noqa: F401  (pycryptodome, as xmss/requirements.txt)

ROOT = __file__.rsplit("/", 1)[0]
ART = json.load(open(f"{ROOT}/../contracts/out/PQValidatorRegistration.sol/PQValidatorRegistration.json"))
CODE = ART["deployedBytecode"]["object"]


def K(b):
    return keccak.new(digest_bits=256, data=b).digest()


DOMAIN = K(b"leanXMSS-K registration proof of possession v1")


def rpc(url, method, params):
    req = urllib.request.Request(url, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=600))
    if "error" in r:
        raise RuntimeError(r["error"])
    return r["result"]


def trace(url, addr, data):
    tr = rpc(url, "debug_traceCall", [
        {"from": "0x00000000000000000000000000000000000a11ce", "to": addr, "data": "0x" + data.hex(),
         "value": hex(1), "gas": hex(30_000_000)}, "latest",
        {"enableMemory": True, "disableStack": False, "disableStorage": True}])
    pre, sstores = [], 0
    for st in tr["structLogs"]:
        if st["op"] == "KECCAK256":
            off, size = int(st["stack"][-1], 16), int(st["stack"][-2], 16)
            mem = "".join(w[2:] if w.startswith("0x") else w for w in st["memory"])
            pre.append(bytes.fromhex(mem[2 * off: 2 * (off + size)]))
        elif st["op"] == "SSTORE":
            sstores += 1
    return pre, sstores, tr["failed"], tr["returnValue"]


def tweak(ty, layer, tree, index, c=0, j=0):
    return bytes([ty, layer]) + tree.to_bytes(4, "big") + index.to_bytes(4, "big") + bytes([c, j]) + bytes(4)


def main():
    url, n = sys.argv[1], int(sys.argv[2])
    rng = random.Random(7002)
    bad = 0
    rpc(url, "anvil_setBalance", ["0x00000000000000000000000000000000000a11ce", hex(10**30)])
    for k in range(n):
        chain_id = rng.choice([1, 31337, 17000, rng.randrange(1, 2**64)])
        rpc(url, "anvil_setChainId", [chain_id])
        addr = "0x" + rng.randbytes(20).hex()
        rpc(url, "anvil_setCode", [addr, CODE])
        rpc(url, "anvil_setStorageAt", [addr, "0x" + "00" * 32, "0x" + "00" * 32])  # excess 0
        stake = rng.choice([rng.randrange(2**40), 2**40 - 1, 2**40, rng.randrange(2**40, 2**64)])
        pk = rng.randbytes(32)
        sig = rng.randbytes(2400)
        length = rng.choice([2440] * 6 + [0, 2439, 2441, 16])
        data = (stake.to_bytes(8, "big") + pk + sig)
        data = data[:length] if length <= len(data) else data + rng.randbytes(length - len(data))
        pre, sstores, failed, ret = trace(url, addr, data)
        # The fallback bumps count and tail (2 SSTOREs) before _addRequest validates; a revert
        # rolls them back. The queue entry itself is only written after verification succeeds.
        ok = True
        if length != 2440 or stake > 2**40 - 1:
            if length == 0:
                ok = failed and sstores == 0 and pre == []  # fee getter rejects value
            else:
                ok = failed and pre == [] and sstores == 2 and ret in ("", "0x")
        else:
            exp_msg = DOMAIN + chain_id.to_bytes(32, "big") + bytes.fromhex(addr[2:]) \
                + stake.to_bytes(8, "big") + pk
            M = K(exp_msg)
            P = pk[16:]
            exp_digest = P + tweak(3, 1, 0xFFFF, 0xFFFF) + sig[1200:1216] + M
            ok = (len(pre) >= 2 and pre[0] == exp_msg and pre[1] == exp_digest
                  and failed and sstores == 2 and ret in ("", "0x"))
        bad += not ok
        print(f"{'OK ' if ok else 'BAD'} chain={chain_id} stake={stake} len={length} "
              f"hashes={len(pre)} sstores={sstores} failed={failed}")
    print(f"{n - bad}/{n} cases agree")
    sys.exit(1 if bad else 0)


main()
