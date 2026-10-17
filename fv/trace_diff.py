"""Differential check of the Lean model against the COMPILED bytecode.

For each input, runs LeanXmssK.verify (deployed LeanXmssKHarness runtime, on anvil, via
debug_traceCall with memory) and records the exact sequence of KECCAK256 preimages taken from
EVM memory. Runs the Lean spec `verify` and model `verifyM` (fv/lean trace executable, real
Keccak) and records their hash preimages. Requires: the EVM sequence == the spec sequence
(order and content), the model's distinct preimages == the spec's, and equal verdicts.

usage: python3 trace_diff.py RPC_URL HARNESS_ADDR N_RANDOM_MUTATIONS
"""

import json
import random
import subprocess
import sys
import urllib.request

ROOT = __file__.rsplit("/", 1)[0]
VEC = json.load(open(f"{ROOT}/../contracts/test/vectors/leanxmss_k.json"))
TRACE = f"{ROOT}/lean/.lake/build/bin/trace"
SEL = "0x" + subprocess.check_output(
    ["cast", "sig", "verify(bytes32,uint32,bytes32,bytes)"], text=True).strip()[2:]


def rpc(url, method, params):
    req = urllib.request.Request(url, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=600))
    if "error" in r:
        raise RuntimeError(r["error"])
    return r["result"]


def evm(url, addr, pk, slot, msg, sig):
    data = subprocess.check_output(
        ["cast", "calldata", "verify(bytes32,uint32,bytes32,bytes)", pk, str(slot), msg, sig],
        text=True).strip()
    tr = rpc(url, "debug_traceCall", [{"to": addr, "data": data, "gas": hex(30_000_000)}, "latest",
                                      {"enableMemory": True, "disableStack": False,
                                       "disableStorage": True}])
    pre = []
    for st in tr["structLogs"]:
        if st["op"] == "KECCAK256":
            stack = st["stack"]
            off, size = int(stack[-1], 16), int(stack[-2], 16)
            mem = "".join(w[2:] if w.startswith("0x") else w for w in st["memory"])
            pre.append(mem[2 * off: 2 * (off + size)])
    ret = tr["returnValue"]
    verdict = int(ret, 16) == 1 if ret not in ("", "0x") else None
    return pre, verdict


def lean(which, pk, slot, msg, sig):
    p = subprocess.run([TRACE, pk, str(slot), msg, sig, which], capture_output=True, text=True)
    pre = [l[2:] for l in p.stderr.splitlines() if l.startswith("K ")]
    return pre, p.stdout.strip().endswith("true")


def check(url, addr, name, pk, slot, msg, sig):
    e, ev = evm(url, addr, pk, slot, msg, sig)
    s, sv = lean("spec", pk, slot, msg, sig)
    m, mv = lean("model", pk, slot, msg, sig)
    ok = (e == s) and (sorted(set(m)) == sorted(set(s))) and ev == sv == mv
    print(f"{'OK ' if ok else 'BAD'} {name}: evm={ev} spec={sv} model={mv} "
          f"hashes evm={len(e)} spec={len(s)} model_distinct={len(set(m))}")
    if not ok:
        for i, (a, b) in enumerate(zip(e, s)):
            if a != b:
                print("  first divergence at hash", i, "\n  evm ", a, "\n  spec", b)
                break
    return ok


def mutate(sig_hex, rng):
    b = bytearray.fromhex(sig_hex[2:])
    kind = rng.choice(["chain", "auth", "rho", "byte"])
    layer = rng.choice([0, 1200])
    if kind == "chain":
        i = layer + 16 + 16 * rng.randrange(58)
    elif kind == "auth":
        i = layer + 944 + 16 * rng.randrange(16)
    elif kind == "rho":
        i = layer + rng.randrange(16)
    else:
        i = rng.randrange(2400)
    i += rng.randrange(16) if kind != "byte" and kind != "rho" else 0
    b[i] ^= 1 << rng.randrange(8)
    return "0x" + b.hex(), f"{kind}@{i}"


def main():
    url, addr, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
    rng = random.Random(8413)
    cases = [
        ("generic", VEC["pubkeyA"], VEC["genericSlot"], VEC["message"], VEC["genericSlotSignature"]),
        ("pop", VEC["pubkeyA"], VEC["popSlot"], VEC["message"], VEC["popSlotSignature"]),
        ("wrong-key", VEC["pubkeyB"], VEC["genericSlot"], VEC["message"], VEC["genericSlotSignature"]),
        ("wrong-slot", VEC["pubkeyA"], VEC["genericSlot"] + 1, VEC["message"], VEC["genericSlotSignature"]),
    ]
    for r in VEC["registrations"]:
        cases.append(("registration", r["pubkey"], VEC["popSlot"], r["message"], r["signature"]))
    for k in range(n):
        base = cases[k % 2]
        sig, what = mutate(base[4], rng)
        cases.append((f"mut-{base[0]}-{what}", base[1], base[2], base[3], sig))
    bad = sum(not check(url, addr, *c) for c in cases)
    print(f"{len(cases) - bad}/{len(cases)} cases agree")
    sys.exit(1 if bad else 0)


main()
