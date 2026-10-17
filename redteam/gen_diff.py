"""Differential test vectors for LeanXmssK.verify vs the Python reference (xmss/leanxmss_k.py).

Writes binary record files contracts/test/vectors/redteam/diff_<k>.bin. Record (2469 bytes):
    pubkey (32) || slot (u32 BE) || message (32) || signature (2400) || expected (1)
`expected` is always x.verify(...) from the reference; the constructors below only shape inputs.

Case kinds (record index i, chosen per i):
  valid   random P, chain values, auth path, message; rho ground so both digit sums are 106;
          pubkey = recomputed root || P. Slots: exhaustive mode covers every top leaf t and every
          bottom leaf b: slot_i = (i << 16) | bitrev16(i) for i in [0, 65536).
  mutant  a valid case with one mutation (bit flip anywhere in pubkey/slot/message/signature,
          layer swap, auth-node swap, chain-value swap, rho swap).
  sumedge digit sum of one layer forced to 105 or 107 (or a valid-looking root built anyway).
  random  uniformly random inputs.

usage: .venv/bin/python ../redteam/gen_diff.py <files> <records per file> [seed]   (cwd: xmss/)
"""

import os
import random
import sys
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "xmss"))
import leanxmss_k as x  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "contracts/test/vectors/redteam"
N, L = x.N, x.LAYER_SIG_LENGTH


def bitrev16(v: int) -> int:
    return int(f"{v:016b}"[::-1], 2)


def layer_root_nocheck(P, layer, tree, leaf, message, sig):
    """Same computation as the reference _layer_root, without the digit-sum check."""
    rho, sigma, auth = sig[:N], sig[N : N + x.CHAINS * N], sig[N + x.CHAINS * N :]
    a = x.digits(x.K(P + x.tweak(x.MESSAGE, layer, tree, leaf) + rho + message))
    ends = [x.chain(P, layer, tree, leaf, i, sigma[i * N : (i + 1) * N], a[i], x.W - 1) for i in range(x.CHAINS)]
    node, idx = x.leaf_value(P, layer, tree, leaf, ends), leaf
    for h in range(1, x.HEIGHT + 1):
        sib, k = auth[(h - 1) * N : h * N], idx >> 1
        l, r = (node, sib) if idx % 2 == 0 else (sib, node)
        node, idx = x.K(P + x.tweak(x.NODE, layer, tree, k, h) + l + r)[:N], k
    return node


def grind_rho(rng, P, layer, tree, leaf, message, want_sum):
    t = x.tweak(x.MESSAGE, layer, tree, leaf)
    while True:
        rho = rng.randbytes(N)
        if sum(x.digits(x.K(P + t + rho + message))) == want_sum:
            return rho


def build(rng, slot, bottom_sum=106, top_sum=106):
    P = rng.randbytes(N)
    msg = rng.randbytes(32)
    t, b = slot >> 16, slot & 0xFFFF
    body = lambda: rng.randbytes(x.CHAINS * N + x.HEIGHT * N)  # noqa: E731
    bot = grind_rho(rng, P, x.BOTTOM, t, b, msg, bottom_sum) + body()
    broot = layer_root_nocheck(P, x.BOTTOM, t, b, msg, bot)
    top = grind_rho(rng, P, x.TOP, 0, t, broot, top_sum) + body()
    root = layer_root_nocheck(P, x.TOP, 0, t, broot, top)
    return root + P, slot, msg, top + bot


def flip(buf: bytes, bit: int) -> bytes:
    a = bytearray(buf)
    a[bit >> 3] ^= 0x80 >> (bit & 7)
    return bytes(a)


def swap(buf: bytes, i: int, j: int, n: int) -> bytes:
    a = bytearray(buf)
    a[i : i + n], a[j : j + n] = buf[j : j + n], buf[i : i + n]
    return bytes(a)


def mutate(rng, pk, slot, msg, sig):
    kind = rng.randrange(9)
    if kind == 0:
        pk = flip(pk, rng.randrange(256))
    elif kind == 1:
        slot ^= 1 << rng.randrange(32)
    elif kind == 2:
        msg = flip(msg, rng.randrange(256))
    elif kind in (3, 4):
        sig = flip(sig, rng.randrange(len(sig) * 8))
    elif kind == 5:
        sig = sig[L:] + sig[:L]  # swap layers
    elif kind == 6:  # swap two auth nodes in one layer
        base = rng.randrange(2) * L + N + x.CHAINS * N
        i, j = rng.sample(range(x.HEIGHT), 2)
        sig = swap(sig, base + i * N, base + j * N, N)
    elif kind == 7:  # swap two chain values in one layer
        base = rng.randrange(2) * L + N
        i, j = rng.sample(range(x.CHAINS), 2)
        sig = swap(sig, base + i * N, base + j * N, N)
    else:  # swap rho between layers
        sig = swap(sig, 0, L, N)
    return pk, slot, msg, sig


def case(args):
    i, seed, exhaustive = args
    rng = random.Random(f"{seed}:{i}")
    if exhaustive:
        slot = (i << 16) | bitrev16(i)
        pk, slot, msg, sig = build(rng, slot)
    else:
        r = rng.random()
        slot = rng.choice([0, 1, 0xFFFF, 0x10000, 0xFFFF0000, 0xFFFFFFFE, 0xFFFFFFFF, rng.getrandbits(32)])
        if r < 0.35:
            pk, slot, msg, sig = build(rng, slot)
        elif r < 0.75:
            pk, slot, msg, sig = mutate(rng, *build(rng, slot))
        elif r < 0.9:
            edge = rng.choice([105, 107])
            pk, slot, msg, sig = build(rng, slot, *((edge, 106) if rng.random() < 0.5 else (106, edge)))
        else:
            pk, msg, sig = rng.randbytes(32), rng.randbytes(32), rng.randbytes(x.SIGNATURE_LENGTH)
    ok = x.verify(pk, slot, msg, sig)
    return pk + slot.to_bytes(4, "big") + msg + sig + bytes([ok])


def main():
    files, per = int(sys.argv[1]), int(sys.argv[2])
    seed = sys.argv[3] if len(sys.argv) > 3 else "rt-xmss"
    exhaustive = seed == "exhaustive"
    OUT.mkdir(parents=True, exist_ok=True)
    stats = [0, 0]
    with Pool(os.cpu_count()) as pool:
        for f in range(files):
            recs = pool.map(case, [(f * per + j, seed, exhaustive) for j in range(per)], chunksize=8)
            for r in recs:
                stats[r[-1]] += 1
            (OUT / f"{seed}_{f}.bin").write_bytes(b"".join(recs))
    print(f"{seed}: {files} files x {per} records; expected false={stats[0]} true={stats[1]}")


if __name__ == "__main__":
    main()
