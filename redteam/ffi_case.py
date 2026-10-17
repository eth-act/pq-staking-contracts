"""FFI helper for the forge fuzz differential test (contracts/test/redteam/LeanXmssKFfi.t.sol).

usage: ffi_case.py <slot> <message 0x..32> <P 0x..16> <seed 0x..32> <mutation u32>
Builds a valid-by-construction signature (see gen_diff.build) for the fuzzer-chosen slot,
message and public seed; if `mutation` is odd, flips bit (mutation >> 1) mod 19744 of
pubkey ‖ slot ‖ message ‖ signature. Prints abi.encode(bytes32 pubkey, uint32 slot,
bytes32 message, bytes signature, bool expected) as 0x-hex; `expected` is the reference verify.
"""

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "xmss"))
import gen_diff as g  # noqa: E402
import leanxmss_k as x  # noqa: E402


def b(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def main():
    slot, msg, P, seed, mutation = int(sys.argv[1]), b(sys.argv[2]), b(sys.argv[3]), b(sys.argv[4]), int(sys.argv[5])
    rng = random.Random(seed)
    t, lf = slot >> 16, slot & 0xFFFF
    body = lambda: rng.randbytes(x.CHAINS * x.N + x.HEIGHT * x.N)  # noqa: E731
    bot = g.grind_rho(rng, P, x.BOTTOM, t, lf, msg, 106) + body()
    broot = g.layer_root_nocheck(P, x.BOTTOM, t, lf, msg, bot)
    top = g.grind_rho(rng, P, x.TOP, 0, t, broot, 106) + body()
    pk = g.layer_root_nocheck(P, x.TOP, 0, t, broot, top) + P
    sig = top + bot
    if mutation & 1:
        blob = g.flip(pk + slot.to_bytes(4, "big") + msg + sig, (mutation >> 1) % ((32 + 4 + 32 + 2400) * 8))
        pk, slot, msg, sig = blob[:32], int.from_bytes(blob[32:36], "big"), blob[36:68], blob[68:]
    ok = x.verify(pk, slot, msg, sig)
    enc = pk + slot.to_bytes(32, "big") + msg + (160).to_bytes(32, "big") + int(ok).to_bytes(32, "big")
    enc += len(sig).to_bytes(32, "big") + sig
    print("0x" + enc.hex())


if __name__ == "__main__":
    main()
