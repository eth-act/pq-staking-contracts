"""FFI helper: sign a registration proof of possession with a site demo key (reference code).

usage: ffi_pop.py <key index 0..11> <chain_id> <contract 0x..20> <stake_id>
Prints abi.encode(bytes32 pubkey, bytes32 message, bytes signature) as 0x-hex, where message is
x.pop_message(...) and signature = demo top layer ‖ x.sign_layer(bottom tree 0xFFFF, leaf 0xFFFF).
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "xmss"))
import leanxmss_k as x  # noqa: E402


def b(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def main():
    key = json.loads((ROOT / "site/src/keys/leanxmss-k-keys.json").read_text())[int(sys.argv[1]) % 12]
    chain_id, contract, stake_id = int(sys.argv[2]), b(sys.argv[3]), int(sys.argv[4])
    sk, P, pk = b(key["skSeed"]), b(key["publicSeed"]), b(key["pubkey"])
    auth = b(key["bottomAuthPath"])
    msg = x.pop_message(chain_id, contract, stake_id, pk)
    bottom = x.sign_layer(sk, P, x.BOTTOM, 0xFFFF, 0xFFFF, msg, [auth[i : i + 16] for i in range(0, 256, 16)])
    sig = b(key["topSignature"]) + bottom
    assert x.verify(pk, x.POP_SLOT, msg, sig)
    enc = pk + msg + (96).to_bytes(32, "big") + len(sig).to_bytes(32, "big") + sig
    print("0x" + enc.hex())


if __name__ == "__main__":
    main()
