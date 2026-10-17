"""Generate leanXMSS-K test vectors for the contracts and demo keys for the site.

Outputs (committed):
  contracts/test/vectors/leanxmss_k.json
  site/src/keys/leanxmss-k-keys.json
"""

import json
import os
from multiprocessing import Pool
from pathlib import Path

import leanxmss_k as x

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_VECTORS = ROOT / "contracts/test/vectors/leanxmss_k.json"
SITE_KEYS = ROOT / "site/src/keys/leanxmss-k-keys.json"

# Registration contracts are etched at these addresses in the forge tests (chain id 31337).
FORGE_CHAIN_ID = 31337
VALIDATOR_REGISTRATION = bytes.fromhex("0000000000000000000000000000000000007a11")
BUILDER_REGISTRATION = bytes.fromhex("000000000000000000000000000000000000b111")

GENERIC_SLOT = 0x0003_0005
SITE_KEY_COUNT = 12


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def seeds(label: str) -> tuple[bytes, bytes]:
    return x.K(f"leanXMSS-K {label} sk_seed".encode()), x.K(f"leanXMSS-K {label} P".encode())[: x.N]


def checked(key: x.KeyPair, slot: int, message: bytes) -> bytes:
    sig = key.sign(slot, message)
    assert x.verify(key.pubkey, slot, message, sig), "reference verify failed"
    tampered = bytearray(sig)
    tampered[-1] ^= 1
    assert not x.verify(key.pubkey, slot, message, bytes(tampered)), "tampered signature verified"
    return sig


def main() -> None:
    with Pool(os.cpu_count()) as pool:
        key_a = x.keygen(*seeds("test key A"), bottom_trees=[0xFFFF, GENERIC_SLOT >> 16], pool=pool)
        key_b = x.keygen(*seeds("test key B"), bottom_trees=[0xFFFF], pool=pool)

        message = x.K(b"leanXMSS-K test message")
        registrations = []
        for key, contract, stake_id in [
            (key_a, VALIDATOR_REGISTRATION, 3),
            (key_a, BUILDER_REGISTRATION, 3),
            (key_b, VALIDATOR_REGISTRATION, 4),
        ]:
            pop = x.pop_message(FORGE_CHAIN_ID, contract, stake_id, key.pubkey)
            registrations.append(
                {
                    "contract": hx(contract),
                    "stakeId": stake_id,
                    "pubkey": hx(key.pubkey),
                    "message": hx(pop),
                    "signature": hx(checked(key, x.POP_SLOT, pop)),
                }
            )

        vectors = {
            "chainId": FORGE_CHAIN_ID,
            "popSlot": x.POP_SLOT,
            "popDomain": hx(x.POP_DOMAIN),
            "pubkeyA": hx(key_a.pubkey),
            "pubkeyB": hx(key_b.pubkey),
            "message": hx(message),
            "popSlotSignature": hx(checked(key_a, x.POP_SLOT, message)),
            "genericSlot": GENERIC_SLOT,
            "genericSlotSignature": hx(checked(key_a, GENERIC_SLOT, message)),
            "registrations": registrations,
        }
        CONTRACT_VECTORS.parent.mkdir(parents=True, exist_ok=True)
        CONTRACT_VECTORS.write_text(json.dumps(vectors, indent=2) + "\n")
        print(f"wrote {CONTRACT_VECTORS}")

        site_keys = []
        for n in range(SITE_KEY_COUNT):
            sk_seed, P = seeds(f"site demo key {n}")
            key = x.keygen(sk_seed, P, bottom_trees=[0xFFFF], pool=pool)
            bottom = key.bottoms[0xFFFF]
            site_keys.append(
                {
                    "skSeed": hx(sk_seed),
                    "publicSeed": hx(P),
                    "pubkey": hx(key.pubkey),
                    # The PoP slot's top layer signs the fixed bottom root, so it never changes.
                    "topSignature": hx(x.sign_layer(sk_seed, P, x.TOP, 0, 0xFFFF, bottom.root, key.top.auth_path(0xFFFF))),
                    "bottomAuthPath": hx(b"".join(bottom.auth_path(0xFFFF))),
                }
            )
            print(f"site key {n + 1}/{SITE_KEY_COUNT}")
        SITE_KEYS.parent.mkdir(parents=True, exist_ok=True)
        SITE_KEYS.write_text(json.dumps(site_keys, indent=2) + "\n")
        print(f"wrote {SITE_KEYS}")


if __name__ == "__main__":
    main()
