"""Generate leanXMSS-K test vectors for the contracts and demo keys for the site.

Outputs (committed):
  contracts/test/vectors/leanxmss_k.json
  site/src/keys/leanxmss-k-keys.json

No key signs two different messages with one leaf (see README "One message per leaf").
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
LAST_SLOT = (1 << 32) - 1
SITE_KEY_COUNT = 12
# The site stores this level of the PoP bottom tree and rebuilds the 2^8-leaf subtree under it.
SITE_STORED_LEVEL = 8


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def seeds(label: str) -> tuple[bytes, bytes]:
    return x.K(f"leanXMSS-K {label} sk_seed".encode()), x.K(f"leanXMSS-K {label} P".encode())[: x.N]


class Signer:
    """Signs with one key and refuses to sign two different messages on one slot."""

    def __init__(self, key: x.KeyPair):
        self.key = key
        self.used: dict[int, bytes] = {}

    def sign(self, slot: int, message: bytes) -> bytes:
        assert self.used.setdefault(slot, message) == message, f"slot {slot:#x} already signed another message"
        sig = self.key.sign(slot, message)
        assert x.verify(self.key.pubkey, slot, message, sig), "reference verify failed"
        tampered = bytearray(sig)
        tampered[-1] ^= 1
        assert not x.verify(self.key.pubkey, slot, message, bytes(tampered)), "tampered signature verified"
        return sig


def registration(signer: Signer, contract: bytes, stake_id: int) -> dict:
    pop = x.pop_message(FORGE_CHAIN_ID, contract, stake_id, signer.key.pubkey)
    slot = x.pop_slot(pop)
    return {
        "contract": hx(contract),
        "stakeId": stake_id,
        "pubkey": hx(signer.key.pubkey),
        "message": hx(pop),
        "slot": slot,
        "signature": hx(signer.sign(slot, pop)),
    }


def main() -> None:
    with Pool(os.cpu_count()) as pool:
        key_a = Signer(x.keygen(*seeds("test key A"), bottom_trees=[x.POP_TOP_LEAF, GENERIC_SLOT >> 16], pool=pool))
        key_b = Signer(x.keygen(*seeds("test key B"), bottom_trees=[x.POP_TOP_LEAF], pool=pool))

        # Key A registers twice (validator and builder role, stake 3); each lands on its own leaf.
        registrations = [
            registration(key_a, VALIDATOR_REGISTRATION, 3),
            registration(key_a, BUILDER_REGISTRATION, 3),
            registration(key_b, VALIDATOR_REGISTRATION, 4),
        ]

        # Registration 0's message signed at a neighbouring PoP leaf: a valid signature that the
        # registration contract must reject, because it derives the leaf from the message.
        reg0 = registrations[0]
        wrong_slot = reg0["slot"] ^ 1
        wrong_leaf = {**reg0, "slot": wrong_slot, "signature": hx(key_a.sign(wrong_slot, bytes.fromhex(reg0["message"][2:])))}

        message = x.K(b"leanXMSS-K test message")
        vectors = {
            "chainId": FORGE_CHAIN_ID,
            "popDomain": hx(x.POP_DOMAIN),
            "pubkeyA": hx(key_a.key.pubkey),
            "pubkeyB": hx(key_b.key.pubkey),
            "message": hx(message),
            "lastSlot": LAST_SLOT,
            "lastSlotSignature": hx(key_a.sign(LAST_SLOT, message)),
            "genericSlot": GENERIC_SLOT,
            "genericSlotSignature": hx(key_a.sign(GENERIC_SLOT, message)),
            "registrations": registrations,
            "wrongLeafRegistration": wrong_leaf,
        }
        CONTRACT_VECTORS.parent.mkdir(parents=True, exist_ok=True)
        CONTRACT_VECTORS.write_text(json.dumps(vectors, indent=2) + "\n")
        print(f"wrote {CONTRACT_VECTORS}")

        site_keys = []
        for n in range(SITE_KEY_COUNT):
            sk_seed, P = seeds(f"site demo key {n}")
            key = x.keygen(sk_seed, P, bottom_trees=[x.POP_TOP_LEAF], pool=pool)
            bottom = key.bottoms[x.POP_TOP_LEAF]
            top_sig = x.sign_layer(sk_seed, P, x.TOP, 0, x.POP_TOP_LEAF, bottom.root, key.top.auth_path(x.POP_TOP_LEAF))
            site_keys.append(
                {
                    "skSeed": hx(sk_seed),
                    "publicSeed": hx(P),
                    "pubkey": hx(key.pubkey),
                    # Top leaf 0xFFFF always signs the PoP bottom tree's root, so with deterministic
                    # rho its top-layer signature is the same for every PoP slot.
                    "topSignature": hx(top_sig),
                    # Level SITE_STORED_LEVEL of the PoP bottom tree (2^8 nodes). The site rebuilds the
                    # 256-leaf subtree under one of these for the levels below.
                    "storedLevel": SITE_STORED_LEVEL,
                    "bottomLevelNodes": hx(b"".join(bottom.levels[SITE_STORED_LEVEL])),
                    "bottomRoot": hx(bottom.root),
                }
            )
            print(f"site key {n + 1}/{SITE_KEY_COUNT}")
        SITE_KEYS.parent.mkdir(parents=True, exist_ok=True)
        SITE_KEYS.write_text(json.dumps(site_keys, indent=2) + "\n")
        print(f"wrote {SITE_KEYS}")


if __name__ == "__main__":
    main()
