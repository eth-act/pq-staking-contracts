# leanXMSS-K

A byte-level instance of the [leanXMSS proposal](https://sphincs.art/xmss/) using the EVM's
Keccak-256, so the registration contracts can verify proofs of possession on the execution
layer.

**This document is the spec** for this repository until the leanXMSS authors publish their
Keccak instance. The leanXMSS proposal fixes the parameters but not the byte encoding (and uses
BLAKE2s), so everything below the parameter table is defined here. When the upstream Keccak
instance appears, compare it against the encoding choices below and align this spec with it.
`leanxmss_k.py` is the reference implementation; the Solidity verifier
(`contracts/src/LeanXmssK.sol`) and the site signer (`site/src/chain/xmss.ts`) must match it
byte for byte.

## Parameters

| Parameter | Value |
| --- | --- |
| Structure | 2 layers of XMSS, each a Merkle tree of height 16 |
| One-time signature | WOTS+C (target-sum Winternitz) |
| Winternitz `w` | 4 (chain positions 0–3) |
| Chains `ℓ` | 58 (58 base-4 digits = 116 bits of message digest) |
| Target sum | 106 |
| Hash | Keccak-256 (the EVM `KECCAK256` opcode, not FIPS SHA3-256) |
| Hash output `n` | 16 bytes (first 16 bytes of Keccak-256) |
| Lifetime | 2³² slots, one leaf per slot |
| Public key | 32 bytes |
| Signature | 2 × 1,200 bytes = 2,400 bytes |
| Verification | 2 × (1 message hash + 68 chain steps + 1 leaf hash + 16 nodes) = 172 Keccak calls |

## Encoding

All integers are big-endian. `‖` is concatenation. `K(x)` is Keccak-256 and `T16(x)` is its
first 16 bytes.

### Keys

- Secret: `sk_seed` (32 bytes) and the public seed `P` (16 bytes).
- Public key (32 bytes): `root ‖ P`, where `root` is the top tree's root.

### Tweak

Every hash call carries a 16-byte tweak:

| Bytes | Field |
| --- | --- |
| 0 | type: `0` chain step, `1` leaf, `2` tree node, `3` message, `4` secret derivation |
| 1 | layer: `0` top, `1` bottom |
| 2–5 | tree (u32): `0` for the top tree; the top leaf index `t` for bottom tree `t` |
| 6–9 | index (u32): leaf index (chain step, leaf, message, secret); node index within its level (tree node) |
| 10 | chain index `i` (chain step, secret) or level `h` 1–16 (tree node); else `0` |
| 11 | chain position `j` (chain step: the step from position `j` to `j + 1`); else `0` |
| 12–15 | zero |

### Hash functions

| Name | Definition | Input bytes |
| --- | --- | --- |
| Secret | `S(T) = T16(K(sk_seed ‖ T))` | 48 |
| Chain step | `F(T, x) = T16(K(P ‖ T ‖ x))` | 48 |
| Tree node | `H(T, l, r) = T16(K(P ‖ T ‖ l ‖ r))` | 64 |
| Leaf | `L(T, e₀…e₅₇) = T16(K(P ‖ T ‖ e₀ ‖ … ‖ e₅₇))` | 960 |
| Message | `D(T, ρ, M) = K(P ‖ T ‖ ρ ‖ M)` (all 32 bytes) | 48 + len(M) |

### WOTS+C

For leaf `(layer, tree, leaf)`:

- Chain `i` starts at `s_i = S(T(4, layer, tree, leaf, i, 0))`.
- `chain(x, a→b)` applies `x ← F(T(0, layer, tree, leaf, i, j), x)` for `j = a … b − 1`.
- The chain end is `e_i = chain(s_i, 0→3)`; the leaf value is `L(T(1, layer, tree, leaf, 0, 0), e₀ … e₅₇)`.

Signing message `M` with randomness `ρ` (16 bytes):

1. `d = D(T(3, layer, tree, leaf, 0, 0), ρ, M)`, read as a 256-bit integer.
2. Digits `a_k = (d >> (254 − 2k)) & 3` for `k = 0 … 57`.
3. The encoding is valid only if `Σ a_k = 106`. The signer retries `ρ` until it is.
4. The signature values are `σ_i = chain(s_i, 0→a_i)`. The verifier finishes each chain:
   `e_i = chain(σ_i, a_i→3)`, which is `Σ (3 − a_i) = 68` chain steps per layer.

`ρ` MUST be deterministic: `ρ = T16(K(sk_seed ‖ T(3, layer, tree, leaf, 0, 0) ‖ M ‖ counter))` with
an 8-byte big-endian counter starting at 0, taking the first counter whose digits sum to 106.
The verifier cannot check this, but a signer that picks a fresh `ρ` when re-signing the same
message at the same leaf produces a different digit vector, which is the reuse described below.

### One message per leaf

Each WOTS+C leaf is a one-time key. A leaf MUST NOT sign two different messages: from two
signatures with digit vectors `a, a'`, anyone can compute chain `i` at every position
`≥ min(a_i, a'_i)` and grind `ρ` for a third message whose digits all lie above those minimums
(about 2⁴⁷ hashes for two signatures, far fewer for three or more).

- Re-signing the same message at the same leaf is safe: deterministic `ρ` makes it byte-identical.
- A top leaf `t` always signs the same message (bottom tree `t`'s root), so with deterministic `ρ`
  its top-layer signature is identical for every slot under `t`.

### Trees

Level 0 holds the 2¹⁶ leaf values. Node `k` at level `h` is
`H(T(2, layer, tree, k, h, 0), node(h−1, 2k), node(h−1, 2k+1))`. The root is node 0 at level 16.
The authentication path for leaf `x` is the sibling at each level 0 … 15.

- Top tree: layer 0, tree 0.
- Bottom tree `t`: layer 1, tree `t` (one per top leaf).

### Signature

For slot `s` (u32): `t = s >> 16`, `b = s & 0xFFFF`.

A layer signature is `ρ (16) ‖ σ₀ … σ₅₇ (928) ‖ auth₀ … auth₁₅ (256)` = 1,200 bytes.

- Bottom layer: bottom tree `t`, leaf `b`, signs the message `M` (32 bytes).
- Top layer: top tree, leaf `t`, signs the bottom tree's root (16 bytes).

Signature = top layer ‖ bottom layer (2,400 bytes).

### Verification

1. Recompute the bottom root from the bottom layer (layer 1, tree `t`, leaf `b`, message `M`).
2. Recompute the top root from the top layer (layer 0, tree 0, leaf `t`, message = bottom root).
3. Valid if both digit sums equal 106 and the top root equals the public key's `root`.

## Registration proof of possession

Proofs of possession use the **PoP range**: top leaf `0xFFFF`, i.e. slots
`0xFFFF0000 … 0xFFFFFFFF`. These 65,536 slots MUST NOT be used for attestations.

- Message:
  `M = K(DOMAIN ‖ chain_id (32) ‖ registration_contract (20) ‖ stake_id (8) ‖ pq_pubkey (32))`,
  with `DOMAIN = K("leanXMSS-K registration proof of possession v1")`.
- Slot: `0xFFFF0000 | (M mod 2¹⁶)`, i.e. the bottom leaf is the last two bytes of `M`. The
  verifier derives the slot from `M`; the request does not carry it.

Binding the registration contract's address stops a copied validator registration from being
replayed into the builder registration contract (and the reverse). Binding `stake_id` and
`chain_id` stops replay onto another stake or chain.

Deriving the leaf from `M` gives each distinct registration (chain, role, stake) its own leaf,
so registering one key several times does not reuse a leaf (issue #2). Two different messages
land on the same leaf with probability about `n² / 2¹⁷` for `n` registrations of one key
(0.005% for 3). A signer MUST track the PoP leaves it has used and refuse to sign a different
message on one of them; the operator then registers with another stake.

## Files

| File | Purpose |
| --- | --- |
| `leanxmss_k.py` | Reference key generation, signing and verification |
| `gen_vectors.py` | Writes `contracts/test/vectors/leanxmss_k.json` and `site/src/keys/leanxmss-k-keys.json` |

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python gen_vectors.py   # ~1 minute on 32 cores
```

Key generation builds two height-16 trees (about 30M hashes), so the generator uses all cores.
The outputs are committed; CI does not regenerate them.
