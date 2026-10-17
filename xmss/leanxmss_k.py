"""Reference implementation of leanXMSS-K (provisional). See README.md for the spec."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from functools import partial
from multiprocessing import Pool

from Crypto.Hash import keccak

N = 16
CHAINS = 58
W = 4
TARGET_SUM = 106
HEIGHT = 16
LEAVES = 1 << HEIGHT
LAYER_SIG_LENGTH = N + CHAINS * N + HEIGHT * N  # 1200
SIGNATURE_LENGTH = 2 * LAYER_SIG_LENGTH  # 2400

CHAIN, LEAF, NODE, MESSAGE, SECRET = 0, 1, 2, 3, 4
TOP, BOTTOM = 0, 1

POP_SLOT = (1 << 32) - 1


def K(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def tweak(kind: int, layer: int, tree: int, index: int, c: int = 0, j: int = 0) -> bytes:
    return struct.pack(">BBIIBB4x", kind, layer, tree, index, c, j)


POP_DOMAIN = K(b"leanXMSS-K registration proof of possession v1")


def pop_message(chain_id: int, registration_contract: bytes, stake_id: int, pubkey: bytes) -> bytes:
    """Message signed by the registration proof of possession."""
    assert len(registration_contract) == 20 and len(pubkey) == 32
    return K(POP_DOMAIN + chain_id.to_bytes(32, "big") + registration_contract + stake_id.to_bytes(8, "big") + pubkey)


def digits(d: bytes) -> list[int]:
    v = int.from_bytes(d, "big")
    return [(v >> (254 - 2 * k)) & 3 for k in range(CHAINS)]


def chain(P: bytes, layer: int, tree: int, leaf: int, i: int, x: bytes, start: int, end: int) -> bytes:
    for j in range(start, end):
        x = K(P + tweak(CHAIN, layer, tree, leaf, i, j) + x)[:N]
    return x


def secret(sk_seed: bytes, layer: int, tree: int, leaf: int, i: int) -> bytes:
    return K(sk_seed + tweak(SECRET, layer, tree, leaf, i))[:N]


def leaf_value(P: bytes, layer: int, tree: int, leaf: int, ends: list[bytes]) -> bytes:
    return K(P + tweak(LEAF, layer, tree, leaf) + b"".join(ends))[:N]


def _wots_leaf(sk_seed: bytes, P: bytes, layer: int, tree: int, leaf: int) -> bytes:
    ends = [chain(P, layer, tree, leaf, i, secret(sk_seed, layer, tree, leaf, i), 0, W - 1) for i in range(CHAINS)]
    return leaf_value(P, layer, tree, leaf, ends)


@dataclass
class Tree:
    """All levels of one XMSS tree; levels[0] are the leaves, levels[HEIGHT] = [root]."""

    levels: list[list[bytes]]

    @property
    def root(self) -> bytes:
        return self.levels[HEIGHT][0]

    def auth_path(self, leaf: int) -> list[bytes]:
        return [self.levels[h][(leaf >> h) ^ 1] for h in range(HEIGHT)]


def build_tree(sk_seed: bytes, P: bytes, layer: int, tree: int, pool: Pool) -> Tree:
    leaves = pool.map(partial(_wots_leaf, sk_seed, P, layer, tree), range(LEAVES), chunksize=512)
    levels = [leaves]
    for h in range(1, HEIGHT + 1):
        below = levels[-1]
        levels.append(
            [K(P + tweak(NODE, layer, tree, k, h) + below[2 * k] + below[2 * k + 1])[:N] for k in range(len(below) // 2)]
        )
    return Tree(levels)


def sign_layer(sk_seed: bytes, P: bytes, layer: int, tree: int, leaf: int, message: bytes, auth: list[bytes]) -> bytes:
    t_msg = tweak(MESSAGE, layer, tree, leaf)
    for counter in range(1 << 32):
        rho = K(sk_seed + t_msg + message + counter.to_bytes(8, "big"))[:N]
        a = digits(K(P + t_msg + rho + message))
        if sum(a) == TARGET_SUM:
            break
    sigma = [chain(P, layer, tree, leaf, i, secret(sk_seed, layer, tree, leaf, i), 0, a[i]) for i in range(CHAINS)]
    return rho + b"".join(sigma) + b"".join(auth)


@dataclass
class KeyPair:
    sk_seed: bytes
    P: bytes
    top: Tree
    bottoms: dict[int, Tree]  # bottom trees built so far, by top leaf

    @property
    def pubkey(self) -> bytes:
        return self.top.root + self.P

    def sign(self, slot: int, message: bytes) -> bytes:
        assert len(message) == 32
        t, b = slot >> 16, slot & 0xFFFF
        bottom = self.bottoms[t]
        top_sig = sign_layer(self.sk_seed, self.P, TOP, 0, t, bottom.root, self.top.auth_path(t))
        bottom_sig = sign_layer(self.sk_seed, self.P, BOTTOM, t, b, message, bottom.auth_path(b))
        return top_sig + bottom_sig


def keygen(sk_seed: bytes, P: bytes, bottom_trees: list[int], pool: Pool) -> KeyPair:
    """Build the top tree and the bottom trees for the given top leaves."""
    top = build_tree(sk_seed, P, TOP, 0, pool)
    bottoms = {t: build_tree(sk_seed, P, BOTTOM, t, pool) for t in bottom_trees}
    return KeyPair(sk_seed, P, top, bottoms)


def _layer_root(P: bytes, layer: int, tree: int, leaf: int, message: bytes, sig: bytes) -> bytes | None:
    rho, sigma, auth = sig[:N], sig[N : N + CHAINS * N], sig[N + CHAINS * N :]
    a = digits(K(P + tweak(MESSAGE, layer, tree, leaf) + rho + message))
    if sum(a) != TARGET_SUM:
        return None
    ends = [chain(P, layer, tree, leaf, i, sigma[i * N : (i + 1) * N], a[i], W - 1) for i in range(CHAINS)]
    node, idx = leaf_value(P, layer, tree, leaf, ends), leaf
    for h in range(1, HEIGHT + 1):
        sibling, k = auth[(h - 1) * N : h * N], idx >> 1
        left, right = (node, sibling) if idx % 2 == 0 else (sibling, node)
        node, idx = K(P + tweak(NODE, layer, tree, k, h) + left + right)[:N], k
    return node


def verify(pubkey: bytes, slot: int, message: bytes, signature: bytes) -> bool:
    if len(pubkey) != 32 or len(message) != 32 or len(signature) != SIGNATURE_LENGTH:
        return False
    root, P = pubkey[:N], pubkey[N:]
    t, b = slot >> 16, slot & 0xFFFF
    bottom_root = _layer_root(P, BOTTOM, t, b, message, signature[LAYER_SIG_LENGTH:])
    if bottom_root is None:
        return False
    return _layer_root(P, TOP, 0, t, bottom_root, signature[:LAYER_SIG_LENGTH]) == root
