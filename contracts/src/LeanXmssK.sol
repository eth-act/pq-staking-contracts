// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title LeanXmssK
/// @notice Verifier for leanXMSS-K: two layers of height-16 XMSS with WOTS+C
///         (w = 4, 58 chains, target sum 106) over Keccak-256 truncated to 16 bytes.
/// @dev Byte-level spec and reference implementation: `xmss/README.md`, `xmss/leanxmss_k.py`.
///      Public key: root (16) ‖ public seed P (16). Signature: top layer ‖ bottom layer, each
///      rho (16) ‖ 58 chain values (928) ‖ 16 auth-path nodes (256). 172 Keccak calls.
library LeanXmssK {
    uint256 internal constant SIGNATURE_LENGTH = 2400;
    uint256 internal constant LAYER_SIGNATURE_LENGTH = 1200;

    uint256 private constant HIGH_128 =
        0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;

    /// @notice Verify `signature` over `message` at `slot` against `pubkey`.
    function verify(bytes32 pubkey, uint32 slot, bytes32 message, bytes calldata signature)
        internal
        pure
        returns (bool)
    {
        if (signature.length != SIGNATURE_LENGTH) return false;
        // Hash inputs start with P ‖ tweak; the tweak's layer (byte 1) and tree (bytes 2-5)
        // are fixed per layer, so they are folded into the first word up front.
        uint256 seedWord = uint256(pubkey) << 128;
        uint256 topLeaf = slot >> 16;

        (bool ok, bytes32 bottomRoot) = _layerRoot(
            seedWord | (1 << 112) | (topLeaf << 80),
            slot & 0xffff,
            message,
            32,
            signature[LAYER_SIGNATURE_LENGTH:]
        );
        if (!ok) return false;
        bytes32 topRoot;
        (ok, topRoot) =
            _layerRoot(seedWord, topLeaf, bottomRoot, 16, signature[:LAYER_SIGNATURE_LENGTH]);
        return ok && topRoot == (pubkey & bytes32(HIGH_128));
    }

    /// @dev Recompute one layer's root. `base` is P (high 16 bytes) with the tweak's layer and
    ///      tree fields set. `message` is left-aligned; `messageLength` is 32 for the bottom layer
    ///      and 16 (a root) for the top layer. Roots are returned left-aligned.
    ///      Tweak fields (low 16 bytes): type << 120, layer << 112, tree << 80, index << 48,
    ///      chain/level << 40, position << 32. Types: 0 chain, 1 leaf, 2 node, 3 message.
    function _layerRoot(
        uint256 base,
        uint256 leaf,
        bytes32 message,
        uint256 messageLength,
        bytes calldata layerSig
    ) private pure returns (bool ok, bytes32 root) {
        assembly ("memory-safe") {
            // Temporary memory past the free pointer: [buf, buf+80) for single hashes and
            // [buf+0x80, buf+0x80+960) for the leaf hash input.
            let buf := mload(0x40)
            let leafBase := or(base, shl(48, leaf))

            // Message digest: P ‖ T(message) ‖ rho ‖ M.
            mstore(buf, or(leafBase, shl(120, 3)))
            calldatacopy(add(buf, 32), layerSig.offset, 16)
            mstore(add(buf, 48), message)
            let d := keccak256(buf, add(48, messageLength))

            // WOTS+C: 58 base-4 digits from the top of d must sum to 106.
            let sum := 0
            for { let k := 0 } lt(k, 58) { k := add(k, 1) } {
                sum := add(sum, and(shr(sub(254, shl(1, k)), d), 3))
            }

            if eq(sum, 106) {
                // Finish each chain from its digit to position 3; chain ends go to buf+0xa0.
                for { let i := 0 } lt(i, 58) { i := add(i, 1) } {
                    let x := and(calldataload(add(layerSig.offset, add(16, shl(4, i)))), HIGH_128)
                    for { let j := and(shr(sub(254, shl(1, i)), d), 3) } lt(j, 3) { j := add(j, 1) }
                    {
                        mstore(buf, or(leafBase, or(shl(40, i), shl(32, j))))
                        mstore(add(buf, 32), x)
                        x := and(keccak256(buf, 48), HIGH_128)
                    }
                    // 32-byte store; its low 16 zero bytes are overwritten by the next end.
                    mstore(add(buf, add(0xa0, shl(4, i))), x)
                }
                mstore(add(buf, 0x80), or(leafBase, shl(120, 1)))
                let node := and(keccak256(add(buf, 0x80), 960), HIGH_128)

                // Merkle path: auth nodes start after rho and the chain values (16 + 928).
                for { let h := 1 } lt(h, 17) { h := add(h, 1) } {
                    let sibling :=
                        and(
                            calldataload(add(layerSig.offset, add(944, shl(4, sub(h, 1))))),
                            HIGH_128
                        )
                    mstore(buf, or(base, or(shl(120, 2), or(shl(48, shr(1, leaf)), shl(40, h)))))
                    switch and(leaf, 1)
                    case 0 { mstore(add(buf, 32), or(node, shr(128, sibling))) }
                    default { mstore(add(buf, 32), or(sibling, shr(128, node))) }
                    node := and(keccak256(buf, 64), HIGH_128)
                    leaf := shr(1, leaf)
                }
                ok := 1
                root := node
            }
        }
    }
}
