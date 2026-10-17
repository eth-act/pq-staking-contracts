// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {LeanXmssK} from "../../src/LeanXmssK.sol";

/// Calls LeanXmssK.verify in three environments that must not change the result:
/// plain calldata, a slice embedded in junk calldata, and dirty memory past the free pointer.
contract DiffHarness {
    function verify(bytes32 pubkey, uint32 slot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        return LeanXmssK.verify(pubkey, slot, message, sig);
    }

    /// `sig` is `data[off:off+len]`, with arbitrary bytes before and after it in calldata.
    function verifyEmbedded(
        bytes32 pubkey,
        uint32 slot,
        bytes32 message,
        bytes calldata data,
        uint256 off,
        uint256 len
    ) external pure returns (bool) {
        return LeanXmssK.verify(pubkey, slot, message, data[off:off + len]);
    }

    /// Fills 4 KiB past the free pointer with junk, verifies, then checks that the free pointer,
    /// the zero slot, the scratch-independent allocated sentinel and all memory below the free
    /// pointer are unchanged.
    function verifyDirty(
        bytes32 pubkey,
        uint32 slot,
        bytes32 message,
        bytes calldata sig,
        bytes32 junk
    ) external pure returns (bool ok) {
        bytes memory sentinel = new bytes(256);
        for (uint256 i; i < 256; i += 32) {
            bytes32 w = keccak256(abi.encode(junk, i));
            assembly ("memory-safe") {
                mstore(add(add(sentinel, 32), i), w)
            }
        }
        bytes32 sentinelHash = keccak256(sentinel);
        uint256 fpBefore;
        bytes32 belowHash;
        assembly ("memory-safe") {
            fpBefore := mload(0x40)
            for { let p := 0 } lt(p, 4096) { p := add(p, 32) } {
                mstore(add(fpBefore, p), xor(junk, p))
            }
            // Everything from 0x80 to the free pointer.
            belowHash := keccak256(0x80, sub(fpBefore, 0x80))
        }
        ok = LeanXmssK.verify(pubkey, slot, message, sig);
        uint256 fpAfter;
        bytes32 belowAfter;
        uint256 zeroSlot;
        assembly ("memory-safe") {
            fpAfter := mload(0x40)
            belowAfter := keccak256(0x80, sub(fpBefore, 0x80))
            zeroSlot := mload(0x60)
        }
        require(fpAfter == fpBefore, "free pointer moved");
        require(belowAfter == belowHash, "memory below free pointer changed");
        require(zeroSlot == 0, "zero slot written");
        require(keccak256(sentinel) == sentinelHash, "sentinel changed");
    }
}

/// Differential test: every record's `expected` was computed by xmss/leanxmss_k.py `verify`
/// (see redteam/gen_diff.py). Any disagreement reverts with the file and record index.
contract LeanXmssKDiffTest is Test {
    uint256 internal constant RECORD = 32 + 4 + 32 + 2400 + 1;

    DiffHarness internal harness;

    function setUp() public {
        harness = new DiffHarness();
    }

    function test_Diff_Mixed() public {
        _runSet("rt-xmss");
    }

    function test_Diff_ExhaustiveLeafIndices() public {
        _runSet("exhaustive");
    }

    function _runSet(string memory prefix) internal {
        uint256 total;
        uint256 valid;
        for (uint256 f;; f++) {
            string memory path =
                string.concat("test/vectors/redteam/", prefix, "_", vm.toString(f), ".bin");
            if (!vm.exists(path)) break;
            (uint256 n, uint256 v) = this.runFile(path);
            total += n;
            valid += v;
        }
        assertGt(total, 0, "no vectors");
        emit log_named_uint("records", total);
        emit log_named_uint("expected valid", valid);
    }

    function runFile(string memory path) external view returns (uint256 n, uint256 valid) {
        bytes memory blob = vm.readFileBinary(path);
        require(blob.length % RECORD == 0, "bad file");
        n = blob.length / RECORD;
        bytes memory sig = new bytes(2400);
        bytes memory embedded = new bytes(2400 + 200);
        for (uint256 r; r < n; r++) {
            bytes32 pubkey;
            uint32 slot;
            bytes32 message;
            bool expected;
            assembly ("memory-safe") {
                let p := add(add(blob, 32), mul(r, RECORD))
                pubkey := mload(p)
                slot := shr(224, mload(add(p, 32)))
                message := mload(add(p, 36))
                mcopy(add(sig, 32), add(p, 68), 2400)
                expected := byte(0, mload(add(p, 2468)))
            }
            if (expected) valid++;
            require(harness.verify(pubkey, slot, message, sig) == expected, _err(path, r, "plain"));

            // Junk before and after the slice (lengths 0..99 each), derived from the record.
            bytes32 seed = keccak256(abi.encode(path, r));
            uint256 pre = uint256(seed) % 100;
            for (uint256 i; i < embedded.length; i += 32) {
                bytes32 w = keccak256(abi.encode(seed, i));
                assembly ("memory-safe") {
                    mstore(add(add(embedded, 32), i), w)
                }
            }
            assembly ("memory-safe") {
                mcopy(add(add(embedded, 32), pre), add(sig, 32), 2400)
                // Trim to pre + 2400 + suffix (suffix 0..99).
                mstore(embedded, add(add(pre, 2400), mod(shr(128, seed), 100)))
            }
            require(
                harness.verifyEmbedded(pubkey, slot, message, embedded, pre, 2400) == expected,
                _err(path, r, "embedded")
            );
            assembly ("memory-safe") {
                mstore(embedded, 2600)
            }
            require(
                harness.verifyDirty(pubkey, slot, message, sig, seed) == expected,
                _err(path, r, "dirty")
            );
        }
    }

    function _err(string memory path, uint256 r, string memory mode)
        internal
        pure
        returns (string memory)
    {
        return string.concat("mismatch ", mode, " ", path, " record ", vm.toString(r));
    }
}
