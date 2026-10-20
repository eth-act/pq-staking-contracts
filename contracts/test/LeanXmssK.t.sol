// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {LeanXmssK} from "../src/LeanXmssK.sol";

contract LeanXmssKHarness {
    function verify(bytes32 pubkey, uint32 slot, bytes32 message, bytes calldata signature)
        external
        pure
        returns (bool)
    {
        return LeanXmssK.verify(pubkey, slot, message, signature);
    }
}

/// Signatures come from the Python reference (xmss/gen_vectors.py), so these tests check the
/// Solidity verifier against an independent implementation of the spec.
contract LeanXmssKTest is Test {
    LeanXmssKHarness internal harness;
    string internal json;

    bytes32 internal pubkeyA;
    bytes32 internal pubkeyB;
    bytes32 internal message;
    uint32 internal lastSlot;
    uint32 internal genericSlot;
    bytes internal lastSig;
    bytes internal genericSig;

    function setUp() public {
        harness = new LeanXmssKHarness();
        json = vm.readFile("test/vectors/leanxmss_k.json");
        pubkeyA = vm.parseJsonBytes32(json, ".pubkeyA");
        pubkeyB = vm.parseJsonBytes32(json, ".pubkeyB");
        message = vm.parseJsonBytes32(json, ".message");
        lastSlot = uint32(vm.parseJsonUint(json, ".lastSlot"));
        genericSlot = uint32(vm.parseJsonUint(json, ".genericSlot"));
        lastSig = vm.parseJsonBytes(json, ".lastSlotSignature");
        genericSig = vm.parseJsonBytes(json, ".genericSlotSignature");
    }

    function test_AcceptsReferenceSignatures() public view {
        assertTrue(harness.verify(pubkeyA, lastSlot, message, lastSig));
        assertTrue(harness.verify(pubkeyA, genericSlot, message, genericSig));
    }

    function test_RejectsWrongSlot() public view {
        assertFalse(harness.verify(pubkeyA, genericSlot, message, lastSig));
        assertFalse(harness.verify(pubkeyA, lastSlot, message, genericSig));
        // Same top leaf, different bottom leaf.
        assertFalse(harness.verify(pubkeyA, genericSlot + 1, message, genericSig));
    }

    function test_RejectsWrongMessage() public view {
        assertFalse(harness.verify(pubkeyA, lastSlot, keccak256("other"), lastSig));
    }

    function test_RejectsWrongPubkey() public view {
        assertFalse(harness.verify(pubkeyB, lastSlot, message, lastSig));
        // Same root, different public seed.
        assertFalse(harness.verify(pubkeyA ^ bytes32(uint256(1)), lastSlot, message, lastSig));
    }

    /// One flipped bit in each field of each layer must invalidate the signature.
    function test_RejectsTamperedFields() public view {
        // rho, first chain value, last chain value, first auth node, last auth node.
        uint256[5] memory offsets = [uint256(0), 16, 16 + 57 * 16, 944, 1199];
        for (uint256 layer; layer < 2; layer++) {
            for (uint256 f; f < offsets.length; f++) {
                bytes memory sig = bytes.concat(lastSig);
                sig[layer * 1200 + offsets[f]] ^= 0x01;
                assertFalse(harness.verify(pubkeyA, lastSlot, message, sig));
            }
        }
    }

    function test_RejectsWrongLength() public view {
        assertFalse(harness.verify(pubkeyA, lastSlot, message, bytes.concat(lastSig, hex"00")));
        bytes memory short = new bytes(2399);
        for (uint256 i; i < short.length; i++) {
            short[i] = lastSig[i];
        }
        assertFalse(harness.verify(pubkeyA, lastSlot, message, short));
    }
}
