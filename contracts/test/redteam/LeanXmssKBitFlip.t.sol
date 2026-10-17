// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {LeanXmssK} from "../../src/LeanXmssK.sol";

contract BitFlipHarness {
    function verify(bytes32 pubkey, uint32 slot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        return LeanXmssK.verify(pubkey, slot, message, sig);
    }
}

/// Exhaustive single-bit malleability check on the committed reference vectors: flipping any
/// one of the 2400*8 signature bits, 256 pubkey bits, 256 message bits or 32 slot bits of a
/// valid (pubkey, slot, message, signature) must make verification fail.
contract LeanXmssKBitFlipTest is Test {
    BitFlipHarness internal h;
    bytes32 internal pubkey;
    bytes32 internal message;
    uint32 internal slot;
    bytes internal sig;

    function setUp() public {
        h = new BitFlipHarness();
        string memory json = vm.readFile("test/vectors/leanxmss_k.json");
        pubkey = vm.parseJsonBytes32(json, ".pubkeyA");
        message = vm.parseJsonBytes32(json, ".message");
        slot = uint32(vm.parseJsonUint(json, ".genericSlot"));
        sig = vm.parseJsonBytes(json, ".genericSlotSignature");
        assertTrue(h.verify(pubkey, slot, message, sig));
    }

    function test_EverySignatureBitFlipRejected() public view {
        bytes memory s = sig;
        for (uint256 bit; bit < 2400 * 8; bit++) {
            bytes1 mask = bytes1(uint8(0x80) >> (bit % 8));
            s[bit / 8] ^= mask;
            assertFalse(h.verify(pubkey, slot, message, s), vm.toString(bit));
            s[bit / 8] ^= mask;
        }
    }

    function test_EveryPubkeyMessageSlotBitFlipRejected() public view {
        for (uint256 bit; bit < 256; bit++) {
            bytes32 mask = bytes32(uint256(1) << bit);
            assertFalse(h.verify(pubkey ^ mask, slot, message, sig));
            assertFalse(h.verify(pubkey, slot, message ^ mask, sig));
        }
        for (uint256 bit; bit < 32; bit++) {
            assertFalse(h.verify(pubkey, slot ^ uint32(1 << bit), message, sig));
        }
    }
}
