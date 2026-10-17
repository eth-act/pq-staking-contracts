// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SystemCallTest} from "../helpers/SystemCallTest.sol";
import {LeanXmssK} from "../../src/LeanXmssK.sol";
import {PQValidatorRegistration} from "../../src/PQValidatorRegistration.sol";
import {PQBuilderRegistration} from "../../src/PQBuilderRegistration.sol";

contract FfiHarness {
    function verify(bytes32 pubkey, uint32 slot, bytes32 message, bytes calldata sig)
        external
        pure
        returns (bool)
    {
        return LeanXmssK.verify(pubkey, slot, message, sig);
    }
}

/// Fuzz differential against the Python reference via FFI (run with --ffi).
contract LeanXmssKFfiTest is SystemCallTest {
    string internal constant PY = "../xmss/.venv/bin/python";
    uint256 internal constant REQUEST_LENGTH = 2440;
    uint64 internal constant MAX_STAKE_ID = 2 ** 40 - 1;

    FfiHarness internal h;

    function setUp() public {
        h = new FfiHarness();
    }

    /// Fuzzer-chosen slot, message, public seed and body seed; odd `mutation` flips one bit.
    function testFuzz_DiffReference(
        uint32 slot,
        bytes32 message,
        bytes16 seedP,
        bytes32 seed,
        uint32 mutation
    ) public {
        string[] memory cmd = new string[](7);
        cmd[0] = PY;
        cmd[1] = "../redteam/ffi_case.py";
        cmd[2] = vm.toString(uint256(slot));
        cmd[3] = vm.toString(message);
        cmd[4] = vm.toString(abi.encodePacked(seedP));
        cmd[5] = vm.toString(seed);
        cmd[6] = vm.toString(uint256(mutation));
        (bytes32 pk, uint32 s, bytes32 m, bytes memory sig, bool expected) =
            abi.decode(vm.ffi(cmd), (bytes32, uint32, bytes32, bytes, bool));
        if (mutation & 1 == 0) assertTrue(expected, "unmutated case must be valid");
        assertEq(h.verify(pk, s, m, sig), expected);
    }

    function pop(uint256 keyIdx, uint256 chainId, address reg, uint64 stakeId)
        internal
        returns (bytes32 pk, bytes memory request)
    {
        string[] memory cmd = new string[](6);
        cmd[0] = PY;
        cmd[1] = "../redteam/ffi_pop.py";
        cmd[2] = vm.toString(keyIdx % 12);
        cmd[3] = vm.toString(chainId);
        cmd[4] = vm.toString(reg);
        cmd[5] = vm.toString(uint256(stakeId));
        bytes memory sig;
        bytes32 message;
        (pk, message, sig) = abi.decode(vm.ffi(cmd), (bytes32, bytes32, bytes));
        // Solidity-side message equals the reference pop_message.
        assertEq(
            keccak256(
                abi.encodePacked(
                    keccak256("leanXMSS-K registration proof of possession v1"),
                    chainId,
                    reg,
                    stakeId,
                    pk
                )
            ),
            message
        );
        request = abi.encodePacked(stakeId, pk, sig);
        assertEq(request.length, REQUEST_LENGTH);
    }

    function usable(address a) internal view returns (bool) {
        return uint160(a) > 0xffff && a != address(this) && a != address(vm) && a != address(h)
            && a != SYSTEM_ADDRESS && a.code.length == 0
            && a != 0x000000000000000000636F6e736F6c652e6c6f67;
    }

    /// End to end: a reference PoP for (chain, contract, stake) is accepted exactly there and
    /// rejected for another chain, another role contract, and another stake id.
    function testFuzz_PopBinding(
        uint8 keyIdx,
        uint64 chainId,
        address validators,
        address builders,
        uint64 stakeId,
        uint64 otherStake
    ) public {
        vm.assume(usable(validators) && usable(builders) && validators != builders);
        stakeId = uint64(bound(stakeId, 0, MAX_STAKE_ID));
        otherStake = uint64(bound(otherStake, 0, MAX_STAKE_ID));
        vm.assume(otherStake != stakeId);
        vm.etch(validators, address(new PQValidatorRegistration()).code);
        vm.etch(builders, address(new PQBuilderRegistration()).code);
        vm.chainId(chainId);

        (, bytes memory request) = pop(keyIdx, chainId, validators, stakeId);
        assertFalse(submit(builders, request), "replayed into other role");
        vm.chainId(chainId ^ 1);
        assertFalse(submit(validators, request), "replayed on other chain");
        vm.chainId(chainId);
        bytes memory moved = bytes.concat(bytes8(otherStake), _slice(request, 8));
        assertFalse(submit(validators, moved), "replayed onto other stake");
        assertTrue(submit(validators, request), "valid PoP rejected");
    }

    function test_StakeIdBoundary() public {
        address reg = address(0x7a11);
        vm.etch(reg, address(new PQValidatorRegistration()).code);
        (, bytes memory ok) = pop(0, block.chainid, reg, MAX_STAKE_ID);
        assertTrue(submit(reg, ok));
        // Valid proofs for stake ids above 40 bits are still rejected.
        (, bytes memory over) = pop(0, block.chainid, reg, MAX_STAKE_ID + 1);
        assertFalse(submit(reg, over));
        (, bytes memory max) = pop(0, block.chainid, reg, type(uint64).max);
        assertFalse(submit(reg, max));
    }

    /// Every calldata length in [1, 4880] other than 2440 reverts, even when it starts with
    /// (or truncates) a valid request.
    function test_EveryOtherLengthReverts() public {
        address reg = address(0x7a11);
        vm.etch(reg, address(new PQValidatorRegistration()).code);
        (, bytes memory request) = pop(1, block.chainid, reg, 7);
        bytes memory buf = bytes.concat(request, request);
        for (uint256 len = 1; len <= 2 * REQUEST_LENGTH; len++) {
            if (len == REQUEST_LENGTH) continue;
            assembly ("memory-safe") {
                mstore(buf, len)
            }
            assertFalse(submit(reg, buf), vm.toString(len));
        }
        assertTrue(submit(reg, request));
    }

    function _slice(bytes memory a, uint256 from) internal pure returns (bytes memory out) {
        out = new bytes(a.length - from);
        for (uint256 i; i < out.length; i++) {
            out[i] = a[i + from];
        }
    }
}
