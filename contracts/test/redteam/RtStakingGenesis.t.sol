// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {PQStaking} from "../../src/PQStaking.sol";

/// Genesis embedding: runtime bytecode + storage slot 0 per contracts/README.md must be
/// indistinguishable from a constructor deployment.
contract RtStakingGenesisTest is Test {
    string internal constant ART = "PQStaking.sol:PQStaking";

    function _deploy(bytes memory initcode) internal returns (address a) {
        assembly {
            a := create(0, add(initcode, 0x20), mload(initcode))
        }
    }

    /// The constructor's only state effects are the runtime code (== artifact
    /// deployedBytecode, which export-bytecode.sh publishes as .bin-runtime) and one write to
    /// slot 0 with value (N << 64) | N. Nothing else a genesis alloc would need to replicate.
    function testFuzz_ConstructorEffectsAreCodePlusSlot0(uint64 n) public {
        n = uint64(bound(n, 0, 2 ** 40 - 1));
        bytes memory initcode = abi.encodePacked(vm.getCode(ART), abi.encode(n));
        vm.startStateDiffRecording();
        address a = _deploy(initcode);
        Vm.AccountAccess[] memory diff = vm.stopAndReturnStateDiff();
        assertTrue(a != address(0));
        assertEq(a.code, vm.getDeployedCode(ART));

        uint256 writes;
        for (uint256 i; i < diff.length; ++i) {
            assertEq(diff[i].value, 0); // no ETH moved
            for (uint256 j; j < diff[i].storageAccesses.length; ++j) {
                Vm.StorageAccess memory sa = diff[i].storageAccesses[j];
                if (!sa.isWrite) continue;
                writes++;
                assertEq(sa.account, a);
                assertEq(sa.slot, bytes32(0));
                assertEq(uint256(sa.newValue), uint256(n) | (uint256(n) << 64));
            }
        }
        // The compiler writes slot 0 once per field (two read-modify-write SSTOREs).
        assertGt(writes, 0);
        assertEq(uint256(vm.load(a, bytes32(0))), uint256(n) | (uint256(n) << 64));
    }

    /// Initcode without the ABI-encoded uint64 (or with a non-canonical one) does not deploy.
    function test_InitcodeWithoutArgsFails() public {
        assertEq(_deploy(vm.getCode(ART)), address(0));
        assertEq(_deploy(abi.encodePacked(vm.getCode(ART), uint256(1) << 64)), address(0));
        assertEq(
            _deploy(abi.encodePacked(vm.getCode(ART), abi.encode(uint64(2 ** 40)))), address(0)
        );
    }

    /// Differential: constructor deployment vs etched runtime + README slot-0 value behave
    /// identically under a random operation sequence (return data, success, logs, storage).
    function testFuzz_GenesisEtchMatchesConstructor(uint64 n, uint256[16] memory ops) public {
        n = uint64(bound(n, 0, 2 ** 40 - 1));
        address a = _deploy(abi.encodePacked(vm.getCode(ART), abi.encode(n)));
        address b = makeAddr("genesis");
        vm.etch(b, vm.getDeployedCode(ART));
        vm.store(b, bytes32(0), bytes32(uint256(n) | (uint256(n) << 64)));
        assertEq(a.code, b.code);

        for (uint256 i; i < ops.length; ++i) {
            uint256 op = ops[i];
            bytes memory data;
            uint256 value =
                (op >> 8) % 3 == 0 ? 1 ether : ((op >> 8) % 3 == 1 ? 2 ether + 1 : 0.5 ether);
            if (op % 3 == 0) {
                data = abi.encodeCall(PQStaking.stake, (bytes32(op), bytes32(~op)));
            } else if (op % 3 == 1) {
                uint64 t = uint64(op >> 16) % (n + 4 + uint64(i));
                data = abi.encodeCall(PQStaking.topup, (t));
            } else {
                data = abi.encodeCall(PQStaking.isStake, (uint64(op >> 16) % (n + 4 + uint64(i))));
                value = 0;
            }
            vm.deal(address(this), 2 * value);
            vm.recordLogs();
            (bool okA, bytes memory retA) = a.call{value: value}(data);
            Vm.Log[] memory logsA = vm.getRecordedLogs();
            (bool okB, bytes memory retB) = b.call{value: value}(data);
            Vm.Log[] memory logsB = vm.getRecordedLogs();
            assertEq(okA, okB);
            assertEq(retA, retB);
            assertEq(logsA.length, logsB.length);
            for (uint256 j; j < logsA.length; ++j) {
                assertEq(logsA[j].data, logsB[j].data);
                assertEq(logsA[j].topics.length, logsB[j].topics.length);
                for (uint256 k; k < logsA[j].topics.length; ++k) {
                    assertEq(logsA[j].topics[k], logsB[j].topics[k]);
                }
            }
            assertEq(vm.load(a, bytes32(0)), vm.load(b, bytes32(0)));
        }
    }

    /// Hazard (not a contract bug): the contract trusts slot 0. If a genesis sets only the low
    /// half (initialEventCount = N, eventCount = 0), new stake IDs collide with migrated IDs.
    function test_GenesisMisconfigCollides() public {
        address b = makeAddr("badGenesis");
        vm.etch(b, vm.getDeployedCode(ART));
        vm.store(b, bytes32(0), bytes32(uint256(5))); // N = 5 but eventCount left 0
        vm.deal(address(this), 1 ether);
        uint64 id = PQStaking(b).stake{value: 1 ether}(bytes32(0), bytes32(0));
        assertEq(id, 0); // collides with migrated validator 0
    }

    /// The other exported contracts: deployed code == artifact runtime, and their only
    /// constructor write is slot 0 = 2^256 - 1 (the inhibitor), as README documents.
    function test_SystemContractsConstructorEffects() public {
        string[4] memory names = [
            "PQWithdrawal.sol:PQWithdrawal",
            "PQConsolidation.sol:PQConsolidation",
            "PQValidatorRegistration.sol:PQValidatorRegistration",
            "PQBuilderRegistration.sol:PQBuilderRegistration"
        ];
        for (uint256 i; i < names.length; ++i) {
            vm.startStateDiffRecording();
            address a = _deploy(vm.getCode(names[i]));
            Vm.AccountAccess[] memory diff = vm.stopAndReturnStateDiff();
            assertTrue(a != address(0));
            assertEq(a.code, vm.getDeployedCode(names[i]));
            for (uint256 k; k < diff.length; ++k) {
                for (uint256 j; j < diff[k].storageAccesses.length; ++j) {
                    Vm.StorageAccess memory sa = diff[k].storageAccesses[j];
                    if (!sa.isWrite) continue;
                    assertEq(sa.slot, bytes32(0));
                    assertEq(sa.newValue, bytes32(type(uint256).max));
                }
            }
        }
    }
}
