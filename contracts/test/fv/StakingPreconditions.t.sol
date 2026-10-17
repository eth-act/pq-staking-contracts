// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {PQStaking} from "../../src/PQStaking.sol";

/// Concrete demonstrations of the preconditions the Halmos proofs (StakingFV) rely on. None is
/// reachable on a correctly configured chain; each shows what breaks if the precondition fails.
contract StakingPreconditionsTest is Test {
    /// P1: msg.value < 2^64 gwei (~18.4e9 ETH). Above it `uint64(msg.value / 1 gwei)` wraps and
    /// the event under-reports the deposit. Unreachable: total ETH supply is ~1.2e8 ETH.
    function test_P1_AmountWrapsAbove2pow64Gwei() public {
        PQStaking s = new PQStaking(0);
        uint256 value = (uint256(1) << 64) * 1 gwei + 1 ether;
        vm.deal(address(this), value);
        vm.recordLogs();
        s.stake{value: value}(bytes32(uint256(1)), bytes32(0));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (,, uint64 amountGwei) = abi.decode(logs[0].data, (bytes32, bytes32, uint64));
        assertEq(amountGwei, 1e9, "event says 1 ETH");
        assertEq(address(s).balance, value);
    }

    /// P2: genesis slot 0 must be (N << 64) | N with N < 2^40. With eventCount < initialEventCount
    /// new stake IDs collide with migrated validator indices.
    function test_P2_GenesisEventCountBelowPrefixCollides() public {
        PQStaking s = new PQStaking(0);
        vm.store(address(s), bytes32(0), bytes32(uint256(5))); // initial 5, eventCount 0
        vm.deal(address(this), 1 ether);
        uint64 id = s.stake{value: 1 ether}(bytes32(uint256(1)), bytes32(0));
        assertEq(id, 0, "new stake reuses migrated validator index 0");
    }

    /// P2': with N >= 2^40 written at genesis (the constructor rejects it, genesis does not),
    /// every stake and top-up reverts forever.
    function test_P2_GenesisPrefixAtCapacityBricks() public {
        PQStaking s = new PQStaking(0);
        uint256 n = 2 ** 40;
        vm.store(address(s), bytes32(0), bytes32((n << 64) | n));
        vm.deal(address(this), 2 ether);
        vm.expectRevert(PQStaking.EventTreeFull.selector);
        s.stake{value: 1 ether}(bytes32(uint256(1)), bytes32(0));
        vm.expectRevert(PQStaking.EventTreeFull.selector);
        s.topup{value: 1 ether}(0);
    }
}
