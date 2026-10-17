// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PQWithdrawal} from "../../src/PQWithdrawal.sol";

/// The Halmos proof that the system call never reverts (QueueFV.check_systemCall_*) assumes
/// INV: head <= tail, and excess (if not the inhibitor) + count < 2^256. Contract code keeps INV
/// from deployment; only a genesis `alloc` can break it. These show what breaks if it does:
/// a reverting end-of-block system call makes every block invalid.
contract QueuePreconditionsTest is Test {
    address internal constant SYS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;

    function test_Genesis_HeadAboveTailMakesSystemCallRevert() public {
        address q = address(new PQWithdrawal());
        vm.store(q, bytes32(uint256(2)), bytes32(uint256(1))); // head 1, tail 0
        vm.prank(SYS);
        (bool ok, bytes memory ret) = q.call("");
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSignature("Panic(uint256)", 0x11));
    }

    function test_Genesis_ExcessPlusCountOverflowMakesSystemCallRevert() public {
        address q = address(new PQWithdrawal());
        vm.store(q, bytes32(0), bytes32(type(uint256).max - 1)); // not the inhibitor
        vm.store(q, bytes32(uint256(1)), bytes32(uint256(2)));
        vm.prank(SYS);
        (bool ok,) = q.call("");
        assertFalse(ok);
    }
}
