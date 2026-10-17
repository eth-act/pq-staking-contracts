// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {console} from "forge-std/console.sol";
import {SystemCallTest} from "../helpers/SystemCallTest.sol";
import {PQWithdrawal} from "../../src/PQWithdrawal.sol";
import {PQConsolidation} from "../../src/PQConsolidation.sol";

/// Spams `n` requests in one call, paying `fee` each (fee is constant within a block).
contract Spammer {
    function spam(address target, uint256 n, uint256 fee, bytes calldata input) external payable {
        for (uint256 i; i < n; i++) {
            (bool ok,) = target.call{value: fee}(input);
            require(ok);
        }
    }
}

/// Red team (rt-queue) PoC: SystemRequestQueue documents "Reverts carry no data"
/// (SystemRequestQueue.sol:6, README "reverts carry no data"), but once `excess` reaches 2893 the
/// checked arithmetic in `_fakeExponential` panics, so the fee getter and every request revert
/// with `Panic(0x11)` (36 bytes of returndata). `excess` >= 2893 is reachable from a clean state
/// in a single block of 1-wei requests (2895 withdrawal requests).
/// These tests assert the documented behavior and FAIL on commit 2e7d21f.
contract RedteamRevertDataPoC is SystemCallTest {
    function test_PoC_FeeOverflowRevertCarriesNoData() public {
        PQWithdrawal w = new PQWithdrawal();
        address t = address(w);
        systemCall(t); // clear the inhibitor: excess = 0, fee = 1 wei

        // One block: 2895 requests at 1 wei each; excess after the system call = 2895 - 2.
        Spammer s = new Spammer();
        uint256 n = 2895;
        vm.deal(address(this), n);
        uint256 g = gasleft();
        s.spam{value: n}(t, n, 1, abi.encodePacked(uint64(1), uint64(0)));
        console.log("gas for 2895 requests (fresh queue slots):", g - gasleft());
        // Drain and update excess as the end-of-block system call does.
        systemCall(t);
        assertEq(uint256(vm.load(t, 0)), 2893);

        (bool ok, bytes memory out) = t.call("");
        assertFalse(ok, "fee getter reverts");
        assertEq(out.length, 0, "documented: reverts carry no data");
    }

    function test_PoC_RequestRevertCarriesNoData() public {
        PQConsolidation c = new PQConsolidation();
        address t = address(c);
        vm.store(t, 0, bytes32(uint256(2893)));
        vm.deal(address(this), 1 ether);
        (bool ok, bytes memory out) = t.call{value: 1 ether}(abi.encodePacked(uint64(1), uint64(2)));
        assertFalse(ok);
        assertEq(out.length, 0, "documented: reverts carry no data");
    }
}
