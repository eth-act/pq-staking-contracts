// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {console} from "forge-std/console.sol";
import {SystemCallTest} from "../helpers/SystemCallTest.sol";
import {PQWithdrawal} from "../../src/PQWithdrawal.sol";
import {PQConsolidation} from "../../src/PQConsolidation.sol";
import {PQValidatorRegistration} from "../../src/PQValidatorRegistration.sol";

/// Red team (rt-queue): gas of the end-of-block system call at maximum dequeue with all storage
/// cold (vm.cool), for both exits (queue drained -> reset; queue not drained -> head store),
/// each with count > 0 (excess changes) so every SSTORE in the path is non-trivial.
contract RedteamSystemCallGasTest is SystemCallTest {
    uint256 internal constant LIMIT = 30_000_000;

    function fill(address t, bytes memory input, uint256 n) internal {
        for (uint256 i; i < n; i++) {
            assertTrue(submit(t, input));
        }
    }

    function measure(address t) internal returns (uint256 used, uint256 len) {
        vm.cool(t);
        vm.prank(SYSTEM_ADDRESS);
        uint256 g = gasleft();
        (bool ok, bytes memory out) = t.call{gas: LIMIT}("");
        used = g - gasleft();
        assertTrue(ok);
        len = out.length;
    }

    function regInput() internal view returns (bytes memory) {
        string memory json = vm.readFile("test/vectors/leanxmss_k.json");
        return abi.encodePacked(
            uint64(vm.parseJsonUint(json, ".registrations[0].stakeId")),
            vm.parseJsonBytes32(json, ".registrations[0].pubkey"),
            vm.parseJsonBytes(json, ".registrations[0].signature")
        );
    }

    function run(string memory name, address t, bytes memory input, uint256 maxPer, uint256 rec)
        internal
    {
        systemCall(t); // clear inhibitor
        // Exit A: exactly maxPer queued -> drained -> head/tail reset to 0.
        fill(t, input, maxPer);
        (uint256 usedA, uint256 lenA) = measure(t);
        assertEq(lenA, maxPer * rec);
        // Exit B: maxPer + 1 queued -> head = maxPer.
        fill(t, input, maxPer + 1);
        (uint256 usedB, uint256 lenB) = measure(t);
        assertEq(lenB, maxPer * rec);
        console.log(name);
        console.log("  drained (reset) gas:", usedA);
        console.log("  partial (head++) gas:", usedB);
        assertLt(usedA, LIMIT);
        assertLt(usedB, LIMIT);
    }

    function test_GasWithdrawal() public {
        run("PQWithdrawal", address(new PQWithdrawal()), abi.encodePacked(uint64(1), uint64(2)),
            16, 36);
    }

    function test_GasConsolidation() public {
        run("PQConsolidation", address(new PQConsolidation()),
            abi.encodePacked(uint64(1), uint64(2)), 2, 36);
    }

    function test_GasRegistration() public {
        address t = address(0x7a11);
        vm.etch(t, address(new PQValidatorRegistration()).code);
        vm.store(t, 0, bytes32(type(uint256).max));
        run("PQValidatorRegistration", t, regInput(), 16, 2440);
    }
}
