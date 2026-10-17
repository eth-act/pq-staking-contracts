// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SystemCallTest} from "../helpers/SystemCallTest.sol";
import {PQWithdrawal} from "../../src/PQWithdrawal.sol";
import {PQConsolidation} from "../../src/PQConsolidation.sol";
import {PQValidatorRegistration} from "../../src/PQValidatorRegistration.sol";

/// Exhaustive check of the fee getter (compiled bytecode) against the EIP-7002 reference
/// `fake_exponential(1, excess, 17)` computed with unbounded integers by fee_table.py, for EVERY
/// excess value at which the 256-bit loop does not overflow, plus the overflow boundary.
contract FeeExhaustiveTest is SystemCallTest {
    string internal json;
    uint256 internal threshold;

    function setUp() public {
        json = vm.readFile("test/fv/fee_table.json");
        threshold = vm.parseJsonUint(json, ".threshold");
    }

    function _setExcess(address q, uint256 e) internal {
        vm.store(q, bytes32(uint256(0)), bytes32(e));
    }

    function _checkAll(address q) internal {
        string[] memory fees = vm.parseJsonStringArray(json, ".fees");
        assertEq(fees.length, threshold);
        for (uint256 e; e < threshold; e++) {
            _setExcess(q, e);
            assertEq(feeOf(q), vm.parseUint(fees[e]), "fee mismatch");
        }
        // At and beyond the overflow boundary the getter reverts.
        for (uint256 e = threshold; e < threshold + 2000; e++) {
            _setExcess(q, e);
            (bool ok,) = q.call("");
            assertFalse(ok);
        }
        uint256[4] memory big = [uint256(2 ** 64), 2 ** 128, 2 ** 255, type(uint256).max - 1];
        for (uint256 k; k < big.length; k++) {
            _setExcess(q, big[k]);
            (bool ok,) = q.call("");
            assertFalse(ok);
        }
    }

    function test_FeeTableWithdrawal() public {
        _checkAll(address(new PQWithdrawal()));
    }

    function test_FeeTableConsolidation() public {
        _checkAll(address(new PQConsolidation()));
    }

    function test_FeeTableRegistration() public {
        _checkAll(address(new PQValidatorRegistration()));
    }

    /// PoC: README/natspec say "Reverts carry no data". At excess >= threshold (2893) the fee
    /// getter and every request revert with Panic(0x11) instead. One block of threshold + 2
    /// requests at the 1-wei fee reaches that state from excess 0.
    function test_PoC_PanicRevertDataReachableInOneBlock() public {
        address q = address(new PQWithdrawal());
        systemCall(q); // clear inhibitor, excess 0, fee 1 wei

        // First burst on never-used queue slots (fresh chain).
        uint256 n = threshold + 2;
        vm.cool(q);
        uint256 gFresh = gasleft();
        for (uint256 i; i < n; i++) {
            (bool ok_,) = q.call{value: 1}(abi.encodePacked(uint64(i), uint64(0)));
            assertTrue(ok_);
        }
        emit log_named_uint("burst gas, fresh queue slots", gFresh - gasleft());
        for (uint256 b; b < (n + 15) / 16; b++) {
            systemCall(q);
        }
        // Let excess decay back to 0.
        while (feeOf(q) > 1 || uint256(vm.load(q, 0)) > 0) systemCall(q);

        // The burst: n requests in ONE block, all paying the 1-wei fee.
        vm.cool(q); // all queue slots cold, as in a fresh transaction
        uint256 g0 = gasleft();
        for (uint256 i; i < n; i++) {
            (bool ok_,) = q.call{value: 1}(abi.encodePacked(uint64(i), uint64(0)));
            assertTrue(ok_);
        }
        uint256 burstGas = g0 - gasleft();
        emit log_named_uint("requests in burst", n);
        emit log_named_uint("burst gas (cold slots, one batched tx, excl. 21k base)", burstGas);
        emit log_named_uint("burst cost in fees (wei)", n);

        systemCall(q);
        assertEq(uint256(vm.load(q, 0)), threshold);

        (bool ok, bytes memory ret) = q.call("");
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSignature("Panic(uint256)", 0x11), "getter revert data");

        (ok, ret) = q.call{value: 1000 ether}(abi.encodePacked(uint64(1), uint64(0)));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSignature("Panic(uint256)", 0x11), "request revert data");

        // Excess decays by target (2) per block; count the blocks with a data-carrying revert.
        uint256 blocks;
        while (true) {
            systemCall(q);
            blocks++;
            (ok,) = q.call("");
            if (ok) break;
        }
        emit log_named_uint("blocks until the getter stops panicking", blocks);
    }
}
