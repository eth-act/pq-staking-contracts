// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SystemCallTest} from "../helpers/SystemCallTest.sol";
import {PQWithdrawal} from "../../src/PQWithdrawal.sol";
import {PQConsolidation} from "../../src/PQConsolidation.sol";
import {PQValidatorRegistration} from "../../src/PQValidatorRegistration.sol";

/// Red team (rt-queue): exhaustive fee check of the deployed bytecode against the EIP-7002
/// reference `fake_exponential(1, excess, 17)`, computed in arbitrary precision by
/// /tmp/pq-redteam/rt-queue/fee_exhaustive.py into test/vectors/rt_fee_table.txt.
contract RedteamQueueFeeTest is SystemCallTest {
    /// First excess at which the checked-arithmetic loop overflows (fee_exhaustive.py).
    uint256 internal constant E_OVERFLOW = 2893;
    /// From here on the reference value itself (pre-division) exceeds 2**256 - 1, so any
    /// non-reverting uint256 implementation is impossible; revert is the only option.
    uint256 internal constant E2 = 2969;

    address[3] internal targets;

    function setUp() public {
        targets[0] = address(new PQWithdrawal());
        targets[1] = address(new PQConsolidation());
        targets[2] = address(new PQValidatorRegistration());
    }

    function setExcess(address t, uint256 e) internal {
        vm.store(t, bytes32(uint256(0)), bytes32(e));
    }

    /// Every excess in [0, E_OVERFLOW): fee getter == reference. [E_OVERFLOW, E2]: reverts.
    function test_FeeGetterMatchesReferenceExhaustively() public {
        string memory path = "test/vectors/rt_fee_table.txt";
        for (uint256 e; e < E_OVERFLOW; e++) {
            uint256 expected = vm.parseUint(string.concat("0x", vm.readLine(path)));
            for (uint256 k; k < 3; k++) {
                setExcess(targets[k], e);
                (bool ok, bytes memory out) = targets[k].staticcall("");
                assertTrue(ok, "fee getter reverted below overflow");
                assertEq(out.length, 32);
                assertEq(abi.decode(out, (uint256)), expected, "fee mismatch");
            }
        }
        for (uint256 e = E_OVERFLOW; e <= E2; e++) {
            for (uint256 k; k < 3; k++) {
                setExcess(targets[k], e);
                (bool ok, bytes memory out) = targets[k].staticcall("");
                assertFalse(ok, "fee getter should revert at overflow");
                // Revert data is Panic(0x11); see RedteamRevertDataPoC for the doc mismatch.
                assertEq(out, abi.encodeWithSelector(0x4e487b71, uint256(0x11)));
            }
        }
    }

    /// Above E2 (monotonicity argument in fee_exhaustive.py): fuzz confirms the fee getter and
    /// requests revert (no wrap-around to a cheap fee as with unchecked math).
    /// Revert data is Panic(0x11), not empty: see RedteamRevertDataPoC.
    function testFuzz_FeeRevertsAboveOverflow(uint256 e, uint64 stakeId, uint64 amount) public {
        e = bound(e, E_OVERFLOW, type(uint256).max - 1);
        stakeId = uint64(bound(stakeId, 0, 2 ** 40 - 1));
        address t = targets[0];
        setExcess(t, e);
        (bool ok, bytes memory out) = t.staticcall("");
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(0x4e487b71, uint256(0x11)));
        vm.deal(address(this), type(uint128).max);
        (ok, out) = t.call{value: type(uint128).max}(abi.encodePacked(stakeId, amount));
        assertFalse(ok);
        assertEq(out, abi.encodeWithSelector(0x4e487b71, uint256(0x11)));
    }

    /// Inhibitor: fee getter and requests revert (no data) for any value; the system call clears it.
    function testFuzz_Inhibitor(uint256 value, uint64 stakeId) public {
        stakeId = uint64(bound(stakeId, 0, 2 ** 40 - 1));
        value = bound(value, 0, type(uint128).max);
        vm.deal(address(this), value);
        for (uint256 k; k < 2; k++) {
            address t = targets[k];
            assertEq(uint256(vm.load(t, 0)), type(uint256).max);
            (bool ok, bytes memory out) = t.call("");
            assertFalse(ok);
            assertEq(out.length, 0);
            (ok, out) = t.call{value: value}(abi.encodePacked(stakeId, stakeId));
            assertFalse(ok);
            assertEq(out.length, 0);
            systemCall(t);
            assertEq(uint256(vm.load(t, 0)), 0, "inhibitor treated as 0, count 0 -> excess 0");
            assertEq(feeOf(t), 1);
        }
    }

    /// Fee getter with any nonzero value reverts; with zero value from any sender returns the fee.
    function testFuzz_FeeGetterValue(address sender, uint256 value, uint16 e) public {
        vm.assume(sender != SYSTEM_ADDRESS);
        e = uint16(bound(e, 0, E_OVERFLOW - 1));
        address t = targets[0];
        setExcess(t, e);
        vm.deal(sender, type(uint256).max);
        vm.prank(sender);
        (bool ok, bytes memory out) = t.call{value: value}("");
        if (value == 0) {
            assertTrue(ok);
            assertEq(out.length, 32);
        } else {
            assertFalse(ok);
            assertEq(out.length, 0);
        }
    }

    /// Payment boundary: fee - 1 reverts, any value >= fee is accepted and kept in full.
    function testFuzz_PaymentBoundary(uint16 e, uint256 extra, uint64 stakeId) public {
        e = uint16(bound(e, 0, 1000));
        extra = bound(extra, 0, type(uint128).max);
        stakeId = uint64(bound(stakeId, 0, 2 ** 40 - 1));
        address t = targets[0];
        setExcess(t, e);
        uint256 fee = feeOf(t);
        vm.deal(address(this), fee + extra);
        bytes memory input = abi.encodePacked(stakeId, uint64(0));
        (bool ok,) = t.call{value: fee - 1}(input);
        assertFalse(ok);
        uint256 before = t.balance;
        (ok,) = t.call{value: fee + extra}(input);
        assertTrue(ok);
        assertEq(t.balance - before, fee + extra, "overpayment kept, not refunded");
    }
}
