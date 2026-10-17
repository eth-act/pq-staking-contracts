// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PQWithdrawal} from "../../../src/PQWithdrawal.sol";
import {PQConsolidation} from "../../../src/PQConsolidation.sol";
import {PQValidatorRegistration} from "../../../src/PQValidatorRegistration.sol";

/// Red team (rt-queue): symbolic (halmos) functional spec of one call into each system contract
/// from an arbitrary pre-state (head <= tail, small queue), arbitrary caller, value and calldata
/// (lengths from --default-bytes-lengths). Every outcome is compared with the EIP-7002 spec
/// adapted to the documented formats. Run:
///   halmos --contract RedteamDispatchSym --loop 20 \
///     --default-bytes-lengths 0,1,4,15,16,17,32,36,56,64,2439,2441
contract RedteamDispatchSym is Test {
    address internal constant SYSTEM = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;
    uint256 internal constant INH = type(uint256).max;

    PQWithdrawal internal w;
    PQConsolidation internal c;
    PQValidatorRegistration internal r;

    function setUp() public {
        w = new PQWithdrawal();
        c = new PQConsolidation();
        r = new PQValidatorRegistration();
    }

    /// Concrete excess choices (the fee loop needs concrete excess) with reference fees from
    /// EIP-7002 fake_exponential(1, e, 17): 0 -> 1, 17 -> 2, 100 -> 357, INH -> inhibitor.
    function pickExcess(uint8 sel) internal pure returns (uint256 e, uint256 fee) {
        sel = sel % 4;
        if (sel == 0) return (0, 1);
        if (sel == 1) return (17, 2);
        if (sel == 2) return (100, 357);
        return (INH, 0);
    }

    struct Pre {
        uint256 excess;
        uint256 fee;
        uint256 count;
        uint256 head;
        uint256 tail;
    }

    /// Queue shapes (head, tail). Concrete so that output sizes are concrete for halmos; each is
    /// explored with symbolic caller, value, calldata, count and the excess choices above.
    function queueShape(uint8 q) internal pure returns (uint256, uint256) {
        q = q % 6;
        if (q == 0) return (0, 0); // empty
        if (q == 1) return (0, 1);
        if (q == 2) return (0, 2);
        if (q == 3) return (5, 8); // mid-queue
        if (q == 4) return (0, 17); // more than any max per block
        return (2 ** 64 - 40, 2 ** 64 - 3); // high indices, 37 queued
    }

    function setState(address t, uint8 sel, uint256 cnt, uint8 q)
        internal
        returns (Pre memory p)
    {
        (p.excess, p.fee) = pickExcess(sel);
        (p.head, p.tail) = queueShape(q);
        vm.assume(cnt < 2 ** 64);
        p.count = cnt;
        vm.store(t, bytes32(uint256(0)), bytes32(p.excess));
        vm.store(t, bytes32(uint256(1)), bytes32(cnt));
        vm.store(t, bytes32(uint256(2)), bytes32(p.head));
        vm.store(t, bytes32(uint256(3)), bytes32(p.tail));
    }

    function slot(address t, uint256 i) internal view returns (uint256) {
        return uint256(vm.load(t, bytes32(i)));
    }

    function checkSystemCall(address t, Pre memory p, uint256 maxPer, uint256 target_,
        uint256 recLen, bool ok, bytes memory out) internal view {
        assertTrue(ok, "system call must not revert");
        uint256 n = p.tail - p.head;
        if (n > maxPer) n = maxPer;
        assertEq(out.length, recLen * n, "output length");
        if (p.head + n == p.tail) {
            assertEq(slot(t, 2), 0);
            assertEq(slot(t, 3), 0);
        } else {
            assertEq(slot(t, 2), p.head + n);
            assertEq(slot(t, 3), p.tail);
        }
        uint256 prev = p.excess == INH ? 0 : p.excess;
        assertEq(slot(t, 0), prev + p.count > target_ ? prev + p.count - target_ : 0, "excess");
        assertEq(slot(t, 1), 0, "count reset");
    }

    function checkUnchanged(address t, Pre memory p) internal view {
        assertEq(slot(t, 0), p.excess);
        assertEq(slot(t, 1), p.count);
        assertEq(slot(t, 2), p.head);
        assertEq(slot(t, 3), p.tail);
    }

    function call16(address t, address caller, uint256 value, bytes memory data)
        internal
        returns (bool ok, bytes memory out)
    {
        vm.deal(caller, value);
        vm.prank(caller);
        (ok, out) = t.call{value: value}(data);
    }

    /// PQWithdrawal / PQConsolidation share this spec up to the stake-id checks and targets.
    function checkPair(address t, bool consolidation, address caller, uint256 value,
        bytes memory data, uint8 sel, uint256 cnt, uint8 q) internal {
        Pre memory p = setState(t, sel, cnt, q);
        (bool ok, bytes memory out) = call16(t, caller, value, data);
        if (caller == SYSTEM) {
            checkSystemCall(t, p, consolidation ? 2 : 16, consolidation ? 1 : 2, 36, ok, out);
            return;
        }
        if (data.length == 0) {
            assertEq(ok, value == 0 && p.excess != INH, "fee getter success");
            if (ok) assertEq(out, abi.encode(p.fee));
            else assertEq(out.length, 0, "revert data");
            checkUnchanged(t, p);
            return;
        }
        assertEq(ok, p.excess != INH && value >= p.fee && idsOk(data, consolidation),
            "request success");
        assertEq(out.length, 0, "return/revert data");
        if (!ok) {
            checkUnchanged(t, p);
            return;
        }
        checkStored(t, p, caller, data);
    }

    function idsOk(bytes memory data, bool consolidation) internal pure returns (bool) {
        if (data.length != 16) return false;
        uint64 a = uint64(bytes8(bytes32(data)));
        uint64 b = uint64(bytes8(bytes32(data) << 64));
        return a < 2 ** 40 && (!consolidation || b < 2 ** 40);
    }

    function checkStored(address t, Pre memory p, address caller, bytes memory data)
        internal
        view
    {
        assertEq(slot(t, 0), p.excess);
        assertEq(slot(t, 1), p.count + 1);
        assertEq(slot(t, 2), p.head);
        assertEq(slot(t, 3), p.tail + 1);
        // Entry at mapping(slot 4)[tail]: slot0 = sender | a << 160, slot1 = b.
        uint256 base = uint256(keccak256(abi.encode(p.tail, uint256(4))));
        uint64 a = uint64(bytes8(bytes32(data)));
        uint64 b = uint64(bytes8(bytes32(data) << 64));
        assertEq(slot(t, base), uint256(uint160(caller)) | (uint256(a) << 160));
        assertEq(slot(t, base + 1), uint256(b));
    }

    function check_withdrawal(address caller, uint256 value, bytes memory data, uint8 sel,
        uint256 cnt, uint8 q) public {
        checkPair(address(w), false, caller, value, data, sel, cnt, q);
    }

    function check_consolidation(address caller, uint256 value, bytes memory data, uint8 sel,
        uint256 cnt, uint8 q) public {
        checkPair(address(c), true, caller, value, data, sel, cnt, q);
    }

    /// Registration: every calldata length other than 0 and 2440 reverts without data and
    /// without state change; length 0 is the fee getter; SYSTEM is the system call with empty
    /// queue entries (n records of 2440 bytes).
    function check_registration(address caller, uint256 value, bytes memory data, uint8 sel,
        uint256 cnt, uint8 q) public {
        vm.assume(data.length != 2440);
        address t = address(r);
        Pre memory p = setState(t, sel, cnt, q);
        (bool ok, bytes memory out) = call16(t, caller, value, data);
        if (caller == SYSTEM) {
            checkSystemCall(t, p, 16, 2, 2440, ok, out);
            return;
        }
        if (data.length == 0) {
            assertEq(ok, value == 0 && p.excess != INH);
            if (ok) assertEq(out, abi.encode(p.fee));
            else assertEq(out.length, 0);
        } else {
            assertFalse(ok, "non-2440 request must revert");
            assertEq(out.length, 0, "revert data");
        }
        checkUnchanged(t, p);
    }
}
