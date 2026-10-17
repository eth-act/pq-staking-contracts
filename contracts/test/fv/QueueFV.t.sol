// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {SymTest} from "./Svm.sol";
import {PQWithdrawal} from "../../src/PQWithdrawal.sol";
import {PQConsolidation} from "../../src/PQConsolidation.sol";

/// Halmos specs for SystemRequestQueue through its two 16-byte instances, run on the compiled
/// runtime bytecode. Each check starts from an ARBITRARY storage state (symbolic storage)
/// constrained only by the reachable-state invariant INV below, executes ONE call, and asserts
/// the EIP-7002-style post-state, return data and revert behavior. Together they form an
/// inductive proof that INV is preserved and every call matches the spec.
///
/// INV (reachable-state invariant):
///   head <= tail < 2^64, count <= tail - head, count < 2^64,
///   excess == 2^256-1 (inhibitor) || excess < 2^64,
///   excess == inhibitor  ->  count == 0 && head == 0 && tail == 0.
abstract contract QueueFV is Test, SymTest {
    address internal constant SYS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;
    uint256 internal constant INHIB = type(uint256).max;
    uint64 internal constant MAX_ID = 2 ** 40 - 1;

    address internal q;

    uint256 internal excess;
    uint256 internal count;
    uint256 internal head;
    uint256 internal tail;

    function deploy() internal virtual returns (address);
    function target() internal pure virtual returns (uint256);
    function maxPerBlock() internal pure virtual returns (uint256);
    /// Whether a 16-byte request body is accepted (both u64 fields BE).
    function fieldsOk(uint64 a, uint64 b) internal pure virtual returns (bool);

    function setUp() public {
        q = deploy();
        svm.enableSymbolicStorage(q);
    }

    // --- state helpers ------------------------------------------------------------------

    function slotOf(uint256 index) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(index, uint256(4))));
    }

    function ld(uint256 slot) internal view returns (uint256) {
        return uint256(vm.load(q, bytes32(slot)));
    }

    function st(uint256 slot, uint256 v) internal {
        vm.store(q, bytes32(slot), bytes32(v));
    }

    /// Arbitrary state satisfying INV. `excessValue` is a concrete excess (possibly the
    /// inhibitor) or `ANY` (symbolic: inhibitor or < 2^64). `queued` fixes tail - head to a
    /// concrete value (head stays symbolic) or is `ANY`.
    uint256 internal constant ANY = type(uint256).max - 1;

    function symState(uint256 excessValue, uint256 queued) internal {
        if (excessValue == ANY) {
            excess = svm.createUint256("excess");
            vm.assume(excess == INHIB || excess < 2 ** 64);
        } else {
            excess = excessValue;
        }
        count = svm.createUint256("count");
        head = svm.createUint256("head");
        if (queued == ANY) {
            tail = svm.createUint256("tail");
            vm.assume(head <= tail);
        } else {
            vm.assume(head < 2 ** 64);
            tail = head + queued;
        }
        vm.assume(tail < 2 ** 64);
        vm.assume(count <= tail - head);
        if (excess == INHIB) vm.assume(count == 0 && head == 0 && tail == 0);
        st(0, excess);
        st(1, count);
        st(2, head);
        st(3, tail);
    }

    /// Independent little-endian encoding (byte loop, not the contract's swap network).
    function le64(uint64 v) internal pure returns (bytes memory out) {
        out = new bytes(8);
        for (uint256 i; i < 8; i++) {
            out[i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    function eq(bytes memory a, bytes memory b) internal pure returns (bool) {
        if (a.length != b.length) return false;
        for (uint256 i; i < a.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    /// Request checks pin excess to concrete values whose EIP-7002 fee is known; the fee
    /// function itself is checked exhaustively against the reference for every non-overflowing
    /// excess (FeeExhaustive.t.sol). Everything else (sender, value, calldata, count, head,
    /// tail, queue contents) is symbolic.
    uint256 internal constant F2892 =
        76059800903738432429721259523001950250726052916847211303159755524395288041;

    function expectedFee(uint256 e) internal pure returns (uint256) {
        if (e <= 11) return 1;
        if (e == 34) return 7;
        if (e == 2892) return F2892; // largest excess whose fee does not overflow
        revert("no reference fee for this excess");
    }

    // --- request path -------------------------------------------------------------------

    function _request(uint256 len, uint256 excessValue) internal {
        symState(excessValue, ANY);
        address sender = svm.createAddress("sender");
        vm.assume(sender != SYS && sender != q && sender != address(this));
        uint256 value = svm.createUint256("value");
        bytes memory data = svm.createBytes(len, "data");
        vm.deal(sender, value);
        uint256 bal0 = q.balance;
        uint256 entry0 = ld(slotOf(tail));
        uint256 entry1 = ld(slotOf(tail) + 1);

        vm.prank(sender);
        (bool ok, bytes memory ret) = q.call{value: value}(data);

        // Spec.
        bool inhibited = excess == INHIB;
        bool expectOk;
        bytes memory expectRet;
        if (inhibited) {
            expectOk = false;
        } else if (len == 0) {
            expectOk = value == 0;
            expectRet = abi.encode(expectedFee(excess));
        } else if (value < expectedFee(excess) || len != 16) {
            expectOk = false;
        } else {
            uint64 a;
            uint64 b;
            assembly {
                a := shr(192, mload(add(data, 32)))
                b := shr(192, mload(add(data, 40)))
            }
            expectOk = fieldsOk(a, b);
            if (expectOk) {
                // Stored entry: slot0 = source (20) | first field << 160 (bits 224-255 are never
                // written by the contract and stay whatever they were); slot1 = second field
                // in the low 8 bytes.
                assert(ld(slotOf(tail)) & ((1 << 224) - 1)
                    == (uint256(uint160(sender)) | (uint256(a) << 160)));
                assert(uint64(ld(slotOf(tail) + 1)) == b);
            }
        }

        assert(ok == expectOk);
        if (!ok) {
            assert(ret.length == 0); // reverts carry no data
            assert(ld(0) == excess && ld(1) == count && ld(2) == head && ld(3) == tail);
            assert(ld(slotOf(tail)) == entry0 && ld(slotOf(tail) + 1) == entry1);
            assert(q.balance == bal0);
            return;
        }
        assert(eq(ret, expectRet));
        assert(q.balance == bal0 + value);
        assert(ld(0) == excess && ld(2) == head);
        if (len == 0) {
            assert(ld(1) == count && ld(3) == tail);
        } else {
            assert(ld(1) == count + 1 && ld(3) == tail + 1);
            // INV preserved (tail grows by one per accepted request, so tail <= #requests ever).
            assert(ld(1) <= ld(3) - ld(2) && ld(3) <= 2 ** 64);
        }
    }

    function check_request_len0() public { _request(0, 0); }
    function check_request_len1() public { _request(1, 0); }
    function check_request_len15() public { _request(15, 0); }
    function check_request_len16() public { _request(16, 0); }
    function check_request_len17() public { _request(17, 0); }
    function check_request_len32() public { _request(32, 0); }
    function check_request_len16_excess11() public { _request(16, 11); }
    function check_request_len0_inhibited() public { _request(0, INHIB); }
    function check_request_len16_inhibited() public { _request(16, INHIB); }
    function check_request_len0_fee7() public { _request(0, 34); }
    function check_request_len16_fee7() public { _request(16, 34); }
    function check_request_len0_feeMax() public { _request(0, 2892); }
    function check_request_len16_feeMax() public { _request(16, 2892); }

    // --- system call --------------------------------------------------------------------

    function expectedRecord(uint256 index) internal view returns (bytes memory) {
        uint256 s0 = ld(slotOf(index));
        uint256 s1 = ld(slotOf(index) + 1);
        return abi.encodePacked(address(uint160(s0)), le64(uint64(s0 >> 160)), le64(uint64(s1)));
    }

    function _systemCall(uint256 len, uint256 queued) internal {
        symState(ANY, queued);
        bytes memory data = svm.createBytes(len, "sysdata");

        uint256 n = tail - head;
        if (n > maxPerBlock()) n = maxPerBlock();
        bytes memory expected;
        for (uint256 i; i < n; i++) {
            expected = bytes.concat(expected, expectedRecord(head + i));
        }

        vm.prank(SYS);
        (bool ok, bytes memory ret) = q.call(data);

        assert(ok); // the system call never reverts from an INV state
        assert(eq(ret, expected)); // FIFO from head, at most maxPerBlock records
        if (head + n == tail) {
            assert(ld(2) == 0 && ld(3) == 0); // drained: reset
        } else {
            assert(ld(2) == head + n && ld(3) == tail);
        }
        uint256 prev = excess == INHIB ? 0 : excess;
        uint256 total = prev + count;
        assert(ld(0) == (total > target() ? total - target() : 0));
        assert(ld(1) == 0);
        // INV preserved (the new excess stays < 2^64 + 2^64, so bound INV on 2^65 for one step).
        assert(ld(2) <= ld(3) && ld(0) < 2 ** 65);
    }

    function check_systemCall_q0() public { _systemCall(0, 0); }
    function check_systemCall_q1() public { _systemCall(0, 1); }
    function check_systemCall_q2() public { _systemCall(0, 2); }
    function check_systemCall_q3() public { _systemCall(0, 3); }
    function check_systemCall_q16() public { _systemCall(0, 16); }
    function check_systemCall_q17() public { _systemCall(0, 17); }
    function check_systemCall_q40() public { _systemCall(0, 40); }
    function check_systemCall_q2_withData() public { _systemCall(16, 2); }
}

contract WithdrawalFV is QueueFV {
    function deploy() internal override returns (address) { return address(new PQWithdrawal()); }
    function target() internal pure override returns (uint256) { return 2; }
    function maxPerBlock() internal pure override returns (uint256) { return 16; }
    function fieldsOk(uint64 a, uint64) internal pure override returns (bool) { return a <= MAX_ID; }
}

contract ConsolidationFV is QueueFV {
    function deploy() internal override returns (address) { return address(new PQConsolidation()); }
    function target() internal pure override returns (uint256) { return 1; }
    function maxPerBlock() internal pure override returns (uint256) { return 2; }
    function fieldsOk(uint64 a, uint64 b) internal pure override returns (bool) {
        return a <= MAX_ID && b <= MAX_ID;
    }
}
