// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "./Svm.sol";
import {PQValidatorRegistration} from "../../src/PQValidatorRegistration.sol";

/// Halmos specs for RegistrationQueue (compiled PQValidatorRegistration runtime; the builder
/// runtime is byte-identical). Requests that pass the length and stake-ID checks run the
/// leanXMSS-K verifier, whose 4^58-way digit branching is out of reach for symbolic execution;
/// those paths are covered by the Lean proof plus the bytecode trace differentials instead.
///
/// INV as in QueueFV, plus: every queued entry (index in [head, tail)) is a 2440-byte `bytes`
/// (storage length word 2*2440+1), as written by `queue[index] = input`.
contract RegistrationFV is Test, SymTest {
    address internal constant SYS = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;
    uint256 internal constant INHIB = type(uint256).max;
    uint256 internal constant LEN = 2440;
    uint256 internal constant WORDS = 77; // ceil(2440 / 32)

    address internal q;
    uint256 internal excess;
    uint256 internal count;
    uint256 internal head;
    uint256 internal tail;

    function setUp() public {
        q = address(new PQValidatorRegistration());
        svm.enableSymbolicStorage(q);
    }

    function ld(uint256 slot) internal view returns (uint256) {
        return uint256(vm.load(q, bytes32(slot)));
    }

    function st(uint256 slot, uint256 v) internal {
        vm.store(q, bytes32(slot), bytes32(v));
    }

    function symState(uint256 maxQueued) internal {
        excess = svm.createUint256("excess");
        count = svm.createUint256("count");
        head = svm.createUint256("head");
        tail = svm.createUint256("tail");
        vm.assume(head <= tail && tail < 2 ** 64 && tail - head <= maxQueued);
        vm.assume(count <= tail - head);
        vm.assume(excess == INHIB || excess < 2 ** 64);
        if (excess == INHIB) vm.assume(count == 0 && head == 0 && tail == 0);
        st(0, excess);
        st(1, count);
        st(2, head);
        st(3, tail);
    }

    function lenSlot(uint256 index) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(index, uint256(4))));
    }

    /// Entry `index` as stored (raw 2440 bytes), with its length word fixed to 2440.
    function entry(uint256 index) internal returns (bytes memory raw) {
        st(lenSlot(index), 2 * LEN + 1);
        uint256 data = uint256(keccak256(abi.encode(lenSlot(index))));
        raw = new bytes(WORDS * 32);
        for (uint256 w; w < WORDS; w++) {
            uint256 v = ld(data + w);
            assembly {
                mstore(add(add(raw, 32), mul(w, 32)), v)
            }
        }
        assembly {
            mstore(raw, LEN)
        }
    }

    /// Record = stake_id little-endian ‖ raw[8:2440] (independent byte loop for the LE part).
    function record(bytes memory raw) internal pure returns (bytes memory out) {
        out = new bytes(LEN);
        for (uint256 i; i < 8; i++) {
            out[i] = raw[7 - i];
        }
        for (uint256 i = 8; i < LEN; i++) {
            out[i] = raw[i];
        }
    }

    function eqWords(bytes memory a, bytes memory b) internal pure returns (bool r) {
        if (a.length != b.length) return false;
        r = true;
        uint256 n = (a.length + 31) / 32;
        for (uint256 i; i < n; i++) {
            bytes32 x;
            bytes32 y;
            assembly {
                x := mload(add(add(a, 32), mul(i, 32)))
                y := mload(add(add(b, 32), mul(i, 32)))
            }
            // Mask the final partial word.
            if (i == n - 1 && a.length % 32 != 0) {
                uint256 keep = (a.length % 32) * 8;
                x = x >> (256 - keep);
                y = y >> (256 - keep);
            }
            if (x != y) r = false;
        }
    }

    /// System call with up to 2 queued registrations: exact output bytes, queue/excess update.
    function check_systemCall_upTo2() public {
        symState(2);
        uint256 n = tail - head;
        bytes memory expected;
        for (uint256 i; i < n; i++) {
            expected = bytes.concat(expected, record(entry(head + i)));
        }
        vm.prank(SYS);
        (bool ok, bytes memory ret) = q.call("");
        assert(ok);
        assert(eqWords(ret, expected));
        assert(ld(2) == 0 && ld(3) == 0); // fully drained (n <= 16): reset
        uint256 prev = excess == INHIB ? 0 : excess;
        assert(ld(0) == (prev + count > 2 ? prev + count - 2 : 0));
        assert(ld(1) == 0);
    }

    /// Requests failing the length or stake-ID check revert with empty data and change nothing,
    /// before the verifier runs (any value, any state, any sender).
    function _rejects(uint256 len, bool badStakeId) internal {
        symState(type(uint256).max);
        vm.assume(excess != INHIB && excess <= 11); // fee 1 wei; the inhibitor case is QueueFV's
        address sender = svm.createAddress("sender");
        vm.assume(sender != SYS && sender != q);
        uint256 value = svm.createUint(128, "value");
        bytes memory data = svm.createBytes(len, "data");
        if (badStakeId) {
            uint64 id;
            assembly {
                id := shr(192, mload(add(data, 32)))
            }
            vm.assume(id > 2 ** 40 - 1);
        }
        vm.deal(sender, value);
        vm.prank(sender);
        (bool ok, bytes memory ret) = q.call{value: value}(data);
        assert(!ok && ret.length == 0);
        assert(ld(0) == excess && ld(1) == count && ld(2) == head && ld(3) == tail);
    }

    function check_rejects_len1() public { _rejects(1, false); }
    function check_rejects_len16() public { _rejects(16, false); }
    function check_rejects_len2439() public { _rejects(2439, false); }
    function check_rejects_len2441() public { _rejects(2441, false); }
    function check_rejects_badStakeId() public { _rejects(2440, true); }
}
