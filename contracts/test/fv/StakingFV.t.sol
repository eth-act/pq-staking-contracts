// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "./Svm.sol";
import {PQStaking} from "../../src/PQStaking.sol";

/// Halmos specs for PQStaking (compiled bytecode), inductive over an ARBITRARY storage state
/// satisfying INV:
///   initialEventCount <= eventCount <= 2^40, slot 0 high 128 bits zero,
///   for all k: createdStake[k] -> initialEventCount <= k < eventCount.
/// The universally quantified part is instantiated at every key the call can touch
/// (the new index, the queried stake ID) plus one arbitrary other key `k` (frame).
contract StakingFV is Test, SymTest {
    uint64 internal constant CAP = 2 ** 40;

    PQStaking internal s;
    uint64 internal initial;
    uint64 internal events;

    function setUp() public {
        s = new PQStaking(0);
        svm.enableSymbolicStorage(address(s));
    }

    function createdSlot(uint64 k) internal pure returns (bytes32) {
        return keccak256(abi.encode(uint256(k), uint256(1)));
    }

    function created(uint64 k) internal view returns (bool) {
        uint256 v = uint256(vm.load(address(s), createdSlot(k)));
        return v & 0xff != 0;
    }

    /// INV at key k, for the symbolic storage.
    function invAt(uint64 k) internal view returns (bool) {
        return !created(k) || (initial <= k && k < events);
    }

    function symState() internal {
        uint256 slot0 = svm.createUint(128, "slot0");
        vm.store(address(s), bytes32(0), bytes32(slot0));
        initial = uint64(slot0);
        events = uint64(slot0 >> 64);
        vm.assume(initial <= events && events <= CAP);
    }

    function stakeIdOk(uint64 id) internal view returns (bool) {
        return id < initial || created(id);
    }

    function check_stake(bytes32 wc, bytes32 ac, uint64 k, address sender) public {
        symState();
        uint256 value = svm.createUint256("value");
        vm.assume(invAt(events) && invAt(k));
        vm.assume(sender != address(s));
        bool kCreated = created(k);
        bool kWasStake = s.isStake(k);
        vm.deal(sender, value);
        uint256 bal0 = address(s).balance;

        vm.prank(sender);
        (bool ok, bytes memory ret) =
            address(s).call{value: value}(abi.encodeCall(PQStaking.stake, (wc, ac)));

        bool expectOk = value >= 1 ether && value % 1 gwei == 0 && events < CAP;
        assert(ok == expectOk);
        if (!ok) return;
        assert(abi.decode(ret, (uint64)) == events); // stake ID = index of this event
        assert(s.eventCount() == events + 1 && s.initialEventCount() == initial);
        assert(created(events) && s.isStake(events));
        assert(address(s).balance == bal0 + value);
        // Frame and INV preservation at an arbitrary other key.
        if (k != events) {
            assert(created(k) == kCreated && s.isStake(k) == kWasStake);
        }
        assert(!created(k) || (initial <= k && k < events + 1));
    }

    function check_topup(uint64 id, uint64 k, address sender) public {
        symState();
        uint256 value = svm.createUint256("value");
        vm.assume(invAt(events) && invAt(id) && invAt(k));
        vm.assume(sender != address(s));
        bool kCreated = created(k);
        bool isStake0 = stakeIdOk(id);
        vm.deal(sender, value);
        uint256 bal0 = address(s).balance;

        vm.prank(sender);
        (bool ok,) = address(s).call{value: value}(abi.encodeCall(PQStaking.topup, (id)));

        bool expectOk = isStake0 && value >= 1 ether && value % 1 gwei == 0 && events < CAP;
        assert(ok == expectOk);
        if (!ok) return;
        assert(s.eventCount() == events + 1 && s.initialEventCount() == initial);
        // The consumed index is never a stake ID.
        assert(!created(events) && !s.isStake(events));
        assert(created(k) == kCreated);
        assert(address(s).balance == bal0 + value);
    }

    /// isStake <=> migrated (id < initialEventCount) or created.
    function check_isStake(uint64 id) public {
        symState();
        assert(s.isStake(id) == (id < initial || created(id)));
    }

    /// No other entry point: any calldata whose selector is not one of the 7 ABI functions
    /// reverts and leaves the balance unchanged (no fallback/receive).
    function check_noOtherEntryPoint(bytes4 sel, address sender) public {
        symState();
        uint256 value = svm.createUint256("value");
        bytes memory tail = svm.createBytes(64, "tail");
        vm.assume(
            sel != PQStaking.stake.selector && sel != PQStaking.topup.selector
                && sel != PQStaking.isStake.selector && sel != s.eventCount.selector
                && sel != s.initialEventCount.selector
                && sel != s.MAX_EVENT_COUNT.selector
                && sel != s.MIN_DEPOSIT.selector
        );
        vm.assume(sender != address(s));
        vm.deal(sender, value);
        vm.prank(sender);
        (bool ok,) = address(s).call{value: value}(abi.encodePacked(sel, tail));
        assert(!ok);
        vm.prank(sender);
        (ok,) = address(s).call{value: value}("");
        assert(!ok);
    }
}
