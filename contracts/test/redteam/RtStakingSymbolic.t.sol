// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PQStaking} from "../../src/PQStaking.sol";

/// Halmos symbolic checks (run: `halmos --contract RtStakingSymbolic`).
///
/// State invariant INV, over the compiled bytecode:
///   (a) n <= e <= 2^40, n < 2^40           (n = initialEventCount, e = eventCount)
///   (b) for every k: createdStake[k] => n <= k < e
///   (c) slot 0 bits >= 128 are zero
/// The pre-state is fully symbolic in slot 0 and in createdStake at the observed index k and
/// the top-up target t (each with an arbitrary boolean, constrained only by INV). Every other
/// mapping slot is 0, which INV forces at the only other slot the code touches (index e).
contract RtStakingSymbolic is Test {
    uint256 internal constant CAP = 2 ** 40;
    uint256 internal constant GWEI = 1e9;
    PQStaking internal s;

    function setUp() public {
        s = new PQStaking(0);
    }

    function _slot(uint64 k) internal pure returns (bytes32) {
        return keccak256(abi.encode(k, uint256(1)));
    }

    function _created(uint64 k) internal view returns (bool) {
        return uint256(vm.load(address(s), _slot(k))) != 0;
    }

    function _slot0() internal view returns (uint256) {
        return uint256(vm.load(address(s), bytes32(0)));
    }

    function _inv(uint64 n, uint64 e, uint64 k) internal view returns (bool) {
        return !_created(k) || (n <= k && k < e);
    }

    function _setup(uint64 n, uint64 e, uint64 k, bool bk, uint64 t, bool bt) internal {
        vm.assume(n < CAP && n <= e && e <= CAP);
        vm.store(address(s), bytes32(0), bytes32(uint256(n) | (uint256(e) << 64)));
        vm.store(address(s), _slot(k), bytes32(uint256(bk ? 1 : 0)));
        vm.store(address(s), _slot(t), bytes32(uint256(bt ? 1 : 0)));
        vm.assume(_inv(n, e, k) && _inv(n, e, t));
    }

    /// stake(): succeeds iff e < 2^40, value >= 1 ETH, value % 1 gwei == 0. On success:
    /// id == e (old event count), id was not a stake before (unique, not migrated), is one
    /// after, e increments by exactly 1, n is unchanged, no other createdStake entry changes,
    /// and INV holds afterwards at k and t.
    function check_stake(
        uint64 n,
        uint64 e,
        uint64 k,
        bool bk,
        uint64 t,
        bool bt,
        uint256 value,
        bytes32 wc,
        bytes32 ac
    ) public {
        _setup(n, e, k, bk, t, bt);
        bool ck = _created(k);
        bool idWasStake = s.isStake(e);
        vm.deal(address(this), value);

        (bool ok, bytes memory ret) =
            address(s).call{value: value}(abi.encodeCall(PQStaking.stake, (wc, ac)));

        bool valid = e < CAP && value >= 1 ether && value % GWEI == 0;
        assert(ok == valid);
        if (!ok) return;

        uint64 id = abi.decode(ret, (uint64));
        assert(id == e);
        assert(!idWasStake);
        assert(s.isStake(id));
        assert(_slot0() == (uint256(n) | (uint256(e + 1) << 64)));
        if (k != id) assert(_created(k) == ck);
        assert(_inv(n, e + 1, k) && _inv(n, e + 1, t));
    }

    /// topup(t): succeeds iff isStake(t), e < 2^40 and the amount rules hold. On success: e
    /// increments by 1, n unchanged, createdStake unchanged at k, t and at the consumed index
    /// e, so the top-up index is not a stake ID afterwards; INV holds afterwards.
    function check_topup(uint64 n, uint64 e, uint64 k, bool bk, uint64 t, bool bt, uint256 value)
        public
    {
        _setup(n, e, k, bk, t, bt);
        bool ck = _created(k);
        bool ct = _created(t);
        bool tIsStake = s.isStake(t);
        vm.deal(address(this), value);

        (bool ok,) = address(s).call{value: value}(abi.encodeCall(PQStaking.topup, (t)));

        bool valid = tIsStake && e < CAP && value >= 1 ether && value % GWEI == 0;
        assert(ok == valid);
        if (!ok) return;

        assert(_slot0() == (uint256(n) | (uint256(e) + 1) << 64));
        assert(_created(k) == ck && _created(t) == ct);
        assert(!s.isStake(e)); // the top-up's own event index is not a stake ID
        assert(_inv(n, e + 1, k) && _inv(n, e + 1, t));
    }

    /// isStake(k) == (k < n || createdStake[k]) for every k, under INV.
    function check_isStake(uint64 n, uint64 e, uint64 k, bool bk) public {
        _setup(n, e, k, bk, k, bk);
        assert(s.isStake(k) == (k < n || _created(k)));
    }

    /// Any call that is not stake/topup leaves all observed storage unchanged (views and the
    /// dispatcher's fallback path never write), so only stake/topup move the event count.
    function check_otherCallsDoNotWrite(
        uint64 n,
        uint64 e,
        uint64 k,
        bool bk,
        uint256 value,
        bytes calldata data
    ) public {
        _setup(n, e, k, bk, k, bk);
        vm.assume(data.length >= 4);
        bytes4 sel = bytes4(data[:4]);
        vm.assume(sel != PQStaking.stake.selector && sel != PQStaking.topup.selector);
        uint256 before0 = _slot0();
        bool ck = _created(k);
        vm.deal(address(this), value);
        address(s).call{value: value}(data);
        assert(_slot0() == before0 && _created(k) == ck);
    }

    /// topup ABI decoding rejects stake IDs with any of the upper 192 bits set (no silent
    /// truncation of a uint256 argument into a uint64 stake ID).
    function check_topupRejectsDirtyStakeId(uint256 raw, uint256 value) public {
        vm.assume(raw > type(uint64).max);
        vm.deal(address(this), value);
        (bool ok,) =
            address(s).call{value: value}(abi.encodeWithSelector(PQStaking.topup.selector, raw));
        assert(!ok);
    }

    /// Constructor: succeeds iff N < 2^40; slot 0 is then exactly (N << 64) | N.
    function check_constructor(uint64 n) public {
        try new PQStaking(n) returns (PQStaking d) {
            assert(n < CAP);
            assert(uint256(vm.load(address(d), bytes32(0))) == (uint256(n) | (uint256(n) << 64)));
        } catch {
            assert(n >= CAP);
        }
    }

    // Negative controls (EXPECTED TO FAIL with a counterexample): show the assumptions above
    // leave reachable success paths, i.e. the passing checks are not vacuous.

    function check_negControl_stakeNeverSucceeds(uint64 n, uint64 e, uint256 value) public {
        _setup(n, e, 0, false, 0, false);
        vm.deal(address(this), value);
        (bool ok,) =
            address(s).call{value: value}(abi.encodeCall(PQStaking.stake, (bytes32(0), bytes32(0))));
        assert(!ok);
    }

    function check_negControl_topupNeverSucceeds(
        uint64 n,
        uint64 e,
        uint64 t,
        bool bt,
        uint256 value
    ) public {
        _setup(n, e, t, bt, t, bt);
        vm.deal(address(this), value);
        (bool ok,) = address(s).call{value: value}(abi.encodeCall(PQStaking.topup, (t)));
        assert(!ok);
    }

    function check_negControl_topupOfCreatedStakeNeverSucceeds(
        uint64 n,
        uint64 e,
        uint64 t,
        uint256 value
    ) public {
        _setup(n, e, t, true, t, true);
        vm.assume(t >= n);
        vm.deal(address(this), value);
        (bool ok,) = address(s).call{value: value}(abi.encodeCall(PQStaking.topup, (t)));
        assert(!ok);
    }

    /// Same harness as check_otherCallsDoNotWrite but with the stake selector: must fail,
    /// showing that harness detects writes.
    function check_negControl_stakeCallDoesNotWrite(
        uint64 n,
        uint64 e,
        uint256 value,
        bytes calldata data
    ) public {
        _setup(n, e, 0, false, 0, false);
        vm.assume(data.length >= 4);
        vm.assume(bytes4(data[:4]) == PQStaking.stake.selector);
        uint256 before0 = _slot0();
        vm.deal(address(this), value);
        address(s).call{value: value}(data);
        assert(_slot0() == before0);
    }
}
