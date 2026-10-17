// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, Vm, console2} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {PQStaking} from "../../src/PQStaking.sol";

/// Reference model of one PQStaking instance, driven through the real contract.
contract StakingHandler is Test {
    uint256 internal constant CAP = 2 ** 40;

    PQStaking[] public instances;
    uint64[] public prefix;

    // Model state per instance.
    mapping(uint256 => uint64) public modelEventCount;
    mapping(uint256 => uint64[]) internal stakeIds;
    mapping(uint256 => uint64[]) internal topupIndices;
    mapping(uint256 => mapping(uint64 => bool)) public modelCreated;
    mapping(uint256 => uint256) public creditedGwei;

    uint256 public calls;
    uint256 public successes;
    uint256 public treeFullHits;
    uint256 public modelViolations; // handler-level mismatches (must stay 0)

    constructor(uint64[] memory ns) {
        for (uint256 i; i < ns.length; ++i) {
            instances.push(new PQStaking(ns[i]));
            prefix.push(ns[i]);
            modelEventCount[i] = ns[i];
        }
    }

    function instanceCount() external view returns (uint256) {
        return instances.length;
    }

    function stakeIdsOf(uint256 i) external view returns (uint64[] memory) {
        return stakeIds[i];
    }

    function topupIndicesOf(uint256 i) external view returns (uint64[] memory) {
        return topupIndices[i];
    }

    function _value(uint256 seed) internal pure returns (uint256) {
        uint256 mode = seed % 5;
        uint256 r = seed >> 8;
        if (mode == 0) return 1 ether; // minimum
        if (mode == 1) return 1 ether - 1 gwei; // just below minimum
        if (mode == 2) return 1 ether + (r % 1e9); // often not a gwei multiple
        if (mode == 3) return (r % (type(uint64).max / 2)) * 1 gwei; // large, below 2^64 gwei
        return (1 + r % 64) * 1 ether;
    }

    function _check(bool cond) internal {
        if (!cond) modelViolations++;
    }

    function stake(uint256 instSeed, uint256 valueSeed, bytes32 wc, bytes32 ac) external {
        uint256 i = instSeed % instances.length;
        PQStaking s = instances[i];
        uint256 value = _value(valueSeed);
        vm.deal(address(this), value);
        uint64 e = modelEventCount[i];
        bool expectOk = e < CAP && value >= 1 ether && value % 1 gwei == 0;
        calls++;
        vm.recordLogs();
        (bool ok, bytes memory ret) =
            address(s).call{value: value}(abi.encodeCall(PQStaking.stake, (wc, ac)));
        _check(ok == expectOk);
        if (!ok) {
            if (e >= CAP) treeFullHits++;
            return;
        }
        successes++;
        uint64 id = abi.decode(ret, (uint64));
        _check(id == e);
        _check(!modelCreated[i][id] && id >= prefix[i]);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        _check(logs.length == 1 && logs[0].topics[0] == PQStaking.CreateStake.selector);
        _check(uint256(logs[0].topics[1]) == id);
        (bytes32 lwc, bytes32 lac, uint64 amt) =
            abi.decode(logs[0].data, (bytes32, bytes32, uint64));
        _check(lwc == wc && lac == ac && uint256(amt) * 1 gwei == value);
        modelCreated[i][id] = true;
        stakeIds[i].push(id);
        creditedGwei[i] += amt;
        modelEventCount[i] = e + 1;
    }

    function topup(uint256 instSeed, uint256 targetSeed, uint256 valueSeed) external {
        uint256 i = instSeed % instances.length;
        PQStaking s = instances[i];
        uint64 t = _target(i, targetSeed);
        uint256 value = _value(valueSeed);
        vm.deal(address(this), value);
        uint64 e = modelEventCount[i];
        bool known = t < prefix[i] || modelCreated[i][t];
        bool expectOk = known && e < CAP && value >= 1 ether && value % 1 gwei == 0;
        calls++;
        vm.recordLogs();
        (bool ok,) = address(s).call{value: value}(abi.encodeCall(PQStaking.topup, (t)));
        _check(ok == expectOk);
        if (!ok) {
            if (known && e >= CAP) treeFullHits++;
            return;
        }
        successes++;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        _check(logs.length == 1 && logs[0].topics[0] == PQStaking.TopUp.selector);
        _check(uint256(logs[0].topics[1]) == t);
        (uint64 amt, uint64 idx) = abi.decode(logs[0].data, (uint64, uint64));
        _check(idx == e && uint256(amt) * 1 gwei == value);
        topupIndices[i].push(idx);
        creditedGwei[i] += amt;
        modelEventCount[i] = e + 1;
    }

    /// Mix of valid and invalid targets: created stakes, migrated IDs, top-up indices, the
    /// next/last indices, the prefix boundary, the capacity boundary and random values.
    function _target(uint256 i, uint256 seed) internal view returns (uint64) {
        uint256 mode = seed % 8;
        uint256 r = seed >> 8;
        uint64 n = prefix[i];
        uint64 e = modelEventCount[i];
        if (mode == 0 && stakeIds[i].length > 0) return stakeIds[i][r % stakeIds[i].length];
        if (mode == 1 && topupIndices[i].length > 0) {
            return topupIndices[i][r % topupIndices[i].length];
        }
        if (mode == 2 && n > 0) return uint64(r % n);
        if (mode == 3) return n; // first non-migrated index
        if (mode == 4) return e; // next index (unused)
        if (mode == 5 && n > 0) return n - 1; // last migrated
        if (mode == 6) return uint64(CAP - 1 - (r % 4));
        return uint64(r);
    }
}

/// Stateful invariant campaign against instances with migration prefixes 0, 8 and
/// 2^40 - 6 (so EventTreeFull is reached within a few calls).
contract RtStakingInvariantTest is StdInvariant, Test {
    StakingHandler internal h;

    function setUp() public {
        uint64[] memory ns = new uint64[](3);
        ns[0] = 0;
        ns[1] = 8;
        ns[2] = uint64(2 ** 40 - 6);
        h = new StakingHandler(ns);
        targetContract(address(h));
        bytes4[] memory sels = new bytes4[](2);
        sels[0] = StakingHandler.stake.selector;
        sels[1] = StakingHandler.topup.selector;
        targetSelector(FuzzSelector({addr: address(h), selectors: sels}));
    }

    function invariant_handlerModelAgrees() public view {
        assertEq(h.modelViolations(), 0);
    }

    function invariant_eventCountsMatchModel() public view {
        for (uint256 i; i < h.instanceCount(); ++i) {
            PQStaking s = h.instances(i);
            assertEq(s.eventCount(), h.modelEventCount(i));
            assertEq(s.initialEventCount(), h.prefix(i));
            assertLe(s.eventCount(), 2 ** 40);
            assertGe(s.eventCount(), s.initialEventCount());
        }
    }

    function invariant_stakeIdsUniqueIncreasingAndRecognised() public view {
        for (uint256 i; i < h.instanceCount(); ++i) {
            PQStaking s = h.instances(i);
            uint64[] memory ids = h.stakeIdsOf(i);
            for (uint256 j; j < ids.length; ++j) {
                assertTrue(s.isStake(ids[j]));
                assertGe(ids[j], s.initialEventCount());
                assertLt(ids[j], s.eventCount());
                if (j > 0) assertGt(ids[j], ids[j - 1]);
            }
        }
    }

    function invariant_topupIndicesAreNeverStakes() public view {
        for (uint256 i; i < h.instanceCount(); ++i) {
            PQStaking s = h.instances(i);
            uint64[] memory idx = h.topupIndicesOf(i);
            for (uint256 j; j < idx.length; ++j) {
                assertFalse(s.isStake(idx[j]));
                assertFalse(h.modelCreated(i, idx[j]));
            }
        }
    }

    function invariant_isStakeBoundaries() public view {
        for (uint256 i; i < h.instanceCount(); ++i) {
            PQStaking s = h.instances(i);
            uint64 n = s.initialEventCount();
            uint64 e = s.eventCount();
            if (n > 0) assertTrue(s.isStake(n - 1));
            if (n > 0) assertTrue(s.isStake(0));
            assertFalse(s.isStake(e)); // not yet used
            assertFalse(s.isStake(uint64(2 ** 40)));
            assertFalse(s.isStake(type(uint64).max));
            assertEq(s.isStake(n), h.modelCreated(i, n));
        }
    }

    function invariant_balanceEqualsCredited() public view {
        for (uint256 i; i < h.instanceCount(); ++i) {
            assertEq(address(h.instances(i)).balance, h.creditedGwei(i) * 1 gwei);
        }
    }

    function afterInvariant() external view {
        console2.log("calls", h.calls(), "successes", h.successes());
        console2.log(
            "treeFullHits", h.treeFullHits(), "instance2 eventCount", h.instances(2).eventCount()
        );
        require(h.calls() > 0);
    }
}
