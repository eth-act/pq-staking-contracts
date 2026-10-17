// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {PQStaking} from "../../src/PQStaking.sol";

/// PoC: `uint64(msg.value / 1 gwei)` (PQStaking.sol:88) silently truncates deposits of
/// 2^64 gwei (~18.45e9 ETH) or more. The contract keeps the full msg.value but the event the
/// CL credits carries `amount mod 2^64` gwei, which can be 0 (below the 1 ETH minimum) or any
/// smaller value. The deposit contract rejects this case ("deposit value too high").
///
/// The `test_PoC_*` tests assert the intended property and FAIL on commit 2e7d21f.
contract RtStakingAmountTest is Test {
    uint256 internal constant U64_GWEI = (uint256(type(uint64).max) + 1) * 1 gwei; // 2^64 gwei

    PQStaking internal staking;

    function setUp() public {
        staking = new PQStaking(0);
    }

    function _stakeAndReadAmount(uint256 value)
        internal
        returns (uint64 stakeId, uint64 amountGwei)
    {
        vm.deal(address(this), value);
        vm.recordLogs();
        stakeId = staking.stake{value: value}(bytes32(uint256(1)), bytes32(uint256(2)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        (,, amountGwei) = abi.decode(logs[0].data, (bytes32, bytes32, uint64));
    }

    function _topupAndReadAmount(uint64 stakeId, uint256 value)
        internal
        returns (uint64 amountGwei)
    {
        vm.deal(address(this), value);
        vm.recordLogs();
        staking.topup{value: value}(stakeId);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (amountGwei,) = abi.decode(logs[0].data, (uint64, uint64));
    }

    /// Largest exact value: 2^64 - 1 gwei is credited exactly.
    function test_MaxExactDeposit() public {
        (, uint64 amountGwei) = _stakeAndReadAmount(U64_GWEI - 1 gwei);
        assertEq(amountGwei, type(uint64).max);
    }

    /// FAILS: 2^64 gwei is accepted and a CreateStake with amountGwei == 0 is emitted,
    /// bypassing the 1 ETH minimum the CL can otherwise rely on.
    function test_PoC_StakeOf2Pow64GweiEmitsZeroAmount() public {
        (uint64 id, uint64 amountGwei) = _stakeAndReadAmount(U64_GWEI);
        emit log_named_uint("stakeId", id);
        emit log_named_uint("emitted amountGwei", amountGwei);
        emit log_named_uint("contract balance (wei)", address(staking).balance);
        assertEq(uint256(amountGwei) * 1 gwei, U64_GWEI, "emitted amount != msg.value");
    }

    /// FAILS: 2^64 gwei + 1 ETH is credited as exactly 1 ETH.
    function test_PoC_StakeCreditedAsOneEth() public {
        (, uint64 amountGwei) = _stakeAndReadAmount(U64_GWEI + 1 ether);
        assertEq(amountGwei, 1e9); // what the event says
        assertEq(uint256(amountGwei) * 1 gwei, U64_GWEI + 1 ether, "emitted amount != msg.value");
    }

    /// FAILS: same truncation on topup.
    function test_PoC_TopUpTruncates() public {
        (uint64 id,) = _stakeAndReadAmount(1 ether);
        uint64 amountGwei = _topupAndReadAmount(id, U64_GWEI);
        assertEq(uint256(amountGwei) * 1 gwei, U64_GWEI, "emitted amount != msg.value");
    }

    /// Property the contract should satisfy: every accepted deposit is credited exactly.
    /// FAILS once the fuzzer picks msg.value >= 2^64 gwei.
    function testFuzz_PoC_EmittedAmountEqualsValue(uint256 gweiAmount) public {
        gweiAmount = bound(gweiAmount, 1e9, type(uint128).max / 1 gwei);
        uint256 value = gweiAmount * 1 gwei;
        (, uint64 amountGwei) = _stakeAndReadAmount(value);
        assertEq(uint256(amountGwei) * 1 gwei, value, "emitted amount != msg.value");
    }

    /// Holds: below 2^64 gwei the amount is exact and the 1 ETH / gwei rules hold.
    function testFuzz_AmountRulesBelowU64(uint256 value) public {
        value = bound(value, 0, U64_GWEI - 1);
        vm.deal(address(this), value);
        vm.recordLogs();
        (bool ok,) = address(staking).call{value: value}(
            abi.encodeCall(PQStaking.stake, (bytes32(0), bytes32(0)))
        );
        assertEq(ok, value >= 1 ether && value % 1 gwei == 0);
        if (ok) {
            Vm.Log[] memory logs = vm.getRecordedLogs();
            (,, uint64 amountGwei) = abi.decode(logs[0].data, (bytes32, bytes32, uint64));
            assertEq(uint256(amountGwei) * 1 gwei, value);
        }
    }
}
