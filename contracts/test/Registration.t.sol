// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Vm} from "forge-std/Vm.sol";
import {SystemCallTest} from "./helpers/SystemCallTest.sol";
import {PQStaking} from "../src/PQStaking.sol";
import {PQValidatorRegistration} from "../src/PQValidatorRegistration.sol";
import {PQBuilderRegistration} from "../src/PQBuilderRegistration.sol";

/// Both registration contracts share RegistrationQueue; each test runs against both.
contract RegistrationTest is SystemCallTest {
    uint256 internal constant SYSTEM_CALL_GAS_LIMIT = 30_000_000;
    uint256 internal constant MAX_PER_BLOCK = 16;
    uint256 internal constant REQUEST_LENGTH = 2584; // 8 + 48 + 96 + 32 + 2400
    uint64 internal constant MAX_STAKE_ID = 2 ** 40 - 1;

    address[2] internal registrations;

    function setUp() public {
        registrations[0] = address(new PQValidatorRegistration());
        registrations[1] = address(new PQBuilderRegistration());
        for (uint256 i; i < 2; i++) {
            systemCall(registrations[i]);
        }
    }

    /// Request calldata with every field filled with byte `fill`.
    function input(uint64 stakeId, bytes1 fill) internal pure returns (bytes memory) {
        return abi.encodePacked(
            stakeId, filled(fill, 48), filled(fill, 96), filled(fill, 32), filled(fill, 2400)
        );
    }

    function test_RegistersAgainstStakeIdFromStaking() public {
        PQStaking staking = new PQStaking(0);
        uint64 stakeId = staking.stake{value: 32 ether}(bytes32(uint256(1)), bytes32(0));
        bytes memory request = input(stakeId, 0xaa);
        assertEq(request.length, REQUEST_LENGTH);

        for (uint256 i; i < 2; i++) {
            vm.recordLogs();
            assertTrue(submit(registrations[i], request));
            Vm.Log[] memory logs = vm.getRecordedLogs();
            assertEq(logs.length, 1);
            assertEq(logs[0].topics.length, 0);
            assertEq(logs[0].data, request);
        }
    }

    /// Output is fixed-size records: the calldata with stake_id little-endian.
    function test_SystemCallReturnsRecordsWithLittleEndianStakeId() public {
        for (uint256 i; i < 2; i++) {
            address reg = registrations[i];
            assertTrue(submit(reg, input(0x0102030405, 0xa1)));
            assertTrue(submit(reg, input(MAX_STAKE_ID, 0xa2)));

            bytes memory expected = bytes.concat(
                hex"0504030201000000",
                filled(0xa1, REQUEST_LENGTH - 8),
                hex"ffffffffff000000",
                filled(0xa2, REQUEST_LENGTH - 8)
            );
            assertEq(systemCall(reg), expected);
        }
    }

    /// Worst case: MAX_PER_BLOCK requests read from cold storage fit the system call gas limit.
    function test_FullBlockSystemCallFitsGasLimit() public {
        address reg = registrations[0];
        for (uint64 i; i <= MAX_PER_BLOCK; i++) {
            assertTrue(submit(reg, input(i, 0x01)));
        }
        vm.cool(reg);

        vm.prank(SYSTEM_ADDRESS);
        uint256 gasBefore = gasleft();
        (bool ok, bytes memory out) = reg.call{gas: SYSTEM_CALL_GAS_LIMIT}("");
        uint256 used = gasBefore - gasleft();

        assertTrue(ok);
        assertEq(out.length, MAX_PER_BLOCK * REQUEST_LENGTH);
        assertLt(used, SYSTEM_CALL_GAS_LIMIT);
    }

    function test_FeeRisesAboveTarget() public {
        for (uint256 i; i < 2; i++) {
            address reg = registrations[i];
            for (uint64 j; j < 36; j++) {
                assertTrue(submit(reg, input(j, 0x01)));
            }
            systemCall(reg);
            assertEq(feeOf(reg), 7); // excess = 36 - 2 = 34
        }
    }

    function test_StakeIdBoundary() public {
        for (uint256 i; i < 2; i++) {
            assertTrue(submit(registrations[i], input(MAX_STAKE_ID, 0x01)));
            assertFalse(submit(registrations[i], input(MAX_STAKE_ID + 1, 0x01)));
        }
    }

    function test_RevertWhen_NotExactLength() public {
        for (uint256 i; i < 2; i++) {
            bytes memory request = input(0, 0x01);
            bytes memory short = new bytes(REQUEST_LENGTH - 1);
            for (uint256 b; b < short.length; b++) {
                short[b] = request[b];
            }
            assertFalse(submit(registrations[i], short));
            assertFalse(submit(registrations[i], bytes.concat(request, hex"00")));
        }
    }

    function filled(bytes1 b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; i++) {
            out[i] = b;
        }
    }
}
