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
    uint256 internal constant MAX_PQ_LENGTH = 8192;
    uint64 internal constant MAX_STAKE_ID = 2 ** 40 - 1;

    bytes internal blsPubkey = new bytes(48);
    bytes internal blsSignature = new bytes(96);

    address[2] internal registrations;

    function setUp() public {
        registrations[0] = address(new PQValidatorRegistration());
        registrations[1] = address(new PQBuilderRegistration());
        for (uint256 i; i < 2; i++) {
            systemCall(registrations[i]);
        }
    }

    function input(
        uint64 stakeId,
        bytes memory blsPk,
        bytes memory blsSig,
        bytes memory pqPk,
        bytes memory pqSig
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(stakeId, blsPk, blsSig, uint16(pqPk.length), pqPk, pqSig);
    }

    function input(uint64 stakeId, bytes memory pqPk, bytes memory pqSig)
        internal
        view
        returns (bytes memory)
    {
        return input(stakeId, blsPubkey, blsSignature, pqPk, pqSig);
    }

    function test_RegistersAgainstStakeIdFromStaking() public {
        PQStaking staking = new PQStaking(0);
        uint64 stakeId = staking.stake{value: 32 ether}(bytes32(uint256(1)), bytes32(0));
        bytes memory request = input(stakeId, hex"aabbccdd", hex"eeff");

        for (uint256 i; i < 2; i++) {
            vm.recordLogs();
            assertTrue(submit(registrations[i], request));
            Vm.Log[] memory logs = vm.getRecordedLogs();
            assertEq(logs.length, 1);
            assertEq(logs[0].topics.length, 0);
            assertEq(logs[0].data, request);
        }
    }

    /// Expected bytes from an independent Python SSZ serialization of
    /// List[RegistrationRequest] with two entries of different PQ lengths.
    function test_SystemCallReturnsSszList() public {
        for (uint256 i; i < 2; i++) {
            address reg = registrations[i];
            assertTrue(
                submit(reg, input(7, filled(0xa1, 48), filled(0xb1, 96), hex"c1c2c3", hex"d1d2"))
            );
            assertTrue(
                submit(
                    reg,
                    input(MAX_STAKE_ID, filled(0xa2, 48), filled(0xb2, 96), hex"c4", hex"d3d4d5d6")
                )
            );

            bytes memory expected = bytes.concat(
                hex"08000000ad000000",
                hex"0700000000000000",
                filled(0xa1, 48),
                filled(0xb1, 96),
                hex"a0000000a3000000c1c2c3d1d2",
                hex"ffffffffff000000",
                filled(0xa2, 48),
                filled(0xb2, 96),
                hex"a0000000a1000000c4d3d4d5d6"
            );
            assertEq(systemCall(reg), expected);
        }
    }

    /// Worst case: MAX_PER_BLOCK requests with maximum-length PQ fields, read from cold
    /// storage, must fit the EIP-7002 system call gas limit.
    function test_WorstCaseSystemCallFitsGasLimit() public {
        address reg = registrations[0];
        bytes memory request = input(0, filled(0x01, MAX_PQ_LENGTH), filled(0x02, MAX_PQ_LENGTH));
        for (uint256 i; i <= MAX_PER_BLOCK; i++) {
            assertTrue(submit(reg, request));
        }
        vm.cool(reg);

        vm.prank(SYSTEM_ADDRESS);
        uint256 gasBefore = gasleft();
        (bool ok, bytes memory out) = reg.call{gas: SYSTEM_CALL_GAS_LIMIT}("");
        uint256 used = gasBefore - gasleft();

        assertTrue(ok);
        assertEq(out.length, MAX_PER_BLOCK * (4 + 160 + 2 * MAX_PQ_LENGTH));
        assertLt(used, SYSTEM_CALL_GAS_LIMIT);
    }

    function test_FeeRisesAboveTarget() public {
        for (uint256 i; i < 2; i++) {
            address reg = registrations[i];
            for (uint64 j; j < 36; j++) {
                assertTrue(submit(reg, input(j, hex"aa", hex"bb")));
            }
            systemCall(reg);
            assertEq(feeOf(reg), 7); // excess = 36 - 2 = 34
        }
    }

    function test_AcceptsBoundaryValues() public {
        for (uint256 i; i < 2; i++) {
            assertTrue(
                submit(
                    registrations[i],
                    input(MAX_STAKE_ID, new bytes(MAX_PQ_LENGTH), new bytes(MAX_PQ_LENGTH))
                )
            );
        }
    }

    function test_RevertWhen_StakeIdExceeds40Bits() public {
        for (uint256 i; i < 2; i++) {
            assertFalse(submit(registrations[i], input(MAX_STAKE_ID + 1, hex"aa", hex"bb")));
        }
    }

    /// Calldata shorter than stake_id + BLS fields + PQ length (154 bytes) is rejected.
    function test_RevertWhen_TooShortForFixedFields() public {
        for (uint256 i; i < 2; i++) {
            (bool ok,) = registrations[i].call{value: 1}(new bytes(153));
            assertFalse(ok);
        }
    }

    function test_RevertWhen_PqFieldsEmptyOrTooLong() public {
        for (uint256 i; i < 2; i++) {
            address reg = registrations[i];
            assertFalse(submit(reg, input(0, "", hex"bb")));
            assertFalse(submit(reg, input(0, new bytes(MAX_PQ_LENGTH + 1), hex"bb")));
            assertFalse(submit(reg, input(0, hex"aa", "")));
            assertFalse(submit(reg, input(0, hex"aa", new bytes(MAX_PQ_LENGTH + 1))));
        }
    }

    function test_RevertWhen_PqPubkeyLengthExceedsCalldata() public {
        for (uint256 i; i < 2; i++) {
            bytes memory request =
                abi.encodePacked(uint64(0), blsPubkey, blsSignature, uint16(10), hex"aabbcc");
            assertFalse(submit(registrations[i], request));
        }
    }

    function filled(bytes1 b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; i++) {
            out[i] = b;
        }
    }
}
