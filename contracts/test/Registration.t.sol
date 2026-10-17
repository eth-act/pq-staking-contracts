// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Vm} from "forge-std/Vm.sol";
import {SystemCallTest} from "./helpers/SystemCallTest.sol";
import {PQStaking} from "../src/PQStaking.sol";
import {PQValidatorRegistration} from "../src/PQValidatorRegistration.sol";
import {PQBuilderRegistration} from "../src/PQBuilderRegistration.sol";

/// Proofs of possession come from xmss/gen_vectors.py. They bind chain id 31337 and the
/// registration contract address, so the contracts are etched at the addresses used there.
contract RegistrationTest is SystemCallTest {
    uint256 internal constant SYSTEM_CALL_GAS_LIMIT = 30_000_000;
    uint256 internal constant MAX_PER_BLOCK = 16;
    uint256 internal constant REQUEST_LENGTH = 2440; // 8 + 32 + 2400

    address internal constant VALIDATORS = address(0x7a11);
    address internal constant BUILDERS = address(0xb111);

    string internal json;

    function setUp() public {
        vm.etch(VALIDATORS, address(new PQValidatorRegistration()).code);
        vm.etch(BUILDERS, address(new PQBuilderRegistration()).code);
        json = vm.readFile("test/vectors/leanxmss_k.json");
        assertEq(block.chainid, vm.parseJsonUint(json, ".chainId"));
    }

    /// Request calldata for registration vector `i`: stake_id ‖ pq_pubkey ‖ signature.
    function vector(uint256 i) internal view returns (address contract_, bytes memory request) {
        string memory key = string.concat(".registrations[", vm.toString(i), "]");
        contract_ = vm.parseJsonAddress(json, string.concat(key, ".contract"));
        request = abi.encodePacked(
            uint64(vm.parseJsonUint(json, string.concat(key, ".stakeId"))),
            vm.parseJsonBytes32(json, string.concat(key, ".pubkey")),
            vm.parseJsonBytes(json, string.concat(key, ".signature"))
        );
        assertEq(request.length, REQUEST_LENGTH);
    }

    function test_AcceptsValidProofsOfPossession() public {
        for (uint256 i; i < 3; i++) {
            (address reg, bytes memory request) = vector(i);
            vm.recordLogs();
            assertTrue(submit(reg, request));
            Vm.Log[] memory logs = vm.getRecordedLogs();
            assertEq(logs.length, 1);
            assertEq(logs[0].topics.length, 0);
            assertEq(logs[0].data, request);
        }
    }

    function test_RegistersStakeCreatedInStaking() public {
        PQStaking staking = new PQStaking(3);
        uint64 stakeId = staking.stake{value: 32 ether}(bytes32(uint256(1)), bytes32(0));
        (address reg, bytes memory request) = vector(0);
        assertEq(uint64(bytes8(request)), stakeId);
        assertTrue(submit(reg, request));
    }

    /// Output records are the calldata with stake_id little-endian.
    function test_SystemCallReturnsRecordsWithLittleEndianStakeId() public {
        (, bytes memory first) = vector(0); // stake 3
        (, bytes memory second) = vector(2); // stake 4
        assertTrue(submit(VALIDATORS, first));
        assertTrue(submit(VALIDATORS, second));

        bytes memory expected =
            bytes.concat(hex"0300000000000000", tail(first), hex"0400000000000000", tail(second));
        assertEq(systemCall(VALIDATORS), expected);
    }

    function test_RevertWhen_SignatureTampered() public {
        (address reg, bytes memory request) = vector(0);
        for (uint256 offset = 40; offset < REQUEST_LENGTH; offset += 397) {
            bytes memory tampered = bytes.concat(request);
            tampered[offset] ^= 0x01;
            assertFalse(submit(reg, tampered));
        }
    }

    /// The proof binds stake_id: the same signature for another stake is rejected.
    function test_RevertWhen_StakeIdChanged() public {
        (address reg, bytes memory request) = vector(0);
        request[7] = 0x09;
        assertFalse(submit(reg, request));
    }

    /// The proof binds the contract: a validator proof cannot register a builder, or vice versa.
    function test_RevertWhen_ReplayedIntoOtherRole() public {
        (, bytes memory validatorRequest) = vector(0);
        (, bytes memory builderRequest) = vector(1);
        assertFalse(submit(BUILDERS, validatorRequest));
        assertFalse(submit(VALIDATORS, builderRequest));
    }

    /// The proof binds the chain id.
    function test_RevertWhen_OtherChain() public {
        (address reg, bytes memory request) = vector(0);
        vm.chainId(1);
        assertFalse(submit(reg, request));
    }

    function test_RevertWhen_StakeIdExceeds40Bits() public {
        (address reg, bytes memory request) = vector(0);
        request[2] = 0x01; // stake_id = 2**40 + 3
        assertFalse(submit(reg, request));
    }

    function test_RevertWhen_NotExactLength() public {
        (address reg, bytes memory request) = vector(0);
        assertFalse(submit(reg, bytes.concat(request, hex"00")));
        bytes memory short = new bytes(REQUEST_LENGTH - 1);
        for (uint256 b; b < short.length; b++) {
            short[b] = request[b];
        }
        assertFalse(submit(reg, short));
    }

    function test_FeeRisesAboveTarget() public {
        (address reg, bytes memory request) = vector(0);
        for (uint256 j; j < 36; j++) {
            assertTrue(submit(reg, request));
        }
        systemCall(reg);
        assertEq(feeOf(reg), 7); // excess = 36 - 2 = 34
    }

    /// Worst case: MAX_PER_BLOCK requests read from cold storage fit the system call gas limit.
    function test_FullBlockSystemCallFitsGasLimit() public {
        (address reg, bytes memory request) = vector(0);
        for (uint256 i; i <= MAX_PER_BLOCK; i++) {
            assertTrue(submit(reg, request));
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

    function tail(bytes memory request) internal pure returns (bytes memory out) {
        out = new bytes(request.length - 8);
        for (uint256 i; i < out.length; i++) {
            out[i] = request[i + 8];
        }
    }
}
