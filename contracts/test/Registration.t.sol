// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PQStaking} from "../src/PQStaking.sol";
import {PQValidatorRegistration} from "../src/PQValidatorRegistration.sol";
import {PQBuilderRegistration} from "../src/PQBuilderRegistration.sol";

contract RegistrationTest is Test {
    bytes internal constant DATA = hex"aabbccdd";

    PQStaking internal staking;
    PQValidatorRegistration internal validators;
    PQBuilderRegistration internal builders;

    function setUp() public {
        staking = new PQStaking(0);
        validators = new PQValidatorRegistration();
        builders = new PQBuilderRegistration();
    }

    function test_ValidatorAndBuilderRegisterAgainstStakeIds() public {
        uint64 validatorStake = staking.stake{value: 32 ether}(bytes32(uint256(1)), bytes32(0));
        uint64 builderStake = staking.stake{value: 1 ether}(bytes32(uint256(2)), bytes32(0));

        vm.expectEmit(address(validators));
        emit PQValidatorRegistration.ValidatorRegistrationRequest(validatorStake, DATA);
        validators.register(validatorStake, DATA);

        vm.expectEmit(address(builders));
        emit PQBuilderRegistration.BuilderRegistrationRequest(builderStake, DATA);
        builders.register(builderStake, DATA);
    }

    function test_MaxStakeIdMatchesEventTreeCapacity() public view {
        assertEq(validators.MAX_STAKE_ID(), staking.MAX_EVENT_COUNT() - 1);
        assertEq(builders.MAX_STAKE_ID(), staking.MAX_EVENT_COUNT() - 1);
    }

    function test_AcceptsMaxStakeId() public {
        uint64 max = validators.MAX_STAKE_ID();
        validators.register(max, DATA);
        builders.register(max, DATA);
    }

    function test_RevertWhen_StakeIdExceeds40Bits() public {
        uint64 tooLarge = validators.MAX_STAKE_ID() + 1;

        vm.expectRevert(
            abi.encodeWithSelector(PQValidatorRegistration.InvalidStakeId.selector, tooLarge)
        );
        validators.register(tooLarge, DATA);

        vm.expectRevert(
            abi.encodeWithSelector(PQBuilderRegistration.InvalidStakeId.selector, tooLarge)
        );
        builders.register(tooLarge, DATA);
    }

    function test_RevertWhen_EmptyRegistrationData() public {
        vm.expectRevert(PQValidatorRegistration.EmptyRegistrationData.selector);
        validators.register(0, "");

        vm.expectRevert(PQBuilderRegistration.EmptyRegistrationData.selector);
        builders.register(0, "");
    }
}
