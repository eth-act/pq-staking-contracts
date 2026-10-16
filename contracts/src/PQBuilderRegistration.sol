// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title PQBuilderRegistration
/// @notice Builder registration contract. Builders create stake through `PQStaking` like
///         validators, then register against their stake ID here instead of in
///         `PQValidatorRegistration`.
/// @dev Emits a BuilderRegistrationRequest for the consensus layer, which verifies the stake and
///      `registrationData` against the stake's authorization commitment.
contract PQBuilderRegistration {
    /// @notice Stake IDs are 40-bit values; larger IDs would be truncated on the consensus layer.
    uint64 public constant MAX_STAKE_ID = 2 ** 40 - 1;

    event BuilderRegistrationRequest(uint64 indexed stakeId, bytes registrationData);

    error InvalidStakeId(uint64 stakeId);
    error EmptyRegistrationData();

    /// @param stakeId Stake to register a builder for.
    /// @param registrationData Builder credential and proof, encoded per the stake's
    ///        authorization commitment version.
    function register(uint64 stakeId, bytes calldata registrationData) external {
        if (stakeId > MAX_STAKE_ID) revert InvalidStakeId(stakeId);
        if (registrationData.length == 0) revert EmptyRegistrationData();
        emit BuilderRegistrationRequest(stakeId, registrationData);
    }
}
