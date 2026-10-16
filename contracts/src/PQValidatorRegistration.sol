// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title PQValidatorRegistration
/// @notice Validator registration contract per EIP-8413. Binds a validator credential to a
///         stake created in `PQStaking`.
/// @dev Emits a ValidatorRegistrationRequest for the consensus layer, which verifies that the
///      stake exists, that `registrationData` opens the stake's authorization commitment, and
///      the registration proof. A rejected registration does not lose the stake.
contract PQValidatorRegistration {
    /// @notice Stake IDs are 40-bit values; larger IDs would be truncated on the consensus layer.
    uint64 public constant MAX_STAKE_ID = 2 ** 40 - 1;

    event ValidatorRegistrationRequest(uint64 indexed stakeId, bytes registrationData);

    error InvalidStakeId(uint64 stakeId);
    error EmptyRegistrationData();

    /// @param stakeId Stake to register a validator for.
    /// @param registrationData Credential and proof, encoded per the stake's authorization
    ///        commitment version (for BLS: public key and proof of possession).
    function register(uint64 stakeId, bytes calldata registrationData) external {
        if (stakeId > MAX_STAKE_ID) revert InvalidStakeId(stakeId);
        if (registrationData.length == 0) revert EmptyRegistrationData();
        emit ValidatorRegistrationRequest(stakeId, registrationData);
    }
}
