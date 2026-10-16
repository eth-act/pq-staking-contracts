// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SystemRequestQueue} from "./SystemRequestQueue.sol";

/// @notice Role registration queue: binds a BLS key and a post-quantum key, each with its own
///         signature, to a stake created in `PQStaking`.
/// @dev The consensus layer verifies the stake, the keys against the stake's authorization
///      commitment, and both signatures. A rejected registration does not lose the stake.
///
///      Request calldata (exactly 2584 bytes):
///        stake_id (u64 BE) ++ bls_pubkey (48) ++ bls_signature (96) ++
///        pq_pubkey (32) ++ pq_signature (2400)
///      Log: log0, data = calldata
///      System call output: concatenated 2584-byte records, i.e. SSZ `List[RegistrationRequest]`
///      of the fixed-size container
///        RegistrationRequest {
///            stake_id: uint64, bls_pubkey: Bytes48, bls_signature: Bytes96,
///            pq_pubkey: Bytes32, pq_signature: Bytes2400
///        }
///      Each record is the calldata with stake_id converted to little-endian.
abstract contract RegistrationQueue is SystemRequestQueue {
    uint256 internal constant TARGET_REQUESTS_PER_BLOCK = 2;
    uint256 internal constant MAX_REQUESTS_PER_BLOCK = 16;
    uint256 internal constant PQ_PUBKEY_LENGTH = 32;
    uint256 internal constant PQ_SIGNATURE_LENGTH = 2400;

    /// @dev stake_id (8) + bls_pubkey (48) + bls_signature (96) + pq_pubkey + pq_signature.
    uint256 internal constant REQUEST_LENGTH = 8 + 48 + 96 + PQ_PUBKEY_LENGTH + PQ_SIGNATURE_LENGTH;

    /// @dev Raw request calldata, validated on entry.
    mapping(uint256 index => bytes) private queue; // slot 4

    function _addRequest(uint256 index, bytes calldata input) internal override {
        if (input.length != REQUEST_LENGTH) revert();
        _checkStakeId(uint64(bytes8(input[0:8])));
        queue[index] = input;
        _log0(input);
    }

    function _targetRequestsPerBlock() internal pure override returns (uint256) {
        return TARGET_REQUESTS_PER_BLOCK;
    }

    function _maxRequestsPerBlock() internal pure override returns (uint256) {
        return MAX_REQUESTS_PER_BLOCK;
    }

    function _encodeRequests(uint256 start, uint256 n)
        internal
        view
        override
        returns (bytes memory out)
    {
        out = new bytes(REQUEST_LENGTH * n);
        uint256 pos;
        for (uint256 i; i < n; i++) {
            bytes memory raw = queue[start + i];
            // stake_id is the first 8 bytes of the request.
            // forge-lint: disable-next-line(unsafe-typecast)
            pos = _write(out, pos, abi.encodePacked(_le64(uint64(bytes8(raw)))));
            pos = _copy(out, pos, raw, 8, REQUEST_LENGTH - 8);
        }
    }
}
