// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SystemRequestQueue} from "./SystemRequestQueue.sol";

/// @notice Role registration queue: binds a BLS key and a post-quantum key, each with its own
///         signature, to a stake created in `PQStaking`.
/// @dev The consensus layer verifies the stake, the keys against the stake's authorization
///      commitment, and both signatures. A rejected registration does not lose the stake.
///      PQ key and signature sizes are not fixed yet; each is capped at 8192 bytes so that
///      dequeuing `MAX_REQUESTS_PER_BLOCK` worst-case requests fits in the 30M-gas system call.
///
///      Request calldata (variable):
///        stake_id (u64 BE) ++ bls_pubkey (48) ++ bls_signature (96) ++
///        pq_pubkey_length (u16 BE) ++ pq_pubkey ++ pq_signature (rest of calldata)
///      Log: log0, data = calldata
///      System call output: SSZ `List[RegistrationRequest]` with
///        RegistrationRequest {
///            stake_id: uint64, bls_pubkey: Bytes48, bls_signature: Bytes96,
///            pq_pubkey: ByteList[8192], pq_signature: ByteList[8192]
///        }
abstract contract RegistrationQueue is SystemRequestQueue {
    uint256 internal constant TARGET_REQUESTS_PER_BLOCK = 2;
    uint256 internal constant MAX_REQUESTS_PER_BLOCK = 16;
    uint256 internal constant MAX_PQ_PUBKEY_LENGTH = 8192;
    uint256 internal constant MAX_PQ_SIGNATURE_LENGTH = 8192;

    /// @dev Calldata layout offsets.
    uint256 private constant BLS_PUBKEY_OFFSET = 8;
    uint256 private constant BLS_SIGNATURE_OFFSET = 56;
    uint256 private constant PQ_LENGTH_OFFSET = 152;
    uint256 private constant PQ_PUBKEY_OFFSET = 154;

    /// @dev SSZ fixed part: stake_id (8) + bls_pubkey (48) + bls_signature (96) + 2 offsets (4 each).
    ///      An SSZ entry is therefore 6 bytes longer than its calldata (8 offset bytes in place
    ///      of the 2-byte length).
    uint32 private constant SSZ_FIXED_LENGTH = 160;

    /// @dev Raw request calldata, validated on entry.
    mapping(uint256 index => bytes) private queue; // slot 4

    function _addRequest(uint256 index, bytes calldata input) internal override {
        if (input.length < PQ_PUBKEY_OFFSET) revert();
        _checkStakeId(uint64(bytes8(input[0:BLS_PUBKEY_OFFSET])));
        uint256 pqPubkeyLength = uint16(bytes2(input[PQ_LENGTH_OFFSET:PQ_PUBKEY_OFFSET]));
        if (pqPubkeyLength == 0 || pqPubkeyLength > MAX_PQ_PUBKEY_LENGTH) revert();
        if (input.length <= PQ_PUBKEY_OFFSET + pqPubkeyLength) revert(); // empty PQ signature
        uint256 pqSignatureLength = input.length - PQ_PUBKEY_OFFSET - pqPubkeyLength;
        if (pqSignatureLength > MAX_PQ_SIGNATURE_LENGTH) revert();

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
        // Size the output first (reads only the length slots) so it is allocated once.
        uint256 total = 4 * n;
        for (uint256 i; i < n; i++) {
            total += queue[start + i].length + 6;
        }
        out = new bytes(total);

        // Offsets fit in uint32: output is at most MAX_REQUESTS_PER_BLOCK * (4 + 160 + 2 * 8192).
        uint256 offsetPos;
        uint256 pos = 4 * n;
        for (uint256 i; i < n; i++) {
            bytes memory raw = queue[start + i];
            uint256 pqPubkeyLength =
                (uint256(uint8(raw[PQ_LENGTH_OFFSET])) << 8) | uint8(raw[PQ_LENGTH_OFFSET + 1]);

            // forge-lint: disable-next-line(unsafe-typecast)
            offsetPos = _write(out, offsetPos, abi.encodePacked(_le32(uint32(pos))));
            // stake_id is the first 8 bytes of the request.
            // forge-lint: disable-next-line(unsafe-typecast)
            pos = _write(out, pos, abi.encodePacked(_le64(uint64(bytes8(raw)))));
            pos = _copy(out, pos, raw, BLS_PUBKEY_OFFSET, PQ_LENGTH_OFFSET - BLS_PUBKEY_OFFSET);
            pos = _write(
                out,
                pos,
                abi.encodePacked(
                    _le32(SSZ_FIXED_LENGTH),
                    // forge-lint: disable-next-line(unsafe-typecast)
                    _le32(uint32(SSZ_FIXED_LENGTH + pqPubkeyLength))
                )
            );
            pos = _copy(out, pos, raw, PQ_PUBKEY_OFFSET, raw.length - PQ_PUBKEY_OFFSET);
        }
    }
}
