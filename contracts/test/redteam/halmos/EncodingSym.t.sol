// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {PQWithdrawal} from "../../../src/PQWithdrawal.sol";
import {PQConsolidation} from "../../../src/PQConsolidation.sol";

/// Red team (rt-queue): symbolic round trip through the deployed bytecode. For every caller,
/// every 16-byte input and every queue position (head <= tail, up to 3 entries already queued),
/// a request followed by system calls returns `caller ‖ le64(a) ‖ le64(b)` as the record of
/// that request. Run: halmos --contract RedteamEncodingSym --loop 20
contract RedteamEncodingSym is Test {
    address internal constant SYSTEM = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;

    PQWithdrawal internal w;
    PQConsolidation internal c;

    function setUp() public {
        w = new PQWithdrawal();
        c = new PQConsolidation();
    }

    /// Reference little-endian encoding, byte by byte.
    function le(uint64 v) internal pure returns (bytes memory b) {
        b = new bytes(8);
        for (uint256 i; i < 8; i++) {
            b[i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    function roundTrip(address t, uint256 maxPer, address caller, uint64 a, uint64 b,
        uint256 head, uint256 queued) internal {
        vm.assume(caller != SYSTEM);
        vm.assume(head < 2 ** 64);
        vm.store(t, 0, 0); // excess 0: fee 1 wei
        vm.store(t, bytes32(uint256(2)), bytes32(head));
        vm.store(t, bytes32(uint256(3)), bytes32(head + queued));
        vm.deal(caller, 1);
        vm.prank(caller);
        (bool ok,) = t.call{value: 1}(abi.encodePacked(a, b));
        if (!ok) {
            // Only the 40-bit checks may reject a paid 16-byte request.
            assertTrue(a >= 2 ** 40 || (maxPer == 2 && b >= 2 ** 40));
            return;
        }
        assertTrue(a < 2 ** 40);
        if (maxPer == 2) assertTrue(b < 2 ** 40);
        // Drain: our request is the last of queued + 1 entries.
        uint256 total = queued + 1;
        bytes memory out;
        while (total > 0) {
            vm.prank(SYSTEM);
            (bool sok, bytes memory o) = t.call("");
            assertTrue(sok);
            uint256 n = total > maxPer ? maxPer : total;
            assertEq(o.length, 36 * n);
            total -= n;
            out = o;
        }
        // Last record of the final batch is ours.
        bytes memory rec = new bytes(36);
        for (uint256 i; i < 36; i++) {
            rec[i] = out[out.length - 36 + i];
        }
        assertEq(rec, bytes.concat(abi.encodePacked(caller), le(a), le(b)));
        assertEq(uint256(vm.load(t, bytes32(uint256(2)))), 0, "head reset");
        assertEq(uint256(vm.load(t, bytes32(uint256(3)))), 0, "tail reset");
    }

    /// `queued` must be concrete for halmos (it sizes the output); branch on q.
    function nQueued(uint8 q) internal pure returns (uint256) {
        q = q % 4;
        if (q == 0) return 0;
        if (q == 1) return 1;
        if (q == 2) return 2;
        return 3;
    }

    function check_withdrawalRoundTrip(address caller, uint64 a, uint64 b, uint256 head, uint8 q)
        public
    {
        roundTrip(address(w), 16, caller, a, b, head, nQueued(q));
    }

    function check_consolidationRoundTrip(address caller, uint64 a, uint64 b, uint256 head,
        uint8 q) public {
        roundTrip(address(c), 2, caller, a, b, head, nQueued(q));
    }
}
