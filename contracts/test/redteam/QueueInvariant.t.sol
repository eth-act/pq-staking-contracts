// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {PQWithdrawal} from "../../src/PQWithdrawal.sol";
import {PQConsolidation} from "../../src/PQConsolidation.sol";
import {PQValidatorRegistration} from "../../src/PQValidatorRegistration.sol";

/// Red team (rt-queue): stateful campaign. The handler drives one system contract with random
/// requests (valid and invalid, random senders, under/exact/over payment), fee-getter calls (with
/// and without value), batches that overfill the queue, and end-of-block system calls. It keeps
/// an independent model written from the EIP-7002 pseudo-code (indices, excess, count, FIFO
/// records with independently computed little-endian encoding) and compares, on every call:
/// success/failure, return data, revert data (must be empty), logs, ETH kept; and, in the
/// invariants, storage slots 0-3.
contract QueueHandler is Test {
    address internal constant SYSTEM = 0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE;
    uint256 internal constant INH = type(uint256).max;

    address public immutable target;
    uint8 public immutable kind; // 0 withdrawal, 1 consolidation, 2 registration
    uint256 public immutable maxPer;
    uint256 public immutable targetPer;

    // Model (EIP-7002 pseudo-code state).
    uint256 public mExcess = INH;
    uint256 public mCount;
    uint256 public mHead;
    uint256 public mTail;
    mapping(uint256 => bytes) internal mRecord;

    // Ghosts.
    string public mismatch; // first divergence, empty if none
    uint256 public nOk;
    uint256 public nRejected;
    uint256 public nSystemCalls;
    uint256 public nFullDequeues; // system calls that hit maxPer with entries left over
    uint256 public nResets;
    uint256 public maxDequeued;
    uint256 public maxQueueLen;
    uint256 public maxExcess;

    bytes[2] internal regValid;

    constructor(address target_, uint8 kind_, bytes[2] memory regValid_) {
        target = target_;
        kind = kind_;
        maxPer = kind_ == 1 ? 2 : 16;
        targetPer = kind_ == 1 ? 1 : 2;
        regValid = regValid_;
    }

    function diverge(string memory why) internal {
        if (bytes(mismatch).length == 0) mismatch = why;
    }

    // --- Independent reference helpers -------------------------------------------------------

    function refFee(uint256 e) public pure returns (uint256) {
        // EIP-7002 fake_exponential(1, e, 17); excess stays far below overflow in this campaign.
        uint256 i = 1;
        uint256 output;
        uint256 acc = 17;
        while (acc > 0) {
            output += acc;
            acc = (acc * e) / (17 * i);
            i += 1;
        }
        return output / 17;
    }

    function leBytes(uint64 v) internal pure returns (bytes memory b) {
        b = new bytes(8);
        for (uint256 i; i < 8; i++) {
            b[i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    function senderOf(uint256 seed) internal pure returns (address) {
        address[5] memory s = [
            address(0x1111), address(0xdead), address(0x7a11), address(type(uint160).max),
            address(uint160(uint256(keccak256(abi.encode(seed)))))
        ];
        return s[seed % 5];
    }

    // --- Actions ------------------------------------------------------------------------------

    function request(uint256 senderSeed, uint64 a, uint64 b, uint8 payMode, uint8 shape)
        public
    {
        _request(senderSeed, a, b, payMode, shape);
    }

    /// Several requests in the same block: overfills the queue beyond maxPer.
    function requestBatch(uint256 seed, uint8 k) public {
        k = uint8(bound(k, 1, kind == 2 ? 20 : 40));
        for (uint256 j; j < k; j++) {
            uint256 s = uint256(keccak256(abi.encode(seed, j)));
            // Mostly valid, small stake ids.
            _request(s, uint64(s % 2 ** 40), uint64(s >> 64), 1, uint8((s >> 128) % 8));
        }
    }

    function _build(uint256 seed, uint64 a, uint64 b, uint8 shape)
        internal
        view
        returns (bytes memory input, bool valid)
    {
        shape = shape % 8;
        if (kind == 2) {
            input = bytes.concat(regValid[seed % 2]);
            valid = true;
            if (shape == 5) {
                input[100 + (a % 2300)] ^= 0x01; // tamper signature
                valid = false;
            } else if (shape == 6) {
                input[7] ^= 0x01; // other stake id: PoP must fail
                valid = false;
            } else if (shape == 7) {
                input = bytes.concat(input, hex"00"); // wrong length
                valid = false;
            }
            return (input, valid);
        }
        if (shape >= 6) a = uint64(bound(a, 2 ** 40, type(uint64).max)); // too large
        else a = uint64(a % 2 ** 40);
        if (kind == 1) {
            if (shape == 5) b = uint64(bound(b, 2 ** 40, type(uint64).max));
            else b = uint64(b % 2 ** 40);
        }
        input = abi.encodePacked(a, b);
        valid = shape < 5 || (kind == 0 && shape == 5);
        if (shape == 4 && (a & 1) == 1) {
            // wrong length: 15 or 17 bytes
            input = (b & 1) == 1 ? bytes.concat(input, hex"01") : _trim(input);
            valid = false;
        }
    }

    function _request(uint256 senderSeed, uint64 a, uint64 b, uint8 payMode, uint8 shape)
        internal
    {
        address sender = senderOf(senderSeed);
        (bytes memory input, bool valid) = _build(senderSeed, a, b, shape);

        uint256 fee = mExcess == INH ? 0 : refFee(mExcess);
        uint256 value;
        payMode = payMode % 3;
        if (payMode == 0) value = fee == 0 ? 0 : fee - 1;
        else if (payMode == 1) value = fee;
        else value = fee + (uint256(keccak256(abi.encode(senderSeed, a))) % 1 ether);
        bool expectOk = mExcess != INH && value >= fee && valid;

        vm.deal(sender, sender.balance + value);
        uint256 balBefore = target.balance;
        // Sender == contract (0x7a11 for registration): a self-transfer leaves the balance as is.
        uint256 credited = sender == target ? 0 : value;
        vm.recordLogs();
        vm.prank(sender);
        (bool ok, bytes memory out) = target.call{value: value}(input);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        if (ok != expectOk) { diverge("request success differs from model"); return; }
        if (out.length != 0) { diverge("request returned data or revert data"); return; }
        if (!ok) {
            nRejected++;
            if (logs.length != 0) diverge("log on rejected request");
            if (target.balance != balBefore) diverge("balance changed on revert");
            return;
        }
        nOk++;
        if (target.balance != balBefore + credited) diverge("fee not kept in full");
        bytes memory expectedLog = kind == 2 ? input : abi.encodePacked(sender, input);
        if (logs.length != 1 || logs[0].topics.length != 0 || logs[0].emitter != target
                || keccak256(logs[0].data) != keccak256(expectedLog)) {
            diverge("log mismatch");
        }

        // Model: count += 1; queue[tail] = record; tail += 1.
        mCount += 1;
        mRecord[mTail] = _record(sender, input);
        mTail += 1;
        if (mTail - mHead > maxQueueLen) maxQueueLen = mTail - mHead;
    }

    /// Expected output record, built byte by byte (independent of the contract's _le64).
    function _record(address sender, bytes memory input) internal view returns (bytes memory) {
        uint64 id = uint64(bytes8(input));
        bytes memory rest = new bytes(input.length - 8);
        for (uint256 i; i < rest.length; i++) {
            rest[i] = input[i + 8];
        }
        if (kind == 2) return bytes.concat(leBytes(id), rest);
        uint64 second = uint64(bytes8(rest));
        return bytes.concat(abi.encodePacked(sender), leBytes(id), leBytes(second));
    }

    function _trim(bytes memory x) internal pure returns (bytes memory y) {
        y = new bytes(x.length - 1);
        for (uint256 i; i < y.length; i++) {
            y[i] = x[i];
        }
    }

    function feeGet(uint256 value, uint256 senderSeed) public {
        value = value % 3 == 0 ? 0 : bound(value, 1, 10 ether);
        address sender = senderOf(senderSeed);
        vm.deal(sender, value);
        vm.prank(sender);
        (bool ok, bytes memory out) = target.call{value: value}("");
        bool expectOk = value == 0 && mExcess != INH;
        if (ok != expectOk) { diverge("fee getter success differs"); return; }
        if (!ok) {
            if (out.length != 0) diverge("fee getter revert data");
            return;
        }
        if (keccak256(out) != keccak256(abi.encode(refFee(mExcess)))) diverge("fee value");
    }

    function systemCall(uint256 gasSeed) public {
        gasSeed;
        vm.recordLogs();
        vm.prank(SYSTEM);
        (bool ok, bytes memory out) = target.call{gas: 30_000_000}("");
        if (!ok) { diverge("system call reverted"); return; }
        if (vm.getRecordedLogs().length != 0) diverge("system call logged");
        nSystemCalls++;

        // Model: dequeue, update excess, reset count.
        uint256 n = mTail - mHead;
        if (n > maxPer) n = maxPer;
        bytes memory expected;
        for (uint256 i; i < n; i++) {
            expected = bytes.concat(expected, mRecord[mHead + i]);
        }
        if (keccak256(out) != keccak256(expected)) diverge("system call output (FIFO/encoding)");
        if (n > maxDequeued) maxDequeued = n;
        if (mHead + n == mTail) {
            if (mTail != 0) nResets++;
            mHead = 0;
            mTail = 0;
        } else {
            nFullDequeues++;
            mHead += n;
        }
        uint256 prev = mExcess == INH ? 0 : mExcess;
        mExcess = prev + mCount > targetPer ? prev + mCount - targetPer : 0;
        if (mExcess > maxExcess) maxExcess = mExcess;
        mCount = 0;
        vm.roll(block.number + 1);
    }
}

abstract contract QueueInvariantBase is Test {
    QueueHandler internal h;
    bytes[2] internal regValid;

    function deployTarget() internal virtual returns (address, uint8);

    function setUp() public {
        string memory json = vm.readFile("test/vectors/leanxmss_k.json");
        // Registration vectors 0 and 2 are for the validator contract at 0x7a11 (chain 31337).
        for (uint256 k; k < 2; k++) {
            string memory key = string.concat(".registrations[", vm.toString(k * 2), "]");
            regValid[k] = abi.encodePacked(
                uint64(vm.parseJsonUint(json, string.concat(key, ".stakeId"))),
                vm.parseJsonBytes32(json, string.concat(key, ".pubkey")),
                vm.parseJsonBytes(json, string.concat(key, ".signature"))
            );
        }
        (address t, uint8 kind) = deployTarget();
        h = new QueueHandler(t, kind, regValid);
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](4);
        sel[0] = QueueHandler.request.selector;
        sel[1] = QueueHandler.requestBatch.selector;
        sel[2] = QueueHandler.feeGet.selector;
        sel[3] = QueueHandler.systemCall.selector;
        targetSelector(FuzzSelector({addr: address(h), selectors: sel}));
    }

    function s(uint256 i) internal view returns (uint256) {
        return uint256(vm.load(h.target(), bytes32(i)));
    }

    function invariant_NoDivergenceFromModel() public view {
        assertEq(h.mismatch(), "");
    }

    function invariant_Slots0to3MatchModel() public view {
        assertEq(s(0), h.mExcess(), "slot 0 excess");
        assertEq(s(1), h.mCount(), "slot 1 count");
        assertEq(s(2), h.mHead(), "slot 2 head");
        assertEq(s(3), h.mTail(), "slot 3 tail");
    }

    function invariant_HeadTail() public view {
        assertLe(s(2), s(3), "head <= tail");
        if (s(2) == s(3)) assertEq(s(2), 0, "drained queue is reset");
    }

    function invariant_DequeueBound() public view {
        assertLe(h.maxDequeued(), h.maxPer());
    }

    /// Campaign coverage, one line per run, appended to redteam-out/coverage-<kind>.txt:
    /// ok rejected systemCalls fullDequeues resets maxDequeued maxQueueLen maxExcess.
    function afterInvariant() public {
        string memory line = string.concat(
            vm.toString(h.nOk()), " ", vm.toString(h.nRejected()), " ",
            vm.toString(h.nSystemCalls()), " ", vm.toString(h.nFullDequeues()), " ",
            vm.toString(h.nResets()), " ", vm.toString(h.maxDequeued()), " ",
            vm.toString(h.maxQueueLen()), " ", vm.toString(h.maxExcess())
        );
        vm.writeLine(string.concat("redteam-out/coverage-", vm.toString(h.kind()), ".txt"), line);
    }
}

contract RedteamWithdrawalInvariant is QueueInvariantBase {
    function deployTarget() internal override returns (address, uint8) {
        return (address(new PQWithdrawal()), 0);
    }
}

contract RedteamConsolidationInvariant is QueueInvariantBase {
    function deployTarget() internal override returns (address, uint8) {
        return (address(new PQConsolidation()), 1);
    }
}

contract RedteamRegistrationInvariant is QueueInvariantBase {
    function deployTarget() internal override returns (address, uint8) {
        vm.chainId(31337);
        vm.etch(address(0x7a11), address(new PQValidatorRegistration()).code);
        vm.store(address(0x7a11), 0, bytes32(type(uint256).max)); // constructor inhibitor
        return (address(0x7a11), 2);
    }
}
