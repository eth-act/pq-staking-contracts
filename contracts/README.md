# Contracts

Foundry project for the pq staking contracts. Run all commands from this directory.

| Contract | Description |
| --- | --- |
| `PQStaking` | Staking contract per [EIP-8413](https://github.com/ethereum/EIPs/pull/12306): `stake(withdrawalCredentials, authorizationCommitment) → stakeId` and `topup(stakeId)`. Stake creations and top-ups share one event index; a stake ID is the index of its `CreateStake` event. |
| `PQValidatorRegistration` | System contract. Queues a registration binding a BLS key and a PQ key, each with its own signature, to a stake. |
| `PQBuilderRegistration` | Same code; queues builder registrations. The consensus layer tells the two apart by address. |
| `PQConsolidation` | System contract. Queues a consolidation with the caller as source address. |
| `PQWithdrawal` | System contract. Queues a withdrawal with the caller as source address. Amount `0` requests a full exit, or recovery of an unregistered stake. |

Validators and builders both create stake through `PQStaking`, then register their stake ID
in the registration contract for their role. Registration carries two public keys, BLS
(48 bytes, 96-byte signature) and post-quantum (sizes not fixed yet, each capped at 8192
bytes), each with its own signature. The consensus layer verifies that the stake exists,
checks the keys against the stake's authorization commitment, and verifies both signatures.

Consolidations, partial withdrawals and exits are keyed by stake ID. The consensus layer
applies the EIP-7251 / EIP-7002 rules, checking the caller against the stake's withdrawal
credentials.

Recovery of unregistered stake reuses the withdrawal request: the consensus layer interprets
it by the stake's state.

| Stake state | Amount `0` | Amount `> 0` |
| --- | --- | --- |
| Registered validator | Full exit | Partial withdrawal |
| Unregistered | Recover full balance | Ignored |
| Registration pending, no validator yet | Ignored | Ignored |

All request contracts reject stake IDs above `2**40 - 1`.

## System contracts: fee, queue and system call

The registration, consolidation and withdrawal contracts copy the
[EIP-7002](https://eips.ethereum.org/EIPS/eip-7002) system-contract design
(`SystemRequestQueue`). They are called with raw calldata, not the Solidity ABI: they have no
ABI functions, reverts carry no data, and any implementation language can match the
bytecode's behavior. Each call is dispatched as in EIP-7002:

- **System call.** At the end of every block the client calls each contract from
  `0xfffffffffffffffffffffffffffffffffffffffe` with no calldata. The call dequeues up to the
  per-block maximum in FIFO order and returns them as raw bytes (the EIP-7685 request data).
  It also sets `excess = max(0, excess + count - target)` and resets `count`.
- **Fee getter.** Empty calldata and no value returns the current fee as a 32-byte big-endian
  word: `fake_exponential(1, excess, 17)` wei.
- **Request.** Any other calldata is a request (formats below). It must pay at least the fee.
  The contract keeps the fee and does not refund overpayment. The request is stored in the
  queue and logged with `log0` (no topics).
- **Storage.** Slots 0-3 hold `excess`, `count`, queue head and queue tail, as in EIP-7002;
  entries start at slot 4.
- **Inhibitor.** Deployment sets `excess = 2**256 - 1`, which rejects requests and fee
  queries until the first system call.

Input integers are big-endian, as in EIP-7002. Output integers are little-endian (SSZ).

| Contract | Request calldata | `log0` data | System call output | Target / max per block |
| --- | --- | --- | --- | --- |
| `PQWithdrawal` | 16 bytes: `stake_id (u64) ++ amount_gwei (u64)` | `source_address (20) ++ calldata` | 36 bytes each: `source_address ++ stake_id (u64 LE) ++ amount_gwei (u64 LE)` | 2 / 16 |
| `PQConsolidation` | 16 bytes: `source_stake_id (u64) ++ target_stake_id (u64)` | `source_address (20) ++ calldata` | 36 bytes each: `source_address ++ source_stake_id (u64 LE) ++ target_stake_id (u64 LE)` | 1 / 2 |
| `PQValidatorRegistration`, `PQBuilderRegistration` | `stake_id (u64) ++ bls_pubkey (48) ++ bls_signature (96) ++ pq_pubkey_length (u16) ++ pq_pubkey ++ pq_signature` (rest of calldata); PQ fields 1-8192 bytes | calldata | SSZ `List[RegistrationRequest]`, `RegistrationRequest { stake_id: uint64, bls_pubkey: Bytes48, bls_signature: Bytes96, pq_pubkey: ByteList[8192], pq_signature: ByteList[8192] }` | 2 / 16 |

Withdrawal and consolidation parameters match EIP-7002 / EIP-7251. The registration
parameters reuse the EIP-7002 values. With maximum-length PQ fields, a full registration
dequeue uses about 18.6M of the 30M system-call gas limit.

Example withdrawal request (full exit of stake 42) with `cast`:

```sh
fee=$(cast to-dec "$(cast call "$WITHDRAWAL_CONTRACT" 0x)")
cast send "$WITHDRAWAL_CONTRACT" "$(cast concat-hex 0x$(printf '%016x' 42) 0x0000000000000000)" --value "$fee"
```

## Using the bytecode

Every [GitHub release](https://github.com/eth-act/pq-staking-contracts/releases) ships these assets:

| File | Contents |
| --- | --- |
| `<Name>.bin` | Creation bytecode (initcode): deploy via a transaction. |
| `<Name>.bin-runtime` | Runtime bytecode: embed directly, e.g. as `code` in a genesis `alloc`. |
| `<Name>.abi.json` | ABI. |
| `bytecode.json` | All of the above plus compiler settings, in one file. |
| `SHA256SUMS` | Checksums of the files above. |

Hex files are `0x`-prefixed with no trailing newline. The CBOR metadata trailer is
stripped (`cbor_metadata = false`), so bytecode changes only when code or compiler
settings change.

Contracts must not use `immutable`: the runtime bytecode would lack the constructor-set
values, so the export script rejects them.

### Constructors and genesis storage

`PQStaking` takes `migratedValidatorCount` (validator registry length `N` at the fork,
`0` for a fresh chain). Deploying from `PQStaking.bin` requires appending the ABI-encoded
`uint64`. When embedding `PQStaking.bin-runtime` in genesis with `N > 0`, set storage slot
`0` to `(N << 64) | N` (`initialEventCount` in the low 8 bytes, `eventCount` in the next 8).

The system contracts' constructors set storage slot `0` (`excess`) to `2**256 - 1`, the
inhibitor. When embedding their `.bin-runtime` in genesis, either set slot `0` to
`0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` to keep requests
disabled until the first system call, or leave it unset to accept requests from genesis.

### Reproducing a release

Compiler settings are pinned in [`foundry.toml`](foundry.toml) (solc 0.8.30, EVM `prague`,
optimizer 200 runs).

```sh
git checkout vX.Y.Z
git submodule update --init --recursive
cd contracts
./scripts/export-bytecode.sh   # writes contracts/dist/
```

## Development

```sh
forge build
forge test
forge fmt
```
