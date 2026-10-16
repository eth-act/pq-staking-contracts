# Contracts

Foundry project for the pq staking contracts. Run all commands from this directory.

| Contract | Description |
| --- | --- |
| `PQStaking` | Staking contract per [EIP-8413](https://github.com/ethereum/EIPs/pull/12306): `stake(withdrawalCredentials, authorizationCommitment) → stakeId` and `topup(stakeId)`. Stake creations and top-ups share one event index; a stake ID is the index of its `CreateStake` event. |
| `PQValidatorRegistration` | `register(stakeId, registrationData)`: emits `ValidatorRegistrationRequest` to bind a validator credential to a stake. |
| `PQBuilderRegistration` | `register(stakeId, registrationData)`: emits `BuilderRegistrationRequest` to register a builder against a stake. |

Validators and builders both create stake through `PQStaking`, then register their stake ID
in the registration contract for their role. The consensus layer verifies that the stake exists
and checks the registration data against the stake's authorization commitment.

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

### `PQStaking` constructor and genesis storage

The constructor takes `migratedValidatorCount` (validator registry length `N` at the fork,
`0` for a fresh chain). Deploying from `PQStaking.bin` requires appending the ABI-encoded
`uint64`. When embedding `PQStaking.bin-runtime` in genesis with `N > 0`, set storage slot
`0` to `(N << 64) | N` (`initialEventCount` in the low 8 bytes, `eventCount` in the next 8).

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
