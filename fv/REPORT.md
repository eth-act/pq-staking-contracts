# fv: formal-verification red-team report

Target: `eth-act/pq-staking-contracts` @ `2e7d21f`. Worktree `/home/kev/work/pq-fv`, branch
`redteam/fv` (pushed; final commit is `2809567` or later). Nothing was merged and no PR was opened.

**Bottom line.** No new contract bug was found. Every property in FV.md was either proved or pinned
to an explicit precondition. One data-carrying revert is reachable: the `Panic(0x11)` from the fee
overflow, which **rt-queue had already filed as #5**. I added FV evidence to #5 as a comment rather
than opening a duplicate. The `uint64` amount truncation is already #3. Both are re-derived below as
preconditions.

## Tool choice

| Target | Tool | Why |
| --- | --- | --- |
| SystemRequestQueue, PQWithdrawal, PQConsolidation, RegistrationQueue (queue part), PQStaking | **Halmos 0.3.3** (yices) | Symbolically executes the **compiled runtime bytecode** inside Foundry. Each check starts from **arbitrary symbolic storage**, constrained only by an invariant, and runs one call. A PASS therefore proves the invariant is inductive and that every call matches the spec. Fast: 54 checks run in about 60 s. |
| Fee function | Exhaustive concrete run on bytecode | The domain is finite: 2,893 non-overflowing excess values plus a monotone overflow tail. Checking all of them is a proof. Symbolic execution of the division loop would be nonlinear. |
| `LeanXmssK` | **Lean 4** (v4.29.0, core + `bv_decide`, no Mathlib) | The verifier's control flow forks on 58 base-4 digits per layer (4^58 paths), so Halmos, hevm and Kontrol all hit path explosion. Lean proves the loops by induction instead. I used a direct Lean model rather than **Verity**: Verity's SPHINCS− proof also rests on a hand transcription of the assembly ("the Lean models match the Solidity source … rests on manual review") and took about 12k lines of proof. For a 60-line Yul block, a direct transcription gives the same guarantee in 831 lines that check in 4 s. |
| `LeanXmssK` and PoP: model vs bytecode | anvil `debug_traceCall` + memory | Closes the transcription gap without trusting a re-model. I extract every `KECCAK256` preimage from EVM memory and require it to equal the Lean spec's hash inputs, in order. |
| Kontrol / Certora | not used | K setup cost and the same 4^58 explosion. Certora would add no bytecode-level guarantee beyond Halmos for the queue code. |

Mutation check against vacuous specs (`fv/mutants.py`): 14 injected bugs, **13 killed**. The one
that survived loosens the registration length check to `< 2440`. It is an *equivalent* mutant for
the rejection property: `LeanXmssK.verify` itself returns false when `signature.length != 2400`,
so 2441-byte requests still revert. This is noted under precondition R2.

## Results by property

### 1. SystemRequestQueue + PQWithdrawal / PQConsolidation (Halmos, bytecode)

Files: `contracts/test/fv/QueueFV.t.sol`, `FeeExhaustive.t.sol`, `QueuePreconditions.t.sol`.
Command: `fv/run_halmos.sh final 1200 4 …` produced `fv/logs/summary_final.txt` with 54/54 PASS
and 0 "not fully explored" warnings.

**Invariant INV** (holds from deployment; I proved it inductive):
- `head ≤ tail < 2^64`
- `count ≤ tail − head`
- `excess = 2^256−1 ∨ excess < 2^64`
- `excess = 2^256−1 ⇒ count = head = tail = 0`

| Property | Statement checked | Result |
| --- | --- | --- |
| No reachable ABI selector | All 4 runtimes contain no `SHR 0xe0` dispatcher. The only `PUSH4` constants are `0x4e487b71` (Panic) and `0xffffffff` masks. `methodIdentifiers` is empty. Halmos: for symbolic 16-byte calldata (any first 4 bytes) the call is a request exactly as specified. | proved |
| Request path | For calldata lengths {0, 1, 15, 16, 17, 32} and excess ∈ {0, 11 (fee 1), 34 (fee 7), 2892 (fee ≈7.6e73), inhibitor}, with symbolic sender, value (uint256), calldata, `count`, `head`, `tail` and queue contents: <br>• accepted ⇔ not inhibited ∧ value ≥ fee ∧ len = 16 ∧ stake ID(s) ≤ 2^40−1 <br>• on accept: `count+1`, `tail+1`, entry at `keccak(tail‖4)` = `source | id₁<<160` and `id₂`/amount in the next slot, `excess` and `head` unchanged, balance += value, empty return data <br>• on reject: **empty revert data**, all storage and the balance unchanged <br>• fee getter (len 0, value 0) returns exactly `abi.encode(fee)`, and reverts when value ≠ 0 | proved (26 checks) |
| System call never reverts, ≤ max dequeued, FIFO, reset, excess, count | For `tail − head` ∈ {0, 1, 2, 3, 16, 17, 40}, with symbolic head, count, excess (INV) and arbitrary queue contents, and calldata empty or 16 symbolic bytes: <br>• `ok` <br>• output = `concat_{i<min(max, tail−head)} source‖LE64(f₁)‖LE64(f₂)` of entries `head+i`, using an independent byte-loop LE encoder <br>• drained ⇒ `head = tail = 0`, else `head += n` <br>• `excess' = max(0, (excess==INHIB?0:excess) + count − target)` <br>• `count' = 0` | proved (16 checks) |
| Fee = fake_exponential(1, excess, 17) | Fee getter on PQWithdrawal, PQConsolidation and PQValidatorRegistration bytecode vs the EIP-7002 reference with unbounded ints, **for every excess in [0, 2892]**. Reverts for [2893, 4893) and for {2^64, 2^128, 2^255, 2^256−2}. Overflow is monotone in excess (each loop term is non-decreasing), so 2893 is the exact boundary. | proved (exhaustive); boundary = #5 |
| Inhibitor | Inhibited ⇒ fee getter and every request revert with empty data. The first system call sets `excess = max(0, count − target) = 0`. | proved |
| Output encoding matches spec | Covered by the system-call row, against an independent LE encoder. The log encoding is not covered by Halmos (no `recordLogs`); the existing concrete tests check it. | proved (output), tested (logs) |
| Funds | No `CALL`/`CALLCODE`/`DELEGATECALL`/`STATICCALL`/`SELFDESTRUCT`/`CREATE`/`CREATE2` in any runtime. Fees can never leave. | proved (opcode scan) |

### 2. PQStaking (Halmos, bytecode)

File: `contracts/test/fv/StakingFV.t.sol`. 4/4 PASS.

**INV:**
- `initialEventCount ≤ eventCount ≤ 2^40`
- `∀k. createdStake[k] ⇒ initialEventCount ≤ k < eventCount`

The quantifier is instantiated at every touched key plus one arbitrary frame key.

| Property | Result |
| --- | --- |
| `stake`: succeeds ⇔ `value ≥ 1 ether ∧ value % 1 gwei = 0 ∧ eventCount < 2^40`. Returns `stakeId = old eventCount`; `eventCount+1`; `createdStake[id]` set; balance += value; other keys untouched; INV preserved. | proved |
| `topup`: succeeds ⇔ `isStake(id) ∧` the same amount and capacity rules. The consumed index has `createdStake = false` and `isStake = false`, so **top-up indices are never stake IDs**. | proved |
| Stake IDs are unique and strictly increasing; `eventCount` is monotone (+1 per event); every consumed index is < 2^40 (`eventCount ≤ 2^40`). | proved (follows from the two rows above) |
| `isStake(id) ⇔ id < initialEventCount ∨ createdStake[id]` | proved |
| No other entry point: any non-ABI selector and empty calldata revert (no fallback or receive), with any value. | proved |
| Balance only increases: no value-moving opcode in the runtime. | proved (opcode scan) |

### 3. RegistrationQueue + LeanXmssK

**LeanXmssK ≡ spec (Lean).** `fv/lean/LeanXmssK/{Spec,Model,Bits,Proofs}.lean`. Check with
`cd fv/lean && lake build` (4 s, 0.8 GB).
- `Spec.lean` transcribes `xmss/README.md` independently: tweak = `struct.pack(">BBIIBB4x")` as `BitVec` append, chains, digits `(d >> (254−2k)) & 3`, sum 106, leaf, Merkle left/right, top/bottom layers.
- `Model.lean` transcribes `_layerRoot` / `verify` statement by statement. It uses 256-bit EVM word semantics and the exact byte offsets.
- **Theorem `verifyM_eq_verify`**: for every hash function `K`, public key, `slot : u32`, message, signature and **arbitrary initial scratch memory**, `verifyM K pk slot msg sig m0 = verify K pk slot msg sig`. Keccak is abstract, so no property of it is assumed. No `sorry`.
- `#print axioms`: Lean's `propext`, `Classical.choice`, `Quot.sound`, plus the `bv_decide` native-LRAT-checker axioms for the 17 bit-level lemmas (tweak packing, masks, shifts).

What the theorem pins down, and why each is correct:
- tweak field positions and widths
- the top layer uses (layer 0, tree 0); the bottom layer uses (layer 1, tree `slot>>16`, leaf `slot&0xffff`)
- chain index and position bytes
- level `h` = 1…16 and node index `idx>>1`
- left/right child order by the parity of `idx`
- 16-byte truncation applied to every hash except the message digest (which stays 32 bytes, as specified)
- the digit sum uses exactly 58 digits from the top of `d`
- the root comparison uses `pubkey & HIGH_128`, and `P` = the low 16 bytes of the pubkey
- calldata over-reads past a layer's 1200 bytes (`calldataload` at 1184 reads 32 bytes) are always masked off
- the overlapping 32-byte chain-end stores at `buf+0xa0+16i` never corrupt an earlier end; the stray 16 zero bytes land at `buf+1088..1104`, outside the hashed range

**Memory safety.** By construction of the model, which the proof checks:
- writes stay within `[fp, fp+1104)`
- `keccak256` reads stay within `[fp, fp+1088)`
- the free pointer is never moved, and the result holds for any prior content

That is the "temporary scratch past the free pointer" use that the `memory-safe` annotation allows.

**Model ↔ compiled bytecode** (`fv/trace_diff.py`, log `fv/logs/trace_diff.txt`): **207/207 agree**.
- Cases: the reference vectors (generic slot `0x30005` with mixed left/right, PoP slot, 3 registrations), wrong key, wrong slot, and 200 random 1-bit mutations of chain values, auth nodes, ρ or any byte.
- For each case, the sequence of `KECCAK256` preimages read from EVM memory equals the spec's hash inputs **in order**. That is 172 hashes on valid signatures, 87 on top-layer failures and 1 on digest failures.
- The distinct preimages of the Lean model run with real Keccak (`Trace/Keccak.lean`) equal the spec's, and all three verdicts agree.

So the transcription is faithful on every executed path shape, and the theorem covers all inputs.

**PoP message binding (bytecode)** (`fv/pop_trace.py`, log `fv/logs/pop_trace.txt`): **500/500 agree**.
- Inputs: random chain IDs (1, 31337, 17000, random u64), random contract addresses, stake IDs (random, 2^40−1, 2^40, random > 2^40), pubkeys and lengths.
- First hash preimage = `K("leanXMSS-K registration proof of possession v1") ‖ chain_id(32 BE) ‖ address(this)(20) ‖ stake_id(8 BE) ‖ pubkey(32)`.
- Second preimage = `P ‖ T(3, 1, 0xFFFF, 0xFFFF) ‖ ρ_bottom ‖ M`, i.e. verified at slot 2^32−1.
- Length ≠ 2440 or stake ID > 2^40−1 ⇒ revert with empty data and **no hash computed**: the verifier never runs.

**Halmos, registration** (`RegistrationFV.t.sol`, 8/8 PASS):
- Lengths {1, 16, 2439, 2441} and 2440-byte requests with stake ID > 2^40−1 revert with empty data and leave `excess`, `count`, `head`, `tail` unchanged, for any sender, value or queue state.
- The system call with 0, 1 or 2 queued 2440-byte entries (arbitrary contents) returns exactly `LE64(stake_id) ‖ raw[8:2440]` per entry, resets the queue and updates excess/count.
- Max-dequeue for registration uses the same `_processSystemCall` bytecode proved above. Its worst-case gas (16 cold records) is **2,786,964** (`test_FullBlockSystemCallFitsGasLimit` trace), under the 30M limit.

## Preconditions and invariants the docs don't state

| # | Precondition / invariant | What breaks otherwise | Evidence |
| --- | --- | --- | --- |
| Q1 | `excess ≤ 2892` for any non-system call to succeed or revert *without data* | Fee getter and requests revert with `Panic(0x11)`. Reachable in one block: 2,895 one-wei requests cost 101.4M gas on fresh queue slots, **44.0M gas on previously used slots**. A multi-block climb fails because the fee compounds. | #5 plus my comment; `FeeExhaustive.t.sol` |
| Q2 | Genesis `alloc` for system contracts must keep INV: `head ≤ tail`, and `excess + count < 2^256` when not inhibited. The README only discusses slot 0. | The end-of-block system call reverts (Panic 0x11), which invalidates every block. | `QueuePreconditions.t.sol` |
| Q3 | Within a block the fee is constant (EIP-7002 design), so one block can add `count − target` to excess at the current fee. | Cheap fee spikes and request DoS for about `(excess − e_affordable)/target` blocks. Inherited from EIP-7002, not a contract bug. | analysis + PoC numbers |
| Q4 | Storage layout is a keccak mapping at slot 4 (matches #6). Slot-0 bits 224–255 of withdrawal/consolidation entries are never written. | Tooling reading EIP-7002 slots sees zeros. | Halmos entry-layout assertions |
| Q5 | `count += 1` and `tail = index + 1` are written *before* `_addRequest` validates. Rejection relies on the revert to roll them back. | Nothing today. A future refactor that catches the revert or splits the frame would leak state. | `pop_trace.py` (2 SSTOREs on rejected requests, `failed=true`) |
| S1 | `msg.value < 2^64 gwei` | `amountGwei` wraps (#3). Unreachable on mainnet. | `StakingPreconditions.t.sol::test_P1` |
| S2 | Genesis slot 0 = `(N<<64)|N` **with N < 2^40** (the constructor enforces this, genesis does not) and `eventCount ≥ initialEventCount` | N ≥ 2^40 makes every stake and top-up revert forever. `eventCount < initialEventCount` makes new stake IDs collide with migrated validator indices. | `test_P2_*` |
| S3 | `eventCount` reaches **2^40** after the last index; the invariant is `index < 2^40`, `eventCount ≤ 2^40`. FV.md's "`eventCount < 2^40`" is off by one. | — | StakingFV |
| R1 | `LeanXmssK.verify` needs no precondition on its inputs: it is correct for every pubkey, slot, message, signature and memory state. It assumes nothing about scratch memory and doesn't bump the free pointer. | — | Lean theorem |
| R2 | The `!= 2440` length check in `RegistrationQueue` is partly redundant: for length > 2440 the verifier's own `signature.length != 2400` rejects. For length < 40, `input[40:]` would revert. | Removing either check alone stays safe. Removing both does not. | surviving equivalent mutant |
| R3 | One PoP per key ever (PoP leaf is one-time) | PoP forgery across stakes, roles and chains: #2 (rt-xmss). Outside what an implementation-equivalence proof can see. The Lean theorem shows the verifier is exact, so the weakness is in the scheme or protocol. | #2 |

## What remains unproved

- **Model fidelity is not a theorem.** `Model.lean` is a hand transcription, as in Verity's approach. The gap is closed empirically, not formally: 207 bytecode-trace differentials compare hash preimages *and order*. These exercise every digit value, both Merkle branches, both layers and every early-exit path. A Lean EVM-bytecode semantics would close it formally, but that is not done.
- The **chunk memory abstraction** (16-byte-aligned accesses relative to the free pointer) holds by inspection of the offsets. It is not derived from a byte-level EVM memory model.
- Halmos request checks use **5 concrete excess values**. The general fee dependence is covered by the exhaustive fee table, and the composition rests on the code structure: the request path depends on excess only through `_getFee`.
- Registration requests that **pass** the length and stake-ID checks (and so enter the verifier) are not symbolically executed. They are covered by the Lean theorem plus `pop_trace.py`.
- Halmos has no log support, so `log0` contents are only covered by the existing concrete tests.
- Gas: only the registration worst case was measured. Withdrawal and consolidation system calls are much smaller. No gas proof.
- Cryptographic security of leanXMSS-K (unforgeability, PoP reuse) is out of scope; see #2.

## Issues

- Opened: **none**. Everything I found was already filed.
- Commented: **#5**, adding the exhaustive bytecode table for three contracts, the exact boundary, 44.0M vs 101.4M gas, the single-block requirement, and the fact that all other revert paths carry empty data.
- Same findings as mine, already filed: **#3** (amount truncation = S1), **#6** (layout = Q4).

## Reproduce (from `contracts/` in the worktree)

```sh
forge test                                   # 51 concrete tests incl. fv/ (fee table, PoC, preconditions)
forge clean && ../fv/run_halmos.sh final 1200 4 <Contract:check…>   # 54/54 PASS, see logs/summary_final.txt
python3 ../fv/mutants.py                     # 13/14 killed, 1 equivalent
cd ../fv/lean && lake build && lake env lean Axioms.lean            # theorem + axioms
lake build trace                             # executable model/spec with real Keccak
anvil --port 18545 &  # then:
python3 ../trace_diff.py http://127.0.0.1:18545 <harness addr> 200 # 207/207
xmss/.venv/bin/python ../pop_trace.py http://127.0.0.1:18545 500 # 500/500
```
