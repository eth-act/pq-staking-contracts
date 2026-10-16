# Site

Interactive model of the staking and request contracts. The released contract bytecode runs in
an EVM in the browser ([`@ethereumjs/evm`](https://github.com/ethereumjs/ethereumjs-monorepo),
Prague rules); the consensus layer is a simplified TypeScript model.

```sh
npm install
npm run dev     # exports the contract bytecode (needs forge), then starts Vite
npm run build   # same export, then a static build in dist/
```

Both scripts run `npm run sync-contracts`, which runs `contracts/scripts/export-bytecode.sh` and
copies `contracts/dist/bytecode.json` to `src/generated/` (git-ignored). The site therefore runs
exactly the bytecode a release from the same commit would ship.

## What is real and what is modeled

| Layer | Source | Notes |
| --- | --- | --- |
| Contracts, fees, queues, encodings, reverts | Real bytecode in the in-browser EVM | `src/chain/` |
| End of block | `SYSTEM_ADDRESS` calls to each system contract | Returned bytes are decoded and shown |
| Staking logs | `CreateStake` / `TopUp` events, read like deposit logs today | |
| Consensus layer | Model in `src/sim/consensus.ts` | Follows EIP-8413 and issue #1; delays, churn and balances simplified |
| Keys and signatures | Random keys, mock signatures the model can check | Sizes follow the chosen PQ scheme |
| Authorization commitment | `0x01 ‖ sha256(bls_pubkey ‖ pq_pubkey)[1:]` | Demo assumption; EIP-8413 defines a BLS-only version |

The chain starts with 3 migrated validators (stake IDs 0–2) so new stake IDs start at 3.

## Layout

- `src/chain/chain.ts`: EVM setup, deployment, raw calls, system calls, queue storage reads.
- `src/chain/encoding.ts`: request calldata, system-call output decoders, credentials.
- `src/sim/consensus.ts`: consensus-layer model.
- `src/sim/simulation.ts`: actors and actions; `nextBlock()` runs the system calls and feeds the model.
- `src/ui/`: operation forms, state panels, labeled byte views.

## Deployment

`.github/workflows/site.yml` builds and deploys to GitHub Pages on every push to `main`.
Enable it once under Settings → Pages → Source: GitHub Actions. CI (`ci.yml`) also builds the
site on every PR.
