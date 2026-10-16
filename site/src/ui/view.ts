// Plain snapshots of the simulation for rendering. The simulation is mutable; React and motion
// need fresh objects per state to diff and animate.
import { type Hex, formatEther } from 'viem'
import { SYSTEM_CONTRACTS, type SystemContract } from '../chain/chain'
import { withdrawalAddressOf } from '../chain/encoding'
import type { ClEvent, Role, StakeStatus } from '../sim/consensus'
import { ACTORS, type QueuedRequest, type Simulation, type TxKind } from '../sim/simulation'

export interface TxView {
  id: number
  kind: TxKind
  title: string
  actor: string
  ok: boolean
}

export interface BlockView {
  number: number
  txs: TxView[]
  requestsOut: number
  events: ClEvent[]
}

export interface QueueView {
  contract: SystemContract
  label: string
  fee: bigint | undefined
  excess: bigint
  target: number
  max: number
  items: QueuedRequest[]
}

export interface StakeView {
  id: bigint
  owner: string
  ownerAddress: Hex
  status: StakeStatus
  role?: Role
  balance: string
  validatorIndex?: number
  migrated: boolean
  hasKeys: boolean
}

export interface View {
  block: number
  currentTxs: TxView[]
  sealed: BlockView[]
  queues: QueueView[]
  stakes: StakeView[]
  balances: { name: string; address: Hex; eth: string }[]
  events: ClEvent[]
}

export const QUEUE_INFO: Record<SystemContract, { label: string; target: number; max: number }> = {
  PQValidatorRegistration: { label: 'Validator registration', target: 2, max: 16 },
  PQBuilderRegistration: { label: 'Builder registration', target: 2, max: 16 },
  PQWithdrawal: { label: 'Withdrawals & exits', target: 2, max: 16 },
  PQConsolidation: { label: 'Consolidations', target: 1, max: 2 },
}

export const formatEth = (wei: bigint) => {
  const n = Number(formatEther(wei))
  return Number.isInteger(n) ? n.toString() : n.toFixed(4).replace(/0+$/, '')
}

export async function buildView(sim: Simulation): Promise<View> {
  const queues: QueueView[] = []
  for (const contract of SYSTEM_CONTRACTS) {
    const state = await sim.chain.queueState(contract)
    queues.push({
      contract,
      ...QUEUE_INFO[contract],
      fee: await sim.chain.fee(contract),
      excess: state.excess,
      items: [...sim.queues[contract]],
    })
  }

  const stakes = [...sim.consensus.stakes.values()]
    .sort((a, b) => (a.stakeId < b.stakeId ? -1 : 1))
    .map((s): StakeView => {
      const ownerAddress = withdrawalAddressOf(s.withdrawalCredentials)
      return {
        id: s.stakeId,
        owner: ACTORS.find((a) => a.address.toLowerCase() === ownerAddress.toLowerCase())?.name ?? 'unknown',
        ownerAddress,
        status: s.status,
        role: s.role,
        balance: formatEth(s.balanceGwei * 1_000_000_000n),
        validatorIndex: s.validatorIndex,
        migrated: s.migrated,
        hasKeys: sim.keys.has(s.stakeId),
      }
    })

  const balances = []
  for (const a of ACTORS) balances.push({ name: a.name, address: a.address, eth: formatEth(await sim.chain.balance(a.address)) })

  // Transactions grouped by block, in execution order (`activity` is newest-first).
  const txsByBlock = new Map<number, TxView[]>()
  for (const a of [...sim.activity].reverse()) {
    const txs = txsByBlock.get(a.block) ?? []
    txs.push({ id: a.id, kind: a.kind, title: a.title, actor: a.actor, ok: a.result.ok })
    txsByBlock.set(a.block, txs)
  }

  // The first report is the fork block, which only clears the inhibitor.
  const sealed = sim.blocks
    .filter((b) => b.block > 1)
    .slice(0, 4)
    .map((b) => ({
      number: b.block,
      txs: txsByBlock.get(b.block) ?? [],
      requestsOut: b.outputs.reduce((n, o) => n + o.dequeued.length, 0),
      events: b.clEvents,
    }))

  return {
    block: sim.block,
    currentTxs: txsByBlock.get(sim.block) ?? [],
    sealed,
    queues,
    stakes,
    balances,
    events: sim.blocks[0]?.block > 1 ? sim.blocks[0].clEvents : [],
  }
}
