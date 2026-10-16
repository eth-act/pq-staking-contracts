// Ties user actions, the in-browser EVM and the consensus-layer model together.
import {
  type Abi,
  type Hex,
  decodeEventLog,
  decodeFunctionResult,
  encodeFunctionData,
  hexToBytes,
  parseEther,
} from 'viem'
import { Chain, type CallResult, type ContractName, SYSTEM_CONTRACTS, type SystemContract, contracts } from '../chain/chain'
import {
  PQ_PUBKEY_LENGTH,
  PQ_SIGNATURE_LENGTH,
  type RegistrationFields,
  authorizationCommitment,
  decodeConsolidationRecords,
  decodeRegistrationRecords,
  decodeWithdrawalRecords,
  encodeConsolidation,
  encodeRegistration,
  encodeWithdrawal,
  mockSignature,
  randomHex,
  withdrawalCredentials,
} from '../chain/encoding'
import { type BlockInput, type ClEvent, Consensus, type Role } from './consensus'

export interface Actor {
  name: string
  address: Hex
}

export const ACTORS: Actor[] = [
  { name: 'Alice', address: '0x00000000000000000000000000000000000a11ce' },
  { name: 'Bob', address: '0x0000000000000000000000000000000000000b0b' },
  { name: 'Legacy operator', address: '0x000000000000000000000000000000000000001e' },
]

/** Validators that exist before the fork; they get stake IDs 0..N-1. */
export const MIGRATED_VALIDATORS = 3

/** Keys an actor generated when creating a stake; needed later to register it. */
export interface KeyBundle {
  blsPubkey: Hex
  pqPubkey: Hex
}

export type TxKind = 'stake' | 'topup' | 'register' | 'withdraw' | 'consolidate'

export interface Activity {
  id: number
  kind: TxKind
  block: number
  actor: string
  title: string
  contract: ContractName
  calldata: Hex
  valueWei: bigint
  result: CallResult
  stakeId?: bigint
}

/** A request waiting in a system contract's queue (mirrors the contract's storage queue). */
export interface QueuedRequest {
  txId: number
  kind: TxKind
  stakeId: bigint
}

export interface BlockReport {
  block: number
  txIds: number[]
  outputs: { contract: SystemContract; raw: Hex; decoded: unknown[]; dequeued: QueuedRequest[] }[]
  clEvents: ClEvent[]
}

const stakingAbi = contracts.PQStaking.abi as Abi

export class Simulation {
  block = 1
  readonly activity: Activity[] = []
  readonly blocks: BlockReport[] = []
  readonly keys = new Map<bigint, KeyBundle & { owner: Hex }>()
  readonly queues: Record<SystemContract, QueuedRequest[]> = {
    PQValidatorRegistration: [],
    PQBuilderRegistration: [],
    PQWithdrawal: [],
    PQConsolidation: [],
  }
  private nextTxId = 1

  private constructor(
    readonly chain: Chain,
    readonly consensus: Consensus,
  ) {}

  static async create(): Promise<Simulation> {
    const chain = await Chain.create(
      BigInt(MIGRATED_VALIDATORS),
      ACTORS.map((a) => ({ address: a.address, balanceWei: parseEther('1000') })),
    )
    const legacy = ACTORS[2].address
    const consensus = new Consensus(Array.from({ length: MIGRATED_VALIDATORS }, () => withdrawalCredentials(legacy)))
    const sim = new Simulation(chain, consensus)
    // Fork block: the first system calls clear the excess inhibitor.
    await sim.nextBlock()
    return sim
  }

  private async send(
    actor: Actor,
    kind: TxKind,
    title: string,
    contract: ContractName,
    calldata: Hex,
    valueWei: bigint,
    stakeId?: bigint,
  ): Promise<Activity> {
    const result = await this.chain.call(actor.address, this.chain.addresses[contract], calldata, valueWei)
    const tx: Activity = {
      id: this.nextTxId++,
      kind,
      block: this.block,
      actor: actor.name,
      title,
      contract,
      calldata,
      valueWei,
      result,
      stakeId,
    }
    this.activity.unshift(tx)
    return tx
  }

  /** System-contract request paying exactly the current fee. */
  private async request(
    actor: Actor,
    kind: TxKind,
    title: string,
    contract: SystemContract,
    calldata: Hex,
    stakeId: bigint,
  ): Promise<Activity> {
    const fee = await this.chain.fee(contract)
    if (fee === undefined) throw new Error(`${contract} is still inhibited`)
    const tx = await this.send(actor, kind, title, contract, calldata, fee, stakeId)
    if (tx.result.ok) this.queues[contract].push({ txId: tx.id, kind, stakeId })
    return tx
  }

  async stake(actor: Actor, amountEth: string): Promise<Activity> {
    const keys: KeyBundle = { blsPubkey: randomHex(48), pqPubkey: randomHex(PQ_PUBKEY_LENGTH) }
    const commitment = authorizationCommitment(keys.blsPubkey, keys.pqPubkey)
    const calldata = encodeFunctionData({
      abi: stakingAbi,
      functionName: 'stake',
      args: [withdrawalCredentials(actor.address), commitment],
    })
    const tx = await this.send(actor, 'stake', `Stake ${amountEth} ETH`, 'PQStaking', calldata, parseEther(amountEth))
    if (tx.result.ok) {
      const stakeId = decodeFunctionResult({ abi: stakingAbi, functionName: 'stake', data: tx.result.returnValue }) as bigint
      tx.stakeId = stakeId
      tx.title = `Stake ${amountEth} ETH → #${stakeId}`
      this.keys.set(stakeId, { ...keys, owner: actor.address })
    }
    return tx
  }

  async topUp(actor: Actor, stakeId: bigint, amountEth: string): Promise<Activity> {
    const calldata = encodeFunctionData({ abi: stakingAbi, functionName: 'topup', args: [stakeId] })
    return this.send(actor, 'topup', `Top up #${stakeId} +${amountEth} ETH`, 'PQStaking', calldata, parseEther(amountEth), stakeId)
  }

  /** Registration with the stake's keys and mock signatures; flags tamper with them. */
  async register(
    actor: Actor,
    role: Role,
    stakeId: bigint,
    tamper: { wrongPqKey?: boolean; badPqSignature?: boolean } = {},
  ): Promise<Activity> {
    const keys = this.keys.get(stakeId)
    if (!keys) throw new Error(`no keys for stake ${stakeId}`)
    const pqPubkey = tamper.wrongPqKey ? randomHex(PQ_PUBKEY_LENGTH) : keys.pqPubkey
    let pqSignature = mockSignature('pq', stakeId, pqPubkey, PQ_SIGNATURE_LENGTH)
    if (tamper.badPqSignature) pqSignature = `0x${pqSignature.slice(2, -2)}00`
    const fields: RegistrationFields = {
      stakeId,
      blsPubkey: keys.blsPubkey,
      blsSignature: mockSignature('bls', stakeId, keys.blsPubkey, 96),
      pqPubkey,
      pqSignature,
    }
    const contract = role === 'validator' ? 'PQValidatorRegistration' : 'PQBuilderRegistration'
    return this.request(actor, 'register', `Register #${stakeId} as ${role}`, contract, encodeRegistration(fields), stakeId)
  }

  async withdraw(actor: Actor, stakeId: bigint, amountGwei: bigint): Promise<Activity> {
    const title = amountGwei === 0n ? `Exit / recover #${stakeId}` : `Withdraw ${Number(amountGwei) / 1e9} ETH from #${stakeId}`
    return this.request(actor, 'withdraw', title, 'PQWithdrawal', encodeWithdrawal(stakeId, amountGwei), stakeId)
  }

  async consolidate(actor: Actor, sourceStakeId: bigint, targetStakeId: bigint): Promise<Activity> {
    return this.request(
      actor,
      'consolidate',
      `Consolidate #${sourceStakeId} → #${targetStakeId}`,
      'PQConsolidation',
      encodeConsolidation(sourceStakeId, targetStakeId),
      sourceStakeId,
    )
  }

  /**
   * End the current block: collect staking logs (EIP-6110 style), run every system call, feed
   * the decoded requests to the consensus model, and pay withdrawals back to the EL.
   */
  async nextBlock(): Promise<BlockReport> {
    const input: BlockInput = { created: [], topUps: [], registrations: [], withdrawals: [], consolidations: [] }

    // `activity` is newest-first for display; the CL must see logs in execution order.
    const blockTxs = this.activity.filter((a) => a.block === this.block).reverse()
    for (const a of blockTxs.filter((a) => a.contract === 'PQStaking' && a.result.ok)) {
      for (const log of a.result.logs) {
        const event = decodeEventLog({ abi: stakingAbi, topics: log.topics as [Hex, ...Hex[]], data: log.data })
        const args = event.args as unknown as Record<string, unknown>
        if (event.eventName === 'CreateStake') {
          input.created.push({
            stakeId: args.stakeId as bigint,
            withdrawalCredentials: args.withdrawalCredentials as Hex,
            authorizationCommitment: args.authorizationCommitment as Hex,
            amountGwei: args.amountGwei as bigint,
          })
        } else if (event.eventName === 'TopUp') {
          input.topUps.push({ stakeId: args.stakeId as bigint, amountGwei: args.amountGwei as bigint })
        }
      }
    }

    const outputs: BlockReport['outputs'] = []
    for (const contract of SYSTEM_CONTRACTS) {
      const raw = await this.chain.systemCall(contract)
      const bytes = hexToBytes(raw)
      let decoded: unknown[]
      if (contract === 'PQWithdrawal') {
        const records = decodeWithdrawalRecords(bytes)
        decoded = records
        input.withdrawals.push(...records)
      } else if (contract === 'PQConsolidation') {
        const records = decodeConsolidationRecords(bytes)
        decoded = records
        input.consolidations.push(...records)
      } else {
        const role: Role = contract === 'PQValidatorRegistration' ? 'validator' : 'builder'
        const requests = decodeRegistrationRecords(bytes)
        decoded = requests
        input.registrations.push(...requests.map((request) => ({ role, request })))
      }
      outputs.push({ contract, raw, decoded, dequeued: this.queues[contract].splice(0, decoded.length) })
    }

    const payouts: { address: Hex; gwei: bigint }[] = []
    const clEvents = this.consensus.processBlock(this.block, input, (address, gwei) => payouts.push({ address, gwei }))
    for (const { address, gwei } of payouts) await this.chain.credit(address, gwei * 1_000_000_000n)

    const report: BlockReport = { block: this.block, txIds: blockTxs.map((t) => t.id), outputs, clEvents }
    this.blocks.unshift(report)
    this.block += 1
    return report
  }
}
