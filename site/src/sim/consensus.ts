// Simplified consensus-layer model. Nothing here runs on-chain: it interprets the requests the
// system contracts emit, following EIP-8413 and the decisions in issue #1. Delays, churn and
// balances are simplified for illustration.
import { type Hex, size } from 'viem'
import {
  type ConsolidationRecord,
  type RegistrationFields,
  type WithdrawalRecord,
  authorizationCommitment,
  mockSignature,
  withdrawalAddressOf,
} from '../chain/encoding'

export type Role = 'validator' | 'builder'
export type StakeStatus = 'unregistered' | 'pending' | 'active' | 'exiting' | 'exited' | 'recovering'

export interface StakePosition {
  stakeId: bigint
  withdrawalCredentials: Hex
  authorizationCommitment: Hex
  balanceGwei: bigint
  status: StakeStatus
  migrated: boolean
  role?: Role
  validatorIndex?: number
  /** Block at which a pending registration activates or an exit completes. */
  readyAtBlock?: number
}

export interface ClEvent {
  outcome: 'accepted' | 'ignored' | 'info'
  text: string
}

export interface BlockInput {
  created: { stakeId: bigint; withdrawalCredentials: Hex; authorizationCommitment: Hex; amountGwei: bigint }[]
  topUps: { stakeId: bigint; amountGwei: bigint }[]
  registrations: { role: Role; request: RegistrationFields }[]
  withdrawals: WithdrawalRecord[]
  consolidations: ConsolidationRecord[]
}

export const ACTIVATION_DELAY_BLOCKS = 2
export const EXIT_DELAY_BLOCKS = 2
export const MAX_RECOVERIES_PER_BLOCK = 8
export const PENDING_RECOVERY_LIMIT = 4096
export const MIN_BALANCE_GWEI: Record<Role, bigint> = { validator: 32_000_000_000n, builder: 1_000_000_000n }

const eth = (gwei: bigint) => `${Number(gwei) / 1e9} ETH`

export class Consensus {
  readonly stakes = new Map<bigint, StakePosition>()
  readonly recoveryQueue: bigint[] = []
  private readonly usedCredentials = new Set<Hex>()
  private nextValidatorIndex: number

  /** Existing validators migrate with stake ID = validator index (EIP-8413). */
  constructor(migratedWithdrawalCredentials: Hex[]) {
    migratedWithdrawalCredentials.forEach((credentials, index) => {
      this.stakes.set(BigInt(index), {
        stakeId: BigInt(index),
        withdrawalCredentials: credentials,
        authorizationCommitment: `0x${'00'.repeat(32)}`,
        balanceGwei: 32_000_000_000n,
        status: 'active',
        migrated: true,
        role: 'validator',
        validatorIndex: index,
      })
    })
    this.nextValidatorIndex = migratedWithdrawalCredentials.length
  }

  /**
   * Process one block's requests, then advance timed transitions. `payOut` credits the
   * execution-layer balance of a withdrawal address.
   */
  processBlock(block: number, input: BlockInput, payOut: (address: Hex, gwei: bigint) => void): ClEvent[] {
    const events: ClEvent[] = []
    const accept = (text: string) => events.push({ outcome: 'accepted', text })
    const ignore = (text: string) => events.push({ outcome: 'ignored', text })

    for (const c of input.created) {
      this.stakes.set(c.stakeId, {
        stakeId: c.stakeId,
        withdrawalCredentials: c.withdrawalCredentials,
        authorizationCommitment: c.authorizationCommitment,
        balanceGwei: c.amountGwei,
        status: 'unregistered',
        migrated: false,
      })
      accept(`Stake ${c.stakeId} created with ${eth(c.amountGwei)}`)
    }

    for (const t of input.topUps) {
      const stake = this.stakes.get(t.stakeId)
      if (!stake) {
        ignore(`Top-up to unknown stake ${t.stakeId}`)
        continue
      }
      stake.balanceGwei += t.amountGwei
      accept(`Stake ${t.stakeId} topped up by ${eth(t.amountGwei)} (${stake.status})`)
    }

    for (const { role, request } of input.registrations) {
      const id = request.stakeId
      const stake = this.stakes.get(id)
      const label = `${role} registration for stake ${id}`
      if (!stake) ignore(`${label}: no such stake`)
      else if (stake.status !== 'unregistered') ignore(`${label}: stake is ${stake.status}`)
      else if (authorizationCommitment(request.blsPubkey, request.pqPubkey) !== stake.authorizationCommitment) {
        ignore(`${label}: keys do not open the authorization commitment; stake kept`)
      } else if (this.usedCredentials.has(request.blsPubkey) || this.usedCredentials.has(request.pqPubkey)) {
        ignore(`${label}: credential already used`)
      } else if (request.blsSignature !== mockSignature('bls', id, request.blsPubkey, 96)) {
        ignore(`${label}: invalid BLS signature; stake kept`)
      } else if (request.pqSignature !== mockSignature('pq', id, request.pqPubkey, size(request.pqSignature))) {
        ignore(`${label}: invalid PQ signature; stake kept`)
      } else {
        this.usedCredentials.add(request.blsPubkey)
        this.usedCredentials.add(request.pqPubkey)
        stake.status = 'pending'
        stake.role = role
        stake.readyAtBlock = block + ACTIVATION_DELAY_BLOCKS
        accept(`${label}: both signatures valid, queued for activation`)
      }
    }

    for (const w of input.withdrawals) {
      const stake = this.stakes.get(w.stakeId)
      const label = `Withdrawal for stake ${w.stakeId}`
      if (!stake) {
        ignore(`${label}: no such stake`)
        continue
      }
      if (withdrawalAddressOf(stake.withdrawalCredentials).toLowerCase() !== w.sourceAddress.toLowerCase()) {
        ignore(`${label}: sender is not the withdrawal address`)
        continue
      }
      if (stake.status === 'active') {
        if (w.amountGwei === 0n) {
          stake.status = 'exiting'
          stake.readyAtBlock = block + EXIT_DELAY_BLOCKS
          accept(`${label}: full exit started`)
        } else {
          const available = stake.balanceGwei - MIN_BALANCE_GWEI[stake.role ?? 'validator']
          const amount = w.amountGwei < available ? w.amountGwei : available
          if (amount <= 0n) {
            ignore(`${label}: nothing above the minimum balance`)
          } else {
            stake.balanceGwei -= amount
            payOut(withdrawalAddressOf(stake.withdrawalCredentials), amount)
            accept(`${label}: partial withdrawal of ${eth(amount)} paid`)
          }
        }
      } else if (stake.status === 'unregistered') {
        if (w.amountGwei !== 0n) ignore(`${label}: unregistered stake, only full recovery (amount 0) is allowed`)
        else if (this.recoveryQueue.length >= PENDING_RECOVERY_LIMIT) ignore(`${label}: recovery queue full`)
        else {
          stake.status = 'recovering'
          this.recoveryQueue.push(stake.stakeId)
          accept(`${label}: unregistered, recovery of the full balance queued`)
        }
      } else {
        ignore(`${label}: stake is ${stake.status}`)
      }
    }

    for (const c of input.consolidations) {
      const source = this.stakes.get(c.sourceStakeId)
      const target = this.stakes.get(c.targetStakeId)
      const label = `Consolidation ${c.sourceStakeId} → ${c.targetStakeId}`
      if (!source || !target) ignore(`${label}: unknown stake`)
      else if (source === target) ignore(`${label}: source and target are the same`)
      else if (source.status !== 'active' || target.status !== 'active') {
        ignore(`${label}: both stakes must be active validators`)
      } else if (withdrawalAddressOf(source.withdrawalCredentials).toLowerCase() !== c.sourceAddress.toLowerCase()) {
        ignore(`${label}: sender is not the source withdrawal address`)
      } else {
        target.balanceGwei += source.balanceGwei
        accept(`${label}: moved ${eth(source.balanceGwei)}`)
        source.balanceGwei = 0n
        source.status = 'exited'
      }
    }

    for (const stake of this.stakes.values()) {
      if (stake.status === 'pending' && block >= (stake.readyAtBlock ?? 0)) {
        if (stake.balanceGwei < MIN_BALANCE_GWEI[stake.role ?? 'validator']) {
          events.push({ outcome: 'info', text: `Stake ${stake.stakeId} waits for a top-up to activate` })
        } else {
          stake.status = 'active'
          stake.validatorIndex = this.nextValidatorIndex++
          accept(`Stake ${stake.stakeId} active as ${stake.role} index ${stake.validatorIndex}`)
        }
      } else if (stake.status === 'exiting' && block >= (stake.readyAtBlock ?? 0)) {
        payOut(withdrawalAddressOf(stake.withdrawalCredentials), stake.balanceGwei)
        accept(`Stake ${stake.stakeId} exited, ${eth(stake.balanceGwei)} paid`)
        stake.balanceGwei = 0n
        stake.status = 'exited'
      }
    }

    for (const id of this.recoveryQueue.splice(0, MAX_RECOVERIES_PER_BLOCK)) {
      const stake = this.stakes.get(id)!
      payOut(withdrawalAddressOf(stake.withdrawalCredentials), stake.balanceGwei)
      accept(`Stake ${id} recovered, ${eth(stake.balanceGwei)} paid; stake ID and commitment kept`)
      stake.balanceGwei = 0n
      stake.status = 'unregistered'
    }

    return events
  }
}
