// Simplified consensus-layer model. Nothing here runs on-chain: it interprets the requests the
// system contracts emit, following EIP-8413 and the decisions in issue #1. Delays, churn and
// balances are simplified for illustration.
import type { Hex } from 'viem'
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
  /** Stake the event is about, when known. */
  stakeId?: bigint
  /** What was processed, e.g. "Validator registration". */
  subject: string
  /** Short outcome, e.g. "invalid PQ signature; stake kept". */
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
    const emit = (outcome: ClEvent['outcome'], stakeId: bigint | undefined, subject: string, text: string) =>
      events.push({ outcome, stakeId, subject, text })

    for (const c of input.created) {
      this.stakes.set(c.stakeId, {
        stakeId: c.stakeId,
        withdrawalCredentials: c.withdrawalCredentials,
        authorizationCommitment: c.authorizationCommitment,
        balanceGwei: c.amountGwei,
        status: 'unregistered',
        migrated: false,
      })
      emit('accepted', c.stakeId, 'Stake', `created with ${eth(c.amountGwei)}`)
    }

    for (const t of input.topUps) {
      const stake = this.stakes.get(t.stakeId)
      if (!stake) {
        emit('ignored', t.stakeId, 'Top-up', 'unknown stake')
        continue
      }
      stake.balanceGwei += t.amountGwei
      emit('accepted', t.stakeId, 'Top-up', `+${eth(t.amountGwei)}`)
    }

    for (const { role, request } of input.registrations) {
      const id = request.stakeId
      const stake = this.stakes.get(id)
      const subject = role === 'validator' ? 'Validator registration' : 'Builder registration'
      const reject = (text: string) => emit('ignored', id, subject, text)
      if (!stake) reject('no such stake')
      else if (stake.status !== 'unregistered') reject(`stake is ${stake.status}`)
      else if (authorizationCommitment(request.pqPubkey) !== stake.authorizationCommitment) {
        reject('key does not match the commitment; stake kept')
      } else if (this.usedCredentials.has(request.pqPubkey)) {
        reject('PQ key already used')
      } else if (request.pqSignature !== mockSignature(id, request.pqPubkey)) {
        reject('invalid PQ signature; stake kept')
      } else {
        this.usedCredentials.add(request.pqPubkey)
        stake.status = 'pending'
        stake.role = role
        stake.readyAtBlock = block + ACTIVATION_DELAY_BLOCKS
        emit('accepted', id, subject, 'PQ signature valid, pending activation')
      }
    }

    for (const w of input.withdrawals) {
      const stake = this.stakes.get(w.stakeId)
      const subject = w.amountGwei === 0n ? 'Exit / recovery' : 'Withdrawal'
      const reject = (text: string) => emit('ignored', w.stakeId, subject, text)
      if (!stake) {
        reject('no such stake')
        continue
      }
      if (withdrawalAddressOf(stake.withdrawalCredentials).toLowerCase() !== w.sourceAddress.toLowerCase()) {
        reject('sender is not the withdrawal address')
        continue
      }
      if (stake.status === 'active') {
        if (w.amountGwei === 0n) {
          stake.status = 'exiting'
          stake.readyAtBlock = block + EXIT_DELAY_BLOCKS
          emit('accepted', w.stakeId, 'Exit', 'started')
        } else {
          const available = stake.balanceGwei - MIN_BALANCE_GWEI[stake.role ?? 'validator']
          const amount = w.amountGwei < available ? w.amountGwei : available
          if (amount <= 0n) {
            reject('nothing above the minimum balance')
          } else {
            stake.balanceGwei -= amount
            payOut(withdrawalAddressOf(stake.withdrawalCredentials), amount)
            emit('accepted', w.stakeId, 'Withdrawal', `${eth(amount)} paid`)
          }
        }
      } else if (stake.status === 'unregistered') {
        if (w.amountGwei !== 0n) reject('unregistered: only full recovery (amount 0)')
        else if (this.recoveryQueue.length >= PENDING_RECOVERY_LIMIT) reject('recovery queue full')
        else {
          stake.status = 'recovering'
          this.recoveryQueue.push(stake.stakeId)
          emit('accepted', w.stakeId, 'Recovery', 'unregistered, full balance queued for recovery')
        }
      } else {
        reject(`stake is ${stake.status}`)
      }
    }

    for (const c of input.consolidations) {
      const source = this.stakes.get(c.sourceStakeId)
      const target = this.stakes.get(c.targetStakeId)
      const subject = `Consolidation into #${c.targetStakeId}`
      const reject = (text: string) => emit('ignored', c.sourceStakeId, subject, text)
      if (!source || !target) reject('unknown stake')
      else if (source === target) reject('source and target are the same')
      else if (source.status !== 'active' || target.status !== 'active') reject('both must be active validators')
      else if (withdrawalAddressOf(source.withdrawalCredentials).toLowerCase() !== c.sourceAddress.toLowerCase()) {
        reject('sender is not the source withdrawal address')
      } else {
        target.balanceGwei += source.balanceGwei
        emit('accepted', c.sourceStakeId, subject, `moved ${eth(source.balanceGwei)}`)
        emit('accepted', c.targetStakeId, `Consolidation from #${c.sourceStakeId}`, `+${eth(source.balanceGwei)}`)
        source.balanceGwei = 0n
        source.status = 'exited'
      }
    }

    for (const stake of this.stakes.values()) {
      if (stake.status === 'pending' && block >= (stake.readyAtBlock ?? 0)) {
        if (stake.balanceGwei < MIN_BALANCE_GWEI[stake.role ?? 'validator']) {
          emit('info', stake.stakeId, 'Activation', 'waiting for a top-up')
        } else {
          stake.status = 'active'
          stake.validatorIndex = this.nextValidatorIndex++
          emit('accepted', stake.stakeId, 'Activation', `active as ${stake.role} #${stake.validatorIndex}`)
        }
      } else if (stake.status === 'exiting' && block >= (stake.readyAtBlock ?? 0)) {
        payOut(withdrawalAddressOf(stake.withdrawalCredentials), stake.balanceGwei)
        emit('accepted', stake.stakeId, 'Exit', `complete, ${eth(stake.balanceGwei)} paid`)
        stake.balanceGwei = 0n
        stake.status = 'exited'
      }
    }

    for (const id of this.recoveryQueue.splice(0, MAX_RECOVERIES_PER_BLOCK)) {
      const stake = this.stakes.get(id)!
      payOut(withdrawalAddressOf(stake.withdrawalCredentials), stake.balanceGwei)
      emit('accepted', id, 'Recovery', `${eth(stake.balanceGwei)} paid; stake ID and commitment kept`)
      stake.balanceGwei = 0n
      stake.status = 'unregistered'
    }

    return events
  }
}
