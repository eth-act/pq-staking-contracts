// One section per operation, mirroring "New contract APIs with StakeID".
import { useState, type ReactNode } from 'react'
import { formatEther } from 'viem'
import type { SystemContract } from '../chain/chain'
import type { Role } from '../sim/consensus'
import { type Actor, PQ_SCHEMES, type PqScheme, type Simulation } from '../sim/simulation'

export interface OperationProps {
  sim: Simulation
  actor: Actor
  fees: Record<SystemContract, bigint | undefined>
  run: (label: string, action: () => Promise<unknown>) => void
}

function Section(props: { index: string; title: string; summary: string; api: string; children: ReactNode }) {
  return (
    <section className="op">
      <div className="op-index">{props.index}</div>
      <div className="op-body">
        <h2>{props.title}</h2>
        <p className="op-summary">{props.summary}</p>
        <code className="op-api">{props.api}</code>
        <div className="op-form">{props.children}</div>
      </div>
    </section>
  )
}

function StakeIdInput(props: { sim: Simulation; value: string; onChange: (v: string) => void; label?: string }) {
  const ids = [...new Set([...props.sim.consensus.stakes.keys(), ...props.sim.keys.keys()])].sort((a, b) =>
    a < b ? -1 : 1,
  )
  return (
    <label>
      {props.label ?? 'stake ID'}
      <select value={props.value} onChange={(e) => props.onChange(e.target.value)}>
        <option value="">select…</option>
        {ids.map((id) => (
          <option key={id.toString()} value={id.toString()}>
            {id.toString()}
          </option>
        ))}
      </select>
    </label>
  )
}

function FeeNote({ fee }: { fee: bigint | undefined }) {
  return <span className="fee-note">{fee === undefined ? 'inhibited' : `fee ${fee} wei`}</span>
}

export function StakeSection({ sim, actor, run }: OperationProps) {
  const [amount, setAmount] = useState('32')
  const [scheme, setScheme] = useState<PqScheme>('ML-DSA-44')
  return (
    <Section
      index="01"
      title="Stake"
      summary="Create a stake position. No keys or signatures yet: only withdrawal credentials and a commitment to the keys that may register it. The stake ID is returned immediately."
      api="PQStaking.stake(withdrawalCredentials, authorizationCommitment) → stakeId"
    >
      <label>
        amount (ETH)
        <input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
      </label>
      <label>
        PQ key sizes
        <select value={scheme} onChange={(e) => setScheme(e.target.value as PqScheme)}>
          {Object.entries(PQ_SCHEMES).map(([name, s]) => (
            <option key={name} value={name}>
              {name} (pk {s.pubkey}B, sig {s.signature}B)
            </option>
          ))}
        </select>
      </label>
      <button onClick={() => run(`${actor.name} stakes ${amount} ETH`, () => sim.stake(actor, amount, scheme))}>
        Stake
      </button>
      <p className="hint">
        Generates a BLS key and a PQ key locally; the commitment is <code>0x01 ‖ sha256(bls ‖ pq)[1:]</code> (demo
        assumption).
      </p>
    </Section>
  )
}

export function TopUpSection({ sim, actor, run }: OperationProps) {
  const [stakeId, setStakeId] = useState('')
  const [amount, setAmount] = useState('1')
  return (
    <Section
      index="02"
      title="Top-ups"
      summary="Add balance to any stake, registered or not. A top-up consumes an event index but does not create a stake ID, so IDs are sparse."
      api="PQStaking.topup(stake_id)"
    >
      <StakeIdInput sim={sim} value={stakeId} onChange={setStakeId} />
      <label>
        amount (ETH)
        <input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" />
      </label>
      <button
        disabled={stakeId === ''}
        onClick={() => run(`${actor.name} tops up stake ${stakeId}`, () => sim.topUp(actor, BigInt(stakeId), amount))}
      >
        Top up
      </button>
    </Section>
  )
}

export function RegisterSection({ sim, actor, fees, run }: OperationProps) {
  const [stakeId, setStakeId] = useState('')
  const [role, setRole] = useState<Role>('validator')
  const [wrongPqKey, setWrongPqKey] = useState(false)
  const [badPqSignature, setBadPqSignature] = useState(false)
  const ownStakes = [...sim.keys.entries()].filter(([, k]) => k.owner === actor.address)
  const contract: SystemContract = role === 'validator' ? 'PQValidatorRegistration' : 'PQBuilderRegistration'
  return (
    <Section
      index="03"
      title="Registration"
      summary="Two signatures now needed, one for each public key. Validators and builders register against a stake ID in separate contracts; the consensus layer checks the keys against the commitment and verifies both signatures."
      api="stake_id ‖ bls_pubkey ‖ bls_signature ‖ pq_pubkey_length ‖ pq_pubkey ‖ pq_signature"
    >
      <label>
        role
        <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
          <option value="validator">validator</option>
          <option value="builder">builder</option>
        </select>
      </label>
      <label>
        your stake
        <select value={stakeId} onChange={(e) => setStakeId(e.target.value)}>
          <option value="">select…</option>
          {ownStakes.map(([id, k]) => (
            <option key={id.toString()} value={id.toString()}>
              {id.toString()} ({k.pqScheme})
            </option>
          ))}
        </select>
      </label>
      <label className="check">
        <input type="checkbox" checked={wrongPqKey} onChange={(e) => setWrongPqKey(e.target.checked)} />
        use a different PQ key
      </label>
      <label className="check">
        <input type="checkbox" checked={badPqSignature} onChange={(e) => setBadPqSignature(e.target.checked)} />
        corrupt PQ signature
      </label>
      <button
        disabled={stakeId === ''}
        onClick={() =>
          run(`${actor.name} registers stake ${stakeId} as ${role}`, () =>
            sim.register(actor, role, BigInt(stakeId), { wrongPqKey, badPqSignature }),
          )
        }
      >
        Register
      </button>
      <FeeNote fee={fees[contract]} />
      {ownStakes.length === 0 && <p className="hint">{actor.name} has no stakes with local keys yet.</p>}
    </Section>
  )
}

export function ConsolidationSection({ sim, actor, fees, run }: OperationProps) {
  const [source, setSource] = useState('')
  const [target, setTarget] = useState('')
  return (
    <Section
      index="04"
      title="Consolidations"
      summary="Source and target by stake ID. The caller must be the source stake's withdrawal address; both must be active validators."
      api="source_stake_id (u64) ‖ target_stake_id (u64)"
    >
      <StakeIdInput sim={sim} value={source} onChange={setSource} label="source" />
      <StakeIdInput sim={sim} value={target} onChange={setTarget} label="target" />
      <button
        disabled={source === '' || target === ''}
        onClick={() =>
          run(`${actor.name} consolidates ${source} → ${target}`, () =>
            sim.consolidate(actor, BigInt(source), BigInt(target)),
          )
        }
      >
        Consolidate
      </button>
      <FeeNote fee={fees.PQConsolidation} />
    </Section>
  )
}

export function WithdrawalSection({ sim, actor, fees, run }: OperationProps) {
  const [stakeId, setStakeId] = useState('')
  const [amountEth, setAmountEth] = useState('0')
  const amountGwei = BigInt(Math.round(Number(amountEth || '0') * 1e9))
  return (
    <Section
      index="05"
      title="Exits and withdrawals"
      summary="Keyed by stake ID. Amount 0 means “withdraw everything”: a full exit for a validator, or recovery of the full balance for an unregistered stake."
      api="stake_id (u64) ‖ amount_gwei (u64)"
    >
      <StakeIdInput sim={sim} value={stakeId} onChange={setStakeId} />
      <label>
        amount (ETH, 0 = all)
        <input value={amountEth} onChange={(e) => setAmountEth(e.target.value)} inputMode="decimal" />
      </label>
      <button
        disabled={stakeId === ''}
        onClick={() =>
          run(`${actor.name} withdraws from stake ${stakeId}`, () => sim.withdraw(actor, BigInt(stakeId), amountGwei))
        }
      >
        {amountGwei === 0n ? 'Exit / recover' : `Withdraw ${formatEther(amountGwei * 1_000_000_000n)} ETH`}
      </button>
      <FeeNote fee={fees.PQWithdrawal} />
      <table className="mini">
        <thead>
          <tr>
            <th>stake state</th>
            <th>amount 0</th>
            <th>amount &gt; 0</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>active</td>
            <td>full exit</td>
            <td>partial withdrawal</td>
          </tr>
          <tr>
            <td>unregistered</td>
            <td>recover full balance</td>
            <td>ignored</td>
          </tr>
          <tr>
            <td>registration pending</td>
            <td>ignored</td>
            <td>ignored</td>
          </tr>
        </tbody>
      </table>
    </Section>
  )
}
