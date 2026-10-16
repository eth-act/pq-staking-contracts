import { useCallback, useEffect, useRef, useState } from 'react'
import { type Hex, formatEther } from 'viem'
import { type QueueState, SYSTEM_CONTRACTS, type SystemContract, compiler } from './chain/chain'
import { ACTORS, MIGRATED_VALIDATORS, Simulation } from './sim/simulation'
import {
  ConsolidationSection,
  RegisterSection,
  StakeSection,
  TopUpSection,
  WithdrawalSection,
} from './ui/operations'
import { ActivityPanel, BlocksPanel, QueuesPanel, StakesPanel } from './ui/panels'

interface Snapshot {
  balances: Record<Hex, bigint>
  queues: Record<SystemContract, QueueState & { inhibited: boolean }>
  fees: Record<SystemContract, bigint | undefined>
}

async function snapshot(sim: Simulation): Promise<Snapshot> {
  const balances = {} as Snapshot['balances']
  for (const a of ACTORS) balances[a.address] = await sim.chain.balance(a.address)
  const queues = {} as Snapshot['queues']
  const fees = {} as Snapshot['fees']
  for (const name of SYSTEM_CONTRACTS) {
    queues[name] = await sim.chain.queueState(name)
    fees[name] = await sim.chain.fee(name)
  }
  return { balances, queues, fees }
}

export function App() {
  const simRef = useRef<Simulation | null>(null)
  const [state, setState] = useState<Snapshot | null>(null)
  const [actorIndex, setActorIndex] = useState(0)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  const reset = useCallback(async () => {
    setBusy(true)
    simRef.current = await Simulation.create()
    setState(await snapshot(simRef.current))
    setMessage(null)
    setBusy(false)
  }, [])

  useEffect(() => {
    void reset()
  }, [reset])

  const run = useCallback((label: string, action: () => Promise<unknown>) => {
    const sim = simRef.current
    if (!sim) return
    setBusy(true)
    action()
      .then(async () => {
        const last = sim.activity[0]
        setMessage(last && !last.result.ok ? `${label}: reverted` : label)
        setState(await snapshot(sim))
      })
      .catch((e: unknown) => setMessage(`${label}: ${e instanceof Error ? e.message : String(e)}`))
      .finally(() => setBusy(false))
  }, [])

  const sim = simRef.current
  if (!sim || !state) return <div className="loading">Deploying contracts into the in-browser EVM…</div>
  const actor = ACTORS[actorIndex]
  const ops = { sim, actor, fees: state.fees, run }

  return (
    <div className={busy ? 'app busy' : 'app'}>
      <header>
        <h1>
          New contract APIs with <em>StakeID</em>
        </h1>
        <p className="lede">
          <s>Today: deposits, top-ups, withdrawals and consolidations all locate the validator by its BLS key.</s>{' '}
          Below, the released contract bytecode runs in an EVM in your browser. The consensus layer is a simplified
          model.
        </p>
        <p className="meta">
          solc {compiler.solc.split('+')[0]} · EVM {compiler.evmVersion} · {MIGRATED_VALIDATORS} validators migrated
          at the fork (stake IDs 0–{MIGRATED_VALIDATORS - 1})
        </p>
      </header>

      <div className="controls">
        <div className="block-no">
          Block <strong>{sim.block}</strong>
        </div>
        <button
          className="primary"
          onClick={() => run(`Block ${sim.block} processed`, () => sim.nextBlock())}
          disabled={busy}
        >
          End block ▸
        </button>
        <label>
          acting as
          <select value={actorIndex} onChange={(e) => setActorIndex(Number(e.target.value))}>
            {ACTORS.map((a, i) => (
              <option key={a.address} value={i}>
                {a.name}
              </option>
            ))}
          </select>
        </label>
        <div className="balances">
          {ACTORS.map((a) => (
            <span key={a.address}>
              {a.name}: {Number(formatEther(state.balances[a.address])).toFixed(4)} ETH
            </span>
          ))}
        </div>
        <button onClick={() => void reset()} disabled={busy}>
          Reset
        </button>
      </div>
      {message && <div className="message">{message}</div>}

      <main>
        <div className="ops">
          <StakeSection {...ops} />
          <TopUpSection {...ops} />
          <RegisterSection {...ops} />
          <ConsolidationSection {...ops} />
          <WithdrawalSection {...ops} />
        </div>
        <div className="state">
          <StakesPanel sim={sim} />
          <QueuesPanel queues={state.queues} fees={state.fees} />
          <BlocksPanel sim={sim} />
          <ActivityPanel sim={sim} />
        </div>
      </main>

      <footer>
        Requests sit in the system contracts until <strong>End block</strong>, when each contract is called from{' '}
        <code>0xff…fe</code> and returns the queued requests. Staking logs are read like today’s deposit logs.
        Signatures are mock values the model can check; key sizes follow the chosen scheme.
      </footer>
    </div>
  )
}
