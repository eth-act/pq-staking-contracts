import { AnimatePresence, LayoutGroup, motion } from 'motion/react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { compiler } from './chain/chain'
import { ACTORS, MIGRATED_VALIDATORS, Simulation } from './sim/simulation'
import { ChainView, type Selection } from './ui/ChainView'
import { Dock } from './ui/Dock'
import { Drawer } from './ui/Drawer'
import { QueueLane, StakeLane } from './ui/Lanes'
import { type View, buildView } from './ui/view'

function pause(ms: number): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>()
  setTimeout(resolve, ms)
  return promise
}

export function App() {
  const simRef = useRef<Simulation | null>(null)
  const [view, setView] = useState<View | null>(null)
  const [actorIndex, setActorIndex] = useState(0)
  const [busy, setBusy] = useState(false)
  const [sealing, setSealing] = useState(false)
  const [selectedStake, setSelectedStake] = useState<bigint | undefined>(undefined)
  const [selection, setSelection] = useState<Selection | null>(null)
  const [error, setError] = useState<string | null>(null)

  const reset = useCallback(async () => {
    setBusy(true)
    const sim = await Simulation.create()
    simRef.current = sim
    setView(await buildView(sim))
    setSelection(null)
    setSelectedStake(undefined)
    setBusy(false)
  }, [])

  useEffect(() => {
    void reset()
  }, [reset])

  const send = useCallback((action: () => Promise<unknown>) => {
    const sim = simRef.current
    if (!sim) return
    setError(null)
    setBusy(true)
    action()
      .then(async () => setView(await buildView(sim)))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setBusy(false))
  }, [])

  /** Seal the block, then show the EL side (queues drain), then the CL side (stakes update). */
  const endBlock = useCallback(async () => {
    const sim = simRef.current
    if (!sim) return
    setBusy(true)
    setSealing(true)
    await sim.nextBlock()
    const next = await buildView(sim)
    await pause(550)
    setSealing(false)
    setView((prev) => (prev ? { ...next, stakes: prev.stakes, events: [] } : next))
    await pause(650)
    setView(next)
    setBusy(false)
  }, [])

  const sim = simRef.current
  if (!sim || !view) return <div className="loading">Deploying the contracts into an in-browser EVM…</div>
  const actor = ACTORS[actorIndex]

  return (
    <LayoutGroup>
      <div className="app">
        <header className="top">
          <div className="brand">
            <h1>
              Staking with <em>StakeID</em>
            </h1>
            <p>
              Real contract bytecode (solc {compiler.solc.split('+')[0]}, {compiler.evmVersion}) running in your
              browser · consensus layer simulated · {MIGRATED_VALIDATORS} validators migrated at the fork
            </p>
          </div>
          <div className="actors">
            {ACTORS.map((a, i) => (
              <button key={a.address} className={i === actorIndex ? 'actor on' : 'actor'} onClick={() => setActorIndex(i)}>
                <span className="actor-name">{a.name}</span>
                <motion.span key={view.balances[i].eth} className="actor-eth" initial={{ y: -6, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
                  {view.balances[i].eth} ETH
                </motion.span>
              </button>
            ))}
            <button className="ghost" onClick={() => void reset()} disabled={busy}>
              Reset
            </button>
          </div>
        </header>

        <AnimatePresence>
          {error && (
            <motion.div className="error" initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
              {error}
            </motion.div>
          )}
        </AnimatePresence>

        <div className="stage">
          <Dock sim={sim} actor={actor} stakes={view.stakes} selectedStake={selectedStake} send={send} />
          <main>
            <ChainView view={view} sealing={sealing} busy={busy} onEndBlock={() => void endBlock()} onSelect={setSelection} />
            <QueueLane queues={view.queues} />
            <StakeLane stakes={view.stakes} events={view.events} selected={selectedStake} onSelect={setSelectedStake} />
          </main>
        </div>
      </div>

      <AnimatePresence>
        {selection && <Drawer key="drawer" sim={sim} selection={selection} onClose={() => setSelection(null)} />}
      </AnimatePresence>
    </LayoutGroup>
  )
}
