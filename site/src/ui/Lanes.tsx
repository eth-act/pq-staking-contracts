// Execution-layer queues (real system contracts) and consensus-layer stake cards (model).
import { AnimatePresence, motion } from 'motion/react'
import type { CSSProperties } from 'react'
import type { ClEvent } from '../sim/consensus'
import { KIND_COLOR } from './Dock'
import type { QueueView, StakeView } from './view'

const spring = { type: 'spring', stiffness: 420, damping: 30 } as const

export function QueueLane({ queues }: { queues: QueueView[] }) {
  return (
    <section className="lane">
      <header className="lane-head">
        <h2>System contracts</h2>
        <span>requests wait here until the end-of-block system call · real bytecode</span>
      </header>
      <div className="queues">
        {queues.map((q) => (
          <div key={q.contract} className="queue">
            <div className="queue-label">
              <strong>{q.label}</strong>
              <span>
                up to {q.max}/block · target {q.target}
              </span>
            </div>
            <div className="queue-track">
              <AnimatePresence initial={false}>
                {q.items.map((item, i) => (
                  <motion.span
                    key={item.txId}
                    layout
                    className="token"
                    style={{ '--kind': KIND_COLOR[item.kind] } as CSSProperties}
                    title={i < q.max ? 'dequeued at the end of this block' : 'over the per-block maximum; waits'}
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: i < q.max ? 1 : 0.35 }}
                    exit={{ y: 36, opacity: 0, scale: 0.6, transition: { duration: 0.35, delay: i * 0.03 } }}
                    transition={spring}
                  >
                    #{item.stakeId.toString()}
                  </motion.span>
                ))}
              </AnimatePresence>
            </div>
            <motion.div key={q.fee?.toString()} className="fee" initial={{ scale: 1.25 }} animate={{ scale: 1 }}>
              {q.fee === undefined ? 'inhibited' : `${q.fee} wei`}
              <span>fee · excess {q.excess.toString()}</span>
            </motion.div>
          </div>
        ))}
      </div>
    </section>
  )
}

interface StakeLaneProps {
  stakes: StakeView[]
  events: ClEvent[]
  selected: bigint | undefined
  onSelect: (id: bigint) => void
}

export function StakeLane({ stakes, events, selected, onSelect }: StakeLaneProps) {
  // Events about stake IDs with no card, e.g. a request naming a stake that doesn't exist.
  const orphans = events.filter((e) => !stakes.some((s) => s.id === e.stakeId))
  return (
    <section className="lane">
      <header className="lane-head">
        <h2>Consensus layer</h2>
        <span>stake positions keyed by stake ID · simplified model · click a stake to use it</span>
      </header>
      <div className="stakes">
        <AnimatePresence initial={false}>
          {stakes.map((s) => {
            const mine = events.filter((e) => e.stakeId === s.id)
            const rejected = mine.some((e) => e.outcome === 'ignored')
            return (
              <motion.button
                key={s.id.toString()}
                layout
                className={`stake ${s.status} ${selected === s.id ? 'selected' : ''}`}
                initial={{ opacity: 0, y: -24, scale: 0.9 }}
                animate={
                  rejected
                    ? { opacity: 1, y: 0, scale: 1, x: [0, -6, 6, -3, 3, 0] }
                    : { opacity: 1, y: 0, scale: mine.length ? [1, 1.04, 1] : 1 }
                }
                transition={{ duration: 0.45 }}
                onClick={() => onSelect(s.id)}
              >
                <div className="stake-top">
                  <span className="stake-id">#{s.id.toString()}</span>
                  <motion.span key={s.status} className={`status ${s.status}`} initial={{ scale: 1.3 }} animate={{ scale: 1 }}>
                    {s.status}
                  </motion.span>
                </div>
                <div className="stake-balance">{s.balance} ETH</div>
                <div className="stake-meta">
                  {s.owner}
                  {s.role && ` · ${s.role}`}
                  {s.validatorIndex !== undefined && ` #${s.validatorIndex}`}
                  {s.migrated && ' · migrated'}
                </div>
                <AnimatePresence>
                  {mine.slice(0, 3).map((e, i) => (
                    <motion.div
                      key={`${e.subject}-${i}`}
                      className={`event ${e.outcome}`}
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      transition={{ delay: 0.15 + i * 0.1 }}
                    >
                      <strong>{e.subject}</strong> {e.text}
                    </motion.div>
                  ))}
                  {mine.length > 3 && (
                    <motion.div key="more" className="event more" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                      +{mine.length - 3} more in this block
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.button>
            )
          })}
        </AnimatePresence>
      </div>
      {orphans.length > 0 && (
        <ul className="loose-events">
          {orphans.map((e, i) => (
            <li key={i}>
              #{e.stakeId?.toString()} {e.subject}: {e.text}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
