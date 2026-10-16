// Block row: sealed blocks shrink into history; the current block collects transaction chips.
import { AnimatePresence, motion } from 'motion/react'
import type { CSSProperties } from 'react'
import { KIND_COLOR } from './Dock'
import type { TxView, View } from './view'

export type Selection = { type: 'tx'; id: number } | { type: 'block'; number: number }

interface ChainProps {
  view: View
  sealing: boolean
  busy: boolean
  onEndBlock: () => void
  onSelect: (s: Selection) => void
}

const spring = { type: 'spring', stiffness: 380, damping: 32 } as const

export function ChainView({ view, sealing, busy, onEndBlock, onSelect }: ChainProps) {
  return (
    <div className="chain">
      <div className="history">
        <AnimatePresence initial={false} mode="popLayout">
          {[...view.sealed].reverse().map((b) => (
            <motion.button
              key={b.number}
              layoutId={`block-${b.number}`}
              className="block sealed"
              transition={spring}
              exit={{ opacity: 0, x: -40 }}
              onClick={() => onSelect({ type: 'block', number: b.number })}
            >
              <span className="block-no">#{b.number}</span>
              <span className="dots">
                {b.txs.map((t) => (
                  <i key={t.id} style={{ background: t.ok ? KIND_COLOR[t.kind] : 'var(--muted)' }} />
                ))}
              </span>
              <span className="block-sub">
                {b.txs.length} tx · {b.requestsOut} req
              </span>
            </motion.button>
          ))}
        </AnimatePresence>
      </div>

      <motion.div
        key={view.block}
        layoutId={`block-${view.block}`}
        className={`block current ${sealing ? 'sealing' : ''}`}
        initial={{ opacity: 0, x: 60 }}
        animate={{ opacity: 1, x: 0 }}
        transition={spring}
      >
        <div className="block-head">
          <span className="block-no">Block #{view.block}</span>
          <span className="block-sub">{sealing ? 'sealing…' : 'collecting transactions'}</span>
        </div>
        <div className="chips">
          <AnimatePresence initial={false}>
            {view.currentTxs.map((tx) => (
              <TxChip key={tx.id} tx={tx} onClick={() => onSelect({ type: 'tx', id: tx.id })} />
            ))}
          </AnimatePresence>
          {view.currentTxs.length === 0 && <span className="empty">Send a transaction from the left.</span>}
        </div>
        <AnimatePresence>
          {sealing && (
            <motion.div
              className="seal"
              initial={{ scale: 1.6, opacity: 0, rotate: -12 }}
              animate={{ scale: 1, opacity: 1, rotate: -8 }}
              exit={{ opacity: 0 }}
              transition={{ type: 'spring', stiffness: 500, damping: 18 }}
            >
              sealed
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      <button className="end-block" disabled={busy} onClick={onEndBlock}>
        End block
        <span>run system calls ▸</span>
      </button>
    </div>
  )
}

function TxChip({ tx, onClick }: { tx: TxView; onClick: () => void }) {
  return (
    <motion.button
      layout
      className={`chip ${tx.ok ? '' : 'failed'}`}
      style={{ '--kind': KIND_COLOR[tx.kind] } as CSSProperties}
      initial={{ opacity: 0, x: -120, scale: 0.7 }}
      animate={tx.ok ? { opacity: 1, x: 0, scale: 1 } : { opacity: 1, scale: 1, x: [0, -8, 8, -5, 5, 0] }}
      transition={tx.ok ? spring : { duration: 0.45 }}
      onClick={onClick}
      title="Show bytes"
    >
      <span className="chip-actor">{tx.actor}</span>
      <span className="chip-title">{tx.title}</span>
      {!tx.ok && <span className="chip-fail">reverted</span>}
    </motion.button>
  )
}
