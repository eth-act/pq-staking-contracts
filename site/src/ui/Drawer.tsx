// Details on demand: labeled bytes of a transaction, or the system-call output of a block.
import { motion } from 'motion/react'
import { size, slice } from 'viem'
import type { Simulation } from '../sim/simulation'
import { RECORD_LENGTH, RawHex, Segments, recordSegments, requestSegments } from './bytes'
import type { Selection } from './ChainView'
import { formatEth } from './view'

export function Drawer({ sim, selection, onClose }: { sim: Simulation; selection: Selection; onClose: () => void }) {
  return (
    <motion.aside
      className="drawer"
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', stiffness: 320, damping: 34 }}
    >
      <button className="close" onClick={onClose}>
        ✕
      </button>
      {selection.type === 'tx' ? <TxDetails sim={sim} id={selection.id} /> : <BlockDetails sim={sim} number={selection.number} />}
    </motion.aside>
  )
}

function TxDetails({ sim, id }: { sim: Simulation; id: number }) {
  const tx = sim.activity.find((a) => a.id === id)
  if (!tx) return null
  const segments = requestSegments(tx.contract, tx.calldata)
  return (
    <div>
      <h3>{tx.title}</h3>
      <dl>
        <dt>from</dt>
        <dd>{tx.actor}</dd>
        <dt>to</dt>
        <dd>{tx.contract}</dd>
        <dt>value</dt>
        <dd>{tx.valueWei < 1_000_000_000n ? `${tx.valueWei} wei (fee)` : `${formatEth(tx.valueWei)} ETH`}</dd>
        <dt>execution gas</dt>
        <dd>{tx.result.gasUsed.toLocaleString()}</dd>
        <dt>result</dt>
        <dd>{tx.result.ok ? 'success' : 'reverted'}</dd>
      </dl>
      <h4>
        Calldata · {size(tx.calldata)} bytes {segments ? '· raw, no ABI' : '· Solidity ABI'}
      </h4>
      {segments ? <Segments segments={segments} /> : <RawHex hex={tx.calldata} />}
      {tx.result.logs.map((log, i) => (
        <div key={i}>
          <h4>
            {log.topics.length === 0 ? 'log0 · no topics' : `log${log.topics.length}`} · {size(log.data)} bytes
          </h4>
          <RawHex hex={log.data} />
        </div>
      ))}
    </div>
  )
}

function BlockDetails({ sim, number }: { sim: Simulation; number: number }) {
  const report = sim.blocks.find((b) => b.block === number)
  if (!report) return null
  const outputs = report.outputs.filter((o) => o.raw !== '0x')
  return (
    <div>
      <h3>Block #{number}</h3>
      <p className="muted">
        At the end of the block each system contract is called from <code>0xff…fe</code> and returns its queued
        requests as bytes for the consensus layer.
      </p>
      {outputs.length === 0 && <p className="muted">No requests were dequeued.</p>}
      {outputs.map((o) => {
        const recordLength = RECORD_LENGTH[o.contract]
        const count = size(o.raw) / recordLength
        return (
          <div key={o.contract}>
            <h4>
              {o.contract} · {count} × {recordLength}-byte record{count === 1 ? '' : 's'}
            </h4>
            {Array.from({ length: count }, (_, i) => (
              <Segments
                key={i}
                segments={recordSegments(o.contract, slice(o.raw, recordLength * i, recordLength * (i + 1)))}
              />
            ))}
          </div>
        )
      })}
      <h4>Consensus layer</h4>
      <ul className="events">
        {report.clEvents.map((e, i) => (
          <li key={i} className={e.outcome}>
            {e.stakeId !== undefined && `#${e.stakeId} `}
            <strong>{e.subject}</strong> {e.text}
          </li>
        ))}
      </ul>
    </div>
  )
}
