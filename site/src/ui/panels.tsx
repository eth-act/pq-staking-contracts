// State panels: consensus-layer stakes, system-contract queues, block reports, EL activity.
import { type Hex, formatEther, size, slice } from 'viem'
import { type QueueState, SYSTEM_CONTRACTS, type SystemContract } from '../chain/chain'
import { withdrawalAddressOf } from '../chain/encoding'
import { ACTORS, type Simulation } from '../sim/simulation'
import { RawHex, Segments, recordSegments, requestSegments } from './bytes'

const nameOf = (address: Hex) =>
  ACTORS.find((a) => a.address.toLowerCase() === address.toLowerCase())?.name ?? address

export function StakesPanel({ sim }: { sim: Simulation }) {
  const stakes = [...sim.consensus.stakes.values()].sort((a, b) => (a.stakeId < b.stakeId ? -1 : 1))
  return (
    <section className="panel">
      <h3>
        Stakes <span className="tag">consensus-layer model</span>
      </h3>
      <table>
        <thead>
          <tr>
            <th>stake ID</th>
            <th>withdrawal address</th>
            <th>status</th>
            <th>role</th>
            <th className="num">balance</th>
            <th className="num">validator index</th>
          </tr>
        </thead>
        <tbody>
          {stakes.map((s) => (
            <tr key={s.stakeId.toString()}>
              <td className="num">
                {s.stakeId.toString()}
                {s.migrated && <span className="tag">migrated</span>}
              </td>
              <td>{nameOf(withdrawalAddressOf(s.withdrawalCredentials))}</td>
              <td>
                <span className={`status ${s.status}`}>{s.status}</span>
              </td>
              <td>{s.role ?? '–'}</td>
              <td className="num">{formatEther(s.balanceGwei * 1_000_000_000n)} ETH</td>
              <td className="num">{s.validatorIndex ?? '–'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {sim.consensus.recoveryQueue.length > 0 && (
        <p className="hint">Recovery queue: {sim.consensus.recoveryQueue.join(', ')}</p>
      )}
    </section>
  )
}

export function QueuesPanel(props: {
  queues: Record<SystemContract, QueueState & { inhibited: boolean }>
  fees: Record<SystemContract, bigint | undefined>
}) {
  return (
    <section className="panel">
      <h3>
        System contracts <span className="tag">real bytecode</span>
      </h3>
      <table>
        <thead>
          <tr>
            <th>contract</th>
            <th className="num">fee (wei)</th>
            <th className="num">excess</th>
            <th className="num">requests this block</th>
            <th className="num">queued</th>
          </tr>
        </thead>
        <tbody>
          {SYSTEM_CONTRACTS.map((name) => {
            const q = props.queues[name]
            return (
              <tr key={name}>
                <td>{name}</td>
                <td className="num">{props.fees[name]?.toString() ?? 'inhibited'}</td>
                <td className="num">{q.inhibited ? '2²⁵⁶−1' : q.excess.toString()}</td>
                <td className="num">{q.count.toString()}</td>
                <td className="num">{(q.tail - q.head).toString()}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
      <p className="hint">
        Fee = <code>fake_exponential(1, excess, 17)</code>. Each block, <code>excess += requests − target</code>{' '}
        (target 2, or 1 for consolidations). Try sending many requests in one block.
      </p>
    </section>
  )
}

function decodedRows(contract: SystemContract, decoded: unknown[]): string[] {
  return decoded.map((d) => {
    const r = d as Record<string, bigint | Hex>
    if (contract === 'PQWithdrawal') {
      return `${nameOf(r.sourceAddress as Hex)} → stake ${r.stakeId}, amount ${r.amountGwei} gwei`
    }
    if (contract === 'PQConsolidation') {
      return `${nameOf(r.sourceAddress as Hex)} → stake ${r.sourceStakeId} into ${r.targetStakeId}`
    }
    return `stake ${r.stakeId}: bls_pubkey 48B, bls_signature 96B, pq_pubkey ${size(r.pqPubkey as Hex)}B, pq_signature ${size(r.pqSignature as Hex)}B`
  })
}

export function BlocksPanel({ sim }: { sim: Simulation }) {
  return (
    <section className="panel">
      <h3>Blocks</h3>
      {sim.blocks.slice(0, 6).map((b) => (
        <div key={b.block} className="block-report">
          <div className="block-title">Block {b.block}: end-of-block system calls</div>
          {b.outputs
            .filter((o) => o.raw !== '0x')
            .map((o) => (
              <div key={o.contract} className="output">
                <div>
                  <strong>{o.contract}</strong> returned {size(o.raw)} bytes
                  {o.contract.endsWith('Registration') ? ' (SSZ list)' : ` (${size(o.raw) / 36} × 36-byte records)`}
                </div>
                {o.contract === 'PQWithdrawal' || o.contract === 'PQConsolidation' ? (
                  Array.from({ length: size(o.raw) / 36 }, (_, i) => (
                    <Segments
                      key={i}
                      segments={recordSegments(o.contract as 'PQWithdrawal' | 'PQConsolidation', slice(o.raw, 36 * i, 36 * i + 36))}
                    />
                  ))
                ) : (
                  <RawHex hex={o.raw} />
                )}
                <ul className="decoded">
                  {decodedRows(o.contract, o.decoded).map((row, i) => (
                    <li key={i}>{row}</li>
                  ))}
                </ul>
              </div>
            ))}
          {b.outputs.every((o) => o.raw === '0x') && <div className="hint">No queued requests.</div>}
          <ul className="cl-events">
            {b.clEvents.map((e, i) => (
              <li key={i} className={e.outcome}>
                {e.text}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  )
}

export function ActivityPanel({ sim }: { sim: Simulation }) {
  return (
    <section className="panel">
      <h3>Transactions</h3>
      {sim.activity.length === 0 && <p className="hint">Nothing sent yet.</p>}
      {sim.activity.slice(0, 20).map((a, i) => {
        const segments = requestSegments(a.contract, a.calldata)
        return (
          <details key={i} className={`tx ${a.result.ok ? '' : 'reverted'}`} open={i === 0}>
            <summary>
              <span className="tx-block">#{a.block}</span> {a.actor}: {a.title}
              <span className="tx-meta">
                {a.result.ok ? '' : 'reverted · '}
                {a.contract} · {a.result.gasUsed.toLocaleString()} gas
                {a.valueWei > 0n &&
                  (a.valueWei < 1_000_000_000n ? ` · ${a.valueWei} wei fee` : ` · ${formatEther(a.valueWei)} ETH`)}
              </span>
            </summary>
            <div className="tx-body">
              <div className="label">calldata ({size(a.calldata)} bytes)</div>
              {segments ? <Segments segments={segments} /> : <RawHex hex={a.calldata} />}
              {a.result.logs.map((log, j) => (
                <div key={j}>
                  <div className="label">
                    {log.topics.length === 0 ? 'log0 (no topics)' : `log${log.topics.length}`} data ({size(log.data)} bytes)
                  </div>
                  <RawHex hex={log.data} />
                </div>
              ))}
            </div>
          </details>
        )
      })}
    </section>
  )
}
