// Labeled hex rendering: splits request calldata and system-call records into their fields.
import { type Hex, size, slice } from 'viem'
import type { ContractName, SystemContract } from '../chain/chain'
import { PQ_PUBKEY_LENGTH, PQ_SIGNATURE_LENGTH, REGISTRATION_LENGTH } from '../chain/encoding'

export interface Segment {
  label: string
  hex: Hex
}

function cut(hex: Hex, fields: [label: string, length: number][]): Segment[] {
  const segments: Segment[] = []
  let offset = 0
  for (const [label, length] of fields) {
    if (offset + length > size(hex)) break
    segments.push({ label, hex: slice(hex, offset, offset + length) })
    offset += length
  }
  return segments
}

/** Registration fields after stake_id; same order in calldata and system-call records. */
const REGISTRATION_FIELDS: [string, number][] = [
  ['pq_pubkey', PQ_PUBKEY_LENGTH],
  ['pq_signature', PQ_SIGNATURE_LENGTH],
]

/** Field layout of request calldata sent to `contract`, or `undefined` for ABI calls. */
export function requestSegments(contract: ContractName, calldata: Hex): Segment[] | undefined {
  if (contract === 'PQWithdrawal') return cut(calldata, [['stake_id (u64 BE)', 8], ['amount_gwei (u64 BE)', 8]])
  if (contract === 'PQConsolidation') {
    return cut(calldata, [['source_stake_id (u64 BE)', 8], ['target_stake_id (u64 BE)', 8]])
  }
  if (contract === 'PQValidatorRegistration' || contract === 'PQBuilderRegistration') {
    return cut(calldata, [['stake_id (u64 BE)', 8], ...REGISTRATION_FIELDS])
  }
  return undefined
}

/** Size of one record in a system contract's system-call output. */
export const RECORD_LENGTH: Record<SystemContract, number> = {
  PQWithdrawal: 36,
  PQConsolidation: 36,
  PQValidatorRegistration: REGISTRATION_LENGTH,
  PQBuilderRegistration: REGISTRATION_LENGTH,
}

/** Field layout of one record returned by a system call. */
export function recordSegments(contract: SystemContract, record: Hex): Segment[] {
  if (contract === 'PQWithdrawal') {
    return cut(record, [['source_address', 20], ['stake_id (u64 LE)', 8], ['amount_gwei (u64 LE)', 8]])
  }
  if (contract === 'PQConsolidation') {
    return cut(record, [['source_address', 20], ['source_stake_id (u64 LE)', 8], ['target_stake_id (u64 LE)', 8]])
  }
  return cut(record, [['stake_id (u64 LE)', 8], ...REGISTRATION_FIELDS])
}

const PREVIEW_BYTES = 12

/** Long fields show their head and tail with the byte count in between. */
function abbreviate(hex: Hex): string {
  const n = size(hex)
  if (n <= PREVIEW_BYTES * 2) return hex.slice(2)
  return `${hex.slice(2, 2 + PREVIEW_BYTES * 2)}…(${n} bytes)…${hex.slice(-PREVIEW_BYTES * 2)}`
}

export function Segments({ segments }: { segments: Segment[] }) {
  return (
    <div className="segments">
      {segments.map((s, i) => (
        <span key={i} className={`segment c${i % 6}`} title={`${s.label}: ${size(s.hex)} bytes`}>
          <span className="segment-label">
            {s.label} · {size(s.hex)}B
          </span>
          <code>{abbreviate(s.hex)}</code>
        </span>
      ))}
    </div>
  )
}

export function RawHex({ hex }: { hex: Hex }) {
  return <code className="raw-hex">{hex === '0x' ? '0x (empty)' : abbreviate(hex)}</code>
}
