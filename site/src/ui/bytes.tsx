// Labeled hex rendering: splits request calldata and system-call records into their fields.
import { type Hex, size, slice } from 'viem'
import type { ContractName } from '../chain/chain'

export interface Segment {
  label: string
  hex: Hex
}

function cut(hex: Hex, fields: [label: string, length: number | 'rest'][]): Segment[] {
  const segments: Segment[] = []
  let offset = 0
  for (const [label, length] of fields) {
    const end = length === 'rest' ? size(hex) : offset + length
    if (end > size(hex) || end <= offset) break
    segments.push({ label, hex: slice(hex, offset, end) })
    offset = end
  }
  return segments
}

/** Field layout of request calldata sent to `contract`, or `undefined` for ABI calls. */
export function requestSegments(contract: ContractName, calldata: Hex): Segment[] | undefined {
  if (contract === 'PQWithdrawal') return cut(calldata, [['stake_id (u64 BE)', 8], ['amount_gwei (u64 BE)', 8]])
  if (contract === 'PQConsolidation') {
    return cut(calldata, [['source_stake_id (u64 BE)', 8], ['target_stake_id (u64 BE)', 8]])
  }
  if (contract === 'PQValidatorRegistration' || contract === 'PQBuilderRegistration') {
    const pqLength = size(calldata) >= 154 ? Number(BigInt(slice(calldata, 152, 154))) : 0
    return cut(calldata, [
      ['stake_id (u64 BE)', 8],
      ['bls_pubkey', 48],
      ['bls_signature', 96],
      ['pq_pubkey_length (u16 BE)', 2],
      ['pq_pubkey', pqLength],
      ['pq_signature', 'rest'],
    ])
  }
  return undefined
}

/** Field layout of one 36-byte withdrawal or consolidation record from a system call. */
export function recordSegments(contract: 'PQWithdrawal' | 'PQConsolidation', record: Hex): Segment[] {
  return contract === 'PQWithdrawal'
    ? cut(record, [['source_address', 20], ['stake_id (u64 LE)', 8], ['amount_gwei (u64 LE)', 8]])
    : cut(record, [['source_address', 20], ['source_stake_id (u64 LE)', 8], ['target_stake_id (u64 LE)', 8]])
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
