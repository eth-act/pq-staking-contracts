// Byte formats of the system contracts (see contracts/README.md). Request calldata uses
// big-endian integers; system-call output uses little-endian (SSZ).
import { type Hex, bytesToHex, concat, numberToHex, sha256, size, slice } from 'viem'

const u64be = (v: bigint) => numberToHex(v, { size: 8 })

function readLe(bytes: Uint8Array, offset: number, length: number): bigint {
  let v = 0n
  for (let i = length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[offset + i])
  return v
}

// --- Request calldata -----------------------------------------------------------------------

export const encodeWithdrawal = (stakeId: bigint, amountGwei: bigint): Hex =>
  concat([u64be(stakeId), u64be(amountGwei)])

export const encodeConsolidation = (sourceStakeId: bigint, targetStakeId: bigint): Hex =>
  concat([u64be(sourceStakeId), u64be(targetStakeId)])

export interface RegistrationFields {
  stakeId: bigint
  blsPubkey: Hex
  blsSignature: Hex
  pqPubkey: Hex
  pqSignature: Hex
}

export const encodeRegistration = (r: RegistrationFields): Hex =>
  concat([
    u64be(r.stakeId),
    r.blsPubkey,
    r.blsSignature,
    numberToHex(size(r.pqPubkey), { size: 2 }),
    r.pqPubkey,
    r.pqSignature,
  ])

// --- System call output ---------------------------------------------------------------------

export interface WithdrawalRecord {
  sourceAddress: Hex
  stakeId: bigint
  amountGwei: bigint
}

export interface ConsolidationRecord {
  sourceAddress: Hex
  sourceStakeId: bigint
  targetStakeId: bigint
}

export function decodeWithdrawalRecords(out: Uint8Array): WithdrawalRecord[] {
  const records: WithdrawalRecord[] = []
  for (let o = 0; o < out.length; o += 36) {
    records.push({
      sourceAddress: bytesToHex(out.slice(o, o + 20)),
      stakeId: readLe(out, o + 20, 8),
      amountGwei: readLe(out, o + 28, 8),
    })
  }
  return records
}

export function decodeConsolidationRecords(out: Uint8Array): ConsolidationRecord[] {
  const records: ConsolidationRecord[] = []
  for (let o = 0; o < out.length; o += 36) {
    records.push({
      sourceAddress: bytesToHex(out.slice(o, o + 20)),
      sourceStakeId: readLe(out, o + 20, 8),
      targetStakeId: readLe(out, o + 28, 8),
    })
  }
  return records
}

/** Decode SSZ `List[RegistrationRequest]` (variable-size elements: 4-byte offsets first). */
export function decodeRegistrationSsz(out: Uint8Array): RegistrationFields[] {
  if (out.length === 0) return []
  const count = Number(readLe(out, 0, 4)) / 4
  const starts = Array.from({ length: count }, (_, i) => Number(readLe(out, 4 * i, 4)))
  return starts.map((start, i) => {
    const end = i + 1 < count ? starts[i + 1] : out.length
    const el = out.slice(start, end)
    const pqPubkeyOffset = Number(readLe(el, 152, 4))
    const pqSignatureOffset = Number(readLe(el, 156, 4))
    return {
      stakeId: readLe(el, 0, 8),
      blsPubkey: bytesToHex(el.slice(8, 56)),
      blsSignature: bytesToHex(el.slice(56, 152)),
      pqPubkey: bytesToHex(el.slice(pqPubkeyOffset, pqSignatureOffset)),
      pqSignature: bytesToHex(el.slice(pqSignatureOffset)),
    }
  })
}

// --- Credentials ----------------------------------------------------------------------------

/** 0x01 execution withdrawal credentials pointing at `address`. */
export const withdrawalCredentials = (address: Hex): Hex =>
  concat(['0x01', numberToHex(0, { size: 11 }), address])

export const withdrawalAddressOf = (credentials: Hex): Hex => slice(credentials, 12, 32)

/**
 * Demo assumption: version 0x01 commits to both public keys,
 * `0x01 || sha256(bls_pubkey || pq_pubkey)[1:]`. EIP-8413 only defines a BLS-only version.
 */
export const authorizationCommitment = (blsPubkey: Hex, pqPubkey: Hex): Hex =>
  concat(['0x01', slice(sha256(concat([blsPubkey, pqPubkey])), 1)])

// --- Mock signatures ------------------------------------------------------------------------

/** Deterministic stand-in for a signature over `stakeId`, so the model can "verify" it. */
export function mockSignature(scheme: 'bls' | 'pq', stakeId: bigint, pubkey: Hex, length: number): Hex {
  const seed = sha256(concat([numberToHex(scheme === 'bls' ? 1 : 2, { size: 1 }), u64be(stakeId), pubkey]))
  const blocks = Array.from({ length: Math.ceil(length / 32) }, (_, i) =>
    sha256(concat([seed, numberToHex(i, { size: 4 })])),
  )
  return slice(concat(blocks), 0, length)
}

export function randomHex(length: number): Hex {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytesToHex(bytes)
}
