// leanXMSS-K proof-of-possession signing with pre-generated demo keys (xmss/gen_vectors.py).
// Follows xmss/README.md byte for byte; the registration contract verifies the result.
import { type Hex, bytesToHex, concat, hexToBytes, keccak256, numberToHex, toBytes } from 'viem'
import demoKeys from '../keys/leanxmss-k-keys.json'

export interface DemoKey {
  skSeed: Hex
  publicSeed: Hex
  pubkey: Hex
  /** Top layer for top leaf 0xFFFF: it always signs the PoP bottom tree's root. */
  topSignature: Hex
  /** Level `storedLevel` of the PoP bottom tree; lower levels are rebuilt per signature. */
  storedLevel: number
  bottomLevelNodes: Hex
  bottomRoot: Hex
}

export const DEMO_KEYS = demoKeys as DemoKey[]

const N = 16
const HEIGHT = 16
const CHAINS = 58
const TARGET_SUM = 106
const POP_TOP_LEAF = 0xffff
const BOTTOM_LAYER = 1
const [CHAIN, LEAF, NODE, MESSAGE, SECRET] = [0, 1, 2, 3, 4]

const POP_DOMAIN = keccak256(toBytes('leanXMSS-K registration proof of possession v1'))

/** 16-byte tweak: type, layer, tree (u32), index (u32), chain/level, position, 4 zero bytes. */
function tweak(kind: number, index: number, c = 0, j = 0): Uint8Array {
  const t = new Uint8Array(16)
  const view = new DataView(t.buffer)
  t[0] = kind
  t[1] = BOTTOM_LAYER
  view.setUint32(2, POP_TOP_LEAF)
  view.setUint32(6, index)
  t[10] = c
  t[11] = j
  return t
}

/** First 16 bytes of Keccak-256 over the concatenated parts. */
function t16(...parts: Uint8Array[]): Uint8Array {
  return keccak256(concat(parts), 'bytes').slice(0, N)
}

/** Message the registration proof of possession signs. */
export function popMessage(chainId: bigint, registrationContract: Hex, stakeId: bigint, pubkey: Hex): Hex {
  return keccak256(
    concat([POP_DOMAIN, numberToHex(chainId, { size: 32 }), registrationContract, numberToHex(stakeId, { size: 8 }), pubkey]),
  )
}

/** PoP slot for `message`: top leaf 0xFFFF, bottom leaf = last two bytes of the message. */
export function popSlot(message: Hex): number {
  return ((POP_TOP_LEAF << 16) | Number(BigInt(message) & 0xffffn)) >>> 0
}

/** Authentication path for `leaf` in the PoP bottom tree. Rebuilds the 2^storedLevel-leaf subtree. */
function bottomAuthPath(key: DemoKey, sk: Uint8Array, P: Uint8Array, leaf: number): Uint8Array[] {
  const stored = key.storedLevel
  const block = leaf >> stored
  const first = block << stored

  // Leaves of the subtree: WOTS+C chain ends hashed into one leaf value each.
  let level: Uint8Array[] = []
  for (let b = first; b < first + (1 << stored); b++) {
    const ends: Uint8Array[] = []
    for (let i = 0; i < CHAINS; i++) {
      let x = t16(sk, tweak(SECRET, b, i))
      for (let j = 0; j < 3; j++) x = t16(P, tweak(CHAIN, b, i, j), x)
      ends.push(x)
    }
    level.push(t16(P, tweak(LEAF, b), ...ends))
  }

  const path: Uint8Array[] = []
  let index = leaf - first
  for (let h = 1; h <= stored; h++) {
    path.push(level[index ^ 1])
    level = Array.from({ length: level.length / 2 }, (_, k) =>
      t16(P, tweak(NODE, (first >> h) + k, h), level[2 * k], level[2 * k + 1]),
    )
    index >>= 1
  }

  // Levels at and above the stored one come from the published nodes.
  const storedBytes = hexToBytes(key.bottomLevelNodes)
  let upper: Uint8Array[] = Array.from({ length: 1 << (HEIGHT - stored) }, (_, k) => storedBytes.slice(k * N, (k + 1) * N))
  if (bytesToHex(upper[block]) !== bytesToHex(level[0])) throw new Error('demo key: rebuilt subtree does not match')
  index = block
  for (let h = stored + 1; h <= HEIGHT; h++) {
    path.push(upper[index ^ 1])
    upper = Array.from({ length: upper.length / 2 }, (_, k) => t16(P, tweak(NODE, k, h), upper[2 * k], upper[2 * k + 1]))
    index >>= 1
  }
  if (bytesToHex(upper[0]) !== key.bottomRoot) throw new Error('demo key: rebuilt root does not match')
  return path
}

/** Sign `message` at its PoP slot. Returns the 2400-byte signature. */
export function signProofOfPossession(key: DemoKey, message: Hex): Hex {
  const sk = hexToBytes(key.skSeed)
  const P = hexToBytes(key.publicSeed)
  const M = hexToBytes(message)
  const leaf = popSlot(message) & 0xffff
  const messageTweak = tweak(MESSAGE, leaf)

  // Deterministic rho: first counter whose digest digits sum to the target.
  let rho = new Uint8Array()
  let digits: number[] = []
  for (let counter = 0n; ; counter++) {
    rho = keccak256(concat([sk, messageTweak, M, hexToBytes(numberToHex(counter, { size: 8 }))]), 'bytes').slice(0, N)
    const d = BigInt(keccak256(concat([P, messageTweak, rho, M])))
    digits = Array.from({ length: CHAINS }, (_, k) => Number((d >> BigInt(254 - 2 * k)) & 3n))
    if (digits.reduce((a, b) => a + b, 0) === TARGET_SUM) break
  }

  const sigma = digits.map((digit, i) => {
    let x = t16(sk, tweak(SECRET, leaf, i))
    for (let j = 0; j < digit; j++) x = t16(P, tweak(CHAIN, leaf, i, j), x)
    return x
  })

  return concat([key.topSignature, bytesToHex(rho), ...sigma.map((s) => bytesToHex(s)), ...bottomAuthPath(key, sk, P, leaf).map((n) => bytesToHex(n))])
}
