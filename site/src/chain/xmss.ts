// leanXMSS-K proof-of-possession signing with pre-generated demo keys (xmss/gen_vectors.py).
// Follows xmss/README.md byte for byte; the registration contract verifies the result.
import { type Hex, concat, keccak256, numberToHex, slice, toBytes } from 'viem'
import demoKeys from '../keys/leanxmss-k-keys.json'

export interface DemoKey {
  skSeed: Hex
  publicSeed: Hex
  pubkey: Hex
  /** Top layer of the PoP signature: it signs the fixed bottom root, so it is precomputed. */
  topSignature: Hex
  bottomAuthPath: Hex
}

export const DEMO_KEYS = demoKeys as DemoKey[]

const POP_TOP_LEAF = 0xffff
const POP_BOTTOM_LEAF = 0xffff
const BOTTOM_LAYER = 1
const CHAINS = 58
const TARGET_SUM = 106
const MESSAGE = 3
const SECRET = 4

const POP_DOMAIN = keccak256(toBytes('leanXMSS-K registration proof of possession v1'))

/** 16-byte tweak: type, layer, tree (u32), index (u32), chain/level, position, 4 zero bytes. */
function tweak(kind: number, layer: number, tree: number, index: number, c = 0, j = 0): Hex {
  return concat([
    numberToHex(kind, { size: 1 }),
    numberToHex(layer, { size: 1 }),
    numberToHex(tree, { size: 4 }),
    numberToHex(index, { size: 4 }),
    numberToHex(c, { size: 1 }),
    numberToHex(j, { size: 1 }),
    '0x00000000',
  ])
}

/** Message the registration proof of possession signs. */
export function popMessage(chainId: bigint, registrationContract: Hex, stakeId: bigint, pubkey: Hex): Hex {
  return keccak256(
    concat([POP_DOMAIN, numberToHex(chainId, { size: 32 }), registrationContract, numberToHex(stakeId, { size: 8 }), pubkey]),
  )
}

/** Sign `message` at the reserved PoP slot (2^32 - 1). Returns the 2400-byte signature. */
export function signProofOfPossession(key: DemoKey, message: Hex): Hex {
  const tree = POP_TOP_LEAF
  const leaf = POP_BOTTOM_LEAF
  const messageTweak = tweak(MESSAGE, BOTTOM_LAYER, tree, leaf)

  let rho: Hex = '0x'
  let digits: number[] = []
  for (let counter = 0n; ; counter++) {
    rho = slice(keccak256(concat([key.skSeed, messageTweak, message, numberToHex(counter, { size: 8 })])), 0, 16)
    const d = BigInt(keccak256(concat([key.publicSeed, messageTweak, rho, message])))
    digits = Array.from({ length: CHAINS }, (_, k) => Number((d >> BigInt(254 - 2 * k)) & 3n))
    if (digits.reduce((a, b) => a + b, 0) === TARGET_SUM) break
  }

  const sigma = digits.map((digit, i) => {
    let x = slice(keccak256(concat([key.skSeed, tweak(SECRET, BOTTOM_LAYER, tree, leaf, i)])), 0, 16)
    for (let j = 0; j < digit; j++) {
      x = slice(keccak256(concat([key.publicSeed, tweak(0, BOTTOM_LAYER, tree, leaf, i, j), x])), 0, 16)
    }
    return x
  })

  return concat([key.topSignature, rho, ...sigma, key.bottomAuthPath])
}
