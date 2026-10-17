/-
Statement-by-statement transcription of `LeanXmssK.verify` / `_layerRoot`
(contracts/src/LeanXmssK.sol @ 2e7d21f) over a 16-byte-granular memory model.

Memory abstraction (the only modelling step): every memory access in `_layerRoot` is at
`buf + 16·k` and every length is a multiple of 16, so memory past the free pointer `buf` is
modelled as `Mem = Nat → C`, chunk `k` = bytes `[buf+16k, buf+16k+16)`:
  * `mstore(buf+16k, w)`        = chunk k := high half of w, chunk k+1 := low half;
  * `calldatacopy(buf+16k, o, 16)` = chunk k := 16 calldata bytes at o;
  * `keccak256(buf+16k, 16n)`   = K [chunk k, …, chunk k+n−1];
  * `calldataload(o + 16c)`     = piece c ‖ piece c+1 of the calldata slice starting at o.
All Yul values are 256-bit words (`W`), including loop counters; `lt`, `add`, `shl`, `shr`,
`and`, `or`, `sub`, `eq` are the corresponding `BitVec 256` operations (EVM semantics:
shifts by ≥ 256 give 0, arithmetic wraps). Loops are written with a fuel argument equal to
their exact trip-count bound; the proofs show the loop condition is false when fuel runs out.
The initial memory content is arbitrary (`m0`).
-/
import LeanXmssK.Spec

namespace LeanXmssK

abbrev Mem := Nat → C

def hiW (w : W) : C := w.extractLsb' 128 128
def loW (w : W) : C := w.extractLsb' 0 128

/-- `mstore(buf + off, w)` with `off` a byte offset multiple of 16. -/
def mstore (m : Mem) (off : Nat) (w : W) : Mem :=
  fun k => if k = off / 16 then hiW w else if k = off / 16 + 1 then loW w else m k

/-- `calldatacopy(buf + off, src, 16)`. -/
def calldatacopy16 (m : Mem) (off : Nat) (src : C) : Mem :=
  fun k => if k = off / 16 then src else m k

def HIGH_128 : W := 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000#256

section
variable (K : List C → W)

/-- `keccak256(buf + off, len)`. -/
def keccakM (m : Mem) (off len : Nat) : W :=
  K ((List.range (len / 16)).map fun k => m (off / 16 + k))

/-- `calldataload(layerSig.offset + byteOff)` for `byteOff` a multiple of 16. -/
def calldataload (sig : Nat → C) (byteOff : Nat) : W := sig (byteOff / 16) ++ sig (byteOff / 16 + 1)

/-- `for { let k := 0 } lt(k, 58) { k := add(k, 1) }
       { sum := add(sum, and(shr(sub(254, shl(1, k)), d), 3)) }` -/
def sumLoop (d : W) : Nat → W → W → W
  | 0, _, sum => sum
  | fuel + 1, k, sum =>
    if k < 58#256 then sumLoop d fuel (k + 1#256) (sum + ((d >>> (254#256 - (k <<< 1))) &&& 3#256))
    else sum

/-- Inner chain loop:
    `for { let j := and(shr(sub(254, shl(1, i)), d), 3) } lt(j, 3) { j := add(j, 1) }
       { mstore(buf, or(leafBase, or(shl(40, i), shl(32, j))))
         mstore(add(buf, 32), x)
         x := and(keccak256(buf, 48), HIGH_128) }` -/
def stepLoop (leafBase i : W) : Nat → W → W × Mem → W × Mem
  | 0, _, s => s
  | fuel + 1, j, (x, m) =>
    if j < 3#256 then
      let m := mstore m 0 (leafBase ||| ((i <<< 40) ||| (j <<< 32)))
      let m := mstore m 32 x
      let x := keccakM K m 0 48 &&& HIGH_128
      stepLoop leafBase i fuel (j + 1#256) (x, m)
    else (x, m)

/-- Outer chain loop:
    `for { let i := 0 } lt(i, 58) { i := add(i, 1) }
       { let x := and(calldataload(add(layerSig.offset, add(16, shl(4, i)))), HIGH_128)
         <stepLoop>
         mstore(add(buf, add(0xa0, shl(4, i))), x) }` -/
def chainsLoop (sig : Nat → C) (leafBase d : W) : Nat → W → Mem → Mem
  | 0, _, m => m
  | fuel + 1, i, m =>
    if i < 58#256 then
      let x := calldataload sig (16 + (i <<< 4).toNat) &&& HIGH_128
      let j0 := (d >>> (254#256 - (i <<< 1))) &&& 3#256
      let (x, m) := stepLoop K leafBase i 3 j0 (x, m)
      let m := mstore m (0xa0 + (i <<< 4).toNat) x
      chainsLoop sig leafBase d fuel (i + 1#256) m
    else m

/-- Merkle loop:
    `for { let h := 1 } lt(h, 17) { h := add(h, 1) }
       { let sibling := and(calldataload(add(layerSig.offset, add(944, shl(4, sub(h, 1))))), HIGH_128)
         mstore(buf, or(base, or(shl(120, 2), or(shl(48, shr(1, leaf)), shl(40, h)))))
         switch and(leaf, 1)
         case 0 { mstore(add(buf, 32), or(node, shr(128, sibling))) }
         default { mstore(add(buf, 32), or(sibling, shr(128, node))) }
         node := and(keccak256(buf, 64), HIGH_128)
         leaf := shr(1, leaf) }` -/
def merkleLoop (sig : Nat → C) (base : W) : Nat → W → W × W × Mem → W × W × Mem
  | 0, _, s => s
  | fuel + 1, h, (node, leaf, m) =>
    if h < 17#256 then
      let sibling := calldataload sig (944 + ((h - 1#256) <<< 4).toNat) &&& HIGH_128
      let m := mstore m 0 (base ||| ((2#256 <<< 120) ||| ((leaf >>> 1) <<< 48 ||| (h <<< 40))))
      let m := if (leaf &&& 1#256) = 0#256 then mstore m 32 (node ||| (sibling >>> 128))
               else mstore m 32 (sibling ||| (node >>> 128))
      let node := keccakM K m 0 64 &&& HIGH_128
      merkleLoop sig base fuel (h + 1#256) (node, leaf >>> 1, m)
    else (node, leaf, m)

/-- `_layerRoot(base, leaf, message, messageLength, layerSig)`: returns `(ok, root, mem)`. -/
def layerRootM (base leaf message messageLength : W) (sig : Nat → C) (m : Mem) :
    Bool × W × Mem :=
  let leafBase := base ||| (leaf <<< 48)
  let m := mstore m 0 (leafBase ||| (3#256 <<< 120))
  let m := calldatacopy16 m 32 (sig 0)
  let m := mstore m 48 message
  let d := keccakM K m 0 (48 + messageLength.toNat)
  let sum := sumLoop d 58 0#256 0#256
  if sum = 106#256 then
    let m := chainsLoop K sig leafBase d 58 0#256 m
    let m := mstore m 0x80 (leafBase ||| (1#256 <<< 120))
    let node := keccakM K m 0x80 960 &&& HIGH_128
    let (node, _, m) := merkleLoop K sig base 16 1#256 (node, leaf, m)
    (true, node, m)
  else (false, 0#256, m)

/-- `verify(pubkey, slot, message, signature)` for `signature.length == 2400`
(the length check itself is `if (signature.length != 2400) return false`). `sig c` = 16-byte
piece c of the signature; `signature[1200:]` starts at piece 75. -/
def verifyM (pubkey : W) (slot32 : BitVec 32) (message : W) (sig : Nat → C) (m0 : Mem) : Bool :=
  let slot : W := slot32.setWidth 256
  let seedWord := pubkey <<< 128
  let topLeaf := slot >>> 16
  let (ok, bottomRoot, m1) :=
    layerRootM K (seedWord ||| (1#256 <<< 112) ||| (topLeaf <<< 80)) (slot &&& 0xffff#256)
      message 32#256 (fun c => sig (75 + c)) m0
  if !ok then false else
  let (ok, topRoot, _) := layerRootM K seedWord topLeaf bottomRoot 16#256 sig m1
  ok && topRoot == (pubkey &&& HIGH_128)

end
end LeanXmssK
