/-
leanXMSS-K verification, transcribed from `xmss/README.md` (the spec), independently of
`LeanXmssK.sol`.

Byte strings that the scheme hashes are always made of whole 16-byte pieces, so they are
represented as lists of `C = BitVec 128` (big-endian: the first byte is the most significant).
Keccak-256 is an arbitrary function `K : List C → W`; every theorem holds for all `K`, so no
property of Keccak is assumed.
-/
namespace LeanXmssK

/-- 16-byte piece / 32-byte word. Notations (not abbrevs) so terms are literally `BitVec n`. -/
scoped notation "C" => BitVec 128
scoped notation "W" => BitVec 256

/-- `T16`: the first 16 bytes of a 32-byte hash. -/
def T16 (w : W) : C := w.extractLsb' 128 128

/-- Last 16 bytes of a 32-byte value. -/
def L16 (w : W) : C := w.extractLsb' 0 128

/-- Tweak = `struct.pack(">BBIIBB4x", type, layer, tree, index, c, j)`. -/
def tweak (ty layer : BitVec 8) (tree index : BitVec 32) (c j : BitVec 8) : C :=
  ty ++ layer ++ tree ++ index ++ c ++ j ++ (0 : BitVec 32)

section
variable (K : List C → W)

/-- `chain(x, a→b)`: `x ← F(T(0, layer, tree, leaf, i, j), x)` for `j = a … b−1`. -/
def chain (P : C) (layer : BitVec 8) (tree leaf : BitVec 32) (i : BitVec 8) (x : C)
    (a b : Nat) : C :=
  (List.range' a (b - a)).foldl
    (fun x j => T16 (K [P, tweak 0 layer tree leaf i (BitVec.ofNat 8 j), x])) x

/-- Digit `a_k = (d >> (254 − 2k)) & 3`. -/
def digit (d : W) (k : Nat) : Nat := ((d >>> (254 - 2 * k)) &&& 3).toNat

def digitSum (d : W) : Nat := ((List.range 58).map (digit d)).sum

/-- One Merkle level `h` (1-based) above index `idx`, sibling `sib`. -/
def nodeStep (P : C) (layer : BitVec 8) (tree : BitVec 32) (sib : C) (h : Nat)
    (acc : C × BitVec 32) : C × BitVec 32 :=
  let (node, idx) := acc
  let k := idx >>> 1
  let t := tweak 2 layer tree k (BitVec.ofNat 8 h) 0
  (T16 (if idx.getLsbD 0 then K [P, t, sib, node] else K [P, t, node, sib]), k)

/-- Recompute one layer's root. `sig c` is the c-th 16-byte piece of the 1,200-byte layer
signature `ρ ‖ σ₀ … σ₅₇ ‖ auth₀ … auth₁₅`. `none` = digit sum ≠ 106. -/
def layerRoot (P : C) (layer : BitVec 8) (tree leaf : BitVec 32) (msg : List C)
    (sig : Nat → C) : Option C :=
  let d := K ([P, tweak 3 layer tree leaf 0 0, sig 0] ++ msg)
  if digitSum d ≠ 106 then none else
  let ends := (List.range 58).map fun i =>
    chain K P layer tree leaf (BitVec.ofNat 8 i) (sig (1 + i)) (digit d i) 3
  let leafValue := T16 (K ([P, tweak 1 layer tree leaf 0 0] ++ ends))
  some ((List.range 16).foldl
    (fun acc h => nodeStep K P layer tree (sig (59 + h)) (h + 1) acc) (leafValue, leaf)).1

/-- Verification. `pk = root ‖ P`; `sig c` is the c-th 16-byte piece of the 2,400-byte
signature (top layer = pieces 0‥74, bottom layer = pieces 75‥149). -/
def verify (pk : W) (slot : BitVec 32) (msg : W) (sig : Nat → C) : Bool :=
  let root := T16 pk
  let P := L16 pk
  let t := slot >>> 16
  let b := slot &&& 0xFFFF
  match layerRoot K P 1 t b [T16 msg, L16 msg] (fun c => sig (75 + c)) with
  | none => false
  | some bottomRoot =>
    match layerRoot K P 0 0 t [bottomRoot] sig with
    | none => false
    | some topRoot => topRoot == root

end
end LeanXmssK
