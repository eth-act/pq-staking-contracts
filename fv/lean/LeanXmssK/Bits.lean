import LeanXmssK.Model
import Std.Tactic.BVDecide

/-! Word-level facts about the tweak/mask arithmetic, discharged by bit-blasting. -/
namespace LeanXmssK

def chunkW (c : C) : W := c ++ (0 : BitVec 128)

/-- Base word of a layer: P in the high half, tweak layer and tree fields set. -/
def baseOf (pk : W) (layer : BitVec 8) (tree : BitVec 32) : W :=
  (pk <<< 128) ||| (layer.setWidth 256 <<< 112) ||| (tree.setWidth 256 <<< 80)

theorem and_high (w : W) : w &&& HIGH_128 = chunkW (T16 w) := by
  unfold HIGH_128 chunkW T16; bv_decide

theorem cd_high (a b : C) : (a ++ b) &&& HIGH_128 = chunkW a := by
  unfold HIGH_128 chunkW; bv_decide

theorem hi_chunkW (c : C) : hiW (chunkW c) = c := by unfold hiW chunkW; bv_decide
theorem lo_chunkW (c : C) : loW (chunkW c) = 0 := by unfold loW chunkW; bv_decide

theorem top_base (pk : W) : pk <<< 128 = baseOf pk 0 0 := by unfold baseOf; bv_decide

theorem bottom_base (pk : W) (slot : BitVec 32) :
    (pk <<< 128) ||| (1#256 <<< 112) ||| ((slot.setWidth 256 >>> 16) <<< 80)
      = baseOf pk 1 (slot >>> 16) := by
  unfold baseOf; bv_decide

theorem top_leaf (slot : BitVec 32) : slot.setWidth 256 >>> 16 = (slot >>> 16).setWidth 256 := by
  bv_decide

theorem bottom_leaf (slot : BitVec 32) :
    slot.setWidth 256 &&& 0xffff#256 = (slot &&& 0xFFFF).setWidth 256 := by
  bv_decide

theorem root_mask (pk : W) : pk &&& HIGH_128 = chunkW (T16 pk) := and_high pk

/-- Message / leaf word: `or(or(base, shl(48, leaf)), shl(120, ty))`. -/
theorem hi_leafWord (pk : W) (layer : BitVec 8) (tree leaf : BitVec 32) (ty : BitVec 8) :
    hiW ((baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48)) ||| (ty.setWidth 256 <<< 120))
      = L16 pk := by
  unfold hiW L16 baseOf; bv_decide

theorem lo_leafWord (pk : W) (layer : BitVec 8) (tree leaf : BitVec 32) (ty : BitVec 8) :
    loW ((baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48)) ||| (ty.setWidth 256 <<< 120))
      = tweak ty layer tree leaf 0 0 := by
  unfold loW baseOf tweak; bv_decide

/-- Chain word: `or(leafBase, or(shl(40, i), shl(32, j)))`. -/
theorem hi_chainWord (pk : W) (layer : BitVec 8) (tree leaf : BitVec 32) (i j : BitVec 8) :
    hiW ((baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48))
      ||| ((i.setWidth 256 <<< 40) ||| (j.setWidth 256 <<< 32))) = L16 pk := by
  unfold hiW L16 baseOf; bv_decide

theorem lo_chainWord (pk : W) (layer : BitVec 8) (tree leaf : BitVec 32) (i j : BitVec 8) :
    loW ((baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48))
      ||| ((i.setWidth 256 <<< 40) ||| (j.setWidth 256 <<< 32))) = tweak 0 layer tree leaf i j := by
  unfold loW baseOf tweak; bv_decide

/-- Node word: `or(base, or(shl(120, 2), or(shl(48, shr(1, leaf)), shl(40, h))))`. -/
theorem hi_nodeWord (pk : W) (layer : BitVec 8) (tree idx : BitVec 32) (h : BitVec 8) :
    hiW (baseOf pk layer tree ||| ((2#256 <<< 120) ||| ((idx.setWidth 256 >>> 1) <<< 48
      ||| (h.setWidth 256 <<< 40)))) = L16 pk := by
  unfold hiW L16 baseOf; bv_decide

theorem lo_nodeWord (pk : W) (layer : BitVec 8) (tree idx : BitVec 32) (h : BitVec 8) :
    loW (baseOf pk layer tree ||| ((2#256 <<< 120) ||| ((idx.setWidth 256 >>> 1) <<< 48
      ||| (h.setWidth 256 <<< 40)))) = tweak 2 layer tree (idx >>> 1) h 0 := by
  unfold loW baseOf tweak; bv_decide

theorem node_left (a b : C) :
    chunkW a ||| (chunkW b >>> 128) = a ++ b := by unfold chunkW; bv_decide

theorem node_right (a b : C) :
    chunkW b ||| (chunkW a >>> 128) = b ++ a := by unfold chunkW; bv_decide

theorem hi_append (a b : C) : hiW (a ++ b) = a := by unfold hiW; bv_decide
theorem lo_append (a b : C) : loW (a ++ b) = b := by unfold loW; bv_decide

theorem leaf_bit (idx : BitVec 32) :
    (idx.setWidth 256 &&& 1#256 = 0#256) ↔ idx.getLsbD 0 = false := by
  constructor <;> intro h <;> bv_decide

theorem leaf_shift (idx : BitVec 32) : idx.setWidth 256 >>> 1 = (idx >>> 1).setWidth 256 := by
  bv_decide

theorem hiW_msg (w : W) : hiW w = T16 w := rfl
theorem loW_msg (w : W) : loW w = L16 w := rfl

end LeanXmssK
