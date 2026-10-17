import LeanXmssK.Bits

/-! `verifyM` (transcribed assembly) = `verify` (README spec), for every hash function `K`,
every public key, slot, message, signature and initial memory. -/
namespace LeanXmssK

/-! ### Small arithmetic facts about loop counters -/

theorem ofNat_lt_const (n c : Nat) (hc : c < 2 ^ 256) :
    (BitVec.ofNat 256 n < BitVec.ofNat 256 c) ↔ n % 2 ^ 256 < c := by
  rw [BitVec.ofNat_lt_ofNat, Nat.mod_eq_of_lt hc]

theorem ofNat_widen (n : Nat) (h : n < 256) :
    BitVec.ofNat 256 n = (BitVec.ofNat 8 n).setWidth 256 := by
  apply BitVec.eq_of_toNat_eq
  simp [BitVec.toNat_setWidth]
  omega

theorem shl_toNat (n k : Nat) (hn : n < 2 ^ 32) (hk : k ≤ 8) :
    (BitVec.ofNat 256 n <<< k).toNat = n * 2 ^ k := by
  rw [BitVec.toNat_shiftLeft, BitVec.toNat_ofNat]
  have h1 : n % 2 ^ 256 = n := Nat.mod_eq_of_lt (by omega)
  rw [h1, Nat.shiftLeft_eq]
  apply Nat.mod_eq_of_lt
  have : 2 ^ k ≤ 2 ^ 8 := Nat.pow_le_pow_right (by omega) hk
  calc n * 2 ^ k ≤ n * 2 ^ 8 := Nat.mul_le_mul_left _ this
    _ < 2 ^ 256 := by omega

theorem digit_le (d : W) (k : Nat) : digit d k ≤ 3 := by
  unfold digit
  rw [BitVec.toNat_and]
  exact Nat.le_trans Nat.and_le_right (by simp)

theorem digit_word (d : W) (n : Nat) (hn : n < 58) :
    (d >>> (254#256 - (BitVec.ofNat 256 n <<< 1))) &&& 3#256 = BitVec.ofNat 256 (digit d n) := by
  unfold digit
  rw [BitVec.ofNat_toNat, BitVec.setWidth_eq, BitVec.ushiftRight_eq']
  congr 2
  rw [BitVec.toNat_sub, shl_toNat n 1 (by omega) (by omega)]
  simp
  omega

/-! ### Memory -/

variable (K : List C → W)

theorem keccak_range (m : Mem) (off n : Nat) :
    keccakM K m off (16 * n) = K ((List.range n).map fun k => m (off / 16 + k)) := by
  unfold keccakM; congr 3; omega

/-! ### Digit-sum loop -/

theorem sumLoop_eq (d : W) : ∀ fuel n (s : W), n + fuel = 58 →
    sumLoop d fuel (BitVec.ofNat 256 n) s
      = s + BitVec.ofNat 256 (((List.range' n fuel).map (digit d)).sum) := by
  intro fuel
  induction fuel with
  | zero => intro n s _; simp [sumLoop]
  | succ fuel ih =>
    intro n s h
    have hn : n < 58 := by omega
    have hlt : BitVec.ofNat 256 n < 58#256 := by
      show BitVec.ofNat 256 n < BitVec.ofNat 256 58
      rw [ofNat_lt_const _ _ (by decide)]; rw [Nat.mod_eq_of_lt (by omega)]; exact hn
    simp only [sumLoop, hlt, if_true]
    have hinc : BitVec.ofNat 256 n + 1#256 = BitVec.ofNat 256 (n + 1) := by
      rw [BitVec.ofNat_add]
    rw [hinc, digit_word d n hn, ih (n + 1) _ (by omega), List.range'_succ]
    simp [BitVec.ofNat_add, BitVec.add_assoc]

theorem sum_range'_le (d : W) : ∀ len n, ((List.range' n len).map (digit d)).sum ≤ 3 * len := by
  intro len
  induction len with
  | zero => intro n; simp
  | succ len ih =>
    intro n
    rw [List.range'_succ, List.map_cons, List.sum_cons]
    have := ih (n + 1); have := digit_le d n; omega

theorem sumLoop_106 (d : W) : (sumLoop d 58 0#256 0#256 = 106#256) ↔ digitSum d = 106 := by
  have h := sumLoop_eq d 58 0 0#256 rfl
  simp only [BitVec.zero_add] at h
  rw [show (0#256) = BitVec.ofNat 256 0 from rfl, h]
  unfold digitSum
  rw [List.range_eq_range']
  have hb := sum_range'_le d 58 0
  constructor
  · intro e
    have := congrArg BitVec.toNat e
    rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt (by omega)] at this
    simpa using this
  · intro e; rw [e]

/-! ### Chain loops -/

theorem chain_step (P : C) (layer : BitVec 8) (tree leaf : BitVec 32) (i : BitVec 8) (y : C)
    (a : Nat) (ha : a < 3) :
    chain K P layer tree leaf i y a 3
      = chain K P layer tree leaf i (T16 (K [P, tweak 0 layer tree leaf i (BitVec.ofNat 8 a), y]))
          (a + 1) 3 := by
  unfold chain
  have : 3 - a = (3 - (a + 1)) + 1 := by omega
  rw [this, List.range'_succ, List.foldl_cons]

theorem chain_done (P : C) (layer : BitVec 8) (tree leaf : BitVec 32) (i : BitVec 8) (y : C) :
    chain K P layer tree leaf i y 3 3 = y := by
  simp [chain]

theorem stepLoop_eq (pk : W) (layer : BitVec 8) (tree leaf : BitVec 32) (i : Nat) (hi : i < 58) :
    ∀ fuel a (y : C) (m : Mem), a ≤ 3 → 3 - a ≤ fuel →
    (stepLoop K (baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48)) (BitVec.ofNat 256 i) fuel
        (BitVec.ofNat 256 a) (chunkW y, m)).1
      = chunkW (chain K (L16 pk) layer tree leaf (BitVec.ofNat 8 i) y a 3) ∧
    ∀ k, 4 ≤ k →
      (stepLoop K (baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48)) (BitVec.ofNat 256 i) fuel
        (BitVec.ofNat 256 a) (chunkW y, m)).2 k = m k := by
  intro fuel
  induction fuel with
  | zero =>
    intro a y m ha hf
    have : a = 3 := by omega
    subst this
    simp [stepLoop, chain_done]
  | succ fuel ih =>
    intro a y m ha hf
    by_cases h3 : a < 3
    · have hlt : BitVec.ofNat 256 a < 3#256 := by
        show BitVec.ofNat 256 a < BitVec.ofNat 256 3
        rw [ofNat_lt_const _ _ (by decide), Nat.mod_eq_of_lt (by omega)]; exact h3
      have hinc : BitVec.ofNat 256 a + 1#256 = BitVec.ofNat 256 (a + 1) := by
        rw [BitVec.ofNat_add]
      have hw1 := hi_chainWord pk layer tree leaf (BitVec.ofNat 8 i) (BitVec.ofNat 8 a)
      have hw2 := lo_chainWord pk layer tree leaf (BitVec.ofNat 8 i) (BitVec.ofNat 8 a)
      rw [← ofNat_widen i (by omega), ← ofNat_widen a (by omega)] at hw1 hw2
      simp only [stepLoop, hlt, if_true, hinc]
      have hk :
          keccakM K (mstore (mstore m 0 ((baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48))
            ||| ((BitVec.ofNat 256 i <<< 40) ||| (BitVec.ofNat 256 a <<< 32)))) 32 (chunkW y)) 0 48
          = K [L16 pk, tweak 0 layer tree leaf (BitVec.ofNat 8 i) (BitVec.ofNat 8 a), y] := by
        simp [keccakM, mstore, List.range_succ, hw1, hw2, hi_chunkW]
      rw [hk, and_high]
      obtain ⟨ih1, ih2⟩ := ih (a + 1) _ (mstore (mstore m 0 ((baseOf pk layer tree |||
        (leaf.setWidth 256 <<< 48)) ||| ((BitVec.ofNat 256 i <<< 40) ||| (BitVec.ofNat 256 a <<< 32))))
        32 (chunkW y)) (by omega) (by omega)
      refine ⟨?_, ?_⟩
      · rw [ih1, chain_step K _ _ _ _ _ _ _ h3]
      · intro k hk4
        rw [ih2 k hk4]
        simp only [mstore]
        rw [if_neg (by omega), if_neg (by omega), if_neg (by omega), if_neg (by omega)]
    · have : a = 3 := by omega
      subst this
      have hnlt : ¬ (BitVec.ofNat 256 3 < 3#256) := by decide
      simp [stepLoop, hnlt, chain_done]

/-- The chain end `e_i` of the spec. -/
def endSpec (pk : W) (layer : BitVec 8) (tree leaf : BitVec 32) (d : W) (sig : Nat → C)
    (i : Nat) : C :=
  chain K (L16 pk) layer tree leaf (BitVec.ofNat 8 i) (sig (1 + i)) (digit d i) 3

theorem chainsLoop_eq (pk : W) (layer : BitVec 8) (tree leaf : BitVec 32) (sig : Nat → C) (d : W) :
    ∀ fuel n (m : Mem), n + fuel = 58 →
    (∀ i, n ≤ i → i < 58 →
      chainsLoop K sig (baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48)) d fuel
        (BitVec.ofNat 256 n) m (10 + i) = endSpec K pk layer tree leaf d sig i) ∧
    (∀ k, 4 ≤ k → k < 10 + n →
      chainsLoop K sig (baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48)) d fuel
        (BitVec.ofNat 256 n) m k = m k) := by
  intro fuel
  induction fuel with
  | zero =>
    intro n m h
    refine ⟨fun i h1 h2 => by omega, fun k _ _ => by simp [chainsLoop]⟩
  | succ fuel ih =>
    intro n m h
    have hn : n < 58 := by omega
    have hlt : BitVec.ofNat 256 n < 58#256 := by
      show BitVec.ofNat 256 n < BitVec.ofNat 256 58
      rw [ofNat_lt_const _ _ (by decide), Nat.mod_eq_of_lt (by omega)]; exact hn
    have hinc : BitVec.ofNat 256 n + 1#256 = BitVec.ofNat 256 (n + 1) := by
      rw [BitVec.ofNat_add]
    have hx : calldataload sig (16 + (BitVec.ofNat 256 n <<< 4).toNat) &&& HIGH_128
        = chunkW (sig (1 + n)) := by
      rw [shl_toNat n 4 (by omega) (by omega)]
      unfold calldataload
      rw [cd_high]
      congr 2
      omega
    have hj := digit_word d n hn
    have hstep := stepLoop_eq K pk layer tree leaf n hn 3 (digit d n) (sig (1 + n)) m
      (digit_le d n) (by omega)
    simp only [chainsLoop, hlt, if_true, hinc, hx, hj]
    generalize hs : stepLoop K (baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48))
      (BitVec.ofNat 256 n) 3 (BitVec.ofNat 256 (digit d n)) (chunkW (sig (1 + n)), m) = s at hstep
    obtain ⟨x, m'⟩ := s
    obtain ⟨hs1, hs2⟩ := hstep
    simp only at hs1 hs2
    subst hs1
    obtain ⟨ih1, ih2⟩ := ih (n + 1) (mstore m' (0xa0 + (BitVec.ofNat 256 n <<< 4).toNat)
      (chunkW (chain K (L16 pk) layer tree leaf (BitVec.ofNat 8 n) (sig (1 + n)) (digit d n) 3)))
      (by omega)
    rw [shl_toNat n 4 (by omega) (by omega)] at ih1 ih2 ⊢
    refine ⟨?_, ?_⟩
    · intro i h1 h2
      by_cases hin : i = n
      · subst hin
        rw [ih2 (10 + i) (by omega) (by omega)]
        simp [mstore, endSpec, hi_chunkW]
        omega
      · exact ih1 i (by omega) h2
    · intro k hk1 hk2
      rw [ih2 k hk1 (by omega)]
      simp only [mstore]
      rw [if_neg (by omega), if_neg (by omega)]
      exact hs2 k hk1

/-! ### Memory reads used by the hashes -/

theorem k48 (m : Mem) (w x : W) :
    keccakM K (mstore (mstore m 0 w) 32 x) 0 48 = K [hiW w, loW w, hiW x] := by
  simp [keccakM, mstore, List.range_succ]

theorem k64 (m : Mem) (w x : W) :
    keccakM K (mstore (mstore m 0 w) 32 x) 0 64 = K [hiW w, loW w, hiW x, loW x] := by
  simp [keccakM, mstore, List.range_succ]

theorem kd32 (m : Mem) (w msg : W) (c : C) :
    keccakM K (mstore (calldatacopy16 (mstore m 0 w) 32 c) 48 msg) 0 (48 + (32#256).toNat)
      = K [hiW w, loW w, c, hiW msg, loW msg] := by
  simp [keccakM, mstore, calldatacopy16, List.range_succ]

theorem kd16 (m : Mem) (w msg : W) (c : C) :
    keccakM K (mstore (calldatacopy16 (mstore m 0 w) 32 c) 48 msg) 0 (48 + (16#256).toNat)
      = K [hiW w, loW w, c, hiW msg] := by
  simp [keccakM, mstore, calldatacopy16, List.range_succ]

theorem kleaf (mm : Mem) (w : W) (f : Nat → C) (h : ∀ i, i < 58 → mm (10 + i) = f i) :
    keccakM K (mstore mm 0x80 w) 0x80 960 = K ([hiW w, loW w] ++ (List.range 58).map f) := by
  unfold keccakM
  congr 1
  show (List.range 60).map (fun k => mstore mm 0x80 w (8 + k)) = _
  rw [List.range_succ_eq_map, List.range_succ_eq_map]
  simp only [List.map_cons, List.map_map, List.cons_append, List.nil_append, List.cons.injEq]
  refine ⟨by simp [mstore], by simp [mstore], ?_⟩
  apply List.map_congr_left
  intro a ha
  simp only [List.mem_range] at ha
  simp only [Function.comp, Nat.succ_eq_add_one, mstore]
  rw [if_neg (by omega), if_neg (by omega), ← h a ha]
  congr 1
  omega

/-! ### Merkle loop -/

theorem nodeStep_even (P : C) (layer : BitVec 8) (tree : BitVec 32) (sib c : C) (h : Nat)
    (idx : BitVec 32) (hb : idx.getLsbD 0 = false) :
    nodeStep K P layer tree sib h (c, idx)
      = (T16 (K [P, tweak 2 layer tree (idx >>> 1) (BitVec.ofNat 8 h) 0, c, sib]), idx >>> 1) := by
  simp only [nodeStep, hb, Bool.false_eq_true, if_false]

theorem nodeStep_odd (P : C) (layer : BitVec 8) (tree : BitVec 32) (sib c : C) (h : Nat)
    (idx : BitVec 32) (hb : idx.getLsbD 0 = true) :
    nodeStep K P layer tree sib h (c, idx)
      = (T16 (K [P, tweak 2 layer tree (idx >>> 1) (BitVec.ofNat 8 h) 0, sib, c]), idx >>> 1) := by
  simp only [nodeStep, hb, if_true]

set_option simprocs false in
theorem merkleLoop_eq (pk : W) (layer : BitVec 8) (tree : BitVec 32) (sig : Nat → C) :
    ∀ fuel n (c : C) (idx : BitVec 32) (m : Mem), n + fuel = 16 →
    (merkleLoop K sig (baseOf pk layer tree) fuel (BitVec.ofNat 256 (n + 1))
        (chunkW c, idx.setWidth 256, m)).1
      = chunkW ((List.range' n fuel).foldl
          (fun acc h => nodeStep K (L16 pk) layer tree (sig (59 + h)) (h + 1) acc) (c, idx)).1 := by
  intro fuel
  induction fuel with
  | zero => intro n c idx m _; rfl
  | succ fuel ih =>
    intro n c idx m h
    have hn : n < 16 := by omega
    have hlt : BitVec.ofNat 256 (n + 1) < 17#256 := by
      show BitVec.ofNat 256 (n + 1) < BitVec.ofNat 256 17
      rw [ofNat_lt_const _ _ (by decide), Nat.mod_eq_of_lt (by omega)]; omega
    have hinc : BitVec.ofNat 256 (n + 1) + 1#256 = BitVec.ofNat 256 (n + 1 + 1) := by
      rw [BitVec.ofNat_add (n + 1) 1]
    have hdec : BitVec.ofNat 256 (n + 1) - 1#256 = BitVec.ofNat 256 n := by
      rw [BitVec.ofNat_add n 1, BitVec.add_sub_cancel]
    have hsib : calldataload sig (944 + ((BitVec.ofNat 256 (n + 1) - 1#256) <<< 4).toNat)
        &&& HIGH_128 = chunkW (sig (59 + n)) := by
      rw [hdec, shl_toNat n 4 (by omega) (by omega)]
      unfold calldataload
      rw [cd_high]
      congr 2
      omega
    have hw1 := hi_nodeWord pk layer tree idx (BitVec.ofNat 8 (n + 1))
    have hw2 := lo_nodeWord pk layer tree idx (BitVec.ofNat 8 (n + 1))
    rw [← ofNat_widen (n + 1) (by omega)] at hw1 hw2
    rw [merkleLoop, if_pos hlt]
    simp only [hinc, hsib]
    rw [List.range'_succ, List.foldl_cons]
    by_cases hb : idx.getLsbD 0 = false
    · have hz : (idx.setWidth 256 &&& 1#256 = 0#256) := (leaf_bit idx).mpr hb
      rw [if_pos hz, node_left, k64, hw1, hw2, hi_append, lo_append, and_high, leaf_shift,
        ih (n + 1) _ _ _ (by omega), nodeStep_even K _ _ _ _ _ _ _ hb]
    · have hb' : idx.getLsbD 0 = true := by simpa using hb
      have hz : ¬ (idx.setWidth 256 &&& 1#256 = 0#256) := by
        rw [leaf_bit idx]; exact hb
      rw [if_neg hz, node_right, k64, hw1, hw2, hi_append, lo_append, and_high, leaf_shift,
        ih (n + 1) _ _ _ (by omega), nodeStep_odd K _ _ _ _ _ _ _ hb']

/-! ### One layer -/

set_option simprocs false in
theorem layerRootM_spec (pk : W) (layer : BitVec 8) (tree leaf : BitVec 32) (message ml : W)
    (msg : List C) (sig : Nat → C) (m : Mem)
    (hmsg : (ml = 32#256 ∧ msg = [T16 message, L16 message]) ∨ (ml = 16#256 ∧ msg = [T16 message])) :
    ((layerRootM K (baseOf pk layer tree) (leaf.setWidth 256) message ml sig m).1,
     (layerRootM K (baseOf pk layer tree) (leaf.setWidth 256) message ml sig m).2.1)
    = match layerRoot K (L16 pk) layer tree leaf msg sig with
      | none => (false, 0#256)
      | some c => (true, chunkW c) := by
  have hw1 := hi_leafWord pk layer tree leaf 3#8
  have hw2 := lo_leafWord pk layer tree leaf 3#8
  have h3 : (3#8 : BitVec 8).setWidth 256 = (3#256 : W) := by decide
  rw [h3] at hw1 hw2
  have hl1 := hi_leafWord pk layer tree leaf 1#8
  have hl2 := lo_leafWord pk layer tree leaf 1#8
  have h1 : (1#8 : BitVec 8).setWidth 256 = (1#256 : W) := by decide
  rw [h1] at hl1 hl2
  -- The message digest.
  have hd : keccakM K (mstore (calldatacopy16 (mstore m 0 ((baseOf pk layer tree |||
      (leaf.setWidth 256 <<< 48)) ||| (3#256 <<< 120))) 32 (sig 0)) 48 message) 0 (48 + ml.toNat)
      = K ([L16 pk, tweak 3 layer tree leaf 0 0, sig 0] ++ msg) := by
    rcases hmsg with ⟨hl, hm⟩ | ⟨hl, hm⟩ <;> subst hl hm
    · rw [kd32, hw1, hw2]; rfl
    · rw [kd16, hw1, hw2]; rfl
  generalize hD : K ([L16 pk, tweak 3 layer tree leaf 0 0, sig 0] ++ msg) = D at hd
  unfold layerRootM layerRoot
  simp only [hd, hD]
  by_cases hs : digitSum D = 106
  · rw [if_pos ((sumLoop_106 D).mpr hs), if_neg (by simpa using hs)]
    simp only
    obtain ⟨hc1, _⟩ := chainsLoop_eq K pk layer tree leaf sig D 58 0
      (mstore (calldatacopy16 (mstore m 0 ((baseOf pk layer tree ||| (leaf.setWidth 256 <<< 48))
        ||| (3#256 <<< 120))) 32 (sig 0)) 48 message) rfl
    rw [kleaf K _ _ _ (fun i hi => hc1 i (Nat.zero_le _) hi), hl1, hl2, and_high]
    have hmk := fun c mm => merkleLoop_eq K pk layer tree sig 16 0 c leaf mm rfl
    simp only [Nat.zero_add] at hmk
    rw [hmk, List.range_eq_range']
    rfl
  · rw [if_neg (fun e => hs ((sumLoop_106 D).mp e)), if_pos (by simpa using hs)]

/-! ### Main theorem -/

set_option simprocs false in
/-- The transcribed assembly computes the README verification function, for every hash
function `K`, public key, slot, message, signature and initial scratch memory. -/
theorem verifyM_eq_verify (pk : W) (slot : BitVec 32) (message : W) (sig : Nat → C) (m0 : Mem) :
    verifyM K pk slot message sig m0 = verify K pk slot message sig := by
  unfold verifyM verify
  simp only
  rw [bottom_base, bottom_leaf]
  have hb := layerRootM_spec K pk 1 (slot >>> 16) (slot &&& 0xFFFF) message 32#256
    [T16 message, L16 message] (fun c => sig (75 + c)) m0 (Or.inl ⟨rfl, rfl⟩)
  generalize hB : layerRootM K (baseOf pk 1 (slot >>> 16)) ((slot &&& 0xFFFF).setWidth 256)
    message 32#256 (fun c => sig (75 + c)) m0 = B at hb
  obtain ⟨ok1, br, m1⟩ := B
  simp only at hb ⊢
  cases hspec : layerRoot K (L16 pk) 1 (slot >>> 16) (slot &&& 0xFFFF) [T16 message, L16 message]
      (fun c => sig (75 + c)) with
  | none =>
    rw [hspec] at hb
    simp only [Prod.mk.injEq] at hb
    rw [hb.1]; rfl
  | some bottomRoot =>
    rw [hspec] at hb
    simp only [Prod.mk.injEq] at hb
    obtain ⟨rfl, rfl⟩ := hb
    simp only [Bool.not_true]
    rw [top_base, top_leaf]
    have ht := layerRootM_spec K pk 0 0 (slot >>> 16) (chunkW bottomRoot) 16#256 [bottomRoot]
      sig m1 (Or.inr ⟨rfl, by rw [show T16 (chunkW bottomRoot) = bottomRoot from hi_chunkW _]⟩)
    generalize hT : layerRootM K (baseOf pk 0 0) ((slot >>> 16).setWidth 256) (chunkW bottomRoot)
      16#256 sig m1 = T at ht
    obtain ⟨ok2, tr, m2⟩ := T
    simp only at ht ⊢
    cases hspec2 : layerRoot K (L16 pk) 0 0 (slot >>> 16) [bottomRoot] sig with
    | none =>
      rw [hspec2] at ht
      simp only [Prod.mk.injEq] at ht
      rw [ht.1]; rfl
    | some topRoot =>
      rw [hspec2] at ht
      simp only [Prod.mk.injEq] at ht
      obtain ⟨rfl, rfl⟩ := ht
      rw [root_mask]
      simp only [Bool.true_and]
      by_cases e : topRoot = T16 pk
      · subst e; simp
      · have : chunkW topRoot ≠ chunkW (T16 pk) := fun h => e (by
          have := congrArg hiW h; rwa [hi_chunkW, hi_chunkW] at this)
        rw [beq_eq_false_iff_ne.mpr this, beq_eq_false_iff_ne.mpr e]
        simp

end LeanXmssK
