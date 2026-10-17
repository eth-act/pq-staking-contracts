import LeanXmssK
import Trace.Keccak

/-! Executes the transcribed model `verifyM` and the spec `verify` with real Keccak-256 and
prints every hash preimage the model requests (stderr, one hex line each, prefix `K `), so the
sequence can be compared with the KECCAK256 preimages of the compiled bytecode. -/
open LeanXmssK Trace

def hexDigit (c : Char) : Nat :=
  if c.isDigit then c.toNat - '0'.toNat
  else if 'a' ≤ c ∧ c ≤ 'f' then c.toNat - 'a'.toNat + 10
  else c.toNat - 'A'.toNat + 10

def parseHex (s : String) : ByteArray := Id.run do
  let s := if s.startsWith "0x" then (s.drop 2).toString else s
  let cs := s.toList.toArray
  let mut out := ByteArray.empty
  for i in [0:cs.size / 2] do
    out := out.push (hexDigit cs[2 * i]! * 16 + hexDigit cs[2 * i + 1]!).toUInt8
  return out

def toHex (b : ByteArray) : String :=
  b.toList.foldl (fun s x =>
    let h := Nat.toDigits 16 x.toNat
    s ++ (if h.length == 1 then "0" else "") ++ String.ofList h) ""

def bytesToNat (b : ByteArray) : Nat := b.toList.foldl (fun n x => n * 256 + x.toNat) 0

def natToBytes (n len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  for i in [0:len] do
    out := out.push ((n >>> (8 * (len - 1 - i))) % 256).toUInt8
  return out

def chunkBytes (c : C) : ByteArray := natToBytes c.toNat 16

def Kreal (l : List C) : W :=
  let pre := l.foldl (fun b c => b ++ chunkBytes c) ByteArray.empty
  dbgTrace ("K " ++ toHex pre) fun _ => BitVec.ofNat 256 (bytesToNat (keccak256 pre))

def main (args : List String) : IO UInt32 := do
  match args with
  | [pkS, slotS, msgS, sigS, which] =>
    let pk : W := BitVec.ofNat 256 (bytesToNat (parseHex pkS))
    let slot : BitVec 32 := BitVec.ofNat 32 slotS.toNat!
    let msg : W := BitVec.ofNat 256 (bytesToNat (parseHex msgS))
    let sigB := parseHex sigS
    let sig : Nat → C := fun c =>
      BitVec.ofNat 128 (bytesToNat (sigB.extract (16 * c) (16 * c + 16)))
    if sigB.size != 2400 then
      IO.println "bad length"; return 1
    let r := if which == "model" then verifyM Kreal pk slot msg sig (fun _ => 0)
      else verify Kreal pk slot msg sig
    IO.println s!"{which} {r}"
    return 0
  | _ => IO.println "usage: trace PK SLOT MSG SIG model|spec"; return 2
