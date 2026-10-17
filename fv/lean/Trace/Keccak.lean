/-! Keccak-256 (original padding 0x01, as the EVM KECCAK256 opcode), for executing the model. -/
namespace Trace

def RC : Array UInt64 := #[
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

def ROT : Array UInt64 := #[
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14]

def rotl (x : UInt64) (n : UInt64) : UInt64 :=
  if n == 0 then x else (x <<< n) ||| (x >>> (64 - n))

/-- State index `x + 5 y`. -/
def keccakF (s : Array UInt64) : Array UInt64 := Id.run do
  let mut a := s
  for r in [0:24] do
    -- θ
    let c := (List.range 5).toArray.map fun x =>
      a[x]! ^^^ a[x + 5]! ^^^ a[x + 10]! ^^^ a[x + 15]! ^^^ a[x + 20]!
    let d := (List.range 5).toArray.map fun x => c[(x + 4) % 5]! ^^^ rotl c[(x + 1) % 5]! 1
    for i in [0:25] do
      a := a.set! i (a[i]! ^^^ d[i % 5]!)
    -- ρ and π
    let mut b := Array.replicate 25 (0 : UInt64)
    for x in [0:5] do
      for y in [0:5] do
        b := b.set! (y + 5 * ((2 * x + 3 * y) % 5)) (rotl a[x + 5 * y]! ROT[x + 5 * y]!)
    -- χ
    for x in [0:5] do
      for y in [0:5] do
        a := a.set! (x + 5 * y)
          (b[x + 5 * y]! ^^^ ((~~~ b[(x + 1) % 5 + 5 * y]!) &&& b[(x + 2) % 5 + 5 * y]!))
    -- ι
    a := a.set! 0 (a[0]! ^^^ RC[r]!)
  return a

def keccak256 (msg : ByteArray) : ByteArray := Id.run do
  let rate := 136
  let mut data := msg.toList.toArray
  data := data.push 0x01
  while data.size % rate != 0 do
    data := data.push 0
  data := data.set! (data.size - 1) (data[data.size - 1]! ||| 0x80)
  let mut s := Array.replicate 25 (0 : UInt64)
  for blk in [0:data.size / rate] do
    for i in [0:rate / 8] do
      let mut w : UInt64 := 0
      for j in [0:8] do
        w := w ||| ((data[blk * rate + 8 * i + j]!).toUInt64 <<< (8 * j).toUInt64)
      s := s.set! i (s[i]! ^^^ w)
    s := keccakF s
  let mut out := ByteArray.empty
  for i in [0:4] do
    for j in [0:8] do
      out := out.push ((s[i]! >>> (8 * j).toUInt64).toUInt8)
  return out

end Trace
