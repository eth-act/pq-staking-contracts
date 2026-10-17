#!/usr/bin/env python3
"""Exhaustive comparison of SystemRequestQueue._fakeExponential(1, excess, 17) with the EIP-7002
reference `fake_exponential` (arbitrary precision).

Solidity model: identical loop, but every ADD/MUL is checked (reverts on result >= 2**256); DIV
and the comparison cannot fail. If no operation overflows, every intermediate value equals the
reference's, so the results agree. The model reports the first overflow.

Claim checked:
  (a) for every excess in [0, E): no overflow, Solidity result == reference result;
  (b) at E the Solidity loop overflows (revert);
  (c) for every excess >= E the Solidity loop overflows. Proof: the reference's pre-division
      `output` is monotone non-decreasing in `numerator` (each accum term is, by induction,
      floor((a*n)/(d*i)) with a non-decreasing in n; nonzero terms only get more). Let E2 be the
      least excess whose reference pre-division output is >= 2**256. For excess >= E2, a run
      without overflow would have to hold that value in a uint256: contradiction, so it reverts.
      For excess in [E, E2) we check (b) exhaustively.
Also writes test/vectors/rt_fee_table.txt: one line per excess in [0, E): hex fee.
"""
import sys

M = 2**256


def ref(factor, numerator, denominator):
    i, output, acc = 1, 0, factor * denominator
    while acc > 0:
        output += acc
        acc = (acc * numerator) // (denominator * i)
        i += 1
    return output // denominator, output


def sol(factor, numerator, denominator):
    """Returns (result, None) or (None, description of first overflow)."""
    def chk(v, what):
        if v >= M:
            raise OverflowError(what)
        return v
    try:
        output = 0
        acc = chk(factor * denominator, "factor*denominator")
        i = 1
        while acc > 0:
            output = chk(output + acc, f"output+=accum (i={i})")
            prod = chk(acc * numerator, f"accum*numerator (i={i})")
            den = chk(denominator * i, f"denominator*i (i={i})")
            acc = prod // den
            i = chk(i + 1, "i++")
        return output // denominator, None
    except OverflowError as e:
        return None, str(e)


def main(table_path):
    E = None
    e = 0
    rows = []
    while True:
        r, err = sol(1, e, 17)
        expected, _ = ref(1, e, 17)
        if err is None:
            assert r == expected, (e, r, expected)
            rows.append(r)
            e += 1
            continue
        E = e
        print(f"first overflow at excess E={E}: {err}")
        break
    # E2: least excess with reference pre-division output >= 2**256 (monotone => bisection
    # would do, but a linear scan from E is exhaustive and cheap).
    e = E
    while True:
        _, pre = ref(1, e, 17)
        r, err = sol(1, e, 17)
        assert err is not None, f"no revert at excess {e} in [E, E2)"
        if pre >= M:
            E2 = e
            break
        e += 1
    print(f"reference pre-division output >= 2**256 from E2={E2}; all of [E, E2] revert")
    # Sanity: monotonicity of the pre-division output over a wide range (spot-check of the
    # inductive argument, not needed for the proof).
    prev = -1
    for e in list(range(0, E2 + 2000)):
        _, pre = ref(1, e, 17)
        assert pre >= prev, e
        prev = pre
    print(f"monotone pre-division output verified on [0, {E2 + 2000})")
    last = rows[-1]
    print(f"largest computable fee: excess={E - 1} fee={last} (~2^{last.bit_length() - 1}, "
          f"{last / 1e18:.3e} ETH)")
    supply = 120_000_000 * 10**18
    first_unaffordable = next(i for i, f in enumerate(rows) if f > supply)
    print(f"fee exceeds 120M ETH from excess {first_unaffordable} (fee {rows[first_unaffordable]})")
    with open(table_path, "w") as f:
        for v in rows:
            f.write(f"{v:x}\n")
    print(f"wrote {len(rows)} rows to {table_path}")
    print(f"E={E} E2={E2}")


if __name__ == "__main__":
    main(sys.argv[1])
