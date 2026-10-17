"""EIP-7002 fake_exponential reference (unbounded ints) -> test/fv/fee_table.json.

For every excess e it records the reference fee and whether a 256-bit checked implementation
of the EIP loop overflows on some intermediate (output += accum, accum * numerator).
"""

import json
import sys

U256 = 1 << 256


def fake_exponential(factor, numerator, denominator):
    # Verbatim from EIP-7002 / EIP-4844.
    i = 1
    output = 0
    numerator_accum = factor * denominator
    while numerator_accum > 0:
        output += numerator_accum
        numerator_accum = (numerator_accum * numerator) // (denominator * i)
        i += 1
    return output // denominator


def overflows(factor, numerator, denominator):
    i = 1
    output = 0
    accum = factor * denominator
    while accum > 0:
        output += accum
        if output >= U256:
            return True
        if accum * numerator >= U256:
            return True
        accum = (accum * numerator) // (denominator * i)
        i += 1
    return False


def main():
    fees = []
    e = 0
    while not overflows(1, e, 17):
        fees.append(fake_exponential(1, e, 17))
        e += 1
    threshold = e
    # Sanity: overflow is monotone over a long window past the threshold.
    assert all(overflows(1, x, 17) for x in range(threshold, threshold + 200_000))
    eth_supply_wei = 130_000_000 * 10**18
    first_unpayable = next(i for i, f in enumerate(fees) if f > eth_supply_wei)
    out = {
        "threshold": threshold,
        "firstFeeAboveEthSupply": first_unpayable,
        "fees": [hex(f) for f in fees],
    }
    json.dump(out, open(sys.argv[1], "w"))
    print("threshold", threshold, "first excess with fee > 130M ETH", first_unpayable,
          "fee at threshold-1", fees[-1])


main()
