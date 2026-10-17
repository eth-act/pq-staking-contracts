"""Mutation check against vacuous Halmos specs: each mutant injects a plausible bug into a
contract (string replacement in a scratch state of the worktree, restored afterwards) and runs
the Halmos checks that should catch it. A mutant must make at least one check FAIL.

usage: python3 mutants.py
"""

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent / "contracts"

MUTANTS = [
    ("stake-id bound off by one", "src/SystemRequestQueue.sol",
     "if (stakeId > MAX_STAKE_ID) revert();", "if (stakeId >= MAX_STAKE_ID) revert();",
     [("WithdrawalFV", "check_request_len16")]),
    ("tail not reset when drained", "src/SystemRequestQueue.sol",
     "queueHead = 0;\n            queueTail = 0;", "queueHead = 0;",
     [("WithdrawalFV", "check_systemCall_q1")]),
    ("inhibitor not cleared in excess update", "src/SystemRequestQueue.sol",
     "if (previousExcess == EXCESS_INHIBITOR) previousExcess = 0;", "",
     [("WithdrawalFV", "check_systemCall_q0")]),
    ("dequeue max off by one", "src/SystemRequestQueue.sol",
     "if (dequeued > _maxRequestsPerBlock()) dequeued = _maxRequestsPerBlock();",
     "if (dequeued > _maxRequestsPerBlock() + 1) dequeued = _maxRequestsPerBlock() + 1;",
     [("WithdrawalFV", "check_systemCall_q17"), ("ConsolidationFV", "check_systemCall_q3")]),
    ("fee getter accepts value", "src/SystemRequestQueue.sol",
     "if (msg.value != 0) revert();", "",
     [("WithdrawalFV", "check_request_len0")]),
    ("count not incremented", "src/SystemRequestQueue.sol",
     "count += 1;", "",
     [("WithdrawalFV", "check_request_len16")]),
    ("le64 swap bug", "src/SystemRequestQueue.sol",
     "return bytes8((v >> 32) | (v << 32));", "return bytes8((v >> 32) | (v << 31));",
     [("WithdrawalFV", "check_systemCall_q1")]),
    ("consolidation target id unchecked", "src/PQConsolidation.sol",
     "_checkStakeId(targetStakeId);", "",
     [("ConsolidationFV", "check_request_len16")]),
    ("withdrawal fields swapped in output", "src/PQWithdrawal.sol",
     "abi.encodePacked(entry.sourceAddress, _le64(entry.stakeId), _le64(entry.amountGwei))",
     "abi.encodePacked(entry.sourceAddress, _le64(entry.amountGwei), _le64(entry.stakeId))",
     [("WithdrawalFV", "check_systemCall_q1")]),
    ("staking capacity off by one", "src/PQStaking.sol",
     "if (index >= MAX_EVENT_COUNT) revert EventTreeFull();",
     "if (index > MAX_EVENT_COUNT) revert EventTreeFull();",
     [("StakingFV", "check_stake")]),
    ("isStake includes prefix end", "src/PQStaking.sol",
     "return stakeId < initialEventCount || createdStake[stakeId];",
     "return stakeId <= initialEventCount || createdStake[stakeId];",
     [("StakingFV", "check_isStake"), ("StakingFV", "check_topup")]),
    ("gwei multiple unchecked", "src/PQStaking.sol",
     "if (msg.value % 1 gwei != 0) revert NotGweiMultiple();", "",
     [("StakingFV", "check_stake")]),
    ("registration length check loosened", "src/RegistrationQueue.sol",
     "if (input.length != REQUEST_LENGTH) revert();", "if (input.length < REQUEST_LENGTH) revert();",
     [("RegistrationFV", "check_rejects_len2441")]),
    ("registration record keeps BE stake id", "src/RegistrationQueue.sol",
     "pos = _write(out, pos, abi.encodePacked(_le64(uint64(bytes8(raw)))));",
     "pos = _write(out, pos, abi.encodePacked(uint64(bytes8(raw))));",
     [("RegistrationFV", "check_systemCall_q1")]),
]


def halmos(contract, fn):
    p = subprocess.run(
        ["timeout", "900", "halmos", "--contract", contract, "--function", f"^{fn}\\(",
         "--loop", "20", "--solver-timeout-branching", "5s", "--solver-timeout-assertion", "0"],
        cwd=ROOT, capture_output=True, text=True)
    out = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr)
    m = re.search(r"\[(PASS|FAIL|ERROR|TIMEOUT)\]", out)
    return m.group(1) if m else f"NO-RESULT(rc={p.returncode})"


def main():
    killed = 0
    for name, path, old, new, checks in MUTANTS:
        f = ROOT / path
        orig = f.read_text()
        assert orig.count(old) == 1, (name, "pattern not unique")
        f.write_text(orig.replace(old, new))
        try:
            results = [(c, fn, halmos(c, fn)) for c, fn in checks]
        finally:
            f.write_text(orig)
        k = any(r == "FAIL" for _, _, r in results)
        killed += k
        print(f"{'KILLED  ' if k else 'SURVIVED'} {name}: " +
              ", ".join(f"{c}.{fn}={r}" for c, fn, r in results), flush=True)
    print(f"{killed}/{len(MUTANTS)} mutants killed")


main()
