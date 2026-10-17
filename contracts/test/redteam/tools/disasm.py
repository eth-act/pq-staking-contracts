#!/usr/bin/env python3
"""Static bytecode analysis of the system contracts' runtime code.

For each runtime: linear-sweep disassembly (data after INVALID/0xfe is not code here: no
CBOR trailer), then report
  - every PUSH4 immediate and whether it feeds an EQ (selector-dispatch pattern),
  - every opcode that can transfer control or value outside the contract,
  - the opcode trace from pc 0 to the first JUMPI, i.e. the dispatcher prologue.
"""
import sys

NAMES = {0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
         0x06: "MOD", 0x0a: "EXP", 0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
         0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1a: "BYTE",
         0x1b: "SHL", 0x1c: "SHR", 0x1d: "SAR", 0x20: "KECCAK256", 0x30: "ADDRESS",
         0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE",
         0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
         0x39: "CODECOPY", 0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY", 0x46: "CHAINID",
         0x47: "SELFBALANCE", 0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
         0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE",
         0x5a: "GAS", 0x5b: "JUMPDEST", 0x5c: "TLOAD", 0x5d: "TSTORE", 0x5e: "MCOPY",
         0x5f: "PUSH0", 0xa0: "LOG0", 0xa1: "LOG1", 0xa2: "LOG2", 0xa3: "LOG3", 0xa4: "LOG4",
         0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN", 0xf4: "DELEGATECALL",
         0xf5: "CREATE2", 0xfa: "STATICCALL", 0xfd: "REVERT", 0xfe: "INVALID",
         0xff: "SELFDESTRUCT"}
for i in range(32):
    NAMES[0x60 + i] = f"PUSH{i + 1}"
for i in range(16):
    NAMES[0x80 + i] = f"DUP{i + 1}"
    NAMES[0x90 + i] = f"SWAP{i + 1}"

EXTERNAL = {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2",
            "SELFDESTRUCT", "LOG1", "LOG2", "LOG3", "LOG4", "ORIGIN", "BALANCE",
            "SELFBALANCE", "TSTORE", "TLOAD"}


def disasm(code):
    pc, out = 0, []
    while pc < len(code):
        op = code[pc]
        name = NAMES.get(op, f"UNKNOWN_0x{op:02x}")
        n = op - 0x5f if 0x60 <= op <= 0x7f else 0
        imm = code[pc + 1:pc + 1 + n]
        out.append((pc, name, imm))
        pc += 1 + n
    return out


def main(path):
    code = bytes.fromhex(open(path).read().strip().removeprefix("0x"))
    ins = disasm(code)
    print(f"{path}: {len(code)} bytes, {len(ins)} instructions")
    push4 = [(pc, imm.hex()) for pc, name, imm in ins if name == "PUSH4"]
    print(f"  PUSH4 immediates: {len(push4)}")
    for k, (pc, name, imm) in enumerate(ins):
        if name == "PUSH4":
            window = [n for _, n, _ in ins[k + 1:k + 4]]
            print(f"    pc={pc:#06x} 0x{imm.hex()} next={window}")
    eqs = [pc for pc, name, _ in ins if name == "EQ"]
    print(f"  EQ count: {len(eqs)}")
    # Selector extraction pattern: PUSH0/PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR
    sel = []
    for k in range(len(ins) - 3):
        a, b, c, d = ins[k:k + 4]
        if (a[1] == "PUSH0" or (a[1] == "PUSH1" and a[2] == b"\x00")) and b[1] == "CALLDATALOAD" \
                and c[1] == "PUSH1" and c[2] == b"\xe0" and d[1] == "SHR":
            sel.append(a[0])
    print(f"  selector-extraction patterns (CALLDATALOAD(0) >> 0xe0): {sel}")
    ext = sorted({name for _, name, _ in ins if name in EXTERNAL})
    print(f"  external-effect / env opcodes present: {ext or 'none'}")
    unknown = sorted({name for _, name, _ in ins if name.startswith("UNKNOWN")})
    print(f"  unknown opcodes (data or invalid): {unknown or 'none'}")
    print("  prologue up to first JUMPI:")
    for pc, name, imm in ins:
        print(f"    {pc:#06x} {name} {('0x' + imm.hex()) if imm else ''}")
        if name in ("JUMPI", "JUMP"):
            break


if __name__ == "__main__":
    for p in sys.argv[1:]:
        main(p)
