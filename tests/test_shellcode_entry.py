#!/usr/bin/env python3
"""test_shellcode_entry.py — the SAC-proof shellcode entry test.

build/beacon_windows.bin is PIC shellcode entered by a plain `call` (the DLL
wrapper does `call beacon` and the PowerShell runner does
`Marshal.GetDelegateForFunctionPointer(mem); fn()` — also a `call`). This test
proves the beacon fires its full dual trace (stdout token + the
sleepmask_beacon.txt filesystem artifact) and returns cleanly when it is placed
at an ARBITRARY RWX address and `call`ed there directly — i.e. exactly the way
`run-shell.ps1`'s VirtualAlloc'd delegate invokes it, with NO DLL image, NO
export table, and NO loader. That is the "runs no matter what" entry mode: the
unsigned-image (SmartScreen / Smart App Control / ACFE) check never sees a disk
image to block, because the bytes never leave shellcode.

For each of four arbitrary addresses (two high user-mode regions, two offsets
each, all 8-byte aligned) the beacon is written in place and entered with a
return slot pre-pushed on the stack (equivalent to the `call` having already
pushed the return address and jumped). The fake ntdll fixture is identical to
test_dll.py (PEB/Ldr chain, four export thunks whose syscall nr is read from
the prologue), so each address is run once with the REAL syscall numbers and
once with DECOY numbers, proving the nr is read at runtime, not hard-coded.

PASS = in all 8 runs: exactly one NtWriteFile of the beacon token on the stdout
handle, exactly one NtCreateFile (name decoded from r8's ObjectAttributes in
live memory == sleepmask_beacon.txt), exactly one NtWriteFile of the token on
the file handle, exactly one NtClose, no other syscall, RIP returns to the
return slot, and R15 (parked with a sentinel) is preserved. Exit 0 pass /
1 fail / 2 build problem.
"""

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import test_dll as td  # noqa: E402  reuse the proven fixture + hook

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_R15,
    UC_X86_REG_GS_BASE,
)

BEACON_BIN = ROOT / "build" / "beacon_windows.bin"

# Four arbitrary RWX landing addresses: two high user-mode regions (the sort of
# thing VirtualAlloc hands out), each at two distinct 8-byte-aligned offsets, so
# a hidden position/alignment assumption in the beacon would surface.
SHELL_TARGETS = (
    (0x400000000000, 0x40),     # 256 TiB region, low offset
    (0x400000000000, 0x1040),   # same region, +4 KB
    (0x700000000000, 0x5040),   # 448 TiB region
    (0x700000000000, 0x8040),   # +0x3000
)
SHELL_REGION = 0x100000


def run_shell(base, off, nr_write, nr_create, nr_close, nr_term, beacon: bytes) -> list:
    """Write the beacon at base+off and `call` it directly (return slot pre-pushed)."""
    p = []
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, 0x100000)                 # low page: gs:0x60 -> PEB
    uc.mem_map(td.NTDLL_BASE, 0x100000)     # fake ntdll
    uc.mem_map(td.STACK, td.STACK_SZ)
    uc.mem_map(base, SHELL_REGION)
    uc.reg_write(UC_X86_REG_GS_BASE, 0)
    td.build_env(uc, nr_write, nr_create, nr_close, nr_term)

    shell_addr = base + off
    uc.mem_write(shell_addr, beacon)

    writes = []
    abi_violations = []
    uc.hook_add(UC_HOOK_CODE, td.make_hook(
        nr_write, nr_create, nr_close, writes, abi_violations
    ))

    uc.reg_write(UC_X86_REG_R15, td.SENTINEL_R15)
    uc.reg_write(UC_X86_REG_RAX, td.JUNK_RAX)
    ret_addr = td.STACK + 0x8000
    rsp = td.STACK + 0x108
    uc.mem_write(rsp, struct.pack("<Q", ret_addr))   # the `call`'s return slot
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RIP, shell_addr)
    uc.emu_start(shell_addr, until=ret_addr, count=20_000_000)
    rip = uc.reg_read(UC_X86_REG_RIP)
    if rip != ret_addr:
        p.append(f"RIP {rip:#x} != return slot {ret_addr:#x} (beacon did not return)")
    create_status = struct.unpack("<Q", uc.mem_read(shell_addr + len(beacon) - 8, 8))[0]
    if create_status != 0:
        p.append(f"create_status {create_status:#x} != 0 (NtCreateFile failed)")
    r15 = uc.reg_read(UC_X86_REG_R15)

    stdout_writes = [w for w in writes if w[0] == "write" and w[1] == td.STDOUT_HDL]
    file_writes = [w for w in writes if w[0] == "write" and w[1] == td.FILE_HDL]
    creates = [w for w in writes if w[0] == "create"]
    closes = [w for w in writes if w[0] == "close"]
    other = [w for w in writes if w[0] not in ("write", "create", "close")]
    if other:
        p.append(f"unexpected syscall activity: {other!r}")
    if len(stdout_writes) != 1:
        p.append(f"expected 1 stdout beacon write, got {len(stdout_writes)}")
    elif stdout_writes[0][2] != td.BEACON_MSG:
        p.append(f"stdout beacon write wrong: {stdout_writes[0][2]!r}")
    if len(file_writes) != 1:
        p.append(f"expected 1 file beacon write, got {len(file_writes)}")
    elif file_writes[0][2] != td.BEACON_MSG:
        p.append(f"file beacon write wrong: {file_writes[0][2]!r}")
    if len(creates) != 1:
        p.append(f"expected 1 NtCreateFile, got {len(creates)}")
    elif creates[0][1] != td.ARTIFACT_NAME:
        p.append(f"artifact filename wrong: {creates[0][1]!r} != {td.ARTIFACT_NAME!r}")
    elif creates[0][2] != 0:
        p.append(f"artifact create failed: 0x{creates[0][2]:08X}")
    if len(closes) != 1:
        p.append(f"expected 1 NtClose, got {len(closes)}")
    if r15 != td.SENTINEL_R15:
        p.append(f"R15 clobbered: {r15:#x} != {td.SENTINEL_R15:#x}")
    if abi_violations:
        p.append(f"direct-syscall ABI violations: {abi_violations!r}")
    return p


def main() -> int:
    if not BEACON_BIN.exists():
        print("FAIL: missing build/beacon_windows.bin — run build.sh first")
        return 2
    beacon = BEACON_BIN.read_bytes()

    all_problems = []
    for base, off in SHELL_TARGETS:
        for label, nw, nc, ncl, nt in (
                ("real", td.NR_WRITE_REAL, td.NR_CREATE_REAL,
                 td.NR_CLOSE_REAL, td.NR_TERM_REAL),
                ("decoy", td.NR_WRITE_DECOY, td.NR_CREATE_DECOY,
                 td.NR_CLOSE_DECOY, td.NR_TERM_DECOY)):
            probs = run_shell(base, off, nw, nc, ncl, nt, beacon)
            addr = base + off
            print(f"[{addr:#x} {label}] ok" if not probs
                  else f"[{addr:#x} {label}] " + "; ".join(probs))
            all_problems += [f"[{addr:#x} {label}] {pr}" for pr in probs]

    for pr in all_problems:
        print(f"RUN FAIL: {pr}")
    if all_problems:
        print("FAIL")
        return 1
    print("PASS (shellcode: beacon `call`ed at 4 arbitrary RWX addresses x real "
          "+ decoy nr -> stdout token AND sleepmask_beacon.txt create/write/close; "
          "returns cleanly; R15 preserved)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
