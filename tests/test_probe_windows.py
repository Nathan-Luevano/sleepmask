#!/usr/bin/env python3
"""test_probe_windows.py — Unicorn harness for the enhanced PEB-walk probe.

Fake ntdll exports four syscalls with distinct numbers:
  NtTerminateCurrentProcessEx = 0x1D
  NtWriteFile                 = 0x1A
  NtCreateFile                = 0x5D
  NtClose                     = 0x40

The 0F 05 hook dispatches on RAX (the syscall number the probe read from
the export prologues):
  NtWriteFile:    capture (handle, buffer) from the stack args
  NtCreateFile:   write a fake handle into *RCX
  NtClose:        record the handle
  NtTerminate... : record the exit status, stop emulation

PASS criteria:
  - clean NtTerminateCurrentProcessEx(0)
  - report text contains the ntdll base + all four resolved numbers
  - the report file got exactly the same content as stdout
  - the report file was closed
  - no unexpected syscalls
"""

import struct
import sys
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_R10,
    UC_X86_REG_RSP,
    UC_X86_REG_GS_BASE,
)

ROOT = Path(__file__).resolve().parent.parent
BLOB = (ROOT / "build" / "probe_windows.bin").read_bytes()

# --- layout (correct real-Windows offsets) -----------------------------------
PEB_ADDR   = 0x00002000
LDR_ADDR   = 0x00003000
LDR_ENTRY  = 0x00004000
NAME_ADDR  = 0x00005000
NTDLL_BASE = 0x100000
SC_BASE    = 0x300000
STACK      = 0x0600000
RSP0       = 0x0610008   # ≡ 8 (mod 16), as the real PE trampoline leaves it

NR_TERM   = 0x1D
NR_WRITE  = 0x1A
NR_CREATE = 0x5D
NR_CLOSE  = 0x40

FILE_H   = 0x4444444444444444
STDOUT_H = 1

NAMES = [
    ("NtTerminateCurrentProcessEx", NR_TERM),
    ("NtWriteFile",                 NR_WRITE),
    ("NtCreateFile",                NR_CREATE),
    ("NtClose",                     NR_CLOSE),
]


def build_env(uc):
    w = uc.mem_write

    # --- PEB / LDR chain (real offsets) ---------------------------------------
    w(0x60, struct.pack("<Q", PEB_ADDR))
    w(PEB_ADDR + 0x18, struct.pack("<Q", LDR_ADDR))       # PEB->Ldr
    w(LDR_ADDR + 0x10, struct.pack("<Q", LDR_ENTRY))      # InLoadOrderModuleList
    w(LDR_ENTRY + 0x00, struct.pack("<Q", LDR_ADDR + 0x10))
    w(LDR_ENTRY + 0x30, struct.pack("<Q", NTDLL_BASE))    # DllBase
    w(LDR_ENTRY + 0x58, struct.pack("<HH", 18, 20))  # BaseDllName {Length,MaxLength}
    w(LDR_ENTRY + 0x60, struct.pack("<Q", NAME_ADDR))     # BaseDllName.Buffer
    w(NAME_ADDR, "ntdll.dll".encode("utf-16-le"))

    # --- fake ntdll PE (correct export directory layout) -----------------------
    w(NTDLL_BASE + 0x3C, struct.pack("<I", 0x100))        # e_lfanew
    w(NTDLL_BASE + 0x100, b"PE\0\0")
    opt = NTDLL_BASE + 0x100 + 0x18
    w(opt, struct.pack("<H", 0x20B))                      # PE32+ magic
    w(opt + 0x70, struct.pack("<I", 0x200))               # DataDirectory[0].RVA

    edir = NTDLL_BASE + 0x200
    w(edir + 0x14, struct.pack("<I", len(NAMES)))         # NumberOfFunctions
    w(edir + 0x18, struct.pack("<I", len(NAMES)))         # NumberOfNames
    w(edir + 0x1C, struct.pack("<I", 0x1000))             # EAT
    w(edir + 0x20, struct.pack("<I", 0x1800))             # ENT
    w(edir + 0x24, struct.pack("<I", 0x2000))             # ORD

    for i, (name, nr) in enumerate(NAMES):
        w(NTDLL_BASE + 0x1000 + i * 4, struct.pack("<I", 0x5000 + i * 0x100))
        w(NTDLL_BASE + 0x1800 + i * 4, struct.pack("<I", 0x2800 + i * 0x100))
        w(NTDLL_BASE + 0x2000 + i * 2, struct.pack("<H", i))
        w(NTDLL_BASE + 0x2800 + i * 0x100, name.encode() + b"\0")
        # thunk: mov rax, nr; syscall; ret
        w(NTDLL_BASE + 0x5000 + i * 0x100,
          b"\x48\xC7\xC0" + struct.pack("<I", nr) + b"\x0F\x05\xC3")

    # --- shellcode + stack ------------------------------------------------------
    w(SC_BASE, BLOB)


def make_hook(uc, results):
    def on_code(uc_, rip, size, _):
        if bytes(uc_.mem_read(rip, 2)) != b"\x0F\x05":
            return
        nr = uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        rsp = uc_.reg_read(UC_X86_REG_RSP)
        rcx = uc_.reg_read(UC_X86_REG_RCX)
        r10 = uc_.reg_read(UC_X86_REG_R10)
        if rsp % 16 != 8:
            results["abi"].append(rsp % 16)
        if nr in (NR_WRITE, NR_CREATE, NR_CLOSE, NR_TERM) and r10 != rcx:
            results["abi"].append(("r10", r10, rcx))
        if nr == NR_TERM:
            results["term"] = uc_.reg_read(UC_X86_REG_RCX)
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            uc_.emu_stop()
        elif nr == NR_WRITE:
            buf = struct.unpack_from("<Q", uc_.mem_read(rsp + 0x30, 8))[0]
            ln = struct.unpack_from("<Q", uc_.mem_read(rsp + 0x38, 8))[0]
            h = uc_.reg_read(UC_X86_REG_RCX)
            results["writes"].append((h, bytes(uc_.mem_read(buf, ln))))
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        elif nr == NR_CREATE:
            fh = uc_.reg_read(UC_X86_REG_RCX)
            uc_.mem_write(fh, struct.pack("<Q", FILE_H))
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        elif nr == NR_CLOSE:
            results["closed"] = uc_.reg_read(UC_X86_REG_RCX)
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        else:
            results.setdefault("unknown", []).append(nr)
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
    return on_code


def main():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x0, 0x100000)
    uc.mem_map(NTDLL_BASE, 0x100000)
    uc.mem_map(SC_BASE, 0x100000)
    uc.mem_map(STACK, 0x20000)
    build_env(uc)
    uc.reg_write(UC_X86_REG_GS_BASE, 0)
    uc.reg_write(UC_X86_REG_RSP, RSP0)

    results = {"writes": [], "term": None, "closed": None, "unknown": [], "abi": []}
    uc.hook_add(UC_HOOK_CODE, make_hook(uc, results))
    uc.emu_start(SC_BASE, 0, count=2_000_000)

    stdout = b"".join(d for h, d in results["writes"] if h == STDOUT_H)
    filedata = b"".join(d for h, d in results["writes"] if h == FILE_H)
    text = stdout.decode("latin-1")

    print(f"blob size: {len(BLOB)} bytes")
    print("--- captured report (stdout) ---")
    print(text, end="")
    print("-------------------------------")

    ok = True

    def fail(msg):
        nonlocal ok
        ok = False
        print(f"FAIL: {msg}")

    if results["term"] != 0:
        fail(f"exit status = {results['term']}, expected 0 (or never terminated: {results['term']})")
    if results["closed"] != FILE_H:
        fail(f"closed = {results['closed']}, expected file handle {FILE_H:#x}")
    if results["unknown"]:
        fail(f"unexpected syscalls: {[hex(n) for n in results['unknown']]}")
    if results["abi"]:
        fail(f"direct-syscall ABI violations: {results['abi']!r}")
    if not text.strip():
        fail("no report captured")
    else:
        expect = [
            "sleepmask probe - windows x64 (pic, no imports)",
            f"ntdll base: 0x{NTDLL_BASE:016x}",
            "done - exit 0",
        ]
        for name, nr in NAMES:
            expect.append(f"{name}: 0x{nr:016x}")
        expect.append("created sleepmask_probe.txt: 0x" + "00" * 8)
        for line in expect:
            if line not in text:
                fail(f"missing line: {line!r}")
    if filedata != stdout:
        fail(f"file content != stdout ({len(filedata)} vs {len(stdout)} bytes)")

    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
