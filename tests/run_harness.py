#!/usr/bin/env python3
"""run_harness.py - Unicorn harness for the sleepmask shellcode.

Builds a fake x64 Windows environment and runs the assembled shellcode
until it returns:

  [gs:0x60] -> PEB(+0x18 = Ldr) -> Ldr(+0x10 = head) -> LDR entry
  LDR entry: BaseDllName = "ntdll.dll" (UTF-16), DllBase = fake ntdll PE
  The PE exports NtDelayExecution / NtProtectVirtualMemory as modern x64
  thunks (`4C 8B D1 B8 <nr:4> F6 04 25 .. 75 03 0F 05 CC ...`), so the
  shellcode reads the syscall number out of the export prologue at runtime,
  plus KeQuerySystemTime as a dummy (the blob no longer resolves it: its
  clock is KUSER_SHARED_DATA->SystemTime at [0x7FFE0014], read directly).

The stub's clock is emulated the honest way: a MEM_READ hook on the
KUSER_SHARED_DATA SystemTime qword advances it by TICK (10 ms) on every
8-byte read, so the stub's poll loop sees time pass, exactly as a real
CPU polling a live clock would.

The CODE hook traps 0F 05: records eax (the NT syscall number), zeroes it,
and steps RIP past it.

PASS criteria:
  - the shellcode returns (RIP reaches RET_ADDR)
  - the syscall trace is exactly [0x2B, 0x2B] (two NtProtect, no 0x3D)
  - done_flag (data slot 66 bytes from the blob tail) == 1
  - the original 12 bytes of NtDelayExecution are restored
  - the shared clock advanced past the 250 ms timeout (the mask slept)
"""

import struct
import sys
from pathlib import Path

from unicorn import (
    Uc, UC_ARCH_X86, UC_MODE_64,
    UC_HOOK_CODE, UC_HOOK_MEM_READ,
)
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_GS_BASE,
)

ROOT = Path(__file__).resolve().parent.parent
# usage: run_harness.py [blob.bin]  (default: build/sleepmask.bin)
BLOB_PATH = (Path(sys.argv[1]) if len(sys.argv) > 1
             else ROOT / "build" / "sleepmask.bin")


def load_blob() -> bytes:
    return BLOB_PATH.read_bytes()


# --- layout ----------------------------------------------------------------
PEB_ADDR   = 0x00002000
LDR_ADDR   = 0x00003000
LDR_ENTRY  = 0x00004000
NAME_ADDR  = 0x00005000        # UTF-16LE "ntdll.dll"
NTDLL_BASE = 0x100000          # fake ntdll.dll image
SC_BASE    = 0x300000          # shellcode
RET_ADDR   = 0x300800          # fake return address pushed on the stack
STACK      = 0x0600000
RSP0       = 0x0610000

# KUSER_SHARED_DATA is mapped at 0x7FFE0000 on every x64 Windows; SystemTime
# (100ns since 1601) is the qword at +0x14. The stub polls it directly.
SHARED      = 0x7FFE0000
SYS_TIME    = SHARED + 0x14
CLOCK0      = 0                # initial SystemTime (100ns since 1601)
TICK        = 100000           # 10 ms in 100ns units; one poll step
TIMEOUT_VAL = 2500000          # the blob's timeout: 250 ms in 100ns units

DONE_TAIL = 66                 # done_flag slot, bytes counted from the blob tail

EXPORTS = [                     # (name, thunk RVA inside the PE)
    (b"NtDelayExecution\0",      0x1000),
    (b"NtProtectVirtualMemory\0", 0x1100),
    (b"KeQuerySystemTime\0",     0x1200),   # dummy: the blob no longer resolves it
]


def _q(v):
    return struct.pack("<Q", v)


def make_thunk(nr: int) -> bytes:
    """A modern x64 ntdll syscall thunk (31 bytes, the real layout):

       4C 8B D1          mov r10, rcx
       B8 <nr:4>         mov eax, <nr>      <- the nr the blob scans for
       F6 04 25 08 03    test byte [0x7FFE0308], 1
       FE 7F 01
       75 03             jne +3
       0F 05             syscall
       CC ...            int3 padding (real ntdll pads thunks this way)
    """
    t = (b"\x4C\x8B\xD1" + b"\xB8" + struct.pack("<I", nr)
         + b"\xF6\x04\x25\x08\x03\xFE\x7F\x01"
         + b"\x75\x03" + b"\x0F\x05")
    return t + b"\xCC" * (31 - len(t))


def install_clock_hook(uc):
    """MEM_READ hook: every read of the KUSER_SHARED_DATA clock qword
    (SystemTime at 0x7FFE0014) advances it by TICK, so a stub polling the
    clock in a tight loop observes time passing, as on real hardware."""
    state = {"clock": CLOCK0}

    def on_mem_read(uc_, access, address, size, value, ud):
        if SYS_TIME <= address < SYS_TIME + 8:
            new = state["clock"] + TICK
            state["clock"] = new
            uc_.mem_write(address, _q(new))

    uc.hook_add(UC_HOOK_MEM_READ, on_mem_read)


def build_env(uc, blob: bytes):
    w = uc.mem_write
    # --- PEB / LDR chain ----------------------------------------------
    w(0x60, _q(PEB_ADDR))
    w(PEB_ADDR + 0x18, _q(LDR_ADDR))          # PEB->Ldr
    w(LDR_ADDR + 0x10, _q(LDR_ENTRY))         # InLoadOrderModuleList head
    w(LDR_ENTRY + 0x00, _q(LDR_ADDR + 0x10))  # Flink: entry -> head (circular)
    w(LDR_ENTRY + 0x30, _q(NTDLL_BASE))       # DllBase
    w(LDR_ENTRY + 0x58, struct.pack("<H", 18))  # BaseDllName.Length (bytes)
    w(LDR_ENTRY + 0x60, _q(NAME_ADDR))        # BaseDllName.Buffer
    w(NAME_ADDR, "ntdll.dll".encode("utf-16-le"))

    # --- fake ntdll PE --------------------------------------------------
    w(NTDLL_BASE + 0x3C, struct.pack("<I", 0x100))      # e_lfanew
    w(NTDLL_BASE + 0x100, b"PE\0\0")
    opt = NTDLL_BASE + 0x100 + 0x18
    w(opt, struct.pack("<H", 0x20B))                   # PE32+ magic
    w(opt + 0x70, struct.pack("<I", 0x200))            # ExportDir.RVA
    edir = NTDLL_BASE + 0x200
    w(edir + 0x14, struct.pack("<I", len(EXPORTS)))    # NumberOfFunctions
    w(edir + 0x18, struct.pack("<I", len(EXPORTS)))    # NumberOfNames
    w(edir + 0x1C, struct.pack("<I", 0x300))           # EAT RVA
    w(edir + 0x20, struct.pack("<I", 0x380))           # ENT RVA
    w(edir + 0x24, struct.pack("<I", 0x400))           # ORD RVA
    for i, (name, rva) in enumerate(EXPORTS):
        w(NTDLL_BASE + 0x300 + 4 * i, struct.pack("<I", rva))
        w(NTDLL_BASE + 0x380 + 4 * i, struct.pack("<I", 0x500 + 0x80 * i))
        w(NTDLL_BASE + 0x400 + 2 * i, struct.pack("<H", i))
        w(NTDLL_BASE + 0x500 + 0x80 * i, name)

    # --- the export thunks ---------------------------------------------
    w(NTDLL_BASE + 0x1000, make_thunk(0x3D))   # NtDelayExecution
    w(NTDLL_BASE + 0x1100, make_thunk(0x2B))   # NtProtectVirtualMemory
    # KeQuerySystemTime dummy: mov rax, &SystemTime; ret (never called)
    w(NTDLL_BASE + 0x1200, b"\x48\xB8" + _q(SYS_TIME) + b"\xC3")

    # --- KUSER_SHARED_DATA: the stub's clock source ----------------------
    w(SYS_TIME, _q(CLOCK0))

    # --- shellcode + fake stack ------------------------------------------
    w(SC_BASE, blob)
    w(RSP0, _q(RET_ADDR))


def main():
    blob = load_blob()
    DONE_OFFSET = len(blob) - DONE_TAIL   # done_flag slot, from the blob tail

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x0, 0x100000)
    uc.mem_map(NTDLL_BASE, 0x100000)
    uc.mem_map(SC_BASE, 0x100000)
    uc.mem_map(SHARED, 0x100000)
    uc.mem_map(STACK, 0x20000)
    build_env(uc, blob)
    install_clock_hook(uc)
    uc.reg_write(UC_X86_REG_GS_BASE, 0)
    uc.reg_write(UC_X86_REG_RSP, RSP0)

    trace = []

    def on_code(uc_, rip, size, _):
        if bytes(uc_.mem_read(rip, 2)) == b"\x0F\x05":
            trace.append(uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF)
            uc_.reg_write(UC_X86_REG_RAX, 0)      # STATUS_SUCCESS
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)

    rip = SC_BASE
    for _ in range(64):
        uc.emu_start(rip, RET_ADDR, count=500_000)
        rip = uc.reg_read(UC_X86_REG_RIP)
        if rip == RET_ADDR:
            break
    else:
        print(f"FAIL: stuck at rip=0x{rip:X} after {len(trace)} syscalls")
        sys.exit(1)

    def rd(addr, n):
        return bytes(uc.mem_read(addr, n))

    done = struct.unpack("<Q", rd(SC_BASE + DONE_OFFSET, 8))[0]
    nt_delay = rd(NTDLL_BASE + 0x1000, 12)
    expect_nt = make_thunk(0x3D)[:12]
    clock = struct.unpack("<Q", rd(SYS_TIME, 8))[0]

    print(f"blob size:   {len(blob)} bytes")
    print(f"done_flag:   {done} (at blob offset {DONE_OFFSET} / 0x{DONE_OFFSET:X})")
    print(f"syscalls:    {' '.join('0x%02X' % n for n in trace)}")
    print(f"sys_time:    {clock} (100ns units; timeout {TIMEOUT_VAL} = 250 ms)")
    print(f"ntdelay[12]: {nt_delay.hex(' ')}")

    ok = True
    if trace != [0x2B, 0x2B]:
        print(f"FAIL: syscalls {[hex(n) for n in trace]} != [0x2B, 0x2B] (want two NtProtect, no 0x3D)")
        ok = False
    if done != 1:
        print(f"FAIL: done_flag == {done}, expected 1")
        ok = False
    if nt_delay != expect_nt:
        print("FAIL: NtDelayExecution prologue not restored")
        ok = False
    if not (TIMEOUT_VAL <= clock <= TIMEOUT_VAL + 2 * TICK):
        print(f"FAIL: clock {clock} did not poll past the {TIMEOUT_VAL} timeout")
        ok = False
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
