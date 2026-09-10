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

The CODE hook traps 0F 05 and emulates the kernel side of the syscall ABI:
it checks RSP ≡ 8 (mod 16), reads the args the way nt!KiSystemCall64 does
(arg0 = R10, arg1 = RDX, arg2 = R8, arg3 = R9, arg4 = [RSP+0x28]), validates
them against the blob, writes the NtProtectVirtualMemory OldProtect out-param,
zeroes RAX (STATUS_SUCCESS) and steps RIP past the instruction.

The blob is run at four entry RSP classes (0, 4, 8, 12 mod 16). A real
`call blob` lands at ≡ 8 (mod 16), but the blob must not depend on that: it
establishes the 16-byte RSP alignment itself before each `syscall`
(`mov r13, rsp; and rsp, -16`), so any caller frame the loader/injector leaves
it on is fine. Every one of the four entries must pass.

PASS criteria (default, --fail-protect off):
  - the shellcode returns (RIP reaches RET_ADDR)
  - the syscall trace is exactly [0x2B]*6 (six NtProtect: 3 cycles x set+restore, no 0x3D)
  - every syscall had RSP ≡ 8 (mod 16) and ABI-shaped arguments
  - the NtProtect calls set RWX then restore the original protection
  - done_flag (data slot 82 bytes from the blob tail) == 1; beacon_cycles (226) == 0
  - the original 12 bytes of NtDelayExecution are restored
  - the shared clock advanced past the 3 x 250 ms timeout (3 beacon cycles; the mask slept)

PASS criteria (--fail-protect): the kernel fails NtProtectVirtualMemory
(STATUS_INVALID_HANDLE), so the blob must fall back to a direct NtDelayExecution
syscall instead of patching/masking:
  - the shellcode returns (RIP reaches RET_ADDR)
  - the syscall trace is exactly [0x2B, 0x3D] (failed NtProtect, then NtDelay)
  - every syscall had RSP ≡ 8 (mod 16) and ABI-shaped arguments
  - NtDelayExecution got Alertable=0 and *Duration = -2500000 (relative 250 ms)
  - done_flag == 1; beacon_cycles == 3 (the fallback never enters the loop); the shared clock did NOT advance (the stub never ran)
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
    UC_X86_REG_R10,
    UC_X86_REG_RDX,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_GS_BASE,
)

ROOT = Path(__file__).resolve().parent.parent
# usage: run_harness.py [--fail-protect] [blob.bin]  (default: build/sleepmask.bin)
_ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
BLOB_PATH = (Path(_ARGS[0]) if _ARGS
             else ROOT / "build" / "sleepmask.bin")
# --fail-protect: the emulated kernel fails NtProtectVirtualMemory, forcing the
# blob down its direct-NtDelayExecution fallback so that path is exercised too.
FAIL_PROTECT = "--fail-protect" in sys.argv[1:]


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
# The RSP of a real `call blob`: the return address is an 8-byte push off a
# 16-aligned frame, so at blob entry RSP ≡ 8 (mod 16).
RSP0       = 0x0610008
# Entry RSP classes to prove the blob is caller-independent: the ≡ 8 class a
# `call` gives, plus jump/injector frames the blob cannot assume. All four must
# produce RSP ≡ 8 (mod 16) at every `syscall`.
ENTRIES    = (0x0610000, 0x0610004, RSP0, 0x061000C)

# KUSER_SHARED_DATA is mapped at 0x7FFE0000 on every x64 Windows; SystemTime
# (100ns since 1601) is the qword at +0x14. The stub polls it directly.
SHARED      = 0x7FFE0000
SYS_TIME    = SHARED + 0x14
CLOCK0      = 0                # initial SystemTime (100ns since 1601)
TICK        = 100000           # 10 ms in 100ns units; one poll step
TIMEOUT_VAL = 2500000          # the per-cycle timeout: 250 ms in 100ns units

DONE_TAIL = 82                 # done_flag slot, bytes counted from the blob tail
CYCLES_TAIL = 226              # beacon_cycles slot, bytes from the blob tail

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
        C3                ret
        CC ...            int3 padding (real ntdll pads thunks this way)
    """
    t = (b"\x4C\x8B\xD1" + b"\xB8" + struct.pack("<I", nr)
         + b"\xF6\x04\x25\x08\x03\xFE\x7F\x01"
         + b"\x75\x03" + b"\x0F\x05" + b"\xC3")
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


def build_env(uc, blob: bytes, rsp0: int):
    w = uc.mem_write
    # --- PEB / LDR chain ----------------------------------------------
    w(0x60, _q(PEB_ADDR))
    w(PEB_ADDR + 0x18, _q(LDR_ADDR))          # PEB->Ldr
    w(LDR_ADDR + 0x10, _q(LDR_ENTRY))         # InLoadOrderModuleList head
    w(LDR_ENTRY + 0x00, _q(LDR_ADDR + 0x10))  # Flink: entry -> head (circular)
    w(LDR_ENTRY + 0x30, _q(NTDLL_BASE))       # DllBase
    w(LDR_ENTRY + 0x58, struct.pack("<HH", 18, 20))  # BaseDllName {Length=18, MaxLength=20}
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
    w(rsp0, _q(RET_ADDR))


def run_case(rsp0: int, blob: bytes, done_offset: int, fail_protect: bool = False):
    """Run the blob with the given entry RSP. Returns (ok, report_lines).

    fail_protect=True makes the emulated kernel fail the NtProtectVirtualMemory
    call (STATUS_INVALID_HANDLE), forcing the blob down its direct-
    NtDelayExecution fallback so that path is exercised too.
    """
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x0, 0x100000)
    uc.mem_map(NTDLL_BASE, 0x100000)
    uc.mem_map(SC_BASE, 0x100000)
    uc.mem_map(SHARED, 0x100000)
    uc.mem_map(STACK, 0x20000)
    build_env(uc, blob, rsp0)
    install_clock_hook(uc)
    uc.reg_write(UC_X86_REG_GS_BASE, 0)
    uc.reg_write(UC_X86_REG_RSP, rsp0)

    trace = []            # syscall nr per 0F 05, in order
    abi_fail = []         # human-readable ABI violations
    prot_calls = []       # the NewProtect arg (arg3/R9) of each NtProtect call
    delay_arg = None      # *Duration value the fallback NtDelayExecution received
    kern = {"prot": 0x20} # the kernel's current protection of the NtDelay text
                        # (0x20 = PAGE_EXECUTE_READ: what ntdll ships its text as)

    def in_blob(addr):
        return SC_BASE <= addr < SC_BASE + len(blob)

    def on_code(uc_, rip, size, _):
        nonlocal delay_arg
        if bytes(uc_.mem_read(rip, 2)) != b"\x0F\x05":
            return
        # It's a `syscall`. Read the args exactly as nt!KiSystemCall64 does for a
        # direct x64 Windows syscall: arg0=R10, arg1=RDX, arg2=R8, arg3=R9,
        # arg4=[RSP+0x28]; and RSP must be ≡ 8 (mod 16).
        rsp  = uc_.reg_read(UC_X86_REG_RSP)
        nr   = uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        r10  = uc_.reg_read(UC_X86_REG_R10)
        rdx  = uc_.reg_read(UC_X86_REG_RDX)
        r8   = uc_.reg_read(UC_X86_REG_R8)
        r9   = uc_.reg_read(UC_X86_REG_R9)
        arg4 = struct.unpack("<Q", bytes(uc_.mem_read(rsp + 0x28, 8)))[0]
        trace.append(nr)

        if rsp % 16 != 8:
            abi_fail.append(
                f"nr=0x{nr:02X} RSP=0x{rsp:X} % 16 != 8 (direct-syscall ABI)"
            )

        if nr == 0x2B:
            # NtProtectVirtualMemory(hProc, *Base, *Size, NewProtect, *OldProtect)
            if r10 != 0xFFFFFFFFFFFFFFFF:
                abi_fail.append(
                    f"0x2B arg0(R10)=0x{r10:X} != -1 (current-process pseudo-handle)"
                )
            for tag, v in (("arg1(RDX)=", rdx), ("arg2(R8)=", r8), ("arg4=[rsp+0x28]", arg4)):
                if not in_blob(v):
                    abi_fail.append(f"0x2B {tag}0x{v:X} is not a blob data pointer")
            prot_calls.append(r9)
            if fail_protect:
                # The emulated process has no valid object for the handle, so the
                # protect fails. *OldProtect is not written and the region is left
                # as it was.
                uc_.reg_write(UC_X86_REG_RAX, 0xC0000008)   # STATUS_INVALID_HANDLE
            else:
                # Emulate the kernel: hand back the current protection as
                # *OldProtect, then apply NewProtect (arg3/R9) to the region.
                uc_.mem_write(arg4, struct.pack("<Q", kern["prot"]))
                kern["prot"] = r9
                uc_.reg_write(UC_X86_REG_RAX, 0)     # STATUS_SUCCESS
        elif nr == 0x3D:
            # NtDelayExecution(Alertable, *Duration) -- only the fallback path.
            # arg0 (Alertable) must be 0; arg1 (*Duration) must point at the
            # blob's timeout slot (overwritten in place to the relative value).
            if r10 != 0:
                abi_fail.append(f"0x3D arg0(R10)=0x{r10:X} != 0 (Alertable=0)")
            if not in_blob(rdx):
                abi_fail.append(f"0x3D arg1(RDX)=0x{rdx:X} is not a blob data pointer")
            else:
                delay_arg = struct.unpack("<q", bytes(uc_.mem_read(rdx, 8)))[0]
            uc_.reg_write(UC_X86_REG_RAX, 0)     # STATUS_SUCCESS
        else:
            abi_fail.append(f"unexpected syscall nr=0x{nr:02X}")
            uc_.reg_write(UC_X86_REG_RAX, 0)

        uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)

    rip = SC_BASE
    for _ in range(64):
        uc.emu_start(rip, RET_ADDR, count=500_000)
        rip = uc.reg_read(UC_X86_REG_RIP)
        if rip == RET_ADDR:
            break
    stuck = rip != RET_ADDR

    def rd(addr, n):
        return bytes(uc.mem_read(addr, n))

    done = struct.unpack("<Q", rd(SC_BASE + done_offset, 8))[0]
    nt_delay = rd(NTDLL_BASE + 0x1000, 12)
    expect_nt = make_thunk(0x3D)[:12]
    clock = struct.unpack("<Q", rd(SYS_TIME, 8))[0]
    cycles_off = len(blob) - CYCLES_TAIL
    cycles = struct.unpack("<Q", rd(SC_BASE + cycles_off, 8))[0]

    lines = [
        f"syscalls:    {' '.join('0x%02X' % n for n in trace)}",
        f"prot calls:  {' '.join('0x%02X' % p for p in prot_calls) or '(none)'}",
        f"final prot:  0x{kern['prot']:02X} (0x20 = original PAGE_EXECUTE_READ)",
        f"done_flag:   {done} (at blob offset {done_offset} / 0x{done_offset:X})",
        f"beacon_cycles: {cycles} (at blob offset {cycles_off} / 0x{cycles_off:X})",
        f"sys_time:    {clock} (100ns units; timeout {TIMEOUT_VAL} = 250 ms)",
        f"ntdelay[12]: {nt_delay.hex(' ')}",
    ]
    if fail_protect:
        lines.append(f"delay arg:   {delay_arg} (100ns; want {-TIMEOUT_VAL} = relative 250 ms)")

    ok = True
    if stuck:
        lines.append(f"FAIL: stuck at rip=0x{rip:X} after {len(trace)} syscalls")
        ok = False
    if abi_fail:
        lines.append("FAIL: syscall ABI violations (kernel would not see these args):")
        for f in abi_fail:
            lines.append(f"  {f}")
        ok = False
    if done != 1:
        lines.append(f"FAIL: done_flag == {done}, expected 1")
        ok = False
    if nt_delay != expect_nt:
        lines.append("FAIL: NtDelayExecution prologue not restored")
        ok = False
    if fail_protect:
        # Fallback: the failed NtProtect must route to a direct NtDelayExecution
        # with a RELATIVE (negative) duration, and the mask stub must never run
        # (the shared clock stays at CLOCK0).
        if trace != [0x2B, 0x3D]:
            lines.append(f"FAIL: syscalls {[hex(n) for n in trace]} != [0x2B, 0x3D] (want failed NtProtect then NtDelayExecution)")
            ok = False
        if prot_calls != [0x40]:
            lines.append(f"FAIL: prot calls {[hex(p) for p in prot_calls]} != [0x40] (one RWX attempt, never restored)")
            ok = False
        if kern["prot"] != 0x20:
            lines.append(f"FAIL: final prot 0x{kern['prot']:02X} != 0x20 (region protection should be untouched)")
            ok = False
        if delay_arg != -TIMEOUT_VAL:
            lines.append(f"FAIL: delay arg {delay_arg} != {-TIMEOUT_VAL} (want relative -{TIMEOUT_VAL}, 100ns)")
            ok = False
        if clock != CLOCK0:
            lines.append(f"FAIL: clock {clock} advanced; the mask stub ran on the fallback path (want {CLOCK0})")
            ok = False
        if cycles != 3:
            lines.append(f"FAIL: beacon_cycles == {cycles}, expected 3 (fallback never enters the loop)")
            ok = False
    else:
        if trace != [0x2B] * 6:
            lines.append(f"FAIL: syscalls {[hex(n) for n in trace]} != [0x2B]*6 (want six NtProtect: 3 cycles x set+restore, no 0x3D)")
            ok = False
        if prot_calls != [0x40, 0x20] * 3:
            lines.append(f"FAIL: prot calls {[hex(p) for p in prot_calls]} != [0x40, 0x20]*3 (3 cycles x set RWX then restore)")
            ok = False
        if kern["prot"] != 0x20:
            lines.append(f"FAIL: final prot 0x{kern['prot']:02X} != 0x20 (original protection not restored)")
            ok = False
        if not (3 * TIMEOUT_VAL <= clock <= 3 * TIMEOUT_VAL + 6 * TICK):
            lines.append(f"FAIL: clock {clock} did not poll past the 3x{TIMEOUT_VAL} timeout (3 beacon cycles)")
            ok = False
        if cycles != 0:
            lines.append(f"FAIL: beacon_cycles == {cycles}, expected 0 (loop must run to completion)")
            ok = False
    if ok:
        lines.append("PASS")
    return ok, lines


def main():
    blob = load_blob()
    done_offset = len(blob) - DONE_TAIL   # done_flag slot, from the blob tail
    print(f"blob size:   {len(blob)} bytes")
    print(f"mode:        {'fail-protect (fallback NtDelayExecution)' if FAIL_PROTECT else 'main (masked NtProtect)'}")

    all_ok = True
    for rsp0 in ENTRIES:
        ok, lines = run_case(rsp0, blob, done_offset, fail_protect=FAIL_PROTECT)
        print(f"--- entry RSP0=0x{rsp0:05X} (rsp % 16 = {rsp0 % 16}) ---")
        for line in lines:
            print(line)
        all_ok &= ok
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
