#!/usr/bin/env python3
"""test_windows.py — the Windows deployable test.

Regenerates build/sleepmask.exe via tools/mk_pe.py, then verifies it three
ways:

  1. STATIC: hand-checks every header field of the PE (DOS stub, e_lfanew,
     PE sig, COFF, PE32+ optional header, section header, the 9-byte entry
     trampoline, and that the embedded blob is byte-identical to
     build/sleepmask.bin).
  2. INDEPENDENT READER: research/pe/pe_exports.py (stdlib-only, written and
     reviewed separately) walks MZ -> PE -> COFF -> optional header on the
     same bytes and accepts the image (zero exports expected: the blob has
     no IAT, it resolves ntdll from the PEB at runtime).
  3. DYNAMIC: the PE image is loaded into Unicorn at its ImageBase and
     entered exactly as the Windows loader would:

         push retaddr
         jmp IMAGE_BASE + AddressOfEntryPoint

     The trampoline at +0 calls the blob at +9; the blob resolves ntdll from
     the fake PEB (same fixture as run_harness.py), reads the syscall
     numbers from the export prologues, masks NtDelayExecution, and its
     final `ret` lands in the trampoline's spin loop — where emulation
     stops and the assertions run:

       - syscall trace == [0x2B, 0x2B] (two NtProtect, masked 0x3D absent)
       - done_flag == 1 in the PE image's OWN copy of the blob
       - NtDelayExecution's 12 original bytes restored
       - the fake clock advanced (the mask actually slept)

PASS = all of the above. Exit 0 pass / 1 fail / 2 usage/build problem.
"""

import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT.parent.parent / "research" / "pe"))

import run_harness as H          # noqa: E402  env constants + build_env()
from pe_exports import pe_exports  # noqa: E402  independent PE reader

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_GS_BASE,
)

BLOB_PATH = ROOT / "build" / "sleepmask.bin"
EXE_PATH = ROOT / "build" / "sleepmask.exe"

IMAGE_BASE = 0x140000000
ENTRY_RVA = 0x1000
TRAMP_SPIN = IMAGE_BASE + ENTRY_RVA + 5   # F4 90 EB FD: pause; nop; jmp -3
BLOB_RVA = ENTRY_RVA + 9                  # trampoline is 9 bytes

MACHINE_X86_64 = 0x8664
OPT_MAGIC_PE32P = 0x20B


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def static_check(data: bytes, blob: bytes) -> list:
    """Return the list of problems (empty = structurally valid)."""
    p = []

    def chk(label, ok, detail=""):
        if not ok:
            p.append(f"{label}: {detail}")

    chk("MZ", data[0:2] == b"MZ", f"got {data[0:2]!r}")
    lfanew = u32(data, 0x3C)
    chk("e_lfanew", lfanew == 0x80, f"got {lfanew:#x}")
    chk("PE sig", data[0x80:0x84] == b"PE\0\0", f"got {data[0x80:0x84]!r}")

    coff = 0x84
    chk("machine", u16(data, coff) == MACHINE_X86_64, f"got {u16(data, coff):#x}")
    chk("nsections", u16(data, coff + 2) == 1, f"got {u16(data, coff + 2)}")
    opt = coff + 20
    chk("sizeofopt", u16(data, coff + 16) == 0xF0, f"got {u16(data, coff + 16):#x}")
    chk("coff chars", u16(data, coff + 18) == 0x0042, f"got {u16(data, coff + 18):#x}")

    chk("opt magic", u16(data, opt) == OPT_MAGIC_PE32P, f"got {u16(data, opt):#x}")
    chk("entry rva", u32(data, opt + 0x10) == ENTRY_RVA, f"got {u32(data, opt + 0x10):#x}")
    chk("image base", u64(data, opt + 0x18) == IMAGE_BASE, f"got {u64(data, opt + 0x18):#x}")
    chk("sect align", u32(data, opt + 0x20) == 0x1000, f"got {u32(data, opt + 0x20):#x}")
    chk("file align", u32(data, opt + 0x24) == 0x200, f"got {u32(data, opt + 0x24):#x}")
    chk("subsystem GUI", u16(data, opt + 0x44) == 2, f"got {u16(data, opt + 0x44)}")
    chk("nrvasizes", u32(data, opt + 0x6C) == 16, f"got {u32(data, opt + 0x6C)}")

    sect = opt + 0xF0
    name = data[sect:sect + 8]
    chk("sect name", name == b".text\0\0\0", f"got {name!r}")
    chk("vsize", u32(data, sect + 8) >= 9 + len(blob), f"got {u32(data, sect + 8)}")
    chk("vaddr", u32(data, sect + 0xC) == ENTRY_RVA, f"got {u32(data, sect + 0xC):#x}")
    chk("rawsize", u32(data, sect + 0x10) == 0x600, f"got {u32(data, sect + 0x10):#x}")
    chk("rawptr", u32(data, sect + 0x14) == 0x200, f"got {u32(data, sect + 0x14):#x}")
    chars = u32(data, sect + 0x24)
    chk("sect RX", chars & 0xC0000000 == 0xC0000000, f"got {chars:#x}")
    chk("sect W", chars & 0x80000000 != 0, f"got {chars:#x} (blob writes its data slots)")

    tramp = data[0x200:0x209]
    chk("trampoline", tramp == b"\xE8\x04\x00\x00\x00\xF4\x90\xEB\xFD",
        f"got {tramp.hex()}")
    chk("embedded blob", data[0x209:0x209 + len(blob)] == blob,
        f"first diff at {next((i for i in range(len(blob)) if data[0x209 + i] != blob[i]), '?')}")

    try:
        exp = pe_exports(data)
        chk("independent reader", exp == [], f"got {exp!r}")
    except Exception as e:  # noqa: BLE001 - any parse error is a fail
        chk("independent reader", False, f"raised {e!r}")

    return p


def dynamic_check(uc: Uc, blob: bytes) -> list:
    """Read the post-run state; return the list of problems."""
    p = []
    rd = uc.mem_read

    done_off = len(blob) - 84  # done_flag slot, counted from the blob tail
    done = struct.unpack("<Q", bytes(rd(IMAGE_BASE + BLOB_RVA + done_off, 8)))[0]
    if done != 1:
        p.append(f"done_flag in PE image == {done}, expected 1")

    nt_delay = bytes(rd(H.NTDLL_BASE + 0x1000, 12))
    expect_nt = bytes.fromhex("b83d0000000f05c300000000")
    if nt_delay != expect_nt:
        p.append(f"NtDelayExecution not restored: {nt_delay.hex()}")

    clock = struct.unpack("<Q", bytes(rd(H.CLOCK, 8)))[0]
    if clock < 2 * 100000:
        p.append(f"clock advanced only {clock} (the mask never slept)")

    return p


def main() -> int:
    if not BLOB_PATH.exists():
        print(f"FAIL: {BLOB_PATH} missing — run build.sh first")
        return 2

    blob = BLOB_PATH.read_bytes()

    # --- rebuild the artifact under test ----------------------------------
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "mk_pe.py"), str(EXE_PATH)],
        capture_output=True, text=True, cwd=ROOT,
    )
    if proc.returncode != 0:
        print(f"FAIL: mk_pe.py exited {proc.returncode}\n{proc.stdout}{proc.stderr}")
        return 2
    print(proc.stdout.strip())

    data = EXE_PATH.read_bytes()

    # --- 1+2. static structure + independent reader ------------------------
    problems = static_check(data, blob)
    for pr in problems:
        print(f"STATIC FAIL: {pr}")
    if problems:
        print("FAIL")
        return 1
    print("static:   PE32+ structure ok; independent reader ok; blob embedded byte-identical")

    # --- 3. run the PE image from its real entry point ----------------------
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x0, 0x100000)
    uc.mem_map(H.NTDLL_BASE, 0x100000)
    uc.mem_map(H.SC_BASE, 0x100000)
    uc.mem_map(H.CLOCK, 0x100000)
    uc.mem_map(H.STACK, 0x20000)
    uc.mem_map(IMAGE_BASE, 0x10000)
    H.build_env(uc)                      # fake PEB/Ldr/ntdll + return addr on stack
    # load the image the way the Windows loader does: headers -> RVA 0, each
    # section's raw data -> its VirtualAddress. read the real offsets from the
    # section header rather than hard-coding them.
    sect_hdr = 0x84 + 20 + u16(data, 0x84 + 16)                   # first section header
    raw_ptr = u32(data, sect_hdr + 0x14)
    raw_size = u32(data, sect_hdr + 0x10)
    vaddr = u32(data, sect_hdr + 0x0C)
    uc.mem_write(IMAGE_BASE, data[:raw_ptr])                       # DOS+COFF+opt+sect -> RVA 0
    uc.mem_write(IMAGE_BASE + vaddr, data[raw_ptr:raw_ptr + raw_size])
    uc.reg_write(UC_X86_REG_GS_BASE, 0)
    uc.reg_write(UC_X86_REG_RSP, H.RSP0)

    trace = []

    def on_code(uc_, rip, size, _):
        if bytes(uc_.mem_read(rip, 2)) == b"\x0F\x05":
            trace.append(uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF)
            uc_.reg_write(UC_X86_REG_RAX, 0)       # STATUS_SUCCESS
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)

    rip = IMAGE_BASE + ENTRY_RVA
    for _ in range(64):
        uc.emu_start(rip, TRAMP_SPIN, count=500_000)
        rip = uc.reg_read(UC_X86_REG_RIP)
        if rip == TRAMP_SPIN:
            break
    else:
        print(f"FAIL: stuck at rip=0x{rip:X} after {len(trace)} syscalls")
        return 1

    problems = dynamic_check(uc, blob)
    if trace != [0x2B, 0x2B]:
        problems.append(f"syscalls {[hex(n) for n in trace]} != [0x2B, 0x2B]")
    for pr in problems:
        print(f"RUN FAIL: {pr}")

    clock = struct.unpack("<Q", bytes(uc.mem_read(H.CLOCK, 8)))[0]
    print(f"entry:    0x{IMAGE_BASE + ENTRY_RVA:X} (trampoline) -> blob @ 0x{IMAGE_BASE + BLOB_RVA:X}")
    print(f"finished: rip=0x{rip:X} (trampoline spin loop — the blob's final ret landed here)")
    print(f"syscalls: {' '.join('0x%02X' % n for n in trace)}")
    print(f"clock:    {clock} (keq calls: {clock // 100000})")

    if problems:
        print("FAIL")
        return 1
    print("PASS (windows exe: structure ok, independent parse ok, full image ran from entry)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
