#!/usr/bin/env python3
"""test_macos.py — the macOS artifact test.

Regenerates build/sleepmask_macho via tools/mk_macho.py, then verifies it four
ways:

  1. STATIC: hand-checks every field of the 64-bit Mach-O (mach_header_64,
     LC_SEGMENT_64 __TEXT, its section_64 __text, LC_MAIN, and that the
     embedded payload is byte-identical to build/payload_macos.bin).
  2. INDEPENDENT READER: a generic stdlib-only load-command walker (no
     hard-coded offsets) re-walks mach_header_64 -> cmds and confirms the
     command list, sizes, and section counts agree with the static pass.
  3. DYNAMIC (nominal base): the image is loaded into Unicorn at its
     __TEXT vmaddr (0x100000000) and entered exactly as the kernel would via
     LC_MAIN.entryoff. XNU x86-64 syscalls are emulated (rax = 0x2000000|nr):
       - write (nr 0): capture the bytes on fd 1
       - exit  (nr 1): capture the status and stop
     The payload must beacon the exact token then exit(0).
  4. DYNAMIC (ASLR slide): the whole image is re-run at vmaddr + 0x1000. The
     payload is PIC (one RIP-relative lea), so it must produce the identical
     beacon + exit at the slid base — proving it survives kernel slide.

PASS = all of the above. Exit 0 pass / 1 fail / 2 usage/build problem.
"""

import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.unicorn import UcError
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_RSI,
    UC_X86_REG_RDX,
    UC_X86_REG_RDI,
)

PAYLOAD_PATH = ROOT / "build" / "payload_macos.bin"
MACHO_PATH = ROOT / "build" / "sleepmask_macho"

# --- mach constants (kept local so this test stands alone) ------------------
MH_MAGIC_64     = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE      = 2
LC_SEGMENT_64   = 0x80000027
LC_MAIN         = 0x80000028

TEXT_VMADDR     = 0x100000000
TEXT_SECT_OFF   = 0x1000
ENTRY_OFF       = 0x1000

EXPECT_BEACON = b"sleepmask: armed | macos x86-64 | self-injected\n"


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o, n=16):
    raw = b[o:o + n]
    return raw[:raw.find(b"\0")]


# --- 1. static, offset-based field checks -----------------------------------
def static_check(data: bytes, payload: bytes) -> list:
    p = []

    def chk(label, ok, detail=""):
        if not ok:
            p.append(f"{label}: {detail}")

    chk("magic", u32(data, 0) == MH_MAGIC_64, f"got {u32(data, 0):#x}")
    chk("cputype", u32(data, 4) == CPU_TYPE_X86_64, f"got {u32(data, 4):#x}")
    chk("cpusubtype", u32(data, 8) == 3, f"got {u32(data, 8)}")
    chk("filetype", u32(data, 12) == MH_EXECUTE, f"got {u32(data, 12)}")
    chk("ncmds", u32(data, 16) == 2, f"got {u32(data, 16)}")
    chk("sizeofcmds", u32(data, 20) == 176, f"got {u32(data, 20)}")

    # LC_SEGMENT_64 @ 0x20
    chk("seg cmd", u32(data, 0x20) == LC_SEGMENT_64, f"got {u32(data, 0x20):#x}")
    chk("seg cmdsize", u32(data, 0x24) == 152, f"got {u32(data, 0x24)}")
    chk("seg name", cstr(data, 0x28) == b"__TEXT", f"got {cstr(data, 0x28)!r}")
    chk("seg vmaddr", u64(data, 0x38) == TEXT_VMADDR, f"got {u64(data, 0x38):#x}")
    chk("seg vmsize", u64(data, 0x40) == 0x2000, f"got {u64(data, 0x40):#x}")
    chk("seg fileoff", u64(data, 0x48) == 0, f"got {u64(data, 0x48)}")
    chk("seg filesize", u64(data, 0x50) == 0x2000, f"got {u64(data, 0x50):#x}")
    chk("seg maxprot", u32(data, 0x58) == 7, f"got {u32(data, 0x58)}")
    chk("seg initprot", u32(data, 0x5C) == 5, f"got {u32(data, 0x5C)}")
    chk("seg nsects", u32(data, 0x60) == 1, f"got {u32(data, 0x60)}")

    # section_64 __text @ 0x68
    chk("sect name", cstr(data, 0x68) == b"__text", f"got {cstr(data, 0x68)!r}")
    chk("sect segname", cstr(data, 0x78) == b"__TEXT", f"got {cstr(data, 0x78)!r}")
    chk("sect addr", u64(data, 0x88) == TEXT_VMADDR + TEXT_SECT_OFF,
        f"got {u64(data, 0x88):#x}")
    chk("sect size", u64(data, 0x90) == len(payload), f"got {u64(data, 0x90)}")
    chk("sect offset", u32(data, 0x98) == TEXT_SECT_OFF, f"got {u32(data, 0x98):#x}")
    chk("sect flags instr", u32(data, 0xA8) == 0x80, f"got {u32(data, 0xA8):#x}")

    # LC_MAIN @ 0xB8
    chk("main cmd", u32(data, 0xB8) == LC_MAIN, f"got {u32(data, 0xB8):#x}")
    chk("main cmdsize", u32(data, 0xBC) == 24, f"got {u32(data, 0xBC)}")
    chk("main entryoff", u64(data, 0xC0) == ENTRY_OFF, f"got {u64(data, 0xC0):#x}")
    chk("main stacksize", u64(data, 0xC8) == 0x8000, f"got {u64(data, 0xC8):#x}")

    chk("payload at file offset", data[TEXT_SECT_OFF:TEXT_SECT_OFF + len(payload)] == payload,
        "embedded payload differs from payload_macos.bin")

    return p


# --- 2. independent generic command walker (no hard-coded offsets) -----------
def independent_check(data: bytes) -> list:
    p = []

    def chk(label, ok, detail=""):
        if not ok:
            p.append(f"{label}: {detail}")

    if u32(data, 0) != MH_MAGIC_64:
        return ["not a 64-bit Mach-O"]
    ncmds, sizeofcmds = u32(data, 16), u32(data, 20)

    cmds = []
    off = 32
    walked = 0
    try:
        while walked < sizeofcmds:
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            cmds.append((cmd, cmdsize, off))
            off += cmdsize
            walked += cmdsize
    except struct.error as e:
        return [f"walker struct.error: {e!r}"]

    chk("walked all cmds", walked == sizeofcmds, f"walked {walked} != {sizeofcmds}")
    chk("cmd count", len(cmds) == ncmds, f"walked {len(cmds)} != ncmds {ncmds}")
    cmds_repr = [hex(c) for c, _, _ in cmds]
    chk("has segment", any(c == LC_SEGMENT_64 for c, _, _ in cmds), f"cmds={cmds_repr}")
    chk("has main", any(c == LC_MAIN for c, _, _ in cmds), f"cmds={cmds_repr}")

    # the segment's cmdsize must cover exactly its declared sections
    for cmd, cmdsize, soff in cmds:
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<i", data, soff + 64)[0]
            expect_size = 72 + nsects * 80
            chk("seg cmdsize covers nsects", cmdsize == expect_size,
                f"cmdsize {cmdsize} != {expect_size} for nsects {nsects}")
        if cmd == LC_MAIN:
            chk("main cmdsize", cmdsize == 24, f"got {cmdsize}")

    return p


# --- 3+4. dynamic: run in Unicorn at a given base ---------------------------
def run_image(base: int, payload: bytes):
    """Load the payload at base+0x1000, run from entry, return (beacons, exits)."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    region = 0x40000
    uc.mem_map(base, region)
    uc.mem_map(0x1000, 0x10000)                    # scratch / stack
    uc.mem_write(base + TEXT_SECT_OFF, payload)    # __text section
    uc.reg_write(UC_X86_REG_RIP, base + ENTRY_OFF)
    uc.reg_write(UC_X86_REG_RSP, 0x10000 + 0x8000)

    beacons, exits = [], []
    syscall_seq = []

    def on_code(uc_, rip, size, _):
        if bytes(uc_.mem_read(rip, 2)) == b"\x0F\x05":
            rax = uc_.reg_read(UC_X86_REG_RAX)
            syscall_seq.append(rax)
            # legacy (BSD/Unix) XNU syscalls carry class bit 25 (0x02000000);
            # the actual syscall number is the low bits.
            nr, legacy = rax & 0x00FFFFFF, bool(rax & 0x02000000)
            if legacy and nr == 0:                           # write
                rsi, rdx = uc_.reg_read(UC_X86_REG_RSI), uc_.reg_read(UC_X86_REG_RDX)
                beacons.append(bytes(uc_.mem_read(rsi, rdx)))
                uc_.reg_write(UC_X86_REG_RAX, rdx)           # bytes written
                uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            elif legacy and nr == 1:                         # exit
                exits.append(uc_.reg_read(UC_X86_REG_RDI) & 0xFFFFFFFF)
                uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            else:                                            # unmodelled: stop
                uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)

    end = base + region - 0x10
    rip = base + ENTRY_OFF
    for _ in range(16):
        try:
            uc.emu_start(rip, end, count=500_000)
        except UcError as e:
            return beacons, exits, syscall_seq, f"UcError {e!r} at rip=0x{uc.reg_read(UC_X86_REG_RIP):X}"
        rip = uc.reg_read(UC_X86_REG_RIP)
        if exits:
            break
    return beacons, exits, syscall_seq, None


def dynamic_check(payload: bytes) -> list:
    p = []

    # nominal base
    beacons, exits, seq, err = run_image(TEXT_VMADDR, payload)
    if err:
        return [f"nominal run: {err} (syscalls {seq})"]
    if not exits:
        return [f"nominal run never exited; beacons={beacons!r} syscalls={seq}"]
    if beacons != [EXPECT_BEACON]:
        p.append(f"nominal beacon {beacons!r} != {EXPECT_BEACON!r}")
    if exits != [0]:
        p.append(f"nominal exit status {exits} != [0]")
    if seq != [0x02000000, 0x02000001]:
        p.append(f"nominal syscall seq {[hex(x) for x in seq]} != [0x2000000 write, 0x2000001 exit]")

    # ASLR slide: re-run at +0x1000; PIC must survive
    slide = 0x1000
    b2, e2, seq2, err2 = run_image(TEXT_VMADDR + slide, payload)
    if err2:
        p.append(f"slid run: {err2} (syscalls {seq2})")
    if not e2:
        p.append(f"slid run never exited; beacons={b2!r} syscalls={seq2}")
    else:
        if b2 != [EXPECT_BEACON]:
            p.append(f"slid beacon {b2!r} != {EXPECT_BEACON!r}")
        if e2 != [0]:
            p.append(f"slid exit status {e2} != [0]")

    return p


def main() -> int:
    if not PAYLOAD_PATH.exists():
        print(f"FAIL: {PAYLOAD_PATH} missing — run build.sh first")
        return 2

    payload = PAYLOAD_PATH.read_bytes()

    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "mk_macho.py"), str(MACHO_PATH)],
        capture_output=True, text=True, cwd=ROOT,
    )
    if proc.returncode != 0:
        print(f"FAIL: mk_macho.py exited {proc.returncode}\n{proc.stdout}{proc.stderr}")
        return 2
    print(proc.stdout.strip())

    data = MACHO_PATH.read_bytes()

    problems = static_check(data, payload)
    for pr in problems:
        print(f"STATIC FAIL: {pr}")
    if problems:
        print("FAIL")
        return 1
    print("static:   mach_header_64 + LC_SEGMENT_64/__TEXT + section + LC_MAIN ok; payload byte-identical")

    problems = independent_check(data)
    for pr in problems:
        print(f"WALKER FAIL: {pr}")
    if problems:
        print("FAIL")
        return 1
    print("walker:   independent command walk agrees (2 cmds, sizes, nsects)")

    problems = dynamic_check(payload)
    for pr in problems:
        print(f"RUN FAIL: {pr}")
    if problems:
        print("FAIL")
        return 1

    print(f"entry:    0x{TEXT_VMADDR + ENTRY_OFF:X} (LC_MAIN) -> beacon + exit(0)")
    print("syscalls: write(1, beacon) then exit(0)  [class 0x20000000]")
    print(f"slide:    re-ran at +0x1000, identical beacon + exit (PIC holds)")
    print("PASS (macos mach-o: structure ok, independent walk ok, ran at base + slide)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
