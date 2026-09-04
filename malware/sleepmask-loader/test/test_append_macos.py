#!/usr/bin/env python3
"""test_append_macos.py — the macOS host-coupling test.

Builds a real host Mach-O (the "victim" — writes its own line then exit(42)),
couples the stealth beacon onto it with tools/append_macho.py, and verifies the
result three ways:

  1. STATIC: parse the coupled Mach-O by hand — the __TEXT segment now carries
     two sections; the new `__bcon` section holds the 10-byte stub
     `call <blob>; jmp <orig entry>`; the beacon is embedded byte-identical;
     the original `__text` raw data is untouched; and LC_MAIN.entryoff was
     re-pointed at `__bcon`.

  2. INDEPENDENT READER: a generic stdlib-only load-command walker (no
     hard-coded offsets) re-walks mach_header_64 -> cmds and confirms the
     command list, sizes, and section counts agree with the static pass.

  3. DYNAMIC: load the coupled image into Unicorn at its __TEXT vmaddr
     (0x100000000) and enter it the way the kernel would via
     LC_MAIN.entryoff. XNU x86-64 syscalls are emulated (rax = 0x02000000|nr):
       - write (nr 0): capture the bytes on fd 1
       - exit  (nr 1): capture the status and stop
     The `__bcon` stub calls the beacon, which fires its write on fd 1 BEFORE
     the host runs, then returns into the host; the host writes its own line
     and dies in exit(42). A sentinel is parked in RBX/R15 before entry and
     must survive the run — the beacon saves and restores every GPR, and the
     host never touches those two. The run is done twice — at the nominal base
     and at a +0x1000 ASLR slide — to prove the stub + beacon are PIC.

PASS = in BOTH slides: the beacon token is the first write, the host's own
line follows it, the exit code is preserved (42), and the sentinel GPRs are
untouched. Exit 0 pass / 1 fail / 2 build problem.
"""

import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))

from mk_macho import make_macho          # noqa: E402  host Mach-O builder

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.unicorn import UcError
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_RBX,
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RDX,
    UC_X86_REG_R15,
)

HOST_BIN = ROOT / "build" / "host_macos.bin"
BEACON_BIN = ROOT / "build" / "beacon_macos.bin"
HOST_MACHO = ROOT / "build" / "host_macos.macho"
COUPLED_MACHO = ROOT / "build" / "host_macos.coupled"

# --- mach constants (kept local so this test stands alone) ------------------
MH_MAGIC_64     = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE      = 2
LC_SEGMENT_64   = 0x80000027
LC_MAIN         = 0x80000028

TEXT_VMADDR = 0x100000000
SLIDE       = 0x1000
STACK       = 0x200000
STACK_SIZE  = 0x10000
RSP0        = STACK + STACK_SIZE - 16

SENTINEL_RBX = 0x1111111111111111
SENTINEL_R15 = 0x2222222222222222

BEACON_MSG = b"sleepmask: coupled | macos x86-64 | host continues\n"
HOST_MSG   = b"host alive\n"
EXIT_CODE  = 42


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o, n=16):
    raw = b[o:o + n]
    return raw[: raw.find(b"\0")]


def parse_sections(data):
    """Walk the coupled Mach-O; return (sections, entryoff, seg_vmaddr).

    sections = list of (name, segname, vaddr, size, fileoff, flags).
    entryoff = LC_MAIN.entryoff (an offset from the segment vmaddr).
    """
    if u32(data, 0) != MH_MAGIC_64:
        raise ValueError("not a 64-bit Mach-O")
    ncmds, sizeofcmds = u32(data, 16), u32(data, 20)
    sections = []
    entryoff = None
    seg_vmaddr = None
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            seg_vmaddr = u64(data, off + 0x18)
            nsects = struct.unpack_from("<i", data, off + 0x40)[0]
            for j in range(nsects):
                s = off + 72 + j * 80
                sections.append((
                    cstr(data, s),
                    cstr(data, s + 0x10),
                    u64(data, s + 0x20),
                    u64(data, s + 0x28),
                    u32(data, s + 0x30),
                    u32(data, s + 0x40),
                ))
        elif cmd == LC_MAIN:
            entryoff = u64(data, off + 8)
        off += cmdsize
    return sections, entryoff, seg_vmaddr


# --- 1. static, offset-based field checks -----------------------------------
def static_check(coupled: bytes, host: bytes, beacon: bytes) -> list:
    p = []

    def chk(label, ok, detail=""):
        if not ok:
            p.append(f"{label}: {detail}")

    chk("magic", u32(coupled, 0) == MH_MAGIC_64, f"got {u32(coupled, 0):#x}")
    chk("cputype", u32(coupled, 4) == CPU_TYPE_X86_64, f"got {u32(coupled, 4):#x}")
    chk("filetype", u32(coupled, 12) == MH_EXECUTE, f"got {u32(coupled, 12)}")
    chk("ncmds", u32(coupled, 16) == 2, f"got {u32(coupled, 16)}")

    try:
        sects, entryoff, seg_vmaddr = parse_sections(coupled)
    except Exception as e:  # noqa: BLE001 - any parse error is a fail
        return [f"parse_sections raised {e!r}"]

    by_name = {s[0]: s for s in sects}
    chk("two sections", len(sects) == 2, f"got {len(sects)}")
    chk("__text present", b"__text" in by_name, f"sects={[s[0] for s in sects]}")
    chk("__bcon present", b"__bcon" in by_name, f"sects={[s[0] for s in sects]}")
    if b"__bcon" not in by_name or b"__text" not in by_name:
        return p

    _n, _sn, b_addr, b_size, b_off, b_flags = by_name[b"__bcon"]
    _n, _sn, t_addr, t_size, t_off, _tf = by_name[b"__text"]

    chk("__bcon is instructions", b_flags & 0x80 != 0, f"flags {b_flags:#x}")
    chk("__bcon size = 10 + beacon", b_size == 10 + len(beacon), f"got {b_size}")

    # --- the stub: call <blob>; jmp <orig entry> -------------------------
    stub = coupled[b_off:b_off + 10]
    chk("stub call", stub[0:5] == b"\xE8\x05\x00\x00\x00", f"got {stub[0:5].hex()}")
    chk("stub jmp", stub[5] == 0xE9, f"got {stub[5]:#x}")
    disp = struct.unpack("<i", stub[6:10])[0]
    jmp_next = (b_addr + 10)
    orig_entry = jmp_next + disp
    chk("stub jmp -> orig entry", orig_entry == t_addr,
        f"jmp lands 0x{orig_entry:x}, host __text 0x{t_addr:x}")

    # --- the beacon is embedded byte-identical ---------------------------
    blob_at = coupled[b_off + 10:b_off + 10 + len(beacon)]
    chk("beacon byte-identical", blob_at == beacon,
        f"first diff at {next((i for i in range(len(beacon)) if blob_at[i] != beacon[i]), '?')}")

    # --- LC_MAIN was re-pointed at the __bcon stub ------------------------
    chk("entry -> __bcon", entryoff == b_addr - seg_vmaddr,
        f"entryoff {entryoff:#x} != __bcon {b_addr:#x} - seg {seg_vmaddr:#x}")

    # --- the original __text raw data is untouched ------------------------
    chk("__text raw byte-identical",
        coupled[t_off:t_off + t_size] == host[t_off:t_off + t_size],
        "raw data differs")

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
    chk("has segment", any(c == LC_SEGMENT_64 for c, _, _ in cmds),
        f"cmds={[hex(c) for c, _, _ in cmds]}")
    chk("has main", any(c == LC_MAIN for c, _, _ in cmds),
        f"cmds={[hex(c) for c, _, _ in cmds]}")

    for cmd, cmdsize, soff in cmds:
        if cmd == LC_SEGMENT_64:
            nsects = struct.unpack_from("<i", data, soff + 0x40)[0]
            expect_size = 72 + nsects * 80
            chk("seg cmdsize covers nsects", cmdsize == expect_size,
                f"cmdsize {cmdsize} != {expect_size} for nsects {nsects}")
        if cmd == LC_MAIN:
            chk("main cmdsize", cmdsize == 24, f"got {cmdsize}")

    return p


# --- 3. dynamic: run the coupled image in Unicorn at a given base ------------
def run_coupled(base: int, data: bytes):
    """Load the coupled image at base; enter via LC_MAIN. Return
    (writes, exit_code, rbx, r15, error)."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    region = 0x40000
    uc.mem_map(base, region)
    uc.mem_map(STACK, STACK_SIZE)

    try:
        sects, entryoff, seg_vmaddr = parse_sections(data)
    except Exception as e:  # noqa: BLE001
        return [], None, None, None, f"parse: {e!r}"

    for _n, _sn, vaddr, size, foff, _f in sects:
        chunk = data[foff:foff + size]
        uc.mem_write(base + (vaddr - seg_vmaddr), chunk)

    writes = []
    exit_code = [None]

    def on_code(uc_, rip, size, _):
        if bytes(uc_.mem_read(rip, 2)) != b"\x0F\x05":
            return
        rax = uc_.reg_read(UC_X86_REG_RAX)
        nr, legacy = rax & 0x00FFFFFF, bool(rax & 0x02000000)
        if legacy and nr == 0:                                   # write
            rsi = uc_.reg_read(UC_X86_REG_RSI)
            rdx = uc_.reg_read(UC_X86_REG_RDX)
            writes.append(bytes(uc_.mem_read(rsi, rdx)))
            uc_.reg_write(UC_X86_REG_RAX, rdx)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        elif legacy and nr == 1:                                 # exit
            exit_code[0] = uc_.reg_read(UC_X86_REG_RDI) & 0xFFFFFFFF
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            uc_.emu_stop()
        else:                                                    # unmodelled
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.reg_write(UC_X86_REG_RSP, RSP0)
    uc.reg_write(UC_X86_REG_RBX, SENTINEL_RBX)
    uc.reg_write(UC_X86_REG_R15, SENTINEL_R15)

    start = base + entryoff
    try:
        uc.emu_start(start, start + 1, count=5_000_000)
    except UcError as e:
        return writes, exit_code[0], None, None, f"UcError {e!r}"
    rbx = uc.reg_read(UC_X86_REG_RBX)
    r15 = uc.reg_read(UC_X86_REG_R15)
    return writes, exit_code[0], rbx, r15, None


def dynamic_check(label, writes, exit_code, rbx, r15, err) -> list:
    p = []
    if err:
        return [f"[{label}] {err}"]
    if writes != [BEACON_MSG, HOST_MSG]:
        p.append(f"[{label}] writes {writes!r} != [{BEACON_MSG!r}, {HOST_MSG!r}]")
    if exit_code != EXIT_CODE:
        p.append(f"[{label}] exit code {exit_code} != {EXIT_CODE}")
    if rbx != SENTINEL_RBX:
        p.append(f"[{label}] RBX clobbered: {rbx:#x} != {SENTINEL_RBX:#x}")
    if r15 != SENTINEL_R15:
        p.append(f"[{label}] R15 clobbered: {r15:#x} != {SENTINEL_R15:#x}")
    return p


def main() -> int:
    missing = [n for n, pth in (("host_macos.bin", HOST_BIN),
                                ("beacon_macos.bin", BEACON_BIN)) if not pth.exists()]
    if missing:
        print(f"FAIL: missing {', '.join(missing)} — run build.sh first")
        return 2

    host_blob = HOST_BIN.read_bytes()
    beacon = BEACON_BIN.read_bytes()

    # --- build the host Mach-O, then couple the beacon onto it ------------
    host_macho = make_macho(host_blob)
    HOST_MACHO.write_bytes(host_macho)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "append_macho.py"),
         str(HOST_MACHO), str(BEACON_BIN), str(COUPLED_MACHO)],
        capture_output=True, text=True, cwd=ROOT,
    )
    if proc.returncode != 0:
        print(f"FAIL: append_macho.py exited {proc.returncode}\n{proc.stdout}{proc.stderr}")
        return 2
    print(proc.stdout.strip())
    coupled = COUPLED_MACHO.read_bytes()

    # --- 1. static structure ---------------------------------------------
    problems = static_check(coupled, host_macho, beacon)
    for pr in problems:
        print(f"STATIC FAIL: {pr}")
    if problems:
        print("FAIL")
        return 1
    print("static:   __bcon at new entry; stub=call+jmp; beacon byte-identical; "
          "__text untouched; LC_MAIN re-pointed")

    # --- 2. independent walker -------------------------------------------
    problems = independent_check(coupled)
    for pr in problems:
        print(f"WALKER FAIL: {pr}")
    if problems:
        print("FAIL")
        return 1
    print("walker:   independent command walk agrees (2 cmds, sizes, nsects)")

    # --- 3. dynamic: nominal base, then ASLR slide ------------------------
    all_problems = []
    for label, base in (("base", TEXT_VMADDR), ("slide", TEXT_VMADDR + SLIDE)):
        writes, exit_code, rbx, r15, err = run_coupled(base, coupled)
        print(f"[{label}] writes={[w.decode(errors='replace') for w in writes]} "
              f"exit={exit_code} rbx={'ok' if rbx == SENTINEL_RBX else 'X'} "
              f"r15={'ok' if r15 == SENTINEL_R15 else 'X'}")
        all_problems += dynamic_check(label, writes, exit_code, rbx, r15, err)

    for pr in all_problems:
        print(f"RUN FAIL: {pr}")
    if all_problems:
        print("FAIL")
        return 1
    print("PASS (macos host coupling: beacon fired first, host ran, exit 42 preserved, "
          "GPRs intact; base + slide)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
