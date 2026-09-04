#!/usr/bin/env python3
"""test_append_windows.py — the Windows host-coupling test.

Builds a real host PE (the "victim"), couples the stealth beacon onto it with
tools/append_pe.py, and verifies the result two ways:

  1. STATIC: parse the coupled PE by hand — it now has two sections; the new
     `.bcon` section is RWX and holds `call <blob>; jmp <orig entry>`; the
     beacon is embedded byte-identical; the original `.text` raw data is
     untouched; and the entry point was re-pointed to `.bcon`. The independent
     reader (research/pe/pe_exports.py) still accepts the image with zero
     imports (the beacon resolves ntdll from the PEB at runtime, no IAT).

  2. DYNAMIC: load the coupled image into Unicorn at its ImageBase and enter
     it the way the Windows loader would (RSP primed, jmp entry). The `.bcon`
     stub calls the beacon, which fires its NtWriteFile on the stdout handle
     BEFORE the host runs, then returns into the host; the host writes its own
     line and dies in NtTerminateProcess(GetCurrentProcess, 42). The run is
     done twice — once with the real syscall numbers and once with decoy
     numbers baked into the fake ntdll — to prove the nr is read from the
     export prologue, not hard-coded.

PASS = in BOTH nr configurations: the beacon token is the first write (on the
stdout handle), the host's own line follows it, the host's exit code is
preserved (42), and the sentinel parked in R15 survives (the beacon saved
every callee-saved reg the host could observe). Exit 0 pass / 1 fail / 2
build problem.
"""

import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "research" / "pe"))

from mk_pe import make_pe            # noqa: E402  host PE builder
from pe_exports import pe_exports    # noqa: E402  independent PE reader

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_R15,
    UC_X86_REG_GS_BASE,
)

HOST_BIN = ROOT / "build" / "host_win.bin"
BEACON_BIN = ROOT / "build" / "beacon_windows.bin"
HOST_PE = ROOT / "build" / "host_win.exe"
COUPLED_PE = ROOT / "build" / "host_win.coupled.exe"

IMAGE_BASE = 0x140000000

# fake Windows environment (same fixture addresses as run_harness.py)
PEB_ADDR   = 0x2000
LDR_ADDR   = 0x3000
LDR_ENTRY  = 0x4000
NAME_ADDR  = 0x5000
PARAMS     = 0x6000
NTDLL_BASE = 0x100000
STACK      = 0x600000
RSP0       = 0x610000
STDOUT_HDL = 0x12345678

BEACON_MSG = b"sleepmask: coupled | windows x86-64 | host continues\n"
HOST_MSG   = b"host alive\n"

NR_WRITE_REAL, NR_TERM_REAL = 0x17, 0x0B    # Win10 x64
NR_WRITE_DECOY, NR_TERM_DECOY = 0x5C, 0x99  # decoys (still distinct)

# Parked in R15 before entry: the beacon saves/restores all 15 GPRs and the
# host never touches R15, so it must survive the whole coupled run. (RBX is
# not a valid sentinel here — the host uses it as a scratch reg.)
SENTINEL_R15 = 0x2222222222222222


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def sect_table(data):
    """Return (opt, sect_off, nsect) for a PE32+ image."""
    lfanew = u32(data, 0x3C)
    coff = lfanew + 4
    nsect = u16(data, coff + 2)
    opt = coff + 20
    sect_off = opt + u16(data, coff + 16)
    return opt, sect_off, nsect


def find_section(data, name: bytes):
    """Return (vaddr, vsize, rawptr, rawsize) for a section by 8-byte name."""
    _opt, sect_off, nsect = sect_table(data)
    for i in range(nsect):
        off = sect_off + i * 40
        if data[off:off + 8] == name:
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
            return vaddr, vsize, rawptr, rawsize
    raise KeyError(name)


def static_check(coupled: bytes, host: bytes, beacon: bytes) -> list:
    p = []

    def chk(label, ok, detail=""):
        if not ok:
            p.append(f"{label}: {detail}")

    chk("MZ", coupled[0:2] == b"MZ", f"got {coupled[0:2]!r}")
    opt, sect_off, nsect = sect_table(coupled)
    chk("two sections", nsect == 2, f"got {nsect}")

    entry = u32(coupled, opt + 0x10)

    # --- the new .bcon section ------------------------------------------
    bcon_hdr = None
    for i in range(nsect):
        off = sect_off + i * 40
        if coupled[off:off + 8] == b".bcon\0\0\0":
            bcon_hdr = off
            break
    if bcon_hdr is None:
        chk(".bcon present", False, "no .bcon section")
        return p
    vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", coupled, bcon_hdr + 8)
    chars = u32(coupled, bcon_hdr + 0x24)
    chk(".bcon RX", chars & 0xC0000000 == 0xC0000000, f"got {chars:#x}")
    chk(".bcon W", chars & 0x80000000 != 0, f"got {chars:#x}")
    chk("entry -> .bcon", entry == vaddr, f"entry {entry:#x} != .bcon {vaddr:#x}")
    chk(".bcon vsize", vsize == 10 + len(beacon), f"got {vsize}")
    chk(".bcon rawsize", rawsize >= 10 + len(beacon), f"got {rawsize}")

    # --- the stub: call <blob>; jmp <orig entry> -------------------------
    stub = coupled[rawptr:rawptr + 10]
    want_call = b"\xE8\x05\x00\x00\x00"          # call +5 -> +10 (the blob)
    want_e9 = b"\xE9"
    chk("stub call", stub[0:5] == want_call, f"got {stub[0:5].hex()}")
    chk("stub jmp", stub[5] == 0xE9, f"got {stub[5]:#x}")
    disp = struct.unpack("<i", stub[6:10])[0]
    orig_entry = (vaddr + 10 + disp) & 0xFFFFFFFF
    host_entry = u32(host, sect_table(host)[0] + 0x10)
    chk("stub jmp -> orig entry", orig_entry == host_entry,
        f"jmp lands 0x{orig_entry:x}, host entry 0x{host_entry:x}")

    # --- the beacon is embedded byte-identical ---------------------------
    blob_at = coupled[rawptr + 10:rawptr + 10 + len(beacon)]
    chk("beacon byte-identical", blob_at == beacon,
        f"first diff at {next((i for i in range(len(beacon)) if blob_at[i] != beacon[i]), '?')}")

    # --- the original .text raw data is untouched ------------------------
    hvaddr, hvsize, hrawptr, hrawsize = find_section(host, b".text\0\0\0")
    cvaddr, cvsize, crawptr, crawsize = find_section(coupled, b".text\0\0\0")
    chk(".text vaddr unchanged", cvaddr == hvaddr,
        f"{cvaddr:#x} != {hvaddr:#x}")
    chk(".text vsize unchanged", cvsize == hvsize, f"{cvsize} != {hvsize}")
    chk(".text raw byte-identical",
        coupled[crawptr:crawptr + hrawsize] == host[hrawptr:hrawptr + hrawsize],
        "raw data differs")

    # --- the independent reader still accepts it, zero imports -----------
    try:
        exp = pe_exports(coupled)
        chk("independent reader", exp == [], f"got {exp!r}")
    except Exception as e:  # noqa: BLE001 - any parse error is a fail
        chk("independent reader", False, f"raised {e!r}")

    return p


def build_env(uc, nr_write, nr_term):
    w = uc.mem_write
    q = "<Q"
    # PEB / Ldr chain
    w(0x60, struct.pack(q, PEB_ADDR))
    w(PEB_ADDR + 0x18, struct.pack(q, LDR_ADDR))     # PEB->Ldr
    w(PEB_ADDR + 0x20, struct.pack(q, PARAMS))       # PEB->Params
    w(PARAMS + 0x28, struct.pack(q, STDOUT_HDL))     # StandardOutput
    w(LDR_ADDR + 0x08, struct.pack(q, LDR_ENTRY))    # InLoadOrder head
    w(LDR_ENTRY + 0x00, struct.pack(q, LDR_ADDR + 0x08))  # Flink (circular)
    w(LDR_ENTRY + 0x50, struct.pack("<H", 18))       # BaseDllName.Length
    w(LDR_ENTRY + 0x58, struct.pack(q, NAME_ADDR))   # BaseDllName.Buffer
    w(LDR_ENTRY + 0x60, struct.pack(q, NTDLL_BASE))  # DllBase
    w(NAME_ADDR, "ntdll.dll".encode("utf-16-le"))

    # fake ntdll PE
    w(NTDLL_BASE + 0x3C, struct.pack("<I", 0x100))   # e_lfanew
    w(NTDLL_BASE + 0x100, b"PE\0\0")
    opt = NTDLL_BASE + 0x100 + 0x18
    w(opt, struct.pack("<H", 0x20B))
    w(opt + 0x70, struct.pack("<I", 0x200))          # ExportDir.RVA
    edir = NTDLL_BASE + 0x200
    w(edir + 0x0C, struct.pack("<I", 2))             # NumberOfFunctions
    w(edir + 0x10, struct.pack("<I", 2))             # NumberOfNames
    w(edir + 0x14, struct.pack("<I", 0x300))         # EAT
    w(edir + 0x18, struct.pack("<I", 0x380))         # ENT
    w(edir + 0x1C, struct.pack("<I", 0x400))         # ORD
    w(NTDLL_BASE + 0x300 + 4 * 0, struct.pack("<I", 0x1000))  # EAT[0]
    w(NTDLL_BASE + 0x300 + 4 * 1, struct.pack("<I", 0x1100))  # EAT[1]
    w(NTDLL_BASE + 0x380 + 4 * 0, struct.pack("<I", 0x500))   # ENT[0]
    w(NTDLL_BASE + 0x380 + 4 * 1, struct.pack("<I", 0x580))   # ENT[1]
    w(NTDLL_BASE + 0x400 + 2 * 0, struct.pack("<H", 0))       # ORD[0]
    w(NTDLL_BASE + 0x400 + 2 * 1, struct.pack("<H", 1))       # ORD[1]
    w(NTDLL_BASE + 0x500, b"NtWriteFile\0")
    w(NTDLL_BASE + 0x580, b"NtTerminateProcess\0")
    # thunks: B8 <nr> 00 00 00 0F 05 C3 (nr is read, not hard-coded)
    w(NTDLL_BASE + 0x1000, bytes((0xB8, nr_write, 0, 0, 0, 0x0F, 0x05, 0xC3)))
    w(NTDLL_BASE + 0x1100, bytes((0xB8, nr_term, 0, 0, 0, 0x0F, 0x05, 0xC3)))


def load_image(uc, data):
    """Write the PE image into Unicorn at IMAGE_BASE; return the entry RVA."""
    opt, sect_off, nsect = sect_table(data)
    raws = [u32(data, sect_off + i * 40 + 0x14) for i in range(nsect)]
    uc.mem_write(IMAGE_BASE, data[:min(raws)])
    for i in range(nsect):
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, sect_off + i * 40 + 8)
        uc.mem_write(IMAGE_BASE + vaddr, data[rawptr:rawptr + rawsize])
    return u32(data, opt + 0x10)


def run_coupled(uc, nr_write, nr_term):
    """Enter the loaded image at its entry; return (writes, exit_code, r15)."""
    writes = []
    exit_code = [None]

    def on_code(uc_, rip, size, _):
        if bytes(uc_.mem_read(rip, 2)) != b"\x0F\x05":
            return
        nr = uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        rsp = uc_.reg_read(UC_X86_REG_RSP)
        rcx = uc_.reg_read(UC_X86_REG_RCX)
        rdx = uc_.reg_read(UC_X86_REG_RDX)
        if nr == nr_write:
            buf = struct.unpack("<Q", bytes(uc_.mem_read(rsp + 0x28, 8)))[0]
            ln = struct.unpack("<I", bytes(uc_.mem_read(rsp + 0x30, 4)))[0]
            writes.append((rcx, bytes(uc_.mem_read(buf, ln))))
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        elif nr == nr_term:
            exit_code[0] = rdx & 0xFFFFFFFF
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
            uc_.emu_stop()
        else:
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)

    uc.hook_add(UC_HOOK_CODE, on_code)
    entry = load_image(uc, COUPLED_PE.read_bytes())
    uc.reg_write(UC_X86_REG_GS_BASE, 0)
    uc.reg_write(UC_X86_REG_RSP, RSP0)
    uc.reg_write(UC_X86_REG_R15, SENTINEL_R15)
    # The run is ended by emu_stop() on NtTerminateProcess; `until` is a
    # sentinel that never becomes a PC: the stub's instruction boundaries are
    # V (the call) and V+5 (the jmp), so V+1 is safe. (begin == until would
    # stop emulation after zero instructions.)
    start = IMAGE_BASE + entry
    uc.emu_start(start, start + 1, count=5_000_000)
    return writes, exit_code[0], uc.reg_read(UC_X86_REG_R15)


def dynamic_check(writes, exit_code, r15, label):
    p = []
    if len(writes) != 2:
        p.append(f"[{label}] expected 2 writes (beacon, host), got {len(writes)}")
    else:
        h0, m0 = writes[0]
        h1, m1 = writes[1]
        if not (m0 == BEACON_MSG and h0 == STDOUT_HDL):
            p.append(f"[{label}] beacon write wrong: handle=0x{h0:x} msg={m0!r}")
        if not (m1 == HOST_MSG and h1 == STDOUT_HDL):
            p.append(f"[{label}] host write wrong: handle=0x{h1:x} msg={m1!r}")
    if exit_code != 42:
        p.append(f"[{label}] host exit code {exit_code} != 42")
    if r15 != SENTINEL_R15:
        p.append(f"[{label}] R15 clobbered: {r15:#x} != {SENTINEL_R15:#x}")
    return p


def main() -> int:
    missing = [n for n, pth in (("host_win.bin", HOST_BIN),
                                ("beacon_windows.bin", BEACON_BIN)) if not pth.exists()]
    if missing:
        print(f"FAIL: missing {', '.join(missing)} — run build.sh first")
        return 2

    host_blob = HOST_BIN.read_bytes()
    beacon = BEACON_BIN.read_bytes()

    # --- build the host PE, then couple the beacon onto it ---------------
    host_pe = make_pe(host_blob)
    HOST_PE.write_bytes(host_pe)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "append_pe.py"),
         str(HOST_PE), str(BEACON_BIN), str(COUPLED_PE)],
        capture_output=True, text=True, cwd=ROOT,
    )
    if proc.returncode != 0:
        print(f"FAIL: append_pe.py exited {proc.returncode}\n{proc.stdout}{proc.stderr}")
        return 2
    print(proc.stdout.strip())
    coupled = COUPLED_PE.read_bytes()

    # --- 1. static structure ---------------------------------------------
    problems = static_check(coupled, host_pe, beacon)
    for pr in problems:
        print(f"STATIC FAIL: {pr}")
    if problems:
        print("FAIL")
        return 1
    print("static:   .bcon RWX at new entry; stub=call+jmp; beacon byte-identical; .text untouched; reader ok")

    # --- 2. dynamic: real nr, then decoy nr ------------------------------
    all_problems = []
    for label, nw, nt in (("real", NR_WRITE_REAL, NR_TERM_REAL),
                          ("decoy", NR_WRITE_DECOY, NR_TERM_DECOY)):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0x0, 0x100000)
        uc.mem_map(NTDLL_BASE, 0x100000)
        uc.mem_map(STACK, 0x20000)
        uc.mem_map(IMAGE_BASE, 0x10000)
        build_env(uc, nw, nt)
        writes, exit_code, r15 = run_coupled(uc, nw, nt)
        print(f"[{label}] writes={[w[1].decode(errors='replace') for w in writes]}"
              f" exit={exit_code} r15={'ok' if r15 == SENTINEL_R15 else 'X'}")
        all_problems += dynamic_check(writes, exit_code, r15, label)

    for pr in all_problems:
        print(f"RUN FAIL: {pr}")
    if all_problems:
        print("FAIL")
        return 1
    print("PASS (windows host coupling: beacon fired first, host ran, exit 42 + r15 preserved; real + decoy nr)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
