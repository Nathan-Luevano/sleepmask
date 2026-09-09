#!/usr/bin/env python3
"""test_dll.py — the Windows DLL artifact test (the error-5 bypass).

build/payload.dll wraps the PIC beacon in a minimal PE32+ *DLL* so a signed
Microsoft LOLBin (rundll32 / regsvr32) can LoadLibrary it on a machine that
rejects an unsigned .exe with "Access is denied" (error 5). This test proves
the artifact is load-and-call correct, two ways:

   1. STATIC: parse the DLL by hand — MZ/PE, one RWX .text section, the beacon
      embedded byte-identical, the DllRegisterServer wrapper exactly
      `call beacon ; xor rax,rax ; ret`, DllMain exactly `mov eax,1 ; ret`,
      DllUnregisterServer exactly `xor rax,rax ; ret`, all three exports
      listed (DllMain imm32 == 1, ordinal base 1), the export Name string is
      "payload.dll", no import directory (the beacon resolves ntdll from the
      PEB at runtime), no other data directories, and the
      DllCharacteristics / COFF characteristics mirror real signed x64 DLLs.
      The independent reader (research/pe/pe_exports.py) agrees.

   2. DYNAMIC: load the image into Unicorn at TWO bases (the preferred
      0x180000000 ImageBase and an ASLR'd 0x190000000 — there are no
      relocations, so any base must work) and enter it the way rundll32 /
      regsvr32 would: the loader calls DllMain (must return TRUE = 1), then
      GetProcAddress("DllRegisterServer") resolves through the export table
      and the wrapper is called. The wrapper fires the beacon, which must
      leave TWO traces (the "runs no matter what" proof): an NtWriteFile of
      the beacon token on the stdout handle AND a filesystem artifact
      (NtCreateFile + NtWriteFile + NtClose on sleepmask_beacon.txt). It
      must then return S_OK = 0 and leave R15 untouched. Each run is done
      once with the real syscall numbers and once with decoy numbers baked
      into the fake ntdll, proving the nr is read from the export prologue
      at runtime, not hard-coded.

PASS = in all 4 runs: DllMain -> 1 with no writes; wrapper -> 0 with exactly
one beacon write on the stdout handle AND exactly one beacon write on the
file handle (bracketed by one NtCreateFile and one NtClose); R15 sentinel
preserved. Exit 0 pass / 1 fail / 2 build problem.
"""

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "research" / "pe"))

from mk_dll import make_dll                      # noqa: E402  the DLL writer under test
from pe_exports import pe_exports, rva_to_file_offset  # noqa: E402  independent reader

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RSP,
    UC_X86_REG_RCX,
    UC_X86_REG_R8,
    UC_X86_REG_R15,
    UC_X86_REG_GS_BASE,
)

BEACON_BIN = ROOT / "build" / "beacon_windows.bin"
DLL_OUT = ROOT / "build" / "payload.dll"

BEACON_MSG = b"sleepmask: coupled | windows x86-64 | host continues\n"

# fixture syscall numbers (all distinct; the beacon reads them at runtime):
#   NtWriteFile / NtCreateFile / NtClose / NtTerminateProcess
NR_WRITE_REAL, NR_CREATE_REAL, NR_CLOSE_REAL, NR_TERM_REAL = 0x17, 0x55, 0x15, 0x0B
NR_WRITE_DECOY, NR_CREATE_DECOY, NR_CLOSE_DECOY, NR_TERM_DECOY = 0x5C, 0x63, 0x77, 0x99

# Parked in R15 before the wrapper call: the beacon saves every callee-saved
# reg the host could observe, so it must survive the whole export call.
SENTINEL_R15 = 0x2222222222222222
JUNK_RAX = 0xDEADBEEFCAFEF00D  # clobbered before each export call

# The header's preferred ImageBase, plus an ASLR'd load 0x10000000 away.
IMAGES = (0x180000000, 0x190000000)

# fake Windows environment (same fixture addresses as test_append_windows.py)
PEB_ADDR   = 0x2000
LDR_ADDR   = 0x3000
LDR_ENTRY  = 0x4000
NAME_ADDR  = 0x5000
PARAMS     = 0x6000
NTDLL_BASE = 0x100000
STACK      = 0x600000
STACK_SZ   = 0x20000
STDOUT_HDL = 0x12345678
FILE_HDL   = 0x55550000     # fake handle the create-hook writes to [rcx]

# The exact on-disk artifact the beacon must leave (the "runs no matter what"
# receipt). The create-hook walks the ObjectAttributes and decodes this from
# the live Unicorn memory, so a typo in the beacon's path string is a failure.
ARTIFACT_NAME = "sleepmask_beacon.txt"

COFF_CHARS_DLL      = 0x2022   # as in real signed x64 DLLs (wslcsdk, _nvngx)
DLL_CHARACTERISTICS = 0x4160   # as in real signed x64 DLLs
IMAGE_BASE_PREF     = 0x180000000
SUBSYSTEM_CONSOLE   = 3


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


def align_up(x, a):
    return ((x + a - 1) // a) * a


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def static_check(dll: bytes, beacon: bytes) -> list:
    p = []

    def chk(label, ok, detail=""):
        if not ok:
            p.append(f"{label}: {detail}")

    chk("MZ", dll[0:2] == b"MZ", f"got {dll[0:2]!r}")
    lfanew = u32(dll, 0x3C)
    coff = lfanew + 4
    opt, sect_off, nsect = sect_table(dll)
    chk("one section", nsect == 1, f"got {nsect}")

    # --- headers: the real-signed-DLL flags --------------------------------
    coff_chars = u16(dll, coff + 18)
    chk("COFF chars (DLL|EXECUTABLE)", coff_chars == COFF_CHARS_DLL, f"got {coff_chars:#x}")
    chk("PE32+ magic", u16(dll, opt) == 0x20B, f"got {u16(dll, opt):#x}")
    chk("ImageBase", u64(dll, opt + 0x18) == IMAGE_BASE_PREF, f"got {u64(dll, opt + 0x18):#x}")
    chk("Subsystem (CUI)", u16(dll, opt + 0x44) == SUBSYSTEM_CONSOLE, f"got {u16(dll, opt + 0x44)}")
    chk("DllCharacteristics", u16(dll, opt + 0x46) == DLL_CHARACTERISTICS,
        f"got {u16(dll, opt + 0x46):#x}")

    # --- the single .text section: RWX at 0x1000 ---------------------------
    name = dll[sect_off:sect_off + 8]
    chk(".text name", name == b".text\0\0\0", f"got {name!r}")
    vsize, vaddr = u32(dll, sect_off + 8), u32(dll, sect_off + 0xC)
    rawsize, rawptr = u32(dll, sect_off + 0x10), u32(dll, sect_off + 0x14)
    chars = u32(dll, sect_off + 0x24)
    chk(".text CODE|EXECUTE", chars & 0xC0000000 == 0xC0000000, f"got {chars:#x}")
    chk(".text WRITE", chars & 0x20 != 0, f"got {chars:#x}")
    chk(".text vaddr", vaddr == 0x1000, f"got {vaddr:#x}")

    # --- data directories: only [0] (exports) may be non-zero --------------
    ed_rva, ed_sz = u32(dll, opt + 0x70), u32(dll, opt + 0x74)
    chk("DataDir[0] (exports) present", ed_rva != 0 and ed_sz == 40,
        f"got ({ed_rva:#x}, {ed_sz})")
    for i in range(1, 16):
        r, sz = u32(dll, opt + 0x70 + 8 * i), u32(dll, opt + 0x70 + 8 * i + 4)
        chk(f"DataDir[{i}] zero (no imports/reloc/etc)", r == 0 and sz == 0,
            f"got ({r:#x}, {sz})")

    # --- file offsets of the .text payload (rawptr + in-text offset) --------
    off_beacon = rawptr                                   # beacon at .text start
    off_wrapper = align_up(off_beacon + len(beacon), 8)   # 9 B wrapper
    off_dllmain = align_up(off_wrapper + 9, 8)            # 6 B DllMain
    blob_at = dll[off_beacon:off_beacon + len(beacon)]
    chk("beacon byte-identical", blob_at == beacon,
        f"first diff at {next((i for i in range(len(beacon)) if blob_at[i] != beacon[i]), '?')}")

    # --- the two fixed code fragments ---------------------------------------
    rel32 = off_beacon - (off_wrapper + 5)                # call beacon (displacement)
    want_wrapper = struct.pack("<B i", 0xE8, rel32) + b"\x48\x31\xC0\xC3"
    chk("wrapper (call beacon; xor rax,rax; ret)",
        dll[off_wrapper:off_wrapper + 9] == want_wrapper,
        f"got {dll[off_wrapper:off_wrapper + 9].hex()} "
        f"want {want_wrapper.hex()}")
    want_dllmain = b"\xB8\x01\x00\x00\x00\xC3"
    chk("DllMain (mov eax,1; ret)",
        dll[off_dllmain:off_dllmain + 6] == want_dllmain,
        f"got {dll[off_dllmain:off_dllmain + 6].hex()}")

    # RVA = 0x1000 + (file offset - rawptr); the in-text offset is off - rawptr
    rva_dllmain = 0x1000 + (off_dllmain - rawptr)
    rva_wrapper = 0x1000 + (off_wrapper - rawptr)

    off_unreg = align_up(off_dllmain + 6, 8)        # 4 B: xor rax,rax ; ret
    want_unreg = b"\x48\x31\xC0\xC3"
    chk("DllUnregisterServer (xor rax,rax; ret)",
        dll[off_unreg:off_unreg + 4] == want_unreg,
        f"got {dll[off_unreg:off_unreg + 4].hex()}")
    rva_unreg = 0x1000 + (off_unreg - rawptr)

    # --- the export table, via the independent reader -----------------------
    exports = pe_exports(dll)
    chk("three exports", len(exports) == 3, f"got {len(exports)}")
    if len(exports) == 3:
        e_main, e_wrap, e_unreg = exports
        chk("export[0] name DllMain", e_main["name"] == "DllMain", f"got {e_main['name']!r}")
        chk("export[0] ordinal (base 1)", e_main["ordinal"] == 1, f"got {e_main['ordinal']}")
        chk("export[0] imm32 == 1", e_main["imm32"] == 1, f"got {e_main['imm32']!r}")
        chk("export[1] name DllRegisterServer",
            e_wrap["name"] == "DllRegisterServer", f"got {e_wrap['name']!r}")
        chk("export[1] ordinal", e_wrap["ordinal"] == 2, f"got {e_wrap['ordinal']}")
        chk("export[1] not a mov-eax stub (is the wrapper)",
            e_wrap["imm32"] is None, f"got {e_wrap['imm32']!r}")
        chk("export[2] name DllUnregisterServer",
            e_unreg["name"] == "DllUnregisterServer", f"got {e_unreg['name']!r}")
        chk("export[2] ordinal", e_unreg["ordinal"] == 3, f"got {e_unreg['ordinal']}")
        chk("export[2] not a mov-eax stub (is the S_OK stub)",
            e_unreg["imm32"] is None, f"got {e_unreg['imm32']!r}")
        chk("DllMain rva", e_main["rva"] == rva_dllmain,
            f"got {e_main['rva']:#x} want {rva_dllmain:#x}")
        chk("wrapper rva", e_wrap["rva"] == rva_wrapper,
            f"got {e_wrap['rva']:#x} want {rva_wrapper:#x}")
        chk("unreg rva", e_unreg["rva"] == rva_unreg,
            f"got {e_unreg['rva']:#x} want {rva_unreg:#x}")
        entry = u32(dll, opt + 0x10)
        chk("entry == DllMain", entry == e_main["rva"],
            f"entry {entry:#x} != DllMain {e_main['rva']:#x}")

    # --- the export Name string is the file name ----------------------------
    ed = rva_to_file_offset(dll, ed_rva)
    name_rva = u32(dll, ed + 0x0C)
    noff = rva_to_file_offset(dll, name_rva)
    chk("export Name == payload.dll", dll[noff:noff + 12] == b"payload.dll\0",
        f"got {dll[noff:noff + 12]!r}")

    return p


def build_env(uc, nr_write, nr_create, nr_close, nr_term):
    w = uc.mem_write
    q = "<Q"
    # PEB / Ldr chain
    w(0x60, struct.pack(q, PEB_ADDR))
    w(PEB_ADDR + 0x18, struct.pack(q, LDR_ADDR))     # PEB->Ldr
    w(PEB_ADDR + 0x20, struct.pack(q, PARAMS))       # PEB->Params
    w(PARAMS + 0x28, struct.pack(q, STDOUT_HDL))     # StandardOutput
    w(LDR_ADDR + 0x10, struct.pack(q, LDR_ENTRY))    # InLoadOrder head
    w(LDR_ENTRY + 0x00, struct.pack(q, LDR_ADDR + 0x10))  # Flink (circular)
    w(LDR_ENTRY + 0x30, struct.pack(q, NTDLL_BASE))  # DllBase
    w(LDR_ENTRY + 0x58, struct.pack("<HH", 18, 20))  # BaseDllName {Length,MaxLength}
    w(LDR_ENTRY + 0x60, struct.pack(q, NAME_ADDR))   # BaseDllName.Buffer
    w(NAME_ADDR, "ntdll.dll".encode("utf-16-le"))

    # fake ntdll PE (4 exports: the beacon resolves all four by name)
    w(NTDLL_BASE + 0x3C, struct.pack("<I", 0x100))   # e_lfanew
    w(NTDLL_BASE + 0x100, b"PE\0\0")
    opt = NTDLL_BASE + 0x100 + 0x18
    w(opt, struct.pack("<H", 0x20B))
    w(opt + 0x70, struct.pack("<I", 0x200))          # ExportDir.RVA
    edir = NTDLL_BASE + 0x200
    w(edir + 0x14, struct.pack("<I", 4))             # NumberOfFunctions
    w(edir + 0x18, struct.pack("<I", 4))             # NumberOfNames
    w(edir + 0x1C, struct.pack("<I", 0x300))         # EAT
    w(edir + 0x20, struct.pack("<I", 0x380))         # ENT
    w(edir + 0x24, struct.pack("<I", 0x400))         # ORD
    w(NTDLL_BASE + 0x300 + 4 * 0, struct.pack("<I", 0x1000))  # EAT[0]
    w(NTDLL_BASE + 0x300 + 4 * 1, struct.pack("<I", 0x1100))  # EAT[1]
    w(NTDLL_BASE + 0x300 + 4 * 2, struct.pack("<I", 0x1200))  # EAT[2]
    w(NTDLL_BASE + 0x300 + 4 * 3, struct.pack("<I", 0x1300))  # EAT[3]
    w(NTDLL_BASE + 0x380 + 4 * 0, struct.pack("<I", 0x500))   # ENT[0]
    w(NTDLL_BASE + 0x380 + 4 * 1, struct.pack("<I", 0x580))   # ENT[1]
    w(NTDLL_BASE + 0x380 + 4 * 2, struct.pack("<I", 0x600))   # ENT[2]
    w(NTDLL_BASE + 0x380 + 4 * 3, struct.pack("<I", 0x680))   # ENT[3]
    w(NTDLL_BASE + 0x400 + 2 * 0, struct.pack("<H", 0))       # ORD[0]
    w(NTDLL_BASE + 0x400 + 2 * 1, struct.pack("<H", 1))       # ORD[1]
    w(NTDLL_BASE + 0x400 + 2 * 2, struct.pack("<H", 2))       # ORD[2]
    w(NTDLL_BASE + 0x400 + 2 * 3, struct.pack("<H", 3))       # ORD[3]
    w(NTDLL_BASE + 0x500, b"NtWriteFile\0")
    w(NTDLL_BASE + 0x580, b"NtCreateFile\0")
    w(NTDLL_BASE + 0x600, b"NtClose\0")
    w(NTDLL_BASE + 0x680, b"NtTerminateProcess\0")
    # thunks: B8 <nr> 00 00 00 0F 05 C3 (nr is read, not hard-coded)
    w(NTDLL_BASE + 0x1000, bytes((0xB8, nr_write, 0, 0, 0, 0x0F, 0x05, 0xC3)))
    w(NTDLL_BASE + 0x1100, bytes((0xB8, nr_create, 0, 0, 0, 0x0F, 0x05, 0xC3)))
    w(NTDLL_BASE + 0x1200, bytes((0xB8, nr_close, 0, 0, 0, 0x0F, 0x05, 0xC3)))
    w(NTDLL_BASE + 0x1300, bytes((0xB8, nr_term, 0, 0, 0, 0x0F, 0x05, 0xC3)))


def read_file_name(uc_, oa_ptr):
    """NtCreateFile's ObjectAttributes (r8) -> UNICODE_STRING -> UTF-16 name.

    OBJECT_ATTRIBUTES: +0x10 = ObjectName (ptr to UNICODE_STRING).
    UNICODE_STRING: +0x00 = Length (bytes), +0x08 = Buffer (ptr, UTF-16LE).
    Returns the decoded name, or None if any pointer is null.
    """
    if not oa_ptr:
        return None
    us_ptr = struct.unpack("<Q", bytes(uc_.mem_read(oa_ptr + 0x10, 8)))[0]
    if not us_ptr:
        return None
    us_len = struct.unpack("<H", bytes(uc_.mem_read(us_ptr, 2)))[0]
    us_buf = struct.unpack("<Q", bytes(uc_.mem_read(us_ptr + 8, 8)))[0]
    if not us_buf or not us_len:
        return None
    return bytes(uc_.mem_read(us_buf, us_len)).decode("utf-16-le", "replace")


def make_hook(nr_write, nr_create, nr_close, writes):
    """CODE hook: trap the `syscall` the fake ntdll thunks execute.

    `writes` collects tagged activity: ("write", handle, bytes) for the two
    NtWriteFile calls, ("create", filename) for NtCreateFile (the hook writes
    FILE_HDL to [rcx] so the beacon's handle test passes, and decodes the
    target path from r8's ObjectAttributes to prove the artifact name),
    ("close", handle), and ("other", nr) for anything unexpected.
    """

    def on_code(uc_, rip, size, _):
        if bytes(uc_.mem_read(rip, 2)) != b"\x0F\x05":
            return
        nr = uc_.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        rsp = uc_.reg_read(UC_X86_REG_RSP)
        rcx = uc_.reg_read(UC_X86_REG_RCX)
        if nr == nr_write:
            buf = struct.unpack("<Q", bytes(uc_.mem_read(rsp + 0x28, 8)))[0]
            ln = struct.unpack("<I", bytes(uc_.mem_read(rsp + 0x30, 4)))[0]
            writes.append(("write", rcx, bytes(uc_.mem_read(buf, ln))))
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        elif nr == nr_create:
            oa = uc_.reg_read(UC_X86_REG_R8)                 # r8 = ObjectAttributes
            uc_.mem_write(rcx, struct.pack("<Q", FILE_HDL))   # rcx = &fh_out
            writes.append(("create", read_file_name(uc_, oa)))
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        elif nr == nr_close:
            writes.append(("close", rcx))
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        else:
            # NtTerminateProcess or anything else: success, advance past it.
            writes.append(("other", nr))
            uc_.reg_write(UC_X86_REG_RAX, 0)
            uc_.reg_write(UC_X86_REG_RIP, rip + 2)

    return on_code


def load_dll(uc, data, base):
    """Map the .text raw data at `base`; return (entry_rva, rva_main, rva_wrap)."""
    opt, sect_off, nsect = sect_table(data)
    entry = u32(data, opt + 0x10)
    vaddr = u32(data, sect_off + 0xC)
    rawsize = u32(data, sect_off + 0x10)
    rawptr = u32(data, sect_off + 0x14)
    uc.mem_map(base, 0x100000)
    uc.mem_write(base + vaddr, data[rawptr:rawptr + rawsize])
    exports = pe_exports(data)
    rva_main = next(e["rva"] for e in exports if e["name"] == "DllMain")
    rva_wrap = next(e["rva"] for e in exports if e["name"] == "DllRegisterServer")
    return entry, rva_main, rva_wrap


def call_export(uc, func_va, rsp, ret_addr):
    """`call` the function at func_va with a return slot at [rsp]; return RAX."""
    uc.mem_write(rsp, struct.pack("<Q", ret_addr))
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RAX, JUNK_RAX)
    uc.reg_write(UC_X86_REG_RIP, func_va)
    uc.emu_start(func_va, until=ret_addr, count=20_000_000)
    if uc.reg_read(UC_X86_REG_RIP) != ret_addr:
        raise RuntimeError(f"RIP {uc.reg_read(UC_X86_REG_RIP):#x} != ret {ret_addr:#x}")
    return uc.reg_read(UC_X86_REG_RAX)


def run_image(base, nr_write, nr_create, nr_close, nr_term, dll: bytes) -> list:
    p = []
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, 0x100000)
    uc.mem_map(NTDLL_BASE, 0x100000)
    uc.mem_map(STACK, STACK_SZ)
    uc.reg_write(UC_X86_REG_GS_BASE, 0)
    build_env(uc, nr_write, nr_create, nr_close, nr_term)

    writes = []
    uc.hook_add(UC_HOOK_CODE, make_hook(nr_write, nr_create, nr_close, writes))

    entry, rva_main, rva_wrap = load_dll(uc, dll, base)
    if entry != rva_main:
        p.append(f"entry {entry:#x} != DllMain {rva_main:#x}")

    uc.reg_write(UC_X86_REG_R15, SENTINEL_R15)
    ret_addr = STACK + 0x8000

    # --- LoadLibrary step: the loader calls DllMain ------------------------
    rax_main = call_export(uc, base + rva_main, STACK + 0x100, ret_addr)
    if rax_main != 1:
        p.append(f"DllMain RAX {rax_main:#x} != 1 (TRUE)")
    if writes:
        p.append(f"DllMain wrote something: {writes!r}")

    # --- GetProcAddress("DllRegisterServer") + call ------------------------
    rax_wrap = call_export(uc, base + rva_wrap, STACK + 0x300, ret_addr)
    r15 = uc.reg_read(UC_X86_REG_R15)

    stdout_writes = [w for w in writes if w[0] == "write" and w[1] == STDOUT_HDL]
    file_writes   = [w for w in writes if w[0] == "write" and w[1] == FILE_HDL]
    creates       = [w for w in writes if w[0] == "create"]
    closes        = [w for w in writes if w[0] == "close"]
    other         = [w for w in writes if w[0] not in ("write", "create", "close")]
    if other:
        p.append(f"unexpected syscall activity: {other!r}")
    if len(stdout_writes) != 1:
        p.append(f"expected 1 stdout beacon write, got {len(stdout_writes)}")
    elif stdout_writes[0][2] != BEACON_MSG:
        p.append(f"stdout beacon write wrong: {stdout_writes[0][2]!r}")
    if len(file_writes) != 1:
        p.append(f"expected 1 file beacon write, got {len(file_writes)}")
    elif file_writes[0][2] != BEACON_MSG:
        p.append(f"file beacon write wrong: {file_writes[0][2]!r}")
    if len(creates) != 1:
        p.append(f"expected 1 NtCreateFile, got {len(creates)}")
    elif creates[0][1] != ARTIFACT_NAME:
        p.append(f"artifact filename wrong: {creates[0][1]!r} != {ARTIFACT_NAME!r}")
    if len(closes) != 1:
        p.append(f"expected 1 NtClose, got {len(closes)}")
    if rax_wrap != 0:
        p.append(f"DllRegisterServer RAX {rax_wrap:#x} != 0 (S_OK)")
    if r15 != SENTINEL_R15:
        p.append(f"R15 clobbered: {r15:#x} != {SENTINEL_R15:#x}")
    return p


def main() -> int:
    if not BEACON_BIN.exists():
        print("FAIL: missing build/beacon_windows.bin — run build.sh first")
        return 2

    beacon = BEACON_BIN.read_bytes()
    dll = make_dll(beacon)
    DLL_OUT.write_bytes(dll)

    # --- 1. static structure ------------------------------------------------
    problems = static_check(dll, beacon)
    for pr in problems:
        print(f"STATIC FAIL: {pr}")
    if problems:
        print("FAIL")
        return 1
    print("static:   RWX .text; beacon byte-identical; wrapper=call+xor+ret; "
          "DllMain=mov eax,1;ret; unreg=xor rax,rax;ret; 3 exports, ordinal "
          "base 1; only DataDir[0] set")

    # --- 2. dynamic: two bases x {real, decoy} syscall numbers -------------
    all_problems = []
    for base in IMAGES:
        for label, nw, nc, ncl, nt in (
                ("real", NR_WRITE_REAL, NR_CREATE_REAL, NR_CLOSE_REAL, NR_TERM_REAL),
                ("decoy", NR_WRITE_DECOY, NR_CREATE_DECOY, NR_CLOSE_DECOY,
                 NR_TERM_DECOY)):
            probs = run_image(base, nw, nc, ncl, nt, dll)
            print(f"[{base:#x} {label}] ok" if not probs else
                  f"[{base:#x} {label}] " + "; ".join(probs))
            all_problems += [f"[{base:#x} {label}] {pr}" for pr in probs]

    for pr in all_problems:
        print(f"RUN FAIL: {pr}")
    if all_problems:
        print("FAIL")
        return 1
    print("PASS (dll: DllMain->TRUE; DllRegisterServer->S_OK + beacon to "
          "stdout AND sleepmask_beacon.txt (create/write/close); R15 preserved; "
          "2 bases x real + decoy nr)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
