#!/usr/bin/env python3
"""mk_pe.py — emit the Windows x64 artifact (PE32+ .exe).

Wraps the assembled PIC shellcode (build/sleepmask.bin) in a minimal but
structurally valid PE32+ executable:

  - DOS stub (0x80 B), e_lfanew = 0x80
  - PE signature + COFF header (x86-64, 1 section, EXECUTABLE|LARGE_ADDRESS)
  - PE32+ optional header: GUI subsystem, ImageBase 0x140000000, zero
    data directories (no IAT, no imports — the blob resolves ntdll at
    runtime from the PEB)
  - one section: .text, RWX (the blob writes its own data slots), holding
    a 9-byte entry trampoline followed by the blob:

      +0x00  E8 04 00 00 00   call +4  (jumps to +9)
      +0x05  F4               pause
      +0x06  90 EB FD         nop; jmp -3   (spin loop: +6 <- +7)
      +0x09  ...the sleepmask blob...

  The loader pushes a return address and jumps to the entry point (the
  trampoline). The `call` turns entry into a function call whose return
  address is the spin loop; the blob's final `ret` (after it has masked
  NtDelayExecution and set done_flag) lands there, and the process sits
  resident — re-entering the mask whenever ntdll calls NtDelayExecution.

usage: mk_pe.py [out.exe]   (default: build/sleepmask.exe)
"""

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
BLOB_PATH = HERE / "build" / "sleepmask.bin"

TRAMPOLINE = b"\xE8\x04\x00\x00\x00" b"\xF4\x90\xEB\xFD"   # 9 bytes

MACHINE_X86_64    = 0x8664
CHAR_EXECUTABLE   = 0x0002
CHAR_LARGE_ADDR   = 0x0040
OPT_MAGIC_PE32P   = 0x020B
SUBSYSTEM_GUI     = 2
SECT_CODE         = 0x20
SECT_MEM_EXECUTE  = 0x20000000
SECT_MEM_READ     = 0x40000000
SECT_MEM_WRITE    = 0x80000000

IMAGE_BASE     = 0x140000000
SECT_ALIGN     = 0x1000
FILE_ALIGN     = 0x200
HDR_SIZE       = 0x200                 # headers padded to FileAlignment
TEXT_RVA       = 0x1000                # = ImageBase-relative offset of .text
TEXT_RAW       = 0x200                 # file offset of .text raw data
TEXT_RAW_SIZE  = 0x600                 # covers 9 + 1267 = 1276 bytes


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


def make_pe(blob: bytes) -> bytes:
    vsize = len(TRAMPOLINE) + len(blob)
    if vsize > TEXT_RAW_SIZE:
        raise ValueError(f"blob too big: {vsize} > {TEXT_RAW_SIZE}")
    image_size = ((TEXT_RVA + vsize + SECT_ALIGN - 1) // SECT_ALIGN) * SECT_ALIGN

    # --- .text raw data: trampoline + blob + zero pad --------------------
    text = bytearray(TEXT_RAW_SIZE)
    text[0:len(TRAMPOLINE)] = TRAMPOLINE
    text[len(TRAMPOLINE):len(TRAMPOLINE) + len(blob)] = blob

    # --- PE signature + COFF header --------------------------------------
    coff = struct.pack(
        "<HHIIIHH",
        MACHINE_X86_64,                 # Machine
        1,                              # NumberOfSections
        0x60000000,                     # TimeDateStamp (deterministic)
        0,                              # PointerToSymbolTable
        0,                              # NumberOfSymbols
        0xF0,                           # SizeOfOptionalHeader (PE32+)
        CHAR_EXECUTABLE | CHAR_LARGE_ADDR,
    )
    assert len(coff) == 20

    # --- PE32+ optional header (0xF0 bytes) ------------------------------
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0x00, OPT_MAGIC_PE32P)
    struct.pack_into("<BB", opt, 0x02, 14, 0)         # linker version
    struct.pack_into("<I", opt, 0x04, TEXT_RAW_SIZE)  # SizeOfCode
    struct.pack_into("<I", opt, 0x10, TEXT_RVA)       # AddressOfEntryPoint
    struct.pack_into("<I", opt, 0x14, TEXT_RVA)       # BaseOfCode
    struct.pack_into("<Q", opt, 0x18, IMAGE_BASE)
    struct.pack_into("<I", opt, 0x20, SECT_ALIGN)
    struct.pack_into("<I", opt, 0x24, FILE_ALIGN)
    struct.pack_into("<H", opt, 0x28, 6)              # OS 6.0
    struct.pack_into("<H", opt, 0x2A, 0)
    struct.pack_into("<H", opt, 0x2C, 0)              # image version
    struct.pack_into("<H", opt, 0x2E, 0)
    struct.pack_into("<H", opt, 0x30, 6)              # subsystem version 6.0
    struct.pack_into("<H", opt, 0x32, 0)
    struct.pack_into("<I", opt, 0x38, image_size)
    struct.pack_into("<I", opt, 0x3C, HDR_SIZE)
    struct.pack_into("<I", opt, 0x40, 0)              # CheckSum (loader fills)
    struct.pack_into("<H", opt, 0x44, SUBSYSTEM_GUI)
    struct.pack_into("<H", opt, 0x46, 0x6000)         # DllCharacteristics
    struct.pack_into("<Q", opt, 0x48, 0x100000)       # stack reserve
    struct.pack_into("<Q", opt, 0x50, 0x1000)         # stack commit
    struct.pack_into("<Q", opt, 0x58, 0x100000)       # heap reserve
    struct.pack_into("<Q", opt, 0x60, 0x1000)         # heap commit
    struct.pack_into("<I", opt, 0x68, 0)              # LoaderFlags
    struct.pack_into("<I", opt, 0x6C, 16)             # NumberOfRvaAndSizes
    # DataDirectories @ 0x70: all 16 zero (no imports, no export, no relocs)

    # --- section header ---------------------------------------------------
    # 8s name, 6xI (vsize, vaddr, rawsize, rawptr, relptr, lnptr),
    # 2xH (nreloc, nline), I characteristics (32-bit, e.g. MEM_WRITE=0x80000000)
    sect = struct.pack(
        "8sIIIIIIHHI",
        b".text\0\0",
        vsize,                          # VirtualSize
        TEXT_RVA,                       # VirtualAddress
        TEXT_RAW_SIZE,                  # SizeOfRawData
        TEXT_RAW,                       # PointerToRawData
        0, 0,                           # no relocations / line numbers
        0, 0,
        SECT_CODE | SECT_MEM_EXECUTE | SECT_MEM_READ | SECT_MEM_WRITE,
    )
    assert len(sect) == 40

    headers = dos_stub() + b"PE\0\0" + coff + bytes(opt) + sect
    assert len(headers) < HDR_SIZE
    headers = headers.ljust(HDR_SIZE, b"\0")
    return headers + bytes(text)


def main() -> None:
    blob = BLOB_PATH.read_bytes()
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "build" / "sleepmask.exe"
    data = make_pe(blob)
    out.write_bytes(data)
    print(f"wrote {out} ({len(data)} bytes); blob {len(blob)} B at file +{TEXT_RAW + len(TRAMPOLINE):#x}, entry RVA {TEXT_RVA:#x}")


if __name__ == "__main__":
    main()
