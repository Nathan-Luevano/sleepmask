#!/usr/bin/env python3
"""mk_macho.py — emit the deployable macOS x86-64 artifact (Mach-O MH_EXECUTE).

Wraps the assembled PIC payload (build/payload_macos.bin) in a minimal but
structurally valid 64-bit Mach-O executable:

  mach_header_64   @0x000  (32 B)  MH_MAGIC_64, x86_64, MH_EXECUTE, 2 cmds
  LC_SEGMENT_64    @0x020  (152 B) __TEXT, vmaddr 0x100000000, 1 section
    section_64     @0x068  (80 B)  __text, addr 0x100001000, at file +0x1000
  LC_MAIN          @0xB8   (24 B)  entryoff 0x1000, stacksize 0x8000
  <pad to 0x1000>
  __text payload   @0x1000 (payload_macos.bin, byte-identical)

The macOS payload is *terminal*: it beacons on fd 1 then exit(0) — no
self-injection, no trampoline, no ntdll. It is PIC (one RIP-relative lea),
so the kernel may map __TEXT at any slide; the test re-runs it at a non-zero
slide to prove the slide tolerance.

usage: mk_macho.py [out.macho]   (default: build/sleepmask_macho)
"""

import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
PAYLOAD_PATH = HERE / "build" / "payload_macos.bin"

# --- mach constants ---------------------------------------------------------
MH_MAGIC_64        = 0xFEEDFACF
CPU_TYPE_X86_64    = 0x01000007
CPU_SUBTYPE_X86_64 = 3
MH_EXECUTE         = 2
LC_SEGMENT_64      = 0x80000027
LC_MAIN            = 0x80000028
SOME_INSTRUCTIONS  = 0x80

SEG_NAME   = b"__TEXT"
SECT_NAME  = b"__text"

TEXT_VMADDR = 0x100000000
TEXT_VMSIZE = 0x2000
TEXT_SECT_OFF = 0x1000                 # file offset of __text payload
HDR_PAD     = 0x1000                   # headers padded to here (payload offset)
STACK_SIZE  = 0x8000


def make_macho(payload: bytes) -> bytes:
    if len(payload) > TEXT_VMSIZE - TEXT_SECT_OFF:
        raise ValueError(f"payload too big: {len(payload)} B")

    sect_size = len(payload)

    # --- LC_MAIN (24 B) -----------------------------------------------------
    lc_main = struct.pack("<IIQQ", LC_MAIN, 24, TEXT_SECT_OFF, STACK_SIZE)
    assert len(lc_main) == 24

    # --- section_64 (80 B): 16s 16s Q Q 8xI ---------------------------------
    section = struct.pack(
        "<16s16sQQ8I",
        SECT_NAME.ljust(16, b"\0"),
        SEG_NAME.ljust(16, b"\0"),
        TEXT_VMADDR + TEXT_SECT_OFF,      # section vaddr
        sect_size,                         # section size
        TEXT_SECT_OFF,                     # file offset
        0,                                 # align
        0,                                 # reloff
        0,                                 # nreloc
        SOME_INSTRUCTIONS,                 # flags
        0, 0, 0,                           # reserved1..3
    )
    assert len(section) == 80

    # --- LC_SEGMENT_64 (72 B) + its section (80 B) = cmdsize 152 ------------
    seg_cmdsize = 72 + 80
    seg = struct.pack(
        "<II16sQQQQ4i",
        LC_SEGMENT_64, seg_cmdsize,
        SEG_NAME.ljust(16, b"\0"),
        TEXT_VMADDR,
        TEXT_VMSIZE,
        0,                                 # fileoff
        TEXT_VMSIZE,                       # filesize
        7,                                 # maxprot rwx
        5,                                 # initprot rx
        1,                                 # nsects
        0,                                 # flags
    )
    assert len(seg) == 72

    sizeofcmds = seg_cmdsize + 24
    header = struct.pack(
        "<8I",
        MH_MAGIC_64, CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64, MH_EXECUTE,
        2,                                  # ncmds
        sizeofcmds,
        0,                                  # flags
        0,                                  # reserved
    )
    assert len(header) == 32

    cmds = seg + section + lc_main
    assert len(cmds) == sizeofcmds

    image = (header + cmds).ljust(HDR_PAD, b"\0")
    image += payload
    return image


def main() -> None:
    payload = PAYLOAD_PATH.read_bytes()
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "build" / "sleepmask_macho"
    data = make_macho(payload)
    out.write_bytes(data)
    print(
        f"wrote {out} ({len(data)} bytes); payload {len(payload)} B at file +{TEXT_SECT_OFF:#x}, "
        f"entry vaddr 0x{TEXT_VMADDR + TEXT_SECT_OFF:X}"
    )


if __name__ == "__main__":
    main()
