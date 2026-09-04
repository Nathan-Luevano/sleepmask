#!/usr/bin/env python3
"""append_macho.py — add a PIC x86-64 function to a host Mach-O executable.

Given a 64-bit Mach-O x86-64 executable and a position-independent function
blob, rebuild the image adding a new `__bcon` section to the __TEXT segment
containing:

    E8 05 00 00 00     call +5   -> the blob (10 bytes further on)
    E9 xx xx xx xx     jmp       -> the original entry point

LC_MAIN.entryoff is re-pointed at the new section. The blob must save and
restore every general register and return; execution then continues at the
host's original entry point. Original sections keep their virtual addresses
and file offsets; only the __TEXT segment command is grown (one section) and
LC_MAIN re-pointed.

Usage: append_macho.py <host.macho> <blob.bin> <out.macho>
Exit 0 on success, 2 on a rejected input.
"""

import struct
import sys
from pathlib import Path


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
LC_SEGMENT_64 = 0x80000027
LC_MAIN = 0x80000028

PAGE = 0x1000
SECT_SIZE = 80
SEG_HDR_SIZE = 72
MAIN_SIZE = 24
SECT_FLAGS_INSTRUC = 0x80


def fail(msg: str) -> None:
    print(f"append_macho: {msg}", file=sys.stderr)
    sys.exit(2)


def align_up(x: int, a: int) -> int:
    return ((x + a - 1) // a) * a


def cstr(b: bytes, off: int, n: int = 16) -> bytes:
    raw = b[off:off + n]
    return raw[: raw.find(b"\0")]


def main() -> int:
    if len(sys.argv) != 4:
        fail("usage: append_macho.py <host.macho> <blob.bin> <out.macho>")

    try:
        host = Path(sys.argv[1]).read_bytes()
        blob = Path(sys.argv[2]).read_bytes()
    except OSError as exc:
        fail(str(exc))

    if len(host) < 32:
        fail("host is too short for a mach_header_64")
    magic, cputype, cpusubtype, filetype = struct.unpack_from("<IIII", host, 0)
    if magic != MH_MAGIC_64:
        fail("host must be a 64-bit Mach-O")
    if cputype != CPU_TYPE_X86_64:
        fail("host must be x86-64")
    ncmds, sizeofcmds, mflags, mres = struct.unpack_from("<IIII", host, 16)

    # --- walk load commands ------------------------------------------------
    cmds = []  # (cmd, cmdsize, offset)
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(host):
            fail("load command table runs past EOF")
        cmd, cmdsize = struct.unpack_from("<II", host, off)
        if cmdsize < 8 or off + cmdsize > len(host):
            fail("load command size is invalid")
        cmds.append((cmd, cmdsize, off))
        off += cmdsize

    seg_idx = None
    main_idx = None
    for i, (cmd, _cs, coff) in enumerate(cmds):
        if cmd == LC_SEGMENT_64 and cstr(host, coff + 8) == b"__TEXT":
            seg_idx = i
        if cmd == LC_MAIN:
            main_idx = i
    if seg_idx is None:
        fail("host has no __TEXT LC_SEGMENT_64")
    if main_idx is None:
        fail("host has no LC_MAIN")

    _sc, _ss, soff = cmds[seg_idx]
    seg_vmaddr, seg_vmsize, seg_fileoff, seg_filesize = struct.unpack_from(
        "<QQQQ", host, soff + 0x18)
    maxprot, initprot, nsects, segflags = struct.unpack_from(
        "<iiII", host, soff + 0x38)

    sects = []  # (name, addr, size, offset, flags)
    for i in range(nsects):
        s = soff + SEG_HDR_SIZE + i * SECT_SIZE
        if s + SECT_SIZE > len(host):
            fail("section table runs past EOF")
        name = cstr(host, s)
        addr, size = struct.unpack_from("<QQ", host, s + 0x20)
        offset = struct.unpack_from("<I", host, s + 0x30)[0]
        flags = struct.unpack_from("<I", host, s + 0x40)[0]
        if name == b"__bcon":
            fail("host already has a __bcon section")
        sects.append((name, addr, size, offset, flags))

    _mc, _ms, moff = cmds[main_idx]
    orig_entryoff, stacksize = struct.unpack_from("<QQ", host, moff + 8)
    orig_entry = orig_entryoff + seg_vmaddr

    # --- place the new section: virtually after every existing one ---------
    hi = max([seg_vmaddr] + [a + s for (_n, a, s, _o, _f) in sects])
    V = align_up(hi, PAGE)
    if V < seg_vmaddr + PAGE:
        V = seg_vmaddr + PAGE

    disp = orig_entry - (V + 10)
    if not (-0x80000000 <= disp < 0x80000000):
        fail(f"original entry 0x{orig_entry:x} is out of stub reach")
    payload = b"\xE8\x05\x00\x00\x00\xE9" + struct.pack("<i", disp) + blob
    new_size = len(payload)
    if V + new_size > 0xFFFFFFFFFFFF:
        fail("new section exceeds the Mach-O address range")

    # disk offset for __bcon: first page after every existing section's data
    content_end = max([32 + sizeofcmds] + [o + s for (_n, _a, s, o, _f) in sects])
    bcon_off = align_up(content_end, PAGE)

    new_vmsize = align_up(V + new_size, PAGE) - seg_vmaddr
    new_seg_cmdsize = SEG_HDR_SIZE + (nsects + 1) * SECT_SIZE
    new_sizeofcmds = sizeofcmds + SECT_SIZE
    new_hdr_size = 32 + new_sizeofcmds
    first_sect_off = min([o for (_n, _a, _s, o, _f) in sects] or [bcon_off])
    if new_hdr_size > first_sect_off:
        fail("rebuilt header would overlap the first section")

    # --- rebuild the header: same commands, grown segment, repointed main --
    hdr = bytearray()
    hdr += struct.pack("<IIII", MH_MAGIC_64, cputype, cpusubtype, filetype)
    hdr += struct.pack("<IIII", ncmds, new_sizeofcmds, mflags, mres)
    for i, (cmd, cmdsize, coff) in enumerate(cmds):
        if i == seg_idx:
            hdr += struct.pack("<II16s", LC_SEGMENT_64, new_seg_cmdsize,
                               b"__TEXT".ljust(16, b"\0"))
            hdr += struct.pack("<QQQQ", seg_vmaddr, new_vmsize, seg_fileoff,
                               new_vmsize)
            hdr += struct.pack("<iiII", maxprot, initprot, nsects + 1, segflags)
            for j in range(nsects):
                s = soff + SEG_HDR_SIZE + j * SECT_SIZE
                hdr += host[s:s + SECT_SIZE]
            hdr += struct.pack(
                "<16s16sQQ8I",
                b"__bcon".ljust(16, b"\0"),
                b"__TEXT".ljust(16, b"\0"),
                V, new_size,
                bcon_off, 0, 0, 0,
                SECT_FLAGS_INSTRUC, 0, 0, 0,
            )
        elif i == main_idx:
            hdr += struct.pack("<IIQQ", LC_MAIN, MAIN_SIZE,
                               V - seg_vmaddr, stacksize)
        else:
            hdr += host[coff:coff + cmdsize]
    if len(hdr) != new_hdr_size:
        fail("internal: rebuilt header size mismatch")

    final_size = align_up(bcon_off + new_size, PAGE)
    out = bytearray(final_size)
    out[0:new_hdr_size] = hdr
    for _n, _a, s, o, _f in sects:
        if o + s > len(host):
            fail("original section data runs past EOF")
        out[o:o + s] = host[o:o + s]
    out[bcon_off:bcon_off + new_size] = payload

    try:
        Path(sys.argv[3]).write_bytes(bytes(out))
    except OSError as exc:
        fail(str(exc))
    print(f"appended: __bcon vaddr 0x{V:x}, file 0x{bcon_off:x} "
          f"(stub 10 B, blob {len(blob)} B, section {new_size} B)")
    print(f"entry:    0x{orig_entry:x} -> 0x{V:x} "
          f"(call blob, jmp old entry)")
    print(f"segment:  nsects {nsects} -> {nsects + 1}, "
          f"vmsize 0x{seg_vmsize:x} -> 0x{new_vmsize:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
