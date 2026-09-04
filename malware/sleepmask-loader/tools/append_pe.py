#!/usr/bin/env python3
"""append_pe.py — add a PIC x86-64 function to a host PE32+ executable.

Given a PE32+ x86-64 executable and a position-independent function blob,
rebuild the image with its original sections packed contiguously and add a
new executable section containing:

    E8 05 00 00 00     call +5   -> the blob (10 bytes further on)
    E9 xx xx xx xx     jmp       -> the original entry point

The new section RVA becomes AddressOfEntryPoint. The blob must save and
restore every general register and return; execution then continues at the
host's original entry point. Original section contents and RVAs are retained.

Usage: append_pe.py <host.exe> <blob.bin> <out.exe>
Exit 0 on success, 2 on a rejected input.
"""

import struct
import sys
from pathlib import Path


MACHINE_X86_64 = 0x8664
OPT_MAGIC_PE32P = 0x020B
SECT_CODE = 0x20
SECT_MEM_EXECUTE = 0x20000000
SECT_MEM_READ = 0x40000000
SECT_MEM_WRITE = 0x80000000
SECTION_HEADER_SIZE = 40


def fail(msg: str) -> None:
    print(f"append_pe: {msg}", file=sys.stderr)
    sys.exit(2)


def align_up(x: int, alignment: int) -> int:
    return ((x + alignment - 1) // alignment) * alignment


def main() -> int:
    if len(sys.argv) != 4:
        fail("usage: append_pe.py <host.exe> <blob.bin> <out.exe>")

    try:
        host = Path(sys.argv[1]).read_bytes()
        blob = Path(sys.argv[2]).read_bytes()
    except OSError as exc:
        fail(str(exc))

    if len(host) < 0x40:
        fail("host is too short for a DOS header")
    e_lfanew = struct.unpack_from("<I", host, 0x3C)[0]
    if e_lfanew + 24 > len(host):
        fail("PE signature or COFF header runs past EOF")
    if host[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        fail("host is not a PE image")

    coff0 = e_lfanew + 4
    machine, nsections = struct.unpack_from("<HH", host, coff0)
    optsize = struct.unpack_from("<H", host, coff0 + 16)[0]
    if machine != MACHINE_X86_64:
        fail("host must be x86-64")
    if nsections == 0xFFFF:
        fail("section count cannot be incremented")

    opt0 = e_lfanew + 4 + 20
    if optsize < 0x40 or opt0 + optsize > len(host):
        fail("optional header is truncated or too short")
    if struct.unpack_from("<H", host, opt0)[0] != OPT_MAGIC_PE32P:
        fail("host must be PE32+")

    orig_entry_rva = struct.unpack_from("<I", host, opt0 + 0x10)[0]
    sect_align = struct.unpack_from("<I", host, opt0 + 0x20)[0]
    file_align = struct.unpack_from("<I", host, opt0 + 0x24)[0]
    if sect_align == 0 or file_align == 0:
        fail("section and file alignments must be nonzero")

    sec0 = opt0 + optsize
    table_end = sec0 + nsections * SECTION_HEADER_SIZE
    if table_end > len(host):
        fail("section table runs past EOF")

    sections = []
    hi = 0
    for i in range(nsections):
        offset = sec0 + i * SECTION_HEADER_SIZE
        section = host[offset:offset + SECTION_HEADER_SIZE]
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", section, 8)
        if raw_ptr + raw_size > len(host):
            fail(f"section {i} raw data runs past EOF")
        if vaddr + vsize > 0xFFFFFFFF:
            fail(f"section {i} virtual extent exceeds the PE32+ RVA range")
        hi = max(hi, vaddr + vsize)
        sections.append((section, raw_size, raw_ptr))

    V = align_up(hi, sect_align)
    if V < sect_align:
        V = sect_align
    if V > 0xFFFFFFFF:
        fail("new section RVA exceeds the PE32+ RVA range")

    disp = orig_entry_rva - (V + 10)
    if not (-0x80000000 <= disp < 0x80000000):
        fail(f"original entry RVA 0x{orig_entry_rva:x} is out of stub reach")
    stub = b"\xE8\x05\x00\x00\x00\xE9" + struct.pack("<i", disp)
    payload = stub + blob
    new_vsize = len(payload)
    if new_vsize > 0xFFFFFFFF or V + new_vsize > 0xFFFFFFFF:
        fail("new section exceeds the PE32+ RVA range")
    new_raw = payload + b"\x00" * ((-len(payload)) % file_align)
    if len(new_raw) > 0xFFFFFFFF:
        fail("new section raw data exceeds the PE32+ field range")

    new_image_size = align_up(max(hi, V + new_vsize), sect_align)
    if new_image_size > 0xFFFFFFFF:
        fail("SizeOfImage exceeds the PE32+ field range")

    new_n = nsections + 1
    header_len = e_lfanew + 4 + 20 + optsize + new_n * SECTION_HEADER_SIZE
    header_padded = align_up(header_len, file_align)
    if header_padded > 0xFFFFFFFF:
        fail("rebuilt headers exceed the PE32+ file-offset range")

    raw_ptrs = []
    rp = header_padded
    for _section, raw_size, _raw_ptr in sections:
        raw_ptrs.append(rp)
        rp += align_up(raw_size, file_align)
        if rp > 0xFFFFFFFF:
            fail("rebuilt section data exceeds the PE32+ file-offset range")
    bcon_rawptr = rp

    hdr = bytearray(host[0:e_lfanew])
    hdr += host[e_lfanew:e_lfanew + 4]
    coff = bytearray(host[coff0:coff0 + 20])
    struct.pack_into("<H", coff, 2, new_n)
    hdr += coff
    optb = bytearray(host[opt0:opt0 + optsize])
    struct.pack_into("<I", optb, 0x10, V)
    struct.pack_into("<I", optb, 0x38, new_image_size)
    struct.pack_into("<I", optb, 0x3C, header_padded)
    hdr += optb
    for i, (section, _raw_size, _raw_ptr) in enumerate(sections):
        sb = bytearray(section)
        struct.pack_into("<I", sb, 20, raw_ptrs[i])
        hdr += sb
    hdr += struct.pack(
        "8sIIIIIIHHI",
        b".bcon\x00\x00",
        new_vsize,
        V,
        len(new_raw),
        bcon_rawptr,
        0,
        0,
        0,
        0,
        SECT_CODE | SECT_MEM_EXECUTE | SECT_MEM_READ | SECT_MEM_WRITE,
    )
    assert len(hdr) == header_len

    out = bytearray(header_padded)
    out[0:header_len] = hdr
    for section, raw_size, raw_ptr in sections:
        chunk = host[raw_ptr:raw_ptr + raw_size]
        out += chunk
        out += b"\x00" * (align_up(len(chunk), file_align) - len(chunk))
    out += new_raw

    out_path = Path(sys.argv[3])
    try:
        out_path.write_bytes(bytes(out))
    except OSError as exc:
        fail(str(exc))
    print(f"appended: .bcon RVA 0x{V:x}, raw 0x{bcon_rawptr:x} "
          f"(stub 10 B, blob {len(blob)} B, section {len(new_raw)} B)")
    print(f"entry:    RVA 0x{orig_entry_rva:x} -> 0x{V:x} "
          f"(call blob, jmp old entry)")
    print(f"image:    {new_n} sections, headers {header_padded} B, "
          f"SizeOfImage 0x{new_image_size:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
