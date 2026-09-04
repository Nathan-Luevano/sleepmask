#!/usr/bin/env python3
"""Build a minimal x64 PE DLL with three named exports (test fixture).

Two exports use a 4-instruction syscall stub:
    B8 <imm32 LE>  0F 05  C3        ; mov eax, imm; <0F 05>; ret
The third (FuncThree) shares the leading B8 but is NOT a syscall stub:
    B8 <imm32 LE>  C3 00 00         ; mov eax, imm; ret; pad
Layout is chosen so the single section has VirtualAddress == PointerToRawData
(0x200), which makes RVA -> file offset the identity. That keeps the fixture
tiny while still exercising a correct section-based RVA translation.

Run:  python make_fixture.py     -> writes sample.dll next to this file
"""

import os

EXPORTS = [
    ("FuncOne", bytes.fromhex("B82B0000000F05C3")),
    ("FuncTwo", bytes.fromhex("B85A0000000F05C3")),
    ("FuncThree", bytes.fromhex("B807000000C30000")),
]

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.dll")


def main() -> None:
    n = len(EXPORTS)
    base = 0x200

    # --- compute every file offset up front (RVA == offset here) ---
    ED = base                 # IMAGE_EXPORT_DIRECTORY (40 bytes)
    EAT = ED + 0x28           # AddressOfFunctions (n * 4)
    ENT = EAT + n * 4         # AddressOfNamePointers (n * 4)
    ORD = ENT + n * 4         # AddressOfNameOrdinals (n * 2)
    NAMES = ORD + n * 2       # null-terminated name strings

    name_off, body_off = {}, {}
    p = NAMES
    for name, _ in EXPORTS:
        name_off[name] = p
        p += len(name) + 1
    first_body = (p + 7) & ~7  # 8-byte align the first body
    for i, (name, _) in enumerate(EXPORTS):
        body_off[name] = first_body + i * 8
    end = first_body + n * 8
    vsize = end - base

    img = bytearray(end)  # zero-filled, sized to actual content

    # --- DOS header ---
    img[0:2] = b"MZ"
    img[0x3C:0x40] = (0x80).to_bytes(4, "little")  # e_lfanew

    elf = 0x80
    img[elf:elf + 4] = b"PE\x00\x00"
    coff = elf + 4            # 0x84
    opt = coff + 20           # 0x98
    sect = opt + 0xF0         # 0x188 (PE32+ optional header w/ 16 data dirs)

    # --- COFF header (20 bytes) ---
    img[coff + 0x00:coff + 0x02] = (0x8664).to_bytes(2, "little")  # Machine = x64
    img[coff + 0x02:coff + 0x04] = (n_sections := 1).to_bytes(2, "little")
    img[coff + 0x10:coff + 0x12] = (0xF0).to_bytes(2, "little")    # SizeOfOptionalHeader
    img[coff + 0x12:coff + 0x14] = (0x0002).to_bytes(2, "little")  # Characteristics = DLL

    # --- Optional header (PE32+) ---
    img[opt + 0x00:opt + 0x02] = (0x20B).to_bytes(2, "little")     # Magic PE32+
    img[opt + 0x68:opt + 0x6C] = (0).to_bytes(4, "little")         # LoaderFlags
    img[opt + 0x6C:opt + 0x70] = (16).to_bytes(4, "little")        # NumberOfRvaAndSizes
    # Data directory 0 = exports, at opt + 0x70
    img[opt + 0x70:opt + 0x74] = (ED).to_bytes(4, "little")        # ExportDir RVA
    img[opt + 0x74:opt + 0x78] = (0x28).to_bytes(4, "little")      # ExportDir size

    # --- one section header (40 bytes) ---
    img[sect + 0x00:sect + 0x08] = b".text\0"
    img[sect + 0x08:sect + 0x0C] = (vsize).to_bytes(4, "little")   # VirtualSize
    img[sect + 0x0C:sect + 0x10] = (base).to_bytes(4, "little")    # VirtualAddress
    img[sect + 0x10:sect + 0x14] = (vsize).to_bytes(4, "little")   # SizeOfRawData
    img[sect + 0x14:sect + 0x18] = (base).to_bytes(4, "little")    # PointerToRawData

    # --- IMAGE_EXPORT_DIRECTORY ---
    img[ED + 0x0C:ED + 0x10] = (0).to_bytes(4, "little")           # Name (RVA)
    img[ED + 0x10:ED + 0x14] = (0).to_bytes(4, "little")           # Base ordinal
    img[ED + 0x14:ED + 0x18] = (n).to_bytes(4, "little")           # NumberOfFunctions
    img[ED + 0x18:ED + 0x1C] = (n).to_bytes(4, "little")           # NumberOfNames
    img[ED + 0x1C:ED + 0x20] = (EAT).to_bytes(4, "little")
    img[ED + 0x20:ED + 0x24] = (ENT).to_bytes(4, "little")
    img[ED + 0x24:ED + 0x28] = (ORD).to_bytes(4, "little")

    # --- EAT / ENT / ORD / names / bodies ---
    for i, (name, body) in enumerate(EXPORTS):
        img[EAT + i * 4:EAT + i * 4 + 4] = body_off[name].to_bytes(4, "little")
        img[ENT + i * 4:ENT + i * 4 + 4] = name_off[name].to_bytes(4, "little")
        img[ORD + i * 2:ORD + i * 2 + 2] = (i).to_bytes(2, "little")
        img[name_off[name]:name_off[name] + len(name) + 1] = name.encode() + b"\x00"
        img[body_off[name]:body_off[name] + 8] = body

    with open(OUT, "wb") as f:
        f.write(bytes(img))

    # --- ground truth (what a correct parser must recover) ---
    print("sample.dll written: %d bytes" % len(img))
    print("  layout: ED=0x%03x EAT=0x%03x ENT=0x%03x ORD=0x%03x NAMES=0x%03x" % (ED, EAT, ENT, ORD, NAMES))
    print("  section VA=0x%03x size=0x%02x (RVA==offset identity)" % (base, vsize))
    for name, body in EXPORTS:
        print("  %-10s name@0x%03x  body@0x%03x  body=%s" % (name, name_off[name], body_off[name], body.hex()))


if __name__ == "__main__":
    main()
