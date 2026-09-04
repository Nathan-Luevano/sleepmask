def u16_le(data: bytes, off: int) -> int:
    """Return the 16-bit little-endian unsigned integer at offset off."""
    return int.from_bytes(data[off:off + 2], "little")


def u32_le(data: bytes, off: int) -> int:
    """Return the 32-bit little-endian unsigned integer at offset off."""
    return int.from_bytes(data[off:off + 4], "little")


def extract_imm32_after_b8(data: bytes) -> int | None:
    """Return the imm32 following an initial B8 opcode when enough data exists."""
    if len(data) >= 6 and data[0] == 0xB8:
        return u32_le(data, 1)
    return None


def rva_to_file_offset(data: bytes, rva: int) -> int:
    """Convert a PE relative virtual address to its file offset."""
    if data[0:2] != b"MZ":
        raise ValueError

    e_lfanew = u32_le(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError

    coff = e_lfanew + 4
    nsections = u16_le(data, coff + 2)
    sizeofopt = u16_le(data, coff + 16)
    section_table = coff + 20 + sizeofopt

    for i in range(nsections):
        base = section_table + i * 40
        virtual_address = u32_le(data, base + 0xC)
        virtual_size = u32_le(data, base + 0x8)
        pointer_to_raw = u32_le(data, base + 0x14)
        raw_size = u32_le(data, base + 0x10)
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return pointer_to_raw + (rva - virtual_address)

    raise ValueError
