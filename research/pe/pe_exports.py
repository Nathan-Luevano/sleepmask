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
