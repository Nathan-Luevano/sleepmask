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


def pe_exports(data: bytes) -> list:
    """Return named PE exports in name-table order."""
    if data[0:2] != b"MZ":
        raise ValueError

    e_lfanew = u32_le(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError

    coff = e_lfanew + 4
    opt = coff + 20
    magic = u16_le(data, opt)
    if magic == 0x20B:
        data_dirs = opt + 0x70
    elif magic == 0x10B:
        data_dirs = opt + 0x60
    else:
        raise ValueError

    export_dir_rva = u32_le(data, data_dirs)
    if export_dir_rva == 0:
        return []

    ed = rva_to_file_offset(data, export_dir_rva)
    base_ord = u32_le(data, ed + 0x10)
    n_funcs = u32_le(data, ed + 0x14)
    n_names = u32_le(data, ed + 0x18)
    eat_rva = u32_le(data, ed + 0x1C)
    ent_rva = u32_le(data, ed + 0x20)
    ord_rva = u32_le(data, ed + 0x24)

    eat = rva_to_file_offset(data, eat_rva)
    ent = rva_to_file_offset(data, ent_rva)
    ords = rva_to_file_offset(data, ord_rva)

    exports = []
    for i in range(n_names):
        name_rva = u32_le(data, ent + i * 4)
        idx = u16_le(data, ords + i * 2)
        func_rva = u32_le(data, eat + idx * 4)
        name_off = rva_to_file_offset(data, name_rva)
        end = data.index(b"\x00", name_off)
        name = data[name_off:end].decode("ascii", "replace")
        body_off = rva_to_file_offset(data, func_rva)
        body = data[body_off:body_off + 16]
        imm = extract_imm32_after_b8(body)
        exports.append({
            "name": name,
            "ordinal": base_ord + idx,
            "rva": func_rva,
            "body": body,
            "imm32": imm,
        })

    return exports


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python pe_exports.py <pe-file>", file=sys.stderr)
        sys.exit(2)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    for export in pe_exports(data):
        print(
            "%-20s  ordinal=%-4d  rva=0x%04x  imm=0x%08x  %s"
            % (
                export["name"],
                export["ordinal"],
                export["rva"],
                export["imm32"] if export["imm32"] is not None else 0,
                export["body"].hex(),
            )
        )
