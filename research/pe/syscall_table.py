from pe_exports import pe_exports


def find_stub_imm(body: bytes) -> int | None:
    """Return int.from_bytes(body[1:5], "little") when len(body) >= 7 and
    body[0] == 0xB8 and body[5] == 0x0F and body[6] == 0x05; otherwise
    return None."""
    if len(body) >= 7 and body[0] == 0xB8 and body[5] == 0x0F and body[6] == 0x05:
        return int.from_bytes(body[1:5], "little")
    return None


def syscall_table(data: bytes) -> list:
    """For each dict returned by pe_exports(data), yield one row.

    Each row is {"name": <the dict["name"]>, "value": find_stub_imm(<the dict["body"]>)},
    in the same order pe_exports returns them.
    """
    return [
        {"name": export["name"], "value": find_stub_imm(export["body"])}
        for export in pe_exports(data)
    ]
