def find_stub_imm(body: bytes) -> int | None:
    """Return int.from_bytes(body[1:5], "little") when len(body) >= 7 and
    body[0] == 0xB8 and body[5] == 0x0F and body[6] == 0x05; otherwise
    return None."""
    if len(body) >= 7 and body[0] == 0xB8 and body[5] == 0x0F and body[6] == 0x05:
        return int.from_bytes(body[1:5], "little")
    return None
