"""Decode a byte sequence into its instruction sequence."""

import capstone

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def disasm(body: bytes) -> list[tuple[int, str, str]]:
    result = []
    for i in MD.disasm(body, 0):
        result.append((i.address, i.mnemonic, i.op_str))
    return result
