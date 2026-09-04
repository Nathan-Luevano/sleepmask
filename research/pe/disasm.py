"""Decode a byte sequence into its instruction sequence."""

import capstone

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def disasm(body: bytes) -> list[tuple[int, str, str]]:
    result = []
    for i in MD.disasm(body, 0):
        result.append((i.address, i.mnemonic, i.op_str))
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python disasm.py <hex>", file=sys.stderr)
        sys.exit(2)

    try:
        body = bytes.fromhex(sys.argv[1])
    except ValueError:
        print("invalid hex", file=sys.stderr)
        sys.exit(1)

    for address, mnemonic, op_str in disasm(body):
        line = f"0x{address:02x}  {mnemonic}"
        if op_str:
            line += f" {op_str}"
        print(line)
