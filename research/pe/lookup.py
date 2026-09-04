"""Resolve syscall immediates from named PE exports."""

from pe_exports import pe_exports
from syscall_table import find_stub_imm


def resolve(data: bytes, name: str):
    """Return the syscall immediate for the first matching export."""
    for export in pe_exports(data):
        if export["name"] == name:
            return find_stub_imm(export["body"])
    return None


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: python lookup.py <pe-file> <name>", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    value = resolve(data, sys.argv[2])
    if value is None:
        print("?")
        sys.exit(1)
    print("0x%02x" % value)
