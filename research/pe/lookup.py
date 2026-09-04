"""Resolve syscall immediates from named PE exports."""

from pe_exports import pe_exports
from syscall_table import find_stub_imm


def resolve(data: bytes, name: str):
    """Return the syscall immediate for the first matching export."""
    for export in pe_exports(data):
        if export["name"] == name:
            return find_stub_imm(export["body"])
    return None
