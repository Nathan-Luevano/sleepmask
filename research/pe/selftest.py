"""Self-test for the PE export toolchain."""

from emit_asm import render_equ
from pe_exports import pe_exports
from syscall_table import find_stub_imm, syscall_table


def check_pe_exports(data: bytes) -> list[tuple[str, bool]]:
    """Return (label, ok) pairs for pe_exports checks against the sample fixture."""
    rows = pe_exports(data)
    return [
        ("3 exports", len(rows) == 3),
        ("names", [r["name"] for r in rows] == ["FuncOne", "FuncTwo", "FuncThree"]),
        ("ordinals", [r["ordinal"] for r in rows] == [0, 1, 2]),
        ("imm32", [r["imm32"] for r in rows] == [0x2B, 0x5A, 0x07]),
    ]


def check_syscall_table(data: bytes) -> list[tuple[str, bool]]:
    """Return (label, ok) pairs for syscall_table checks."""
    rows = syscall_table(data)
    stub = b"\xb8\x2b\x00\x00\x00\x0f\x05\xc3"
    not_stub = b"\xb8\x07\x00\x00\x00\xc3"
    return [
        ("table rows", [r["name"] for r in rows] == ["FuncOne", "FuncTwo", "FuncThree"]),
        ("table values", [r["value"] for r in rows] == [0x2B, 0x5A, None]),
        ("find_stub_imm ok", find_stub_imm(stub) == 0x2B),
        ("find_stub_imm short", find_stub_imm(stub[:6]) is None),
        ("find_stub_imm not stub", find_stub_imm(not_stub) is None),
    ]


def check_emit(data: bytes) -> list[tuple[str, bool]]:
    """Return (label, ok) pairs for render_equ checks."""
    rows = syscall_table(data)
    expected = (
        "SYS_FuncOne equ 0x0000002b"
        "\nSYS_FuncTwo equ 0x0000005a"
        "\n; SYS_FuncThree not a syscall stub"
    )
    return [
        ("render_equ output", render_equ(rows) == expected),
        ("render_equ empty", render_equ([]) == ""),
    ]
