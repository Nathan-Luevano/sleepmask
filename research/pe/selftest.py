"""Self-test for the PE export toolchain."""

from emit_asm import render_equ
from emit_thunk import thunk_bytes
from pe_exports import pe_exports
from pathlib import Path
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


def check_thunk(data: bytes) -> list[tuple[str, bool]]:
    """Return (label, ok) pairs for emit_thunk checks."""
    low_raises = False
    try:
        thunk_bytes(-1)
    except ValueError:
        low_raises = True

    high_raises = False
    try:
        thunk_bytes(2**32)
    except ValueError:
        high_raises = True

    return [
        ("thunk_bytes 0x2b", thunk_bytes(0x2B) == b"\xb8\x2b\x00\x00\x00\x0f\x05\xc3"),
        ("thunk_bytes 0x3d", thunk_bytes(0x3D) == b"\xb8\x3d\x00\x00\x00\x0f\x05\xc3"),
        (
            "thunk round-trip",
            all(find_stub_imm(thunk_bytes(n)) == n for n in (0, 1, 0x2B, 0x3D, 0xFF, 0xFFFF)),
        ),
        ("thunk range low", low_raises),
        ("thunk range high", high_raises),
    ]


def main() -> int:
    """Run every check against the fixture and print a report."""
    fixture = Path(__file__).with_name("sample.dll")
    if not fixture.exists():
        import make_fixture
        make_fixture.main()
    data = fixture.read_bytes()
    checks = (check_pe_exports, check_syscall_table, check_emit, check_thunk)
    results = []
    for check in checks:
        results.extend(check(data))
    failed = sum(1 for _, ok in results if not ok)
    for label, ok in results:
        print(("ok    " if ok else "FAIL  ") + label)
    print(f"{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
