"""Self-test for the PE export toolchain."""

from pe_exports import pe_exports


def check_pe_exports(data: bytes) -> list[tuple[str, bool]]:
    """Return (label, ok) pairs for pe_exports checks against the sample fixture."""
    rows = pe_exports(data)
    return [
        ("3 exports", len(rows) == 3),
        ("names", [r["name"] for r in rows] == ["FuncOne", "FuncTwo", "FuncThree"]),
        ("ordinals", [r["ordinal"] for r in rows] == [0, 1, 2]),
        ("imm32", [r["imm32"] for r in rows] == [0x2B, 0x5A, 0x07]),
    ]
