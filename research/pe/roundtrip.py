from emit_thunk import thunk_bytes
from syscall_table import find_stub_imm


def roundtrip(exports: list) -> list:
    result = []
    for export in exports:
        number = find_stub_imm(export["body"])
        result.append(
            {
                "name": export["name"],
                "number": number,
                "matched": (
                    None
                    if number is None
                    else thunk_bytes(number) == export["body"][:8]
                ),
            }
        )
    return result


if __name__ == "__main__":
    import sys
    from pe_exports import pe_exports

    if len(sys.argv) != 2:
        print("usage: python roundtrip.py <file>", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1], "rb") as file:
        data = file.read()
    rows = roundtrip(pe_exports(data))
    for row in rows:
        print(
            "%-20s %-6s %s"
            % (
                row["name"],
                ("0x%02x" % row["number"]) if row["number"] is not None else "?",
                "ok" if row["matched"] is True else "no" if row["matched"] is False else "-",
            )
        )
    sys.exit(1 if any(row["matched"] is False for row in rows) else 0)
