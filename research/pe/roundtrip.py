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
