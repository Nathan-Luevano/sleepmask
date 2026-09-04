def render_equ(rows: list) -> str:
    """Return a text block with one output line per dict in rows.

    Each dict has keys "name" (str) and "value" (int or None).
    For each row, in order:
      - if "value" is not None:
            emit:  SYS_<name> equ 0x<value:08x>
        e.g. name="FuncOne", value=0x2B  ->  "SYS_FuncOne equ 0x0000002b"
      - otherwise:
            emit:  ; SYS_<name> not a syscall stub
        e.g. name="Nope"                ->  "; SYS_Nope not a syscall stub"

    Join the lines with a single "\n". Return "" (empty string) when rows is empty.
    """
    return "\n".join(
        f'SYS_{row["name"]} equ 0x{row["value"]:08x}'
        if row["value"] is not None
        else f'; SYS_{row["name"]} not a syscall stub'
        for row in rows
    )
