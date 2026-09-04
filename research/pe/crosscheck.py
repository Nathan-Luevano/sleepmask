#!/usr/bin/env python3
"""Cross-check helper (offline table vs runtime trace)."""

def parse_trace(stdout: str) -> list[int]:
    """Return the base-16 integers written on the line that starts with 'syscalls:'.

    Find the first line (after stripping) that starts with 'syscalls:'. Take the
    substring after the first ':'. Split that substring on whitespace. Parse each
    token with int(token, 16); skip any token that raises ValueError. Collect the
    parsed integers in order and return them. If no line starts with 'syscalls:',
    return an empty list. Stop scanning once the matching line has been processed.
    """
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("syscalls:"):
            values = []
            for token in line.split(":", 1)[1].split():
                try:
                    values.append(int(token, 16))
                except ValueError:
                    pass
            return values
    return []
