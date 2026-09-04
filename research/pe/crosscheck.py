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


def check_consistency(expected, trace, present, absent):
    """Cross-check an observed integer trace against an expected label->value map.

    expected: dict mapping a label (str) to an int, or to None.
    trace: list of observed ints.
    present: list of labels whose value must NOT be None and MUST occur in trace.
    absent: list of labels whose value, when not None, must NOT occur in trace.

    Build a list called reasons (list of str), appending in this exact order:

      1. For each label in present, in the given order:
         - if expected[label] is None, append the string "<label>: unresolved"
           (where <label> is the label text).
         - otherwise, if expected[label] is not a member of trace, append the
           string "<label>: 0xVV not in trace", where VV is the value formatted as
           two lowercase hex digits (as in  "0x%02x" % value).
      2. For each label in absent, in the given order:
         - if expected[label] is not None and expected[label] is a member of trace,
           append the string "<label>: 0xVV unexpectedly in trace", with VV as above.
      3. Let observed = set(trace) and known = the set of all non-None values among
         expected.values(). For each integer n in sorted(observed - known), append
         the string "trace 0xVV not in expected", with VV the value of n.

    Return the two-item tuple (len(reasons) == 0, reasons).
    """
    reasons = []
    for label in present:
        value = expected[label]
        if value is None:
            reasons.append("%s: unresolved" % label)
        elif value not in trace:
            reasons.append("%s: 0x%02x not in trace" % (label, value))

    for label in absent:
        value = expected[label]
        if value is not None and value in trace:
            reasons.append("%s: 0x%02x unexpectedly in trace" % (label, value))

    observed = set(trace)
    known = {value for value in expected.values() if value is not None}
    for n in sorted(observed - known):
        reasons.append("trace 0x%02x not in expected" % n)

    return len(reasons) == 0, reasons
