"""Encode an integer as a fixed 8-byte little-endian sequence."""


def thunk_bytes(n: int) -> bytes:
    """Return the 8-byte little-endian encoding of n.

    The result is exactly 8 bytes:
      byte 0     = 0xB8
      bytes 1-4  = n, as an unsigned 32-bit little-endian integer
      bytes 5-7  = 0x0F, 0x05, 0xC3

    Raise ValueError if n < 0 or n >= 2**32.
    """
    if n < 0 or n >= 2**32:
        raise ValueError("n must be an unsigned 32-bit integer")
    return b"\xB8" + n.to_bytes(4, "little") + b"\x0F\x05\xC3"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python emit_thunk.py <number>", file=sys.stderr)
        sys.exit(2)

    argument = sys.argv[1]
    try:
        if argument.startswith(("0x", "0X")):
            number = int(argument[2:], 16)
        else:
            number = int(argument, 10)
    except ValueError:
        print(f"invalid number: {argument}", file=sys.stderr)
        sys.exit(1)

    try:
        result = thunk_bytes(number)
    except ValueError:
        print(f"number out of range: {argument}", file=sys.stderr)
        sys.exit(1)

    print(result.hex())
