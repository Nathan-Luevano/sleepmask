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
