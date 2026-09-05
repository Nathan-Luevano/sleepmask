"""Regenerate the media captures for blogs/sleep-masking-direct-syscalls/.

Run after `bash build.sh` with:
    micromamba run -n mdev python tests/regen_sleepmask_media.py

It overwrites the committed captures so the post's bytes always match the blob:
    media/harness-output.txt
    media/sleepmask.disasm.txt
    media/sleepmask.entry.hex
    media/sleepmask.tail.hex
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MEDIA = ROOT / "blogs" / "sleep-masking-direct-syscalls" / "media"
BLOB = ROOT / "build" / "sleepmask.bin"

import capstone

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
# X86 syntax is Intel by default in capstone 5.


def dump_region(data: bytes, off: int, ln: int) -> bytes:
    """8-hex offset, 2sp, 16 single-byte hex groups, 3sp, ascii (non-printable .)."""
    lines = []
    for o in range(off, off + ln, 16):
        chunk = data[o:o + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{o:08x}  {hexs:<31}   {asc}")
    return ("\n".join(lines) + "\n").encode()


def disasm_blob(data: bytes) -> bytes:
    lines = []
    for insn in MD.disasm(data, 0):
        if insn.op_str:
            lines.append(f"{insn.address:06x}: {insn.mnemonic:<23} {insn.op_str}")
        else:
            lines.append(f"{insn.address:06x}: {insn.mnemonic}")
    return ("\n".join(lines) + "\n").encode()


def harness_output() -> bytes:
    r = subprocess.run(
        ["micromamba", "run", "-n", "mdev", "python",
         str(ROOT / "tests" / "run_harness.py")],
        capture_output=True, text=True, cwd=ROOT)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        sys.exit(1)
    return r.stdout.encode()


def write_capture(name: str, data: bytes) -> None:
    path = MEDIA / name
    old = path.read_bytes() if path.is_file() else b""
    same = old == data
    path.write_bytes(data)
    print(f"{'SAME ' if same else 'UPDATED '} {name}  ({len(data)} B)")


def main():
    MEDIA.mkdir(parents=True, exist_ok=True)
    if not BLOB.is_file():
        sys.exit(f"missing {BLOB} — run `bash build.sh` first")
    blob = BLOB.read_bytes()
    entry_len = min(320, len(blob))
    tail_len = min(256, len(blob))
    write_capture("harness-output.txt", harness_output())
    write_capture("sleepmask.disasm.txt", disasm_blob(blob))
    write_capture("sleepmask.entry.hex", dump_region(blob, 0, entry_len))
    write_capture("sleepmask.tail.hex", dump_region(blob, len(blob) - tail_len, tail_len))


if __name__ == "__main__":
    main()
