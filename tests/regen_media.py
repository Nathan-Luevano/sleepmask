"""Regenerate every media capture in the grafting-shellcode-onto-a-live-process
post from scratch and byte-diff against the committed file.

Exit 0 = all captures byte-identical (the blog's bytes are reproducible).
Run with:  micromamba run -n mdev python test/regen_media.py

Requires `bash build.sh` to have run (build/beacon_*.bin, build/host_*.bin).
"""

import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # malware/sleepmask-loader
MEDIA = (ROOT.parent.parent / "blogs"
         / "grafting-shellcode-onto-a-live-process" / "media")

sys.path.insert(0, str(ROOT / "tools"))
from mk_pe import make_pe        # noqa: E402
from mk_macho import make_macho  # noqa: E402
import capstone                  # noqa: E402

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
HOST_C = (
    "#include <unistd.h>\n"
    "int main(void) {\n"
    "  const char m[] = \"host alive\\n\";\n"
    "  (void)!write(1, m, sizeof m - 1);\n"
    "  return 42;\n"
    "}\n"
)

results = []


def report(name: str, regen: bytes, scratch: Path):
    committed = (MEDIA / name).read_bytes()
    same = regen == committed
    results.append((name, same))
    print(f"{'SAME ' if same else 'DIFF '} {name}  ({len(committed)} B committed)")
    if not same:
        out = scratch / f"regen_{name}"
        out.write_bytes(regen)
        print(f"      regen written to {out}")


def dump_region(path: Path, off: int, ln: int) -> bytes:
    """8-hex offset, 2sp, 16 single-byte hex groups, 3sp, ascii (non-printable .)."""
    data = path.read_bytes()
    lines = []
    for o in range(off, off + ln, 16):
        chunk = data[o:o + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{o:08x}  {hexs:<31}   {asc}")
    return ("\n".join(lines) + "\n").encode()


def main():
    tmp = Path(tempfile.mkdtemp(prefix="regen_media."))
    try:
        for need in ("beacon_linux.bin", "beacon_windows.bin", "beacon_macos.bin",
                     "host_win.bin", "host_macos.bin"):
            if not (ROOT / "build" / need).is_file():
                sys.exit(f"missing build/{need} — run `bash build.sh` first")

        # ---------------- linux --------------------------------------------
        src = tmp / "host_pie.c"          # basename lands in the FILE symbol
        src.write_text(HOST_C)
        host_elf = tmp / "host_pie"
        subprocess.run(["gcc", "-O2", "-o", str(host_elf), str(src)], check=True)
        host_size = host_elf.stat().st_size

        coup_elf = tmp / "host_pie.coupled"
        r = subprocess.run(["micromamba", "run", "-n", "mdev", "python",
                            str(ROOT / "tools" / "append_elf.py"),
                            str(host_elf), str(ROOT / "build" / "beacon_linux.bin"),
                            str(coup_elf)], capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr); sys.exit(2)

        tramp_linux = (
            f"# region: file 0x4000 -> vaddr 0x6000   (host = gcc -O2, {host_size} B, PIE)\n"
            "# first 48 bytes of the appended region: [trampoline:10][beacon...]\n\n"
        ).encode() + dump_region(coup_elf, 0x4000, 48)
        report("tramp_linux_elf.txt", tramp_linux, tmp)

        rh = subprocess.run(["readelf", "-hW", str(coup_elf)], capture_output=True)
        rl = subprocess.run(["readelf", "-lW", str(coup_elf)], capture_output=True)
        report("readelf_coupled_elf.txt", rh.stdout + b"\n" + rl.stdout, tmp)

        # ---------------- windows ------------------------------------------
        host_win = tmp / "host_win.exe"
        host_win.write_bytes(make_pe((ROOT / "build" / "host_win.bin").read_bytes()))
        coup_pe = tmp / "host_win.coupled.exe"
        r = subprocess.run(["micromamba", "run", "-n", "mdev", "python",
                            str(ROOT / "tools" / "append_pe.py"),
                            str(host_win), str(ROOT / "build" / "beacon_windows.bin"),
                            str(coup_pe)], capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr); sys.exit(2)

        d = coup_pe.read_bytes()
        lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        coff = lfanew + 4
        nsect = struct.unpack_from("<H", d, coff + 2)[0]
        opt = coff + 20
        sect_off = opt + struct.unpack_from("<H", d, coff + 16)[0]
        entry = struct.unpack_from("<I", d, opt + 0x10)[0]
        rows = []
        bcon_raw = None
        for i in range(nsect):
            off = sect_off + i * 40
            name = d[off:off + 8].split(b"\0")[0].decode()
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, off + 8)
            chars = struct.unpack_from("<I", d, off + 0x24)[0]
            if d[off:off + 8] == b".bcon\0\0\0":
                bcon_raw = rawptr
            rows.append(f"  {name:<8}VA {vaddr:#06x}  vsize {vsize:#06x}  "
                        f"raw {rawptr:#06x}  rawsize {rawsize:#06x}  chars {chars:#x}")
        pe_sections = (
            f"# host_win.coupled.exe — PE section table (entry RVA {entry:#x})\n\n"
        ).encode() + ("\n".join(rows) + "\n").encode()
        report("pe_sections_coupled.txt", pe_sections, tmp)

        tramp_win = (
            "# .bcon section: RVA 0x2000, raw 0x800, 1024 B   "
            "(entry re-pointed 0x1000 -> 0x2000)\n"
            "# first 32 bytes at raw 0x800: [stub:10][beacon...]\n\n"
        ).encode() + dump_region(coup_pe, bcon_raw, 32)
        report("tramp_windows_pe.txt", tramp_win, tmp)

        # ---------------- macos --------------------------------------------
        host_macho = tmp / "host_macos.macho"
        host_macho.write_bytes(make_macho((ROOT / "build" / "host_macos.bin").read_bytes()))
        coup_macho = tmp / "host_macos.coupled"
        r = subprocess.run(["micromamba", "run", "-n", "mdev", "python",
                            str(ROOT / "tools" / "append_macho.py"),
                            str(host_macho), str(ROOT / "build" / "beacon_macos.bin"),
                            str(coup_macho)], capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr); sys.exit(2)

        tramp_mac = (
            "# __bcon section: vaddr 0x100002000, file 0x2000, 132 B   "
            "(entry re-pointed 0x100001000 -> 0x100002000)\n"
            "# first 32 bytes at file 0x2000: [stub:10][beacon...]\n\n"
        ).encode() + dump_region(coup_macho, 0x2000, 32)
        report("tramp_macos_macho.txt", tramp_mac, tmp)

        # ---------------- beacon disassemblies ------------------------------
        for plat in ("linux", "windows", "macos"):
            blob = (ROOT / "build" / f"beacon_{plat}.bin").read_bytes()
            lines = [f"# beacon_{plat}.bin — {len(blob)} bytes, x86-64, intel syntax"]
            for insn in MD.disasm(blob, 0):
                line = f"0x{insn.address:04x}:  {insn.mnemonic}"
                if insn.op_str:
                    line += f" {insn.op_str}"
                lines.append(line)
            report(f"beacon_{plat}.disasm.txt",
                   ("\n".join(lines) + "\n").encode(), tmp)

        # ---------------- test stdout ---------------------------------------
        for name, cmd in (
            ("test_linux.txt", ["bash", str(ROOT / "test" / "test_append_linux.sh")]),
            ("test_windows.txt", ["micromamba", "run", "-n", "mdev", "python",
                                  str(ROOT / "test" / "test_append_windows.py")]),
            ("test_macos.txt", ["micromamba", "run", "-n", "mdev", "python",
                                str(ROOT / "test" / "test_append_macos.py")]),
        ):
            r = subprocess.run(cmd, capture_output=True, cwd=ROOT)
            if r.returncode != 0:
                print(f"{name}: test exited {r.returncode}\n{r.stdout}\n{r.stderr}")
            report(name, r.stdout, tmp)

        bad = [n for n, s in results if not s]
        print(f"\n{len(results) - len(bad)}/{len(results)} byte-identical")
        sys.exit(1 if bad else 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
