---
title: Below the kernel
description: Firmware rootkits live in the SPI flash, below the OS and the driver signature check — LoJax, ESPecter, CosmicStrand, MoonBounce, and BlackLotus, and why a reinstall never touches them.
publishedAt: 2026-09-03
updatedAt: null
draft: true
tags: [malware, firmware, uefi, security]
cover: null
artifacts: []
---
# Below the kernel

The operating system is not the bottom of the stack. Beneath the kernel, beneath the
driver you signed into Windows, there is a few-megabyte image in a serial flash chip on
the motherboard that runs every boot, before the OS exists, and that a reinstall will
never overwrite. Malware that lives there is not *on* your computer in the way that word
means. It is in the building, and it gets to watch every tenant that comes in after it.
This is the UEFI firmware rootkit, and it has been found in the wild for less than a
decade.

## The layer you do not think about

On every x86 PC since the UEFI era, the first code to run is the firmware in the **SPI
flash** — a small serial flash chip, the one marked on the board, the one a `flashrom`
command can read. That firmware initializes hardware and then loads the operating system.
It runs in a privileged mode — SMM, the System Management Monitor, on Intel — that is
above and separate from the OS. A firmware rootkit is a patch, or an added module, in
that image. It runs at boot, before your OS, before your AV, before the driver signature
check even runs. Remove it and the machine reboots into a "clean" OS that still carries
it. Reinstall Windows a hundred times and the firmware does not change.

That is the whole persistence model, and it is why *"I wiped the disk and reinstalled"*
is not a remediation. You have to touch the flash.

## LoJax: the first one actually found in the wild

ESET's Sednit group (APT28 / Fancy Bear) was the first to be caught with one, in 2018,
targeting government organizations in the Balkans and Central-Eastern Europe. LoJax is
the reference case because it is a real, complete, in-the-wild implant and not a concept:
Sednit dumped the UEFI firmware, patched it on a test machine, and wrote it back,
planting a malicious module that drops the LoJax agent on the system. ESET recovered the
entire toolchain — dump, patch, reflash — which is what makes it a rootkit instead of a
clever driver. Two details worth keeping: it lived in **SPI flash** (true firmware, not
the boot partition), and ESET later corrected their own writeup to say **Secure Boot did
not protect against it** — the real hardware defense is an Intel Boot Guard–class root of
trust that verifies the firmware before running it.

## The others, and the pattern

The catalog is short but instructive, because every one of them is a different answer to
"where in the pre-OS do I sit so you have to chase me":

- **CosmicStrand** (attributed to the Gamma Group's FinFisher, first spotted by
  Qihoo360 in 2017) sat in the firmware images of **ASUS and Gigabyte motherboards** and
  dropped a kernel implant on every boot. A commercial product carrying a rootkit is the
  least surprising and the most annoying version of this story.
- **MosaicRegressor** (Kaspersky, 2021) and **MoonBounce** (Kaspersky, 2022) are both
  SPI-flash rootkits in the same "patch the firmware, run before the OS" family.
- **ESPecter** (ESET, 2021) is the interesting twist: it does *not* live deep in the
  firmware. It lives on the **EFI System Partition** — a real partition on your disk —
  and **patches the Windows Boot Manager** so it can load an unsigned driver while
  bypassing Driver Signature Enforcement. ESET traced its roots back to 2012, when it was
  still a classic MBR bootkit. It is the same idea (own the pre-OS loader) expressed at a
  layer you can, in principle, inspect with a filesystem tool.
- **BlackLotus** (Microsoft's 2022 campaign name; ESET "confirmed" it in 2023) is the one
  that keeps showing up because it exploits a vulnerability in a **validly signed
  Microsoft UEFI binary** — a "valid but vulnerable" image. That is why it was not on the
  revocation list: the signature is fine, the bug is in the code. ESET called it out for
  surviving on patched Windows 11.

## Why you cannot see it with the usual tools

A firmware rootkit is invisible to the normal forensics stack. **Volatility** reads the
OS's memory — but the firmware already ran by the time the OS is up, or it is running in
SMM in a place the OS never maps. The disk looks clean because the persistence is in the
chip, not on the disk. You need the firmware tools: **UEFITool** to dump and parse the
firmware image, **chipsec** to audit it for known weaknesses, and **flashrom** to actually
read and write the SPI chip. The remediation for a confirmed implant is unglamorous and
unmissable: **reflash the firmware**, and ideally put a hardware root of trust (Intel Boot
Guard) in front of it so a bad re-flashed image is caught at the next boot.

## What this means for the rest of the trust chain

The firmware rootkit is the reason the "driver signature enforcement" and "Secure Boot"
story is more complicated than the marketing: both are only as strong as the firmware
that enforces them, and BlackLotus specifically found a signed-but-vulnerable path around
Secure Boot. The defense that actually works is the one you cannot software-patch your way
around — verify the firmware against a hardware root of trust. Until then, a machine is
only as trusted as the chip on the board, and the chip does not reinstall.

## Sources
https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild-courtesy-sednit-group/
https://www.welivesecurity.com/2021/10/05/uefi-threats-moving-esp-introducing-especter-bootkit/
https://www.bleepingcomputer.com/news/security/cosmicstrand-uefi-malware-found-in-gigabyte-asus-motherboards/
https://www.bleepingcomputer.com/news/security/blacklotus-bootkit-bypasses-uefi-secure-boot-on-patched-windows-11/
https://www.bleepingcomputer.com/news/security/source-code-for-blacklotus-windows-uefi-malware-leaked-on-github/
https://arstechnica.com/information-technology/2022/07/researchers-unpack-unkillable-uefi-rootkit-that-survives-os-reinstalls/
https://github.com/killvxk/uefi-rootkit
https://andreafortuna.org/2026/06/12/uefi-bootkits/
