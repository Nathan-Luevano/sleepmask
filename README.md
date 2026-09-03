# m-dev

Malware we **build and test** (never deploy), and the blog posts that come from
building it. One repo, two halves that feed each other:

- `malware/` — position-independent x64 Windows shellcode in NASM, exercised by
  a Unicorn harness with a hand-built fake PEB/ntdll. Real bytes, real
  disassembly, real passing tests. Nothing runs where it could cost us anything.
- `blogs/` — dense, reproducible field notes: sleep-masking direct syscalls,
  UEFI firmware rootkits, darknet pharmacopoeia, practical propellants. The
  posts show the actual build output and captured test runs that produced them.

## Layout
```
AGENTS.md        repo rules + orientation (read this first, agents and humans)
HANDOVER.md      live session state
blogs/<slug>/    one dir per post: index.md + media/
malware/<proj>/  nasm sources, build.sh, test/ (harness + evidence), build/
research/notes/  scratch + citations
```

## Reproducing the flagship sample
```
bash malware/sleepmask-loader/build.sh
micromamba run -n mdev python malware/sleepmask-loader/test/run_harness.py
```
Requires the `mdev` micromamba env (python 3.12 + capstone + keystone +
unicorn). See `AGENTS.md` for the env quirk and the full conventions.

## Status
All posts ship `draft: true` until they read complete. Malware here is a
specimen under glass, not a deployment.
