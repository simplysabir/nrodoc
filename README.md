# nrodoc

Scan a Nintendo Switch SD card and find out which of your homebrew still runs on modern
firmware — and which of it a patch won't save.

```text
$ nrodoc scan /Volumes/SD

 NAME            | FILE                         | VERSION | VERDICT             | NOTE
-----------------+------------------------------+---------+---------------------+-----------------------------------
 ovlmenu         | switch/.overlays/ovlmenu.ovl |         | NEEDS-PATCH         | 1 legacy TLS signature(s)…
 DBI             | switch/DBI.nro               | v658    | OK                  | built against libnx with the new…
 Goldleaf        | switch/Goldleaf.nro          | 0.10.0  | NEEDS-PATCH         | 3 legacy TLS signature(s)…
 mGBA            | switch/mGBA.nro              | 0.10.2  | PATCH-INSUFFICIENT? | generates code at runtime…
 Old But Patched | switch/oldpatched.nro        | 1.0     | PATCHED             | 1 patched TLS signature(s)…
 sphaira         | switch/sphaira.nro           | v0.11.0 | OK                  | built against libnx…

6 file(s): 2 OK, 1 PATCHED, 2 NEEDS-PATCH, 1 PATCH-INSUFFICIENT?
```

## The problem

Firmware 21.0.0 added a `thread_cpu_time` field at TLS offset `0x108`. libnx before
v4.10.0 put *user* TLS slots at exactly that offset, so the kernel now overwrites
them on every thread switch. Affected homebrew crashes — usually error 2168-0002,
often on exit or thread creation — and hbmenu shows a red "does not support the
current ABI" warning. Atmosphère 1.10.0 reimplemented the same kernel change, so
this reaches every firmware, not just 21.0.0.

[alula's hbpatcher](https://github.com/alula/hbpatcher) fixes the byte patterns. It
is a web page: one file at a time, no card-wide view, and no way to tell "already
patched" from "fine". nrodoc is the offline, scriptable version of the same idea,
plus the answer hbpatcher can't give you — *this one needs a rebuild, not a patch.*

## Install

```sh
cargo install nrodoc
cargo install --path .            # from a clone
```

Runs on the desktop side against a mounted SD card. macOS, Linux and Windows.
Nothing runs on the console.

## Usage

```sh
nrodoc scan <path>                  # file, directory, or SD root — recursive, read-only
  --json                            # machine-readable reports
  --explain                         # per-finding offsets plus the background

nrodoc info <file>                  # header, build ID, MOD0/LNY markers, NACP, syscalls

nrodoc patch <file>                 # writes <name>.patched.nro alongside
  --in-place                        # rewrite the file, keeping <name>.nro.bak
  --no-backup                       # skip the .bak (with --in-place or --all)
  --dry-run                         # report what would change, write nothing

nrodoc patch <dir> --all            # patch a whole card in place, backing up each file
```

`scan` and `info` never write. Exit codes: **0** everything OK or already patched,
**1** findings, **2** errors — so it drops into CI or a shell script.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `OK` | Carries the LNY2 ABI marker and no legacy TLS code. Built against libnx ≥ 4.10.0. |
| `NEEDS-PATCH` | Legacy TLS code found. `nrodoc patch` fixes it. |
| `PATCHED` | Already carries patched TLS bytes. Runs; hbmenu still warns. |
| `PATCH-INSUFFICIENT?` | As above, but it also maps its own executable memory. A JIT can fail in ways a TLS patch cannot reach. |
| `UNKNOWN` | Unparseable, or parseable with no signature and no marker — non-libnx homebrew, or a build nrodoc doesn't recognise. |

## The worked example

PPSSPP for Switch v1.17.1, on FW 22.5.0 / AMS 1.11.2:

1. hbmenu showed the red ABI warning; launching crashed with 2168-0002.
2. hbpatcher found and patched three patterns. Re-uploading the result said *"does
   not contain the expected ABI pattern"* — no help at all in deciding what to do next.
3. **It still crashed.** PPSSPP's JIT allocates and rewrites executable memory; the
   TLS patch never addressed that. Same story reported for pFBNeo.

nrodoc says all of that in one command:

```text
$ nrodoc scan PPSSPP_GL.nro --explain

PPSSPP (GL) — PPSSPP_GL.nro
  verdict: PATCH-INSUFFICIENT?
  - generates code at runtime; likely needs a rebuild, not a patch
  - maps its own executable memory: svcCreateCodeMemory, svcControlCodeMemory,
    svcSetProcessMemoryPermission, svcMapProcessCodeMemory, svcUnmapProcessCodeMemory
  - 3 patched TLS signature(s) already present
  - hbmenu will show the "unsupported ABI" warning (no LNY2 marker)
  @ 0x00b9b3a0  patched  threadEntry() LibNX patch 1
  @ 0x00b9b4e0  patched  threadTlsGet()
  @ 0x00b9b4f0  patched  threadTlsSet()
```

Three offsets identical to hbpatcher's own log, plus the three things it never told
you: the patch was already applied, the ABI marker is still missing, and this binary
JITs — so stop patching and go find a rebuild.

## How it decides

**Signatures.** Eight legacy patterns and their eight patched forms, ported from
hbpatcher: `threadTlsGet`, `threadTlsSet`, and six `threadEntry` shapes across GCC
13/14/15 at -O1 and -O2. Every one moves a TLS access from `+0x108` to `+0x180`.
Scanning for *both* forms is what separates `PATCHED` from `OK`. Matches must be
4-byte aligned — they're AArch64 instructions — and every occurrence is patched, not
just the first.

**The ABI marker.** `OK` is not "no legacy pattern found". It requires the LNY2
marker at `MOD0+0x34` with revision ≥ 1, which is literally what nx-hbmenu reads to
decide whether to draw its red warning. Only a real rebuild writes it — patchers
deliberately don't, nrodoc included, because the warning is honest.

**Runtime code generation.** `svc #imm16` encodes as `0xD4000001 | (imm16 << 5)`, so
one pass over `.text` reading 4-byte-aligned words yields every syscall the binary
can make, no disassembler needed. Five of them mean JIT: `svcCreateCodeMemory`,
`svcControlCodeMemory`, `svcSetProcessMemoryPermission`, `svcMapProcessCodeMemory`,
`svcUnmapProcessCodeMemory` — exactly what libnx's `jitCreate` uses. libnx puts each
wrapper in its own section, so `--gc-sections` prunes the unused ones and presence is
real evidence. It's a heuristic, and it only ever *downgrades confidence*: it never
turns a clean app into a finding.

**Patching is verified.** After rewriting, the buffer is re-parsed from scratch and
re-scanned. If the header no longer validates or any legacy signature survived, the
bytes are reverted and nothing is written. Writes go to a temp file and rename, and
an existing `.bak` is refused rather than overwritten.

## What it doesn't do

No network, ever — nothing is downloaded, nothing is reported anywhere. No console
component, no payloads, no exploits. No NSP/XCI/game files. No GUI. It reads and
patches homebrew you already have.

## Credit

The byte signatures, the transformation, and the research behind both are
[alula's hbpatcher](https://github.com/alula/hbpatcher) — nrodoc's patch *is*
hbpatcher's patch. What nrodoc adds is batch scanning, an offline CLI, the
patched-state and marker verdicts, and the runtime-codegen warning. If your homebrew
is maintained, the real fix is still a rebuild against libnx ≥ 4.10.0.

Also drawing on [libnx](https://github.com/switchbrew/libnx)
(commit `cad06c0` for the TLS fix), [nx-hbmenu](https://github.com/switchbrew/nx-hbmenu)
for the ABI-warning rule, and the switchbrew wiki for NRO/NACP layout.

## License

GPL-2.0-or-later, inherited from hbpatcher. See [LICENSE](LICENSE).
