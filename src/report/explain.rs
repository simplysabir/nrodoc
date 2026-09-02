//! The reasoning behind `--explain`: per-finding detail, then the background needed
//! to act on it.

use std::path::Path;

use nrodoc::core::verdict::Report;

/// Everything nrodoc knows about one file.
pub fn finding(report: &Report, root: &Path) {
    println!(
        "\n{} — {}",
        report.display_name(),
        super::relative(&report.path, root)
    );
    println!("  verdict: {}", report.verdict.label());
    for note in &report.notes {
        println!("  - {note}");
    }
    for hit in &report.legacy_hits {
        println!("  @ {:#010x}  legacy   {}", hit.offset, hit.label);
    }
    for hit in &report.patched_hits {
        println!("  @ {:#010x}  patched  {}", hit.offset, hit.label);
    }
    if !report.jit_syscalls.is_empty() {
        for syscall in &report.jit_syscalls {
            println!("  svc {:#04x}     {}", syscall.number, syscall.name);
        }
    }
}

/// Printed once, after the findings. Offsets and file paths mean nothing without it.
pub const BACKGROUND: &str = "\
Background
──────────
  What broke
    The Thread Local Region is 0x200 bytes. The kernel owns the first 0x180; the
    last 0x80 are userland's. libnx before v4.10.0 started its TLS slots at 0x108,
    inside the kernel's half, to get more of them. That was harmless until firmware
    21.0.0 put a thread_cpu_time field at 0x108. The kernel now writes there on
    every thread switch, shredding whatever the app had stored. The result is a
    crash — often 2168-0002, often on exit or on thread creation.

    Atmosphere 1.10.0 reimplemented the same kernel change, so this reaches every
    firmware, not just 21.0.0.

  What the patch does
    It rewrites the TLS accesses in threadTlsGet, threadTlsSet and threadEntry to
    use 0x180 instead of 0x108 — the same transformation as libnx commit
    cad06c0. Only displacement bits inside existing instructions change; nothing
    moves and the file stays the same size.

    It does not relocate ThreadVars, which lives at the end of the region. So the
    space for TLS slots is squeezed rather than moved, and an app using an unusual
    number of slots can still misbehave. Rebuilding against libnx >= 4.10.0 is
    always the better fix.

  Why a patched app still shows the red hbmenu warning
    hbmenu reads an LNY2 marker at MOD0+0x34 and warns when its revision is below
    1. Only a real rebuild writes that marker. Patchers deliberately leave it
    alone — nrodoc does too — because the warning is honest: the binary is a
    patched legacy build, not a current one.

  Verdicts
    OK                   carries the LNY2 marker and no legacy TLS code.
    NEEDS-PATCH          legacy TLS code found. `nrodoc patch` fixes it.
    PATCHED              already carries patched TLS bytes. Runs; hbmenu still warns.
    PATCH-INSUFFICIENT?  as above, but the binary also maps its own executable
                         memory. Emulators with a JIT fail in ways a TLS patch
                         cannot reach, so treat a successful patch as unproven and
                         prefer a rebuild.
    UNKNOWN              unparseable, or parseable with no signature and no marker —
                         non-libnx homebrew, or a build nrodoc does not recognise.

  Credit
    The byte signatures and the transformation come from alula's hbpatcher
    (https://github.com/alula/hbpatcher). nrodoc adds batch scanning, offline
    patching and the runtime-codegen warning; the patch itself is hbpatcher's.";
