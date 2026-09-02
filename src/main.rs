use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use memmap2::Mmap;
use nrodoc::core::nro::{Assets, Nro, Segment};
use nrodoc::core::verdict::Report;
use nrodoc::core::{nacp, svc, verdict};

/// Scan found at least one file that is not OK or already patched.
const EXIT_FINDINGS: u8 = 1;
/// I/O or usage error.
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(name = "nrodoc", version, about = "Switch homebrew ABI doctor")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dump an NRO's header, MOD0/ABI markers and NACP metadata.
    Info {
        /// Path to a .nro or .ovl file.
        file: PathBuf,
    },
    /// Report each app's ABI compatibility verdict. Read-only.
    Scan {
        /// Path to a .nro or .ovl file.
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Info { file } => info(&file).map(|()| 0),
        Command::Scan { path } => scan(&path),
    };

    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// Maps a file read-only.
///
/// SAFETY: as unsafe as any mmap — a concurrent truncation would fault the process.
/// These are files sitting on the user's own SD card and we only ever read them.
fn map_file(path: &Path) -> Result<Mmap> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    unsafe { Mmap::map(&file) }.with_context(|| format!("mapping {}", path.display()))
}

fn scan(path: &Path) -> Result<u8> {
    let data = map_file(path)?;
    let report = verdict::analyze(path.to_path_buf(), &data);
    print_report(&report);
    Ok(u8::from(report.verdict.is_finding()) * EXIT_FINDINGS)
}

fn print_report(report: &Report) {
    println!(
        "{}  {}  {}",
        report.verdict.label(),
        report.display_name(),
        report.path.display()
    );
    for note in &report.notes {
        println!("  - {note}");
    }
    for hit in report.legacy_hits.iter().chain(&report.patched_hits) {
        println!("  @ {:#010x}  {}", hit.offset, hit.label);
    }
}

fn info(path: &Path) -> Result<()> {
    let data = map_file(path)?;
    let nro = Nro::parse(&data).with_context(|| format!("parsing {}", path.display()))?;

    println!("File:         {}", path.display());
    println!("Size:         {} bytes", data.len());

    if let Some(bytes) = nro.nacp_bytes()
        && let Some(nacp) = nacp::parse(bytes)
    {
        println!("\nNACP");
        if nacp.titles_compressed {
            println!("  Name:       <compressed title data, not read>");
        } else {
            println!("  Name:       {}", nacp.name);
            println!("  Author:     {}", nacp.author);
        }
        println!("  Version:    {}", nacp.display_version);
    }

    let h = &nro.header;
    println!("\nNRO");
    println!("  Version:    {}", h.version);
    println!("  Image size: {:#x}", h.size);
    println!("  Flags:      {:#x}", h.flags);
    println!("  Build ID:   {}", build_id_hex(&h.build_id));
    println!("  Segments:");
    print_segment(".text", h.text);
    print_segment(".rodata", h.rodata);
    print_segment(".data", h.data);
    println!("    {:<8}{:20}size {:#010x}", ".bss", "", h.bss_size);

    print_mod0(&nro);
    print_syscalls(&nro);
    print_assets(nro.assets);

    Ok(())
}

fn print_syscalls(nro: &Nro) {
    let text = nro.text();
    println!("\nSyscalls      {} distinct", svc::syscalls(text).len());
    let jit = svc::jit_syscalls(text);
    if jit.is_empty() {
        println!("  JIT:        none detected");
        return;
    }
    for (i, syscall) in jit.iter().enumerate() {
        let label = if i == 0 { "JIT:" } else { "" };
        println!("  {label:<10}  {:#04x} {}", syscall.number, syscall.name);
    }
}

fn print_segment(name: &str, seg: Segment) {
    println!(
        "    {:<8} offset {:#010x}  size {:#010x}",
        name, seg.file_off, seg.size
    );
}

fn print_mod0(nro: &Nro) {
    let Some(mod0) = nro.mod0 else {
        println!(
            "\nMOD0          not found (expected at {:#x})",
            nro.mod_offset
        );
        println!("  ABI:        unknown — hbmenu will show the ABI warning");
        return;
    };

    println!("\nMOD0 @ {:#x}", mod0.offset);
    println!("  LNY0:       {}", present(mod0.lny0));
    println!("  LNY1:       {}", present(mod0.lny1));
    match mod0.lny2_revision {
        Some(rev) => println!("  LNY2:       present, ABI revision {rev}"),
        None => println!("  LNY2:       absent"),
    }
    if nro.hbmenu_warns() {
        println!("  ABI:        hbmenu will show the \"unsupported ABI\" warning");
    } else {
        println!("  ABI:        current — hbmenu will not warn");
    }
}

fn print_assets(assets: Option<Assets>) {
    let Some(assets) = assets else {
        println!("\nAssets        none");
        return;
    };

    println!("\nAssets @ {:#x} (ASET v{})", assets.offset, assets.version);
    for (name, section) in [
        ("icon", assets.icon),
        ("nacp", assets.nacp),
        ("romfs", assets.romfs),
    ] {
        if section.is_present() {
            println!(
                "  {:<11} offset {:#010x}  size {:#010x}",
                name, section.offset, section.size
            );
        } else {
            println!("  {name:<11} absent");
        }
    }
}

fn present(flag: bool) -> &'static str {
    if flag { "present" } else { "absent" }
}

/// Build IDs are a 20-byte hash in a 32-byte field; drop the zero padding.
fn build_id_hex(build_id: &[u8; 0x20]) -> String {
    let end = build_id.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    build_id[..end].iter().map(|b| format!("{b:02x}")).collect()
}
