use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use memmap2::Mmap;
use nrodoc::core::nacp;
use nrodoc::core::nro::{Assets, Nro, Segment};

/// Exit code for I/O and usage errors. Scan verdict codes come later.
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Info { file } => info(&file),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn info(path: &Path) -> Result<()> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    // SAFETY: as unsafe as any mmap — a concurrent truncation of the file would
    // fault. We only read, and these are files on the user's own SD card.
    let data =
        unsafe { Mmap::map(&file) }.with_context(|| format!("mapping {}", path.display()))?;
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
    print_assets(nro.assets);

    Ok(())
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
