use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use memmap2::Mmap;
use nrodoc::core::nro::{Assets, Nro, Segment};
use nrodoc::core::patch as core_patch;
use nrodoc::core::verdict::Report;
use nrodoc::core::{nacp, svc, verdict, walk};

mod report;

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
    /// Rewrite legacy TLS access to the new ABI. The only command that writes.
    Patch {
        /// Path to a .nro or .ovl file.
        file: PathBuf,
        /// Rewrite the file itself instead of writing <name>.patched.nro alongside.
        #[arg(long)]
        in_place: bool,
        /// Skip the .bak copy that --in-place makes.
        #[arg(long, requires = "in_place")]
        no_backup: bool,
        /// Report what would change without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Report each app's ABI compatibility verdict. Read-only.
    Scan {
        /// A .nro/.ovl file, a directory, or an SD card root. Directories are
        /// searched recursively.
        path: PathBuf,
        /// Emit the reports as JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Print the full reasoning and pattern offsets for every finding.
        #[arg(long)]
        explain: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Info { file } => info(&file).map(|()| 0),
        Command::Scan {
            path,
            json,
            explain,
        } => scan(&path, json, explain),
        Command::Patch {
            file,
            in_place,
            no_backup,
            dry_run,
        } => patch(&file, in_place, no_backup, dry_run),
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

fn scan(path: &Path, json: bool, explain: bool) -> Result<u8> {
    let walk = walk::collect(path);
    if walk.files.is_empty() && walk.errors.is_empty() {
        anyhow::bail!(
            "no .nro or .ovl files found under {} (and it is not a file)",
            path.display()
        );
    }

    let reports: Vec<Report> = walk
        .files
        .iter()
        .map(|file| {
            let data = map_file(file)?;
            Ok(verdict::analyze(file.clone(), &data))
        })
        .collect::<Result<_>>()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    } else {
        let root = if path.is_file() {
            path.parent().unwrap_or(path)
        } else {
            path
        };
        println!("{}", report::table::render(&reports, root));
        println!("\n{}", report::table::summary(&reports));

        if explain {
            for finding in reports.iter().filter(|r| r.verdict.is_finding()) {
                print_explanation(finding, root);
            }
        }
    }

    for error in &walk.errors {
        eprintln!("warning: {error}");
    }

    let findings = reports.iter().any(|report| report.verdict.is_finding());
    Ok(u8::from(findings) * EXIT_FINDINGS)
}

fn patch(file: &Path, in_place: bool, no_backup: bool, dry_run: bool) -> Result<u8> {
    anyhow::ensure!(file.is_file(), "{} is not a file", file.display());

    let mut data = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let applied = match core_patch::patch(&mut data) {
        Ok(applied) => applied,
        // Already patched, or a build with no signature nrodoc recognises. Not an
        // error — `scan` explains which, and the file is untouched either way.
        Err(err @ core_patch::PatchError::NothingToPatch) => {
            println!("{}: {err}", file.display());
            return Ok(EXIT_FINDINGS);
        }
        Err(err) => return Err(err.into()),
    };

    println!(
        "{}: {} signature(s) to rewrite",
        file.display(),
        applied.len()
    );
    for application in &applied {
        println!("  @ {:#010x}  {}", application.offset, application.label);
    }

    if dry_run {
        println!("dry run: nothing written");
        return Ok(0);
    }

    // Resolved only now: if there was nothing to patch we never get here, and a name
    // collision should not mask that more useful answer.
    let Destination { target, backup } = destination(file, in_place, no_backup)?;
    if let Some(backup) = &backup {
        fs::copy(file, backup).with_context(|| format!("writing backup {}", backup.display()))?;
        println!("backup: {}", backup.display());
    }
    write_atomic(&target, &data)?;
    println!("wrote: {}", target.display());
    Ok(0)
}

struct Destination {
    target: PathBuf,
    backup: Option<PathBuf>,
}

/// Decides where the patched bytes go, refusing anything that would destroy a file
/// that is already there. Overwriting an existing `.bak` is the one mistake that
/// loses the original for good, so it is refused outright rather than forced.
fn destination(file: &Path, in_place: bool, no_backup: bool) -> Result<Destination> {
    if !in_place {
        let target = patched_path(file);
        anyhow::ensure!(
            !target.exists(),
            "{} already exists — remove it or use --in-place",
            target.display()
        );
        return Ok(Destination {
            target,
            backup: None,
        });
    }

    let backup = (!no_backup).then(|| with_suffix(file, "bak"));
    if let Some(backup) = &backup {
        anyhow::ensure!(
            !backup.exists(),
            "{} already exists — refusing to overwrite what may be the only copy of \
             the original; move it aside first",
            backup.display()
        );
    }
    Ok(Destination {
        target: file.to_path_buf(),
        backup,
    })
}

/// `foo.nro` -> `foo.patched.nro`. The extension is preserved so hbmenu and Tesla
/// still recognise the result.
fn patched_path(file: &Path) -> PathBuf {
    match file.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => file.with_extension(format!("patched.{ext}")),
        None => with_suffix(file, "patched"),
    }
}

/// `foo.nro` + `bak` -> `foo.nro.bak`; the original extension is kept so it stays
/// obvious what the file was.
fn with_suffix(file: &Path, suffix: &str) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// Writes via a sibling temp file and renames, so an interrupted write cannot leave
/// a half-patched NRO where the original was.
fn write_atomic(target: &Path, data: &[u8]) -> Result<()> {
    let temp = with_suffix(target, "nrodoc-tmp");
    let mut file = File::create(&temp).with_context(|| format!("creating {}", temp.display()))?;
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", temp.display()))?;
    drop(file);

    fs::rename(&temp, target).with_context(|| format!("renaming into {}", target.display()))
}

fn print_explanation(report: &Report, root: &Path) {
    println!(
        "\n{} — {}",
        report.display_name(),
        report::relative(&report.path, root)
    );
    println!("  verdict: {}", report.verdict.label());
    for note in &report.notes {
        println!("  - {note}");
    }
    for hit in &report.legacy_hits {
        println!("  @ {:#010x}  legacy  {}", hit.offset, hit.label);
    }
    for hit in &report.patched_hits {
        println!("  @ {:#010x}  patched {}", hit.offset, hit.label);
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
