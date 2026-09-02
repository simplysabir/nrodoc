//! Turning the signals in an NRO into a verdict.
//!
//! Four signals matter, in this order of authority:
//!
//! 1. legacy TLS signatures in `.text` — the binary *will* be corrupted;
//! 2. patched TLS signatures — somebody already ran a patcher over it;
//! 3. JIT/W^X syscalls — the TLS patch may not be enough on its own;
//! 4. the LNY2 ABI marker — hbmenu's own definition of "this build is current".

use std::path::PathBuf;

use serde::Serialize;

use crate::core::nacp;
use crate::core::nro::{Nro, NroError};
use crate::core::patterns::{self, Hit};
use crate::core::svc::{self, Syscall};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Built against libnx >= 4.10.0: carries the LNY2 marker, no legacy code.
    Ok,
    /// Legacy TLS access present. Patchable.
    NeedsPatch,
    /// Carries patched TLS bytes. Runs, but hbmenu still warns.
    Patched,
    /// Legacy or patched TLS code *plus* runtime code generation. The TLS patch
    /// addresses thread-local storage only; a JIT that maps its own executable
    /// memory can fail for reasons the patch cannot touch.
    PatchInsufficient,
    /// Not parseable, or parseable but unrecognisable.
    Unknown,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Ok => "OK",
            Verdict::NeedsPatch => "NEEDS-PATCH",
            Verdict::Patched => "PATCHED",
            Verdict::PatchInsufficient => "PATCH-INSUFFICIENT?",
            Verdict::Unknown => "UNKNOWN",
        }
    }

    /// Whether this verdict should make `scan` exit non-zero.
    pub fn is_finding(self) -> bool {
        !matches!(self, Verdict::Ok | Verdict::Patched)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub path: PathBuf,
    pub verdict: Verdict,
    pub name: Option<String>,
    pub author: Option<String>,
    pub version: Option<String>,
    /// LNY2 revision, if the build carries the marker.
    pub abi_revision: Option<u32>,
    /// Whether hbmenu will show its red "unsupported ABI" warning.
    pub hbmenu_warns: bool,
    /// Offsets are relative to the start of `.text`, matching hbpatcher's log.
    pub legacy_hits: Vec<Hit>,
    pub patched_hits: Vec<Hit>,
    pub jit_syscalls: Vec<Syscall>,
    /// Human-readable findings; the first is the headline shown in the table.
    pub notes: Vec<String>,
    pub parse_error: Option<String>,
}

impl Report {
    pub fn headline(&self) -> &str {
        self.notes.first().map_or("", String::as_str)
    }

    /// Falls back to the file stem when the NRO carries no NACP.
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                self.path
                    .file_stem()
                    .map_or_else(|| "?".into(), |stem| stem.to_string_lossy().into_owned())
            })
    }
}

/// Analyses one already-read NRO. Never fails: a file that will not parse comes back
/// as [`Verdict::Unknown`] carrying the reason, because a scan should report every
/// file it was pointed at.
pub fn analyze(path: PathBuf, data: &[u8]) -> Report {
    let nro = match Nro::parse(data) {
        Ok(nro) => nro,
        Err(err) => return unparseable(path, err),
    };

    let text = nro.text();
    let legacy = patterns::find_legacy(text);
    let patched = patterns::find_patched(text);
    let jit = svc::jit_syscalls(text);
    let abi_revision = nro.mod0.and_then(|mod0| mod0.lny2_revision);

    let verdict = classify(&legacy, &patched, &jit, abi_revision.is_some());
    let nacp = nro.nacp_bytes().and_then(nacp::parse);

    Report {
        path,
        verdict,
        name: nacp.as_ref().map(|n| n.name.clone()),
        author: nacp.as_ref().map(|n| n.author.clone()),
        version: nacp.as_ref().map(|n| n.display_version.clone()),
        abi_revision,
        hbmenu_warns: nro.hbmenu_warns(),
        notes: notes(verdict, &legacy, &patched, &jit, abi_revision, &nro),
        legacy_hits: legacy,
        patched_hits: patched,
        jit_syscalls: jit,
        parse_error: None,
    }
}

/// The verdict table. Legacy code outranks everything: a partially-patched binary is
/// still a broken binary.
fn classify(legacy: &[Hit], patched: &[Hit], jit: &[Syscall], has_abi_marker: bool) -> Verdict {
    match (legacy.is_empty(), patched.is_empty(), jit.is_empty()) {
        (false, _, true) => Verdict::NeedsPatch,
        (false, _, false) => Verdict::PatchInsufficient,
        (true, false, true) => Verdict::Patched,
        (true, false, false) => Verdict::PatchInsufficient,
        // Nothing to go on but the marker.
        (true, true, _) if has_abi_marker => Verdict::Ok,
        (true, true, _) => Verdict::Unknown,
    }
}

fn notes(
    verdict: Verdict,
    legacy: &[Hit],
    patched: &[Hit],
    jit: &[Syscall],
    abi_revision: Option<u32>,
    nro: &Nro,
) -> Vec<String> {
    let mut notes = Vec::new();

    match verdict {
        Verdict::Ok => notes.push(format!(
            "built against libnx with the new TLS ABI (LNY2 revision {})",
            abi_revision.unwrap_or(0)
        )),
        Verdict::NeedsPatch => notes.push(format!(
            "{} legacy TLS signature(s); run `nrodoc patch`",
            legacy.len()
        )),
        Verdict::Patched => notes.push(format!(
            "{} patched TLS signature(s) already present",
            patched.len()
        )),
        Verdict::PatchInsufficient => {
            notes.push("generates code at runtime; likely needs a rebuild, not a patch".into())
        }
        Verdict::Unknown => {
            notes.push("unrecognised build: no TLS signature and no LNY2 marker".into());
        }
    }

    if verdict == Verdict::Unknown {
        notes.push(
            "either non-libnx homebrew, or a libnx build whose thread code does not match \
             any known signature — nrodoc cannot patch it either way"
                .into(),
        );
    }

    if !jit.is_empty() {
        notes.push(format!(
            "maps its own executable memory: {}",
            jit.iter()
                .map(|syscall| syscall.name)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if !legacy.is_empty() && !patched.is_empty() {
        notes.push(format!(
            "partially patched: {} legacy and {} patched signature(s) coexist",
            legacy.len(),
            patched.len()
        ));
    }

    // The headline for a JIT app is the JIT itself, so spell out its TLS state too.
    if verdict == Verdict::PatchInsufficient {
        if !legacy.is_empty() {
            notes.push(format!(
                "{} legacy TLS signature(s) are still patchable, but that may not be sufficient",
                legacy.len()
            ));
        }
        if !patched.is_empty() {
            notes.push(format!(
                "{} patched TLS signature(s) already present",
                patched.len()
            ));
        }
    }

    if abi_revision.is_some() && !legacy.is_empty() {
        notes.push(
            "carries the LNY2 marker yet still contains legacy TLS code — the marker cannot \
             be trusted here"
                .into(),
        );
    }

    if nro.hbmenu_warns() && verdict != Verdict::Unknown {
        notes.push("hbmenu will show the \"unsupported ABI\" warning (no LNY2 marker)".into());
    }

    notes
}

fn unparseable(path: PathBuf, err: NroError) -> Report {
    Report {
        path,
        verdict: Verdict::Unknown,
        name: None,
        author: None,
        version: None,
        abi_revision: None,
        hbmenu_warns: true,
        legacy_hits: Vec::new(),
        patched_hits: Vec::new(),
        jit_syscalls: Vec::new(),
        notes: vec![err.to_string()],
        parse_error: Some(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JIT: &[Syscall] = &[Syscall {
        number: 0x4b,
        name: "svcCreateCodeMemory",
    }];
    const HIT: &[Hit] = &[Hit {
        label: "threadTlsGet()",
        offset: 0x100,
    }];

    #[test]
    fn legacy_code_outranks_everything() {
        assert_eq!(classify(HIT, &[], &[], false), Verdict::NeedsPatch);
        // Even a build claiming the new ABI is broken if it still has legacy code.
        assert_eq!(classify(HIT, &[], &[], true), Verdict::NeedsPatch);
        // Partially patched is still needs-patch.
        assert_eq!(classify(HIT, HIT, &[], false), Verdict::NeedsPatch);
    }

    #[test]
    fn jit_downgrades_both_patchable_states() {
        assert_eq!(classify(HIT, &[], JIT, false), Verdict::PatchInsufficient);
        assert_eq!(classify(&[], HIT, JIT, false), Verdict::PatchInsufficient);
    }

    #[test]
    fn jit_alone_is_not_a_finding() {
        // A modern JIT app with the marker is fine; JIT is only a qualifier.
        assert_eq!(classify(&[], &[], JIT, true), Verdict::Ok);
    }

    #[test]
    fn clean_text_needs_the_marker_to_be_ok() {
        assert_eq!(classify(&[], &[], &[], true), Verdict::Ok);
        assert_eq!(classify(&[], &[], &[], false), Verdict::Unknown);
    }

    #[test]
    fn patched_without_a_marker_is_its_own_state() {
        assert_eq!(classify(&[], HIT, &[], false), Verdict::Patched);
    }

    #[test]
    fn only_ok_and_patched_are_clean() {
        assert!(!Verdict::Ok.is_finding());
        assert!(!Verdict::Patched.is_finding());
        assert!(Verdict::NeedsPatch.is_finding());
        assert!(Verdict::PatchInsufficient.is_finding());
        assert!(Verdict::Unknown.is_finding());
    }
}
