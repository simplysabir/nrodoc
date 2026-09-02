//! End-to-end verdicts over synthetic NROs — the CI-safe half of the suite.

mod common;

use std::path::PathBuf;

use common::NroBuilder;
use nrodoc::core::verdict::{Verdict, analyze};
use nrodoc::core::walk;
use nrodoc::core::{patch, patterns};

/// `svc 0x4b` (svcCreateCodeMemory), the cheapest JIT tell.
const SVC_CREATE_CODE_MEMORY: u32 = 0xd400_0961;

fn verdict_of(data: &[u8]) -> Verdict {
    analyze(PathBuf::from("synthetic.nro"), data).verdict
}

#[test]
fn every_legacy_signature_needs_a_patch() {
    for pattern in patterns::all() {
        let nro = NroBuilder::new()
            .with_pattern(&pattern.legacy)
            .with_abi_marker(1)
            .build();
        assert_eq!(
            verdict_of(&nro),
            Verdict::NeedsPatch,
            "{}: legacy code must outrank the ABI marker",
            pattern.label
        );
    }
}

#[test]
fn every_patched_signature_reads_as_patched() {
    for pattern in patterns::all() {
        let nro = NroBuilder::new().with_pattern(&pattern.patched).build();
        assert_eq!(
            verdict_of(&nro),
            Verdict::Patched,
            "{}: patched bytes without a marker are their own state",
            pattern.label
        );
    }
}

#[test]
fn hits_are_reported_at_their_offset_in_text() {
    let pattern = &patterns::all()[0];
    let nro = NroBuilder::new().with_pattern(&pattern.legacy).build();
    let report = analyze(PathBuf::from("synthetic.nro"), &nro);

    assert_eq!(report.legacy_hits.len(), 1);
    assert_eq!(report.legacy_hits[0].offset, common::body_offset());
    assert_eq!(report.legacy_hits[0].label, pattern.label);
}

#[test]
fn a_clean_build_with_the_marker_is_ok() {
    let nro = NroBuilder::new().with_abi_marker(1).build();
    assert_eq!(verdict_of(&nro), Verdict::Ok);
}

#[test]
fn a_clean_build_without_the_marker_is_unknown() {
    assert_eq!(verdict_of(&NroBuilder::new().build()), Verdict::Unknown);
    assert_eq!(
        verdict_of(&NroBuilder::new().without_mod0().build()),
        Verdict::Unknown
    );
}

#[test]
fn a_jit_app_with_legacy_code_may_need_more_than_a_patch() {
    let nro = NroBuilder::new()
        .with_pattern(&patterns::all()[0].legacy)
        .with_words(&[SVC_CREATE_CODE_MEMORY])
        .build();
    assert_eq!(verdict_of(&nro), Verdict::PatchInsufficient);
}

#[test]
fn a_jit_app_that_is_already_current_is_still_ok() {
    let nro = NroBuilder::new()
        .with_words(&[SVC_CREATE_CODE_MEMORY])
        .with_abi_marker(1)
        .build();
    assert_eq!(verdict_of(&nro), Verdict::Ok);
}

#[test]
fn nacp_metadata_reaches_the_report() {
    let nro = NroBuilder::new()
        .with_abi_marker(1)
        .with_nacp("Test App", "somebody", "v2.3")
        .build();
    let report = analyze(PathBuf::from("synthetic.nro"), &nro);

    assert_eq!(report.name.as_deref(), Some("Test App"));
    assert_eq!(report.author.as_deref(), Some("somebody"));
    assert_eq!(report.version.as_deref(), Some("v2.3"));
    assert_eq!(report.display_name(), "Test App");
}

#[test]
fn a_report_without_a_nacp_falls_back_to_the_file_stem() {
    let report = analyze(
        PathBuf::from("sd/switch/dbi.nro"),
        &NroBuilder::new().build(),
    );
    assert_eq!(report.display_name(), "dbi");
}

#[test]
fn malformed_files_are_reported_not_dropped() {
    for (case, data) in [
        ("empty", Vec::new()),
        ("truncated", NroBuilder::new().build()[..0x40].to_vec()),
        ("bad magic", {
            let mut nro = NroBuilder::new().build();
            nro[0x10] = b'X';
            nro
        }),
        ("segment past the image", {
            let mut nro = NroBuilder::new().build();
            nro[0x24..0x28].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
            nro
        }),
        ("image larger than the file", {
            let mut nro = NroBuilder::new().build();
            nro[0x18..0x1c].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
            nro
        }),
    ] {
        let report = analyze(PathBuf::from("broken.nro"), &data);
        assert_eq!(report.verdict, Verdict::Unknown, "{case}");
        assert!(report.parse_error.is_some(), "{case}: reason must be kept");
    }
}

#[test]
fn patching_a_legacy_build_reproduces_the_patched_build_byte_for_byte() {
    for pattern in patterns::all() {
        let mut legacy = NroBuilder::new()
            .with_pattern(&pattern.legacy)
            .with_nacp("App", "author", "1.0")
            .build();
        let expected = NroBuilder::new()
            .with_pattern(&pattern.patched)
            .with_nacp("App", "author", "1.0")
            .build();

        let applied = patch::patch(&mut legacy).expect(pattern.label);
        assert_eq!(applied.len(), 1, "{}", pattern.label);
        assert_eq!(applied[0].label, pattern.label);
        assert_eq!(applied[0].offset, common::body_offset());
        assert_eq!(
            legacy, expected,
            "{}: patching must change nothing but the signature",
            pattern.label
        );
        assert_eq!(verdict_of(&legacy), Verdict::Patched, "{}", pattern.label);
    }
}

#[test]
fn patching_rewrites_every_occurrence_not_just_the_first() {
    let pattern = &patterns::all()[0];
    let mut nro = NroBuilder::new()
        .with_pattern(&pattern.legacy)
        .with_words(&[0xd503_201f]) // nop, to keep the two copies apart
        .with_pattern(&pattern.legacy)
        .build();

    let applied = patch::patch(&mut nro).unwrap();
    assert_eq!(applied.len(), 2);
    assert!(patterns::find_legacy(&nro).is_empty());
}

#[test]
fn patching_an_already_patched_build_changes_nothing() {
    let mut nro = NroBuilder::new()
        .with_pattern(&patterns::all()[0].patched)
        .build();
    let before = nro.clone();

    assert!(matches!(
        patch::patch(&mut nro),
        Err(patch::PatchError::NothingToPatch)
    ));
    assert_eq!(nro, before, "a refused patch must not touch the buffer");
}

#[test]
fn walking_a_tree_finds_nro_and_ovl_only() {
    let dir = std::env::temp_dir().join("nrodoc-walk-test");
    let nested = dir.join("switch").join(".overlays");
    std::fs::create_dir_all(&nested).unwrap();
    for (path, body) in [
        (dir.join("app.nro"), &b"x"[..]),
        (nested.join("ovlmenu.ovl"), &b"x"[..]),
        (dir.join("notes.txt"), &b"x"[..]),
        (dir.join("game.nsp"), &b"x"[..]),
    ] {
        std::fs::write(path, body).unwrap();
    }

    let walk = walk::collect(&dir);
    let found: Vec<_> = walk
        .files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();

    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(found, vec!["app.nro", "ovlmenu.ovl"]);
    assert!(walk.errors.is_empty());
}
