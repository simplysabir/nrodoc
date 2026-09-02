//! Tests against a real .nro. Ignored by default so the suite passes without it:
//!
//! ```sh
//! cargo test -- --ignored
//! ```
//!
//! The fixture is gitignored — it is a third-party build, not ours to redistribute.
//! Ground truth comes from the hbpatcher run that produced it, which logged
//! threadTlsGet/threadTlsSet/threadEntry-LibNX-1 at 0xb9b4e0/0xb9b4f0/0xb9b3a0.

use std::path::Path;

use nrodoc::core::nacp;
use nrodoc::core::nro::Nro;
use nrodoc::core::patterns;

const FIXTURE: &str = "fixtures/local/PPSSPP_GL.nro";

fn load() -> Vec<u8> {
    let path = Path::new(FIXTURE);
    assert!(path.exists(), "missing fixture: {FIXTURE}");
    std::fs::read(path).unwrap()
}

#[test]
#[ignore = "requires the local PPSSPP_GL.nro fixture"]
fn ppsspp_header_and_nacp() {
    let data = load();
    let nro = Nro::parse(&data).unwrap();

    assert_eq!(nro.header.size, 0x14f6000);
    assert_eq!(nro.header.text.file_off, 0);
    assert_eq!(nro.header.text.size, 0xe9b000);
    assert_eq!(
        hex(&nro.header.build_id[..20]),
        "599345599c50219004bf87f18f908416b2754b3f"
    );

    let mod0 = nro.mod0.expect("MOD0 should be found");
    assert_eq!(mod0.offset, 0x118);
    assert!(mod0.lny0, "LNY0 is present");
    assert!(!mod0.lny1, "LNY1 is absent — real code sits where it would be");
    assert_eq!(mod0.lny2_revision, None);
    assert!(nro.hbmenu_warns(), "hbmenu shows the red ABI warning");

    let nacp = nacp::parse(nro.nacp_bytes().expect("NACP asset")).unwrap();
    assert_eq!(nacp.name, "PPSSPP (GL)");
    assert_eq!(nacp.author, "PPSSPP Team. M4xw");
    assert_eq!(nacp.display_version, "v1.17.1");
}

#[test]
#[ignore = "requires the local PPSSPP_GL.nro fixture"]
fn ppsspp_is_already_patched() {
    let data = load();
    let nro = Nro::parse(&data).unwrap();
    let text = nro.text();

    assert!(
        patterns::find_legacy(text).is_empty(),
        "this fixture was already patched, so no legacy signature should remain"
    );

    let hits: Vec<_> = patterns::find_patched(text)
        .into_iter()
        .map(|hit| (hit.label, hit.offset))
        .collect();
    assert_eq!(
        hits,
        vec![
            ("threadEntry() LibNX patch 1", 0xb9b3a0),
            ("threadTlsGet()", 0xb9b4e0),
            ("threadTlsSet()", 0xb9b4f0),
        ]
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
