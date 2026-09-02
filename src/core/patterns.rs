//! The legacy-ABI signatures, ported byte-for-byte from hbpatcher's `LegacyAbiPatch`
//! (`src/patcher/patches.ts`).
//!
//! libnx before v4.10.0 started its user TLS slots at `+0x108`, inside the region the
//! FW 21.0.0 kernel now uses for `thread_cpu_time`. The fix, in every variant below,
//! is the same: move the access to `+0x180`, the start of the real userland region.
//! See libnx commit cad06c006e4e0caf9c63755ac6c2a10a52333e27.
//!
//! Only the compiled shapes of `threadTlsGet`/`threadTlsSet`/`threadEntry` differ, and
//! only because GCC version and optimisation level move the instructions around.

use std::sync::LazyLock;

use crate::core::pattern::Pattern;

/// One legacy signature and the ABI-correct bytes that replace it. Both forms are
/// scanned for: `legacy` present means "needs patching", `patched` present means
/// "somebody already patched this".
pub struct AbiPattern {
    /// hbpatcher's own label, so nrodoc's log lines are comparable to its.
    pub label: &'static str,
    pub legacy: Pattern,
    pub patched: Pattern,
}

/// Raw specs: (label, legacy, patched). Wildcards (`??`) match any byte and are
/// preserved when patching.
#[rustfmt::skip]
const SPECS: &[(&str, &str, &str)] = &[
    (
        "threadTlsGet()",
        // mrs x1, tpidrro_el0 / add x0, x1, w0,sxtw#3 / ldr x0, [x0,#0x108] / ret
        "61 D0 3B D5  20 CC 20 8B  00 84 40 F9  C0 03 5F D6",
        //                          ldr x0, [x0,#0x180]
        "61 D0 3B D5  20 CC 20 8B  00 C0 40 F9  C0 03 5F D6",
    ),
    (
        "threadTlsSet()",
        // mrs x2, tpidrro_el0 / add x0, x2, w0,sxtw#3 / str x1, [x0,#0x108] / ret
        "62 D0 3B D5  40 CC 20 8B  01 84 00 F9  C0 03 5F D6",
        //                          str x1, [x0,#0x180]
        "62 D0 3B D5  40 CC 20 8B  01 C0 00 F9  C0 03 5F D6",
    ),
    (
        "threadEntry() GCC 15 -O2",
        // ldr x1,[x0,#24] / str x1,[x21,#496] / adrp x1,0 / str x3,[x21,#488]
        // / add x21, x21, #0x108 / ldr x1,[x1]
        "01 0C 40 F9  A1 FA 00 F9  01 00 00 90  A3 F6 00 F9  B5 22 04 91  21 00 40 F9",
        "01 0C 40 F9  A1 FA 00 F9  01 00 00 90  A3 F6 00 F9  B5 02 06 91  21 00 40 F9",
    ),
    (
        "threadEntry() GCC 14 -O2",
        // mrs x21, tpidrro_el0 / ldp x4,x2,[x19,#24] / add x1,x21,#0x1e0
        // / str w5,[x21,#484] / add x21, x21, #0x108
        "75 D0 3B D5  64 8A 41 A9  A1 82 07 91  A5 E6 01 B9  B5 22 04 91",
        "75 D0 3B D5  64 8A 41 A9  A1 82 07 91  A5 E6 01 B9  B5 02 06 91",
    ),
    (
        "threadEntry() GCC 13 and below -O2",
        // mrs x21, tpidrro_el0 / str w2,[x21,#480] / str w5,[x21,#484]
        // / stp x3,x4,[x21,#488] / add x21, x21, #0x108
        "75 D0 3B D5  A2 E2 01 B9  A5 E6 01 B9  A3 92 1E A9  B5 22 04 91",
        "75 D0 3B D5  A2 E2 01 B9  A5 E6 01 B9  A3 92 1E A9  B5 02 06 91",
    ),
    (
        "threadEntry() GCC 15 and below -O1",
        // ldr x0,[x19] / add x21, x21, #0x108 / str x21,[x0,#32] / ldr x0,[x19]
        // / add x1,x20,#8 / str x1,[x0,#48] / ldr x1,[x19] / ldr x0,[x20,#8] / str x0,[x1,#40]
        "60 02 40 F9  B5 22 04 91  15 10 00 F9  60 02 40 F9  81 22 00 91  01 18 00 F9  \
         61 02 40 F9  80 06 40 F9  20 14 00 F9",
        "60 02 40 F9  B5 02 06 91  15 10 00 F9  60 02 40 F9  81 22 00 91  01 18 00 F9  \
         61 02 40 F9  80 06 40 F9  20 14 00 F9",
    ),
    (
        "threadEntry() LibNX patch 1",
        // str w4,[x20,#0x1e0] / ldr x4,[x19,#0x18] / str x3,[x20,#0x1e8] / ldr w3,[x3]
        // / sub x2,x2,#0x10 / stp x4,x2,[x20,#0x1f0] / add x20, x20, #0x108 / str w3,[x20,#0xdc]
        "84 E2 01 B9  64 0E 40 F9  83 F6 00 F9  63 00 40 B9  42 40 00 D1  84 0A 1F A9  \
         94 22 04 91  83 DE 00 B9",
        "84 E2 01 B9  64 0E 40 F9  83 F6 00 F9  63 00 40 B9  42 40 00 D1  84 0A 1F A9  \
         94 02 06 91  83 DE 00 B9",
    ),
    (
        // The only variant where moving the base by +0x78 also has to walk back every
        // displacement that was relative to the old base.
        "threadEntry() LibNX patch 2",
        "02 02 80 D2  F3 53 01 A9  F3 03 00 AA  74 D0 3B D5  94 22 04 91  03 00 40 F9  \
         F5 13 00 F9  81 DA 00 B9  01 0C 40 F9  83 72 00 F9  81 76 00 F9  ?? ?? ?? ??  \
         ?? ?? ?? ??  21 00 40 F9  3F 40 00 F1  21 20 82 9A  02 10 40 F9  ?? ?? ?? ??  \
         ?? ?? ?? ??  41 00 01 CB  81 7A 00 F9  61 00 40 B9  81 DE 00 B9",
        "02 02 80 D2  F3 53 01 A9  F3 03 00 AA  74 D0 3B D5  94 02 06 91  03 00 40 F9  \
         F5 13 00 F9  81 62 00 B9  01 0C 40 F9  83 36 00 F9  81 3A 00 F9  ?? ?? ?? ??  \
         ?? ?? ?? ??  21 00 40 F9  3F 40 00 F1  21 20 82 9A  02 10 40 F9  ?? ?? ?? ??  \
         ?? ?? ?? ??  41 00 01 CB  81 3E 00 F9  61 00 40 B9  81 66 00 B9",
    ),
];

static PATTERNS: LazyLock<Vec<AbiPattern>> = LazyLock::new(|| {
    SPECS
        .iter()
        .map(|&(label, legacy, patched)| {
            let legacy = Pattern::parse(legacy).expect("legacy pattern literal is malformed");
            let patched = Pattern::parse(patched).expect("patched pattern literal is malformed");
            assert!(
                legacy.same_shape(&patched),
                "{label}: legacy and patched forms must have identical length and wildcards"
            );
            AbiPattern {
                label,
                legacy,
                patched,
            }
        })
        .collect()
});

pub fn all() -> &'static [AbiPattern] {
    &PATTERNS
}

/// A signature found in a `.text` slice, at an offset relative to that slice.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Hit {
    pub label: &'static str,
    pub offset: usize,
}

/// Every legacy signature in `text`. Non-empty means the binary predates libnx 4.10.0
/// and will be corrupted by the FW 21.0.0 kernel.
pub fn find_legacy(text: &[u8]) -> Vec<Hit> {
    find(text, |p| &p.legacy)
}

/// Every already-patched signature in `text`. Non-empty with no legacy hits means
/// somebody ran hbpatcher (or nrodoc) over this file.
pub fn find_patched(text: &[u8]) -> Vec<Hit> {
    find(text, |p| &p.patched)
}

fn find(text: &[u8], pick: fn(&AbiPattern) -> &Pattern) -> Vec<Hit> {
    let mut hits: Vec<Hit> = all()
        .iter()
        .flat_map(|p| {
            pick(p).find_all(text).into_iter().map(|offset| Hit {
                label: p.label,
                offset,
            })
        })
        .collect();
    hits.sort_by_key(|hit| hit.offset);
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Places `pattern`'s literal bytes at an aligned offset in an otherwise blank buffer.
    fn buffer_with(spec: &str, offset: usize) -> Vec<u8> {
        let pattern = Pattern::parse(spec).unwrap();
        let mut buf = vec![0u8; offset + pattern.len() + 64];
        pattern.apply(&mut buf, offset);
        buf
    }

    #[test]
    fn every_spec_parses_and_the_two_forms_agree_in_length() {
        assert_eq!(all().len(), SPECS.len());
    }

    #[test]
    fn each_legacy_form_is_found_and_only_it() {
        for (label, legacy, _) in SPECS {
            let buf = buffer_with(legacy, 16);
            let hits = find_legacy(&buf);
            assert_eq!(hits.len(), 1, "{label}: expected exactly one legacy hit");
            assert_eq!(hits[0].label, *label);
            assert_eq!(hits[0].offset, 16);
            assert!(
                find_patched(&buf).is_empty(),
                "{label}: legacy bytes must not look already-patched"
            );
        }
    }

    #[test]
    fn each_patched_form_is_found_and_only_it() {
        for (label, _, patched) in SPECS {
            let buf = buffer_with(patched, 16);
            let hits = find_patched(&buf);
            assert_eq!(hits.len(), 1, "{label}: expected exactly one patched hit");
            assert_eq!(hits[0].label, *label);
            assert!(
                find_legacy(&buf).is_empty(),
                "{label}: patched bytes must not look legacy"
            );
        }
    }

    #[test]
    fn patching_a_legacy_form_produces_the_patched_form() {
        for (label, legacy, _) in SPECS {
            let mut buf = buffer_with(legacy, 16);
            let entry = all().iter().find(|p| p.label == *label).unwrap();
            entry.patched.apply(&mut buf, 16);

            assert!(find_legacy(&buf).is_empty(), "{label}: legacy bytes remain");
            assert_eq!(
                find_patched(&buf).len(),
                1,
                "{label}: not recognised as patched"
            );
        }
    }

    #[test]
    fn wildcard_bytes_survive_patching() {
        // LibNX patch 2 is the only spec with wildcards.
        let entry = all()
            .iter()
            .find(|p| p.label == "threadEntry() LibNX patch 2")
            .unwrap();
        let mut buf = buffer_with(SPECS[7].1, 0);
        // Wildcard slots are instructions 11-12 and 17-18 (bytes 44..52 and 68..76).
        let sentinel: Vec<u8> = (0..8).map(|i| 0xa0 + i).collect();
        buf[44..52].copy_from_slice(&sentinel);
        buf[68..76].copy_from_slice(&sentinel);

        assert_eq!(find_legacy(&buf).len(), 1, "wildcards must match any bytes");
        entry.patched.apply(&mut buf, 0);
        assert_eq!(&buf[44..52], &sentinel[..]);
        assert_eq!(&buf[68..76], &sentinel[..]);
    }

    #[test]
    fn no_signature_matches_a_different_signature() {
        for (label, legacy, patched) in SPECS {
            for form in [legacy, patched] {
                let buf = buffer_with(form, 0);
                let hits: Vec<_> = find_legacy(&buf)
                    .into_iter()
                    .chain(find_patched(&buf))
                    .collect();
                assert_eq!(hits.len(), 1, "{label}: signature is ambiguous: {hits:?}");
            }
        }
    }
}
