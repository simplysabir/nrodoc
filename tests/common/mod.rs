//! Builds minimal but structurally valid NROs, so the scanner can be tested without
//! shipping anyone else's homebrew.
//!
//! Layout produced (mirroring a real libnx NRO, where .text covers the header too):
//!
//! ```text
//! 0x00  NroStart          mod_offset -> 0x80
//! 0x10  NroHeader         .text 0..text_end, .rodata/.data empty at text_end
//! 0x80  MOD0 (+ LNY0/LNY1/LNY2 when an ABI marker is requested)
//! 0xC0  body              instructions under test
//! size  ASET + NACP       when metadata is requested
//! ```

use nrodoc::core::pattern::Pattern;

const HEADER_SIZE: usize = 0x80;
const MOD0_OFFSET: usize = HEADER_SIZE;
const MOD0_SIZE: usize = 0x40;
const BODY_OFFSET: usize = MOD0_OFFSET + MOD0_SIZE;
const NACP_SIZE: usize = 0x4000;
const ASET_HEADER_SIZE: usize = 0x38;

#[derive(Default)]
pub struct NroBuilder {
    body: Vec<u8>,
    abi_revision: Option<u32>,
    nacp: Option<(String, String, String)>,
    omit_mod0: bool,
}

impl NroBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a pattern's literal bytes; wildcard positions stay zero.
    pub fn with_pattern(mut self, pattern: &Pattern) -> Self {
        let offset = self.body.len();
        self.body.resize(offset + pattern.len(), 0);
        pattern.apply(&mut self.body, offset);
        self
    }

    /// Appends raw AArch64 instruction words, e.g. an `svc`.
    pub fn with_words(mut self, words: &[u32]) -> Self {
        for word in words {
            self.body.extend_from_slice(&word.to_le_bytes());
        }
        self
    }

    /// Adds the LNY0/LNY1/LNY2 chain that marks a libnx >= 4.10.0 build.
    pub fn with_abi_marker(mut self, revision: u32) -> Self {
        self.abi_revision = Some(revision);
        self
    }

    pub fn with_nacp(mut self, name: &str, author: &str, version: &str) -> Self {
        self.nacp = Some((name.into(), author.into(), version.into()));
        self
    }

    /// Produces a file with no MOD0 at all, like non-libnx homebrew.
    pub fn without_mod0(mut self) -> Self {
        self.omit_mod0 = true;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let body_len = self.body.len().next_multiple_of(4);
        let image_size = BODY_OFFSET + body_len;

        let mut out = vec![0u8; image_size];
        out[0x04..0x08].copy_from_slice(&(MOD0_OFFSET as u32).to_le_bytes());

        out[0x10..0x14].copy_from_slice(b"NRO0");
        out[0x18..0x1c].copy_from_slice(&(image_size as u32).to_le_bytes());
        // .text spans the whole image; .rodata and .data are empty but in bounds.
        write_segment(&mut out, 0x20, 0, image_size as u32);
        write_segment(&mut out, 0x28, image_size as u32, 0);
        write_segment(&mut out, 0x30, image_size as u32, 0);
        out[0x40..0x54].copy_from_slice(&[0xab; 0x14]); // build id

        if !self.omit_mod0 {
            out[MOD0_OFFSET..MOD0_OFFSET + 4].copy_from_slice(b"MOD0");
            if let Some(revision) = self.abi_revision {
                out[MOD0_OFFSET + 0x1c..MOD0_OFFSET + 0x20].copy_from_slice(b"LNY0");
                out[MOD0_OFFSET + 0x28..MOD0_OFFSET + 0x2c].copy_from_slice(b"LNY1");
                out[MOD0_OFFSET + 0x34..MOD0_OFFSET + 0x38].copy_from_slice(b"LNY2");
                out[MOD0_OFFSET + 0x38..MOD0_OFFSET + 0x3c]
                    .copy_from_slice(&revision.to_le_bytes());
            }
        }

        out[BODY_OFFSET..BODY_OFFSET + self.body.len()].copy_from_slice(&self.body);

        if let Some((name, author, version)) = self.nacp {
            out.extend_from_slice(&aset_header());
            out.extend_from_slice(&nacp_blob(&name, &author, &version));
        }
        out
    }
}

/// Offset of the body within a built file, for asserting on reported hit offsets.
pub const fn body_offset() -> usize {
    BODY_OFFSET
}

fn write_segment(out: &mut [u8], at: usize, file_off: u32, size: u32) {
    out[at..at + 4].copy_from_slice(&file_off.to_le_bytes());
    out[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
}

fn aset_header() -> Vec<u8> {
    let mut aset = vec![0u8; ASET_HEADER_SIZE];
    aset[0x00..0x04].copy_from_slice(b"ASET");
    // icon is empty; the NACP follows the header immediately.
    aset[0x18..0x20].copy_from_slice(&(ASET_HEADER_SIZE as u64).to_le_bytes());
    aset[0x20..0x28].copy_from_slice(&(NACP_SIZE as u64).to_le_bytes());
    aset
}

fn nacp_blob(name: &str, author: &str, version: &str) -> Vec<u8> {
    let mut nacp = vec![0u8; NACP_SIZE];
    nacp[..name.len()].copy_from_slice(name.as_bytes());
    nacp[0x0200..0x0200 + author.len()].copy_from_slice(author.as_bytes());
    nacp[0x3060..0x3060 + version.len()].copy_from_slice(version.as_bytes());
    nacp
}
