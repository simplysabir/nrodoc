//! NRO container parsing: header, segments, MOD0 (+ libnx LNY extensions), ASET assets.
//!
//! Layout per switchbrew and libnx `switch/nro.h`:
//!
//! ```text
//! 0x00  NroStart   { u32 unused; u32 mod_offset; u8 pad[8]; }
//! 0x10  NroHeader  { u32 magic "NRO0"; u32 version; u32 size; u32 flags;
//!                    NroSegment segments[3];   // { u32 file_off; u32 size; }
//!                    u32 bss_size; u32 reserved; u8 build_id[0x20]; u8 pad[0x20]; }
//! size  NroAssetHeader (optional) { u32 magic "ASET"; u32 version;
//!                    NroAssetSection icon, nacp, romfs; }  // { u64 offset; u64 size; }
//! ```

use serde::Serialize;

pub const NRO_MAGIC: [u8; 4] = *b"NRO0";
pub const MOD0_MAGIC: [u8; 4] = *b"MOD0";
pub const LNY0_MAGIC: [u8; 4] = *b"LNY0";
pub const LNY1_MAGIC: [u8; 4] = *b"LNY1";
pub const LNY2_MAGIC: [u8; 4] = *b"LNY2";
pub const ASET_MAGIC: [u8; 4] = *b"ASET";

/// Offset of the LNY2 magic within MOD0. nx-hbmenu reads the ABI revision from
/// `NroStart.mod_offset + 0x34` (`nx_main/nx_launch.c`).
pub const MOD0_LNY2_OFFSET: usize = 0x34;

/// `NRO_ABI_CURRENT_REVISION` in nx-hbmenu `common/menu.h`. Anything below this
/// gets the red "does not support the current ABI" warning in the menu.
pub const HBMENU_ABI_REVISION: u32 = 1;

const NRO_HEADER_OFFSET: usize = 0x10;
const MOD0_SIZE: usize = 0x40;
const ASET_HEADER_SIZE: usize = 0x38;

#[derive(Debug, thiserror::Error)]
pub enum NroError {
    #[error("file is too small to be an NRO ({0} bytes)")]
    TooSmall(usize),
    #[error("bad magic at 0x10: expected NRO0, found {0:02x?}")]
    BadMagic([u8; 4]),
    #[error("NRO image size {size:#x} exceeds the file size {file_len:#x}")]
    ImageTooLarge { size: u32, file_len: usize },
    #[error("{name} segment (offset {off:#x}, size {size:#x}) extends past the {limit:#x}-byte image")]
    SegmentOutOfBounds {
        name: &'static str,
        off: u32,
        size: u32,
        limit: usize,
    },
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Segment {
    pub file_off: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct NroHeader {
    pub version: u32,
    /// Size of the NRO image proper; assets, if any, start here.
    pub size: u32,
    pub flags: u32,
    pub text: Segment,
    pub rodata: Segment,
    pub data: Segment,
    pub bss_size: u32,
    pub build_id: [u8; 0x20],
}

/// MOD0 plus the libnx homebrew extensions (`switch_crt0.s`).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Mod0 {
    /// File offset of the MOD0 magic.
    pub offset: usize,
    pub dynamic: i32,
    pub bss_start: i32,
    pub bss_end: i32,
    pub eh_frame_hdr_start: i32,
    pub eh_frame_hdr_end: i32,
    pub module_object: i32,
    pub lny0: bool,
    pub lny1: bool,
    /// LNY2 revision, present only on libnx builds carrying the new-ABI marker.
    pub lny2_revision: Option<u32>,
}

impl Mod0 {
    /// Whether hbmenu considers this binary ABI-current, by hbmenu's own rule.
    pub fn abi_current(&self) -> bool {
        self.lny2_revision
            .is_some_and(|rev| rev >= HBMENU_ABI_REVISION)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct AssetSection {
    /// Relative to the start of the asset header.
    pub offset: u64,
    pub size: u64,
}

impl AssetSection {
    pub fn is_present(&self) -> bool {
        self.size != 0
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Assets {
    /// File offset of the ASET magic.
    pub offset: usize,
    pub version: u32,
    pub icon: AssetSection,
    pub nacp: AssetSection,
    pub romfs: AssetSection,
}

/// A parsed NRO borrowing the whole file buffer.
#[derive(Debug)]
pub struct Nro<'a> {
    data: &'a [u8],
    /// `NroStart.mod_offset`, as written by crt0.
    pub mod_offset: u32,
    pub header: NroHeader,
    pub mod0: Option<Mod0>,
    pub assets: Option<Assets>,
}

impl<'a> Nro<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, NroError> {
        // Enough for NroStart + the full NroHeader.
        if data.len() < 0x80 {
            return Err(NroError::TooSmall(data.len()));
        }

        let magic: [u8; 4] = data[NRO_HEADER_OFFSET..NRO_HEADER_OFFSET + 4]
            .try_into()
            .unwrap();
        if magic != NRO_MAGIC {
            return Err(NroError::BadMagic(magic));
        }

        let mod_offset = u32_at(data, 0x04);
        let size = u32_at(data, 0x18);
        if size as usize > data.len() {
            return Err(NroError::ImageTooLarge {
                size,
                file_len: data.len(),
            });
        }

        let segment = |off: usize| Segment {
            file_off: u32_at(data, off),
            size: u32_at(data, off + 4),
        };
        let header = NroHeader {
            version: u32_at(data, 0x14),
            size,
            flags: u32_at(data, 0x1c),
            text: segment(0x20),
            rodata: segment(0x28),
            data: segment(0x30),
            bss_size: u32_at(data, 0x38),
            build_id: data[0x40..0x60].try_into().unwrap(),
        };

        // Segments are offsets into the image, not the file: assets live past `size`.
        let limit = size as usize;
        for (name, seg) in [
            ("text", header.text),
            ("rodata", header.rodata),
            ("data", header.data),
        ] {
            let end = seg.file_off as u64 + seg.size as u64;
            if end > limit as u64 {
                return Err(NroError::SegmentOutOfBounds {
                    name,
                    off: seg.file_off,
                    size: seg.size,
                    limit,
                });
            }
        }

        let mod0 = parse_mod0(data, mod_offset, header.text);
        let assets = parse_assets(data, limit);

        Ok(Nro {
            data,
            mod_offset,
            header,
            mod0,
            assets,
        })
    }

    pub fn text(&self) -> &'a [u8] {
        self.segment_bytes(self.header.text)
    }

    pub fn rodata(&self) -> &'a [u8] {
        self.segment_bytes(self.header.rodata)
    }

    pub fn data(&self) -> &'a [u8] {
        self.segment_bytes(self.header.data)
    }

    /// The raw NACP blob from the asset section, if the NRO carries one.
    pub fn nacp_bytes(&self) -> Option<&'a [u8]> {
        let assets = self.assets?;
        if !assets.nacp.is_present() {
            return None;
        }
        let start = assets.offset.checked_add(assets.nacp.offset as usize)?;
        let end = start.checked_add(assets.nacp.size as usize)?;
        self.data.get(start..end)
    }

    /// Whether hbmenu will show the "unsupported ABI" warning for this file.
    pub fn hbmenu_warns(&self) -> bool {
        !self.mod0.is_some_and(|m| m.abi_current())
    }

    fn segment_bytes(&self, seg: Segment) -> &'a [u8] {
        // Bounds were validated in `parse`.
        &self.data[seg.file_off as usize..(seg.file_off + seg.size) as usize]
    }
}

/// MOD0 normally sits at `NroStart.mod_offset`. If that doesn't point at the magic,
/// fall back to scanning the first 0x20 bytes of .text, as hbpatcher does.
fn parse_mod0(data: &[u8], mod_offset: u32, text: Segment) -> Option<Mod0> {
    let offset = std::iter::once(mod_offset as usize)
        .chain((0..0x20).step_by(4).map(|i| text.file_off as usize + i))
        .find(|&off| {
            data.get(off..off + 4)
                .is_some_and(|magic| magic == MOD0_MAGIC)
        })?;
    if data.len() < offset + MOD0_SIZE {
        return None;
    }

    // The LNY extensions are chained: each one's presence is only meaningful if the
    // previous magic is there too, since otherwise we would be reading real code.
    let lny0 = data[offset + 0x1c..offset + 0x20] == LNY0_MAGIC;
    let lny1 = lny0 && data[offset + 0x28..offset + 0x2c] == LNY1_MAGIC;
    let lny2 = lny1 && data[offset + MOD0_LNY2_OFFSET..offset + MOD0_LNY2_OFFSET + 4] == LNY2_MAGIC;

    Some(Mod0 {
        offset,
        dynamic: i32_at(data, offset + 0x04),
        bss_start: i32_at(data, offset + 0x08),
        bss_end: i32_at(data, offset + 0x0c),
        eh_frame_hdr_start: i32_at(data, offset + 0x10),
        eh_frame_hdr_end: i32_at(data, offset + 0x14),
        module_object: i32_at(data, offset + 0x18),
        lny0,
        lny1,
        lny2_revision: lny2.then(|| u32_at(data, offset + 0x38)),
    })
}

fn parse_assets(data: &[u8], image_size: usize) -> Option<Assets> {
    if data.get(image_size..image_size + 4)? != ASET_MAGIC {
        return None;
    }
    if data.len() < image_size + ASET_HEADER_SIZE {
        return None;
    }

    let section = |off: usize| AssetSection {
        offset: u64_at(data, image_size + off),
        size: u64_at(data, image_size + off + 8),
    };
    Some(Assets {
        offset: image_size,
        version: u32_at(data, image_size + 0x04),
        icon: section(0x08),
        nacp: section(0x18),
        romfs: section(0x28),
    })
}

/// Panics if out of bounds; every call site checks the length first.
fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}

fn i32_at(data: &[u8], off: usize) -> i32 {
    u32_at(data, off) as i32
}

fn u64_at(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}
