//! NACP (`control.nacp`) parsing — just the three fields worth reporting.
//!
//! Offsets per libnx `switch/nacp.h` / switchbrew:
//!
//! ```text
//! 0x0000  NacpLanguageEntry lang[16]   // { char name[0x200]; char author[0x100]; }
//! 0x3060  char display_version[0x10]
//! 0x3215  u8   titles_data_format      // [21.0.0+] 1 = lang entries are DEFLATE-compressed
//! ```

use serde::Serialize;

pub const NACP_SIZE: usize = 0x4000;

const LANG_ENTRY_COUNT: usize = 16;
const LANG_ENTRY_SIZE: usize = 0x300;
const NAME_SIZE: usize = 0x200;
const AUTHOR_SIZE: usize = 0x100;
const DISPLAY_VERSION_OFFSET: usize = 0x3060;
const DISPLAY_VERSION_SIZE: usize = 0x10;
const TITLES_DATA_FORMAT_OFFSET: usize = 0x3215;

#[derive(Debug, Clone, Serialize)]
pub struct Nacp {
    pub name: String,
    pub author: String,
    pub display_version: String,
    /// [21.0.0+] title strings are DEFLATE-compressed, so `name`/`author` are empty.
    /// nacptool never emits this, but a real NACP copied out of a game would.
    pub titles_compressed: bool,
}

/// Returns `None` if the blob is too short to be a NACP.
pub fn parse(data: &[u8]) -> Option<Nacp> {
    if data.len() < TITLES_DATA_FORMAT_OFFSET + 1 {
        return None;
    }

    let titles_compressed = data[TITLES_DATA_FORMAT_OFFSET] == 1;
    let (name, author) = if titles_compressed {
        (String::new(), String::new())
    } else {
        first_populated_language(data)
    };

    Some(Nacp {
        name,
        author,
        display_version: cstr(&data[DISPLAY_VERSION_OFFSET..][..DISPLAY_VERSION_SIZE]),
        titles_compressed,
    })
}

/// Homebrew fills every language entry identically, but a NACP with only some
/// languages populated leaves the unused ones zeroed — take the first real one.
fn first_populated_language(data: &[u8]) -> (String, String) {
    (0..LANG_ENTRY_COUNT)
        .map(|i| {
            let entry = &data[i * LANG_ENTRY_SIZE..][..LANG_ENTRY_SIZE];
            (
                cstr(&entry[..NAME_SIZE]),
                cstr(&entry[NAME_SIZE..][..AUTHOR_SIZE]),
            )
        })
        .find(|(name, author)| !name.is_empty() || !author.is_empty())
        .unwrap_or_default()
}

/// UTF-8 up to the first NUL. Lossy: a corrupt NACP should not fail a scan.
fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}
