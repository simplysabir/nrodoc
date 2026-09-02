//! Finding the files to scan.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Extensions treated as homebrew binaries. `.ovl` files are Tesla overlays, which
/// are NROs too and break in exactly the same way.
pub const EXTENSIONS: &[&str] = &["nro", "ovl"];

#[derive(Debug, Default)]
pub struct Walk {
    pub files: Vec<PathBuf>,
    /// Directories that could not be read. Reported rather than silently skipped:
    /// an unreadable directory means the scan is incomplete, and saying "all clear"
    /// when part of the card was never looked at would be a lie.
    pub errors: Vec<String>,
}

/// Collects the files to scan. An explicit file path is taken as-is whatever its
/// extension; a directory is walked recursively for [`EXTENSIONS`].
///
/// Symlinks are not followed — an SD card mounted on a desktop can contain links
/// pointing anywhere, and a scan should stay inside what the user pointed at.
pub fn collect(root: &Path) -> Walk {
    if root.is_file() {
        return Walk {
            files: vec![root.to_path_buf()],
            errors: Vec::new(),
        };
    }

    let mut walk = Walk::default();
    for entry in WalkDir::new(root).follow_links(false) {
        match entry {
            Ok(entry) if entry.file_type().is_file() && has_scanned_extension(entry.path()) => {
                walk.files.push(entry.into_path());
            }
            Ok(_) => {}
            Err(err) => walk.errors.push(err.to_string()),
        }
    }
    walk.files.sort();
    walk
}

fn has_scanned_extension(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| EXTENSIONS.iter().any(|want| ext.eq_ignore_ascii_case(want)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_both_extensions_case_insensitively() {
        assert!(has_scanned_extension(Path::new("a/b.nro")));
        assert!(has_scanned_extension(Path::new("a/b.NRO")));
        assert!(has_scanned_extension(Path::new("a/b.ovl")));
        assert!(!has_scanned_extension(Path::new("a/b.nsp")));
        assert!(!has_scanned_extension(Path::new("a/nro")));
    }
}
