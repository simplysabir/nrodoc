pub mod table;

use std::path::Path;

/// Paths shown relative to the directory that was scanned, so a deep SD card tree
/// does not repeat the same prefix on every line.
pub fn relative(path: &Path, root: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    // `root` being the file itself strips the path down to nothing.
    if relative.as_os_str().is_empty() {
        path.file_name().unwrap_or(path.as_os_str())
    } else {
        relative.as_os_str()
    }
    .to_string_lossy()
    .into_owned()
}
