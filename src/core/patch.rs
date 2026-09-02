//! Applying the ABI patch.
//!
//! The transformation is hbpatcher's, byte for byte: each legacy signature is
//! overwritten with its ABI-correct form, which only ever changes TLS displacements
//! within instructions already there. Nothing moves, nothing resizes, and the file
//! stays exactly the same length.
//!
//! No marker is written. hbpatcher deliberately leaves the LNY2 field alone, and so
//! does nrodoc: forging it would silence hbmenu's warning on a binary that is still
//! a patched legacy build rather than a proper rebuild.

use serde::Serialize;

use crate::core::nro::{Nro, NroError};
use crate::core::patterns;

#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    // The reason lives in the source, so `{:#}` does not print it twice.
    #[error("not a valid NRO")]
    Parse(#[from] NroError),
    #[error("no legacy TLS signature found — nothing to patch")]
    NothingToPatch,
    #[error("patched output no longer parses as an NRO")]
    VerifyParse(#[source] NroError),
    #[error("{0} legacy signature(s) survived patching; the file was left untouched")]
    VerifyIncomplete(usize),
}

/// One signature rewritten, at an offset relative to the start of `.text`.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Application {
    pub label: &'static str,
    pub offset: usize,
}

/// Rewrites every legacy signature in `data` and verifies the result.
///
/// On any error `data` is left as it was, so a caller can hand it a buffer it
/// intends to write out and only write when this returns `Ok`.
pub fn patch(data: &mut [u8]) -> Result<Vec<Application>, PatchError> {
    let text = text_range(data)?;

    // Collect first: the search borrows `data`, the rewrite needs it mutable.
    let plan: Vec<(usize, usize)> = patterns::all()
        .iter()
        .enumerate()
        .flat_map(|(index, entry)| {
            entry
                .legacy
                .find_all(&data[text.clone()])
                .into_iter()
                .map(move |offset| (index, offset))
        })
        .collect();

    if plan.is_empty() {
        return Err(PatchError::NothingToPatch);
    }

    let mut applied: Vec<Application> = plan
        .iter()
        .map(|&(index, offset)| {
            let entry = &patterns::all()[index];
            entry.patched.apply(&mut data[text.clone()], offset);
            Application {
                label: entry.label,
                offset,
            }
        })
        .collect();
    applied.sort_by_key(|application| application.offset);

    verify(data).inspect_err(|_| revert(data, &text, &plan))?;
    Ok(applied)
}

/// Re-reads the patched bytes from scratch: the header must still be valid and no
/// legacy signature may remain anywhere in `.text`.
fn verify(data: &[u8]) -> Result<(), PatchError> {
    let nro = Nro::parse(data).map_err(PatchError::VerifyParse)?;
    let remaining = patterns::find_legacy(nro.text()).len();
    if remaining > 0 {
        return Err(PatchError::VerifyIncomplete(remaining));
    }
    Ok(())
}

/// Puts the legacy bytes back, so a failed patch leaves the caller's buffer untouched.
fn revert(data: &mut [u8], text: &std::ops::Range<usize>, plan: &[(usize, usize)]) {
    for &(index, offset) in plan {
        patterns::all()[index]
            .legacy
            .apply(&mut data[text.clone()], offset);
    }
}

fn text_range(data: &[u8]) -> Result<std::ops::Range<usize>, PatchError> {
    let nro = Nro::parse(data)?;
    let start = nro.header.text.file_off as usize;
    Ok(start..start + nro.header.text.size as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_a_file_with_nothing_to_patch() {
        // A buffer that parses is required first; anything shorter fails earlier.
        let mut data = vec![0u8; 0x100];
        data[0x10..0x14].copy_from_slice(b"NRO0");
        data[0x18..0x1c].copy_from_slice(&0x100u32.to_le_bytes());
        data[0x24..0x28].copy_from_slice(&0x100u32.to_le_bytes());

        assert!(matches!(patch(&mut data), Err(PatchError::NothingToPatch)));
    }

    #[test]
    fn refuses_a_file_that_is_not_an_nro() {
        let mut data = vec![0u8; 0x100];
        assert!(matches!(patch(&mut data), Err(PatchError::Parse(_))));
    }
}
