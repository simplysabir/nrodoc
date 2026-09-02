//! Masked byte-pattern matching, ported from hbpatcher's `PatternMatcher`.
//!
//! Two deliberate differences from hbpatcher:
//!
//! * matches must be 4-byte aligned within the searched slice — every pattern is a
//!   run of AArch64 instructions, so an unaligned hit is by definition a false one;
//! * [`Pattern::find_all`] returns every occurrence, not just the first.

use memchr::memmem;

/// Mask byte meaning "this byte must match"; `0x00` means wildcard.
const MATCH: u8 = 0xff;

#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("pattern has an odd number of hex digits")]
    OddLength,
    #[error("invalid hex byte {0:?} in pattern")]
    BadByte(String),
    #[error("pattern is entirely wildcards")]
    AllWildcards,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    /// Longest run of non-wildcard bytes, used as the search anchor.
    anchor: std::ops::Range<usize>,
}

impl Pattern {
    /// Parses `"61 D0 3B D5 ?? ?? ?? ??"`. Whitespace is ignored, `??` is a wildcard.
    pub fn parse(spec: &str) -> Result<Self, PatternError> {
        let clean: String = spec.chars().filter(|c| !c.is_whitespace()).collect();
        if !clean.len().is_multiple_of(2) {
            return Err(PatternError::OddLength);
        }

        let mut bytes = Vec::with_capacity(clean.len() / 2);
        let mut mask = Vec::with_capacity(clean.len() / 2);
        for pair in clean.as_bytes().chunks(2) {
            let pair = std::str::from_utf8(pair).map_err(|_| PatternError::BadByte(clean.clone()))?;
            if pair == "??" {
                bytes.push(0);
                mask.push(0);
            } else {
                bytes.push(
                    u8::from_str_radix(pair, 16)
                        .map_err(|_| PatternError::BadByte(pair.to_string()))?,
                );
                mask.push(MATCH);
            }
        }

        let anchor = longest_match_run(&mask).ok_or(PatternError::AllWildcards)?;
        Ok(Pattern {
            bytes,
            mask,
            anchor,
        })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Every 4-byte-aligned offset in `haystack` where this pattern matches.
    pub fn find_all(&self, haystack: &[u8]) -> Vec<usize> {
        let anchor = &self.bytes[self.anchor.clone()];
        memmem::find_iter(haystack, anchor)
            .filter_map(|hit| hit.checked_sub(self.anchor.start))
            .filter(|start| start.is_multiple_of(4))
            .filter(|&start| self.matches_at(haystack, start))
            .collect()
    }

    pub fn matches_at(&self, haystack: &[u8], offset: usize) -> bool {
        let Some(window) = haystack.get(offset..offset + self.bytes.len()) else {
            return false;
        };
        std::iter::zip(window, std::iter::zip(&self.bytes, &self.mask))
            .all(|(&got, (&want, &mask))| got & mask == want & mask)
    }

    /// Writes this pattern's non-wildcard bytes at `offset`, leaving wildcard
    /// positions untouched. Panics if the write would run past the end of `buf`.
    pub fn apply(&self, buf: &mut [u8], offset: usize) {
        let window = &mut buf[offset..offset + self.bytes.len()];
        for (slot, (&byte, &mask)) in
            std::iter::zip(window, std::iter::zip(&self.bytes, &self.mask))
        {
            if mask == MATCH {
                *slot = byte;
            }
        }
    }
}

fn longest_match_run(mask: &[u8]) -> Option<std::ops::Range<usize>> {
    let mut best: Option<std::ops::Range<usize>> = None;
    let mut start = None;
    for (i, &m) in mask.iter().enumerate() {
        match (m == MATCH, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                best = longer(best, s..i);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        best = longer(best, s..mask.len());
    }
    best
}

fn longer(
    best: Option<std::ops::Range<usize>>,
    candidate: std::ops::Range<usize>,
) -> Option<std::ops::Range<usize>> {
    match best {
        Some(b) if b.len() >= candidate.len() => Some(b),
        _ => Some(candidate),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bytes_and_wildcards() {
        let p = Pattern::parse("AA ?? bb").unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p.bytes, [0xaa, 0x00, 0xbb]);
        assert_eq!(p.mask, [0xff, 0x00, 0xff]);
    }

    #[test]
    fn rejects_malformed_specs() {
        assert!(matches!(
            Pattern::parse("A"),
            Err(PatternError::OddLength)
        ));
        assert!(matches!(
            Pattern::parse("zz"),
            Err(PatternError::BadByte(_))
        ));
        assert!(matches!(
            Pattern::parse("?? ??"),
            Err(PatternError::AllWildcards)
        ));
    }

    #[test]
    fn anchor_is_the_longest_literal_run() {
        // Runs of 1 and 3; the 3-byte run wins.
        let p = Pattern::parse("aa ?? bb cc dd ??").unwrap();
        assert_eq!(p.anchor, 2..5);
    }

    #[test]
    fn finds_every_aligned_occurrence() {
        let p = Pattern::parse("de ad be ef").unwrap();
        let mut hay = vec![0u8; 32];
        hay[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        hay[20..24].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(p.find_all(&hay), vec![4, 20]);
    }

    #[test]
    fn ignores_unaligned_occurrences() {
        let p = Pattern::parse("de ad be ef").unwrap();
        let mut hay = vec![0u8; 32];
        hay[6..10].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(p.find_all(&hay).is_empty());
    }

    #[test]
    fn wildcards_match_anything_and_survive_apply() {
        let p = Pattern::parse("aa ?? ?? dd").unwrap();
        let mut hay = vec![0x11, 0x22, 0x33, 0x44, 0xaa, 0x99, 0x88, 0xdd];
        assert_eq!(p.find_all(&hay), vec![4]);

        let replacement = Pattern::parse("bb ?? ?? ee").unwrap();
        replacement.apply(&mut hay, 4);
        assert_eq!(hay[4..], [0xbb, 0x99, 0x88, 0xee]);
    }

    #[test]
    fn does_not_match_past_the_end() {
        let p = Pattern::parse("de ad be ef").unwrap();
        assert!(!p.matches_at(&[0xde, 0xad], 0));
    }
}
