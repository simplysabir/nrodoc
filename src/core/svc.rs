//! AArch64 `svc` scanning, used to spot homebrew that maps its own executable memory.
//!
//! `svc #imm16` encodes as `0xD4000001 | (imm16 << 5)`, so the syscalls a binary can
//! make are readable straight out of `.text` with no disassembler. libnx emits each
//! wrapper into its own `.text.<name>` section, so `--gc-sections` drops the ones the
//! program never calls — a syscall being present is evidence, not noise.

use std::collections::BTreeSet;

use serde::Serialize;

const SVC_MASK: u32 = 0xffe0_001f;
const SVC_BASE: u32 = 0xd400_0001;

/// The syscalls libnx's `jitCreate` uses, by either of its two strategies
/// (`kernel/jit.c`): CodeMemory objects on [4.0.0+], or process memory permissions.
pub const JIT_SYSCALLS: &[Syscall] = &[
    Syscall::new(0x4b, "svcCreateCodeMemory"),
    Syscall::new(0x4c, "svcControlCodeMemory"),
    Syscall::new(0x73, "svcSetProcessMemoryPermission"),
    Syscall::new(0x77, "svcMapProcessCodeMemory"),
    Syscall::new(0x78, "svcUnmapProcessCodeMemory"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Syscall {
    pub number: u16,
    pub name: &'static str,
}

impl Syscall {
    const fn new(number: u16, name: &'static str) -> Self {
        Syscall { number, name }
    }
}

/// Decodes a 32-bit word as `svc #imm16`.
pub fn decode(word: u32) -> Option<u16> {
    (word & SVC_MASK == SVC_BASE).then_some(((word >> 5) & 0xffff) as u16)
}

/// Every distinct syscall number reachable from `text`.
pub fn syscalls(text: &[u8]) -> BTreeSet<u16> {
    text.chunks_exact(4)
        .filter_map(|word| decode(u32::from_le_bytes(word.try_into().unwrap())))
        .collect()
}

/// The JIT/W^X syscalls this binary links, if any. A non-empty result means the
/// program rewrites executable memory at runtime, which the TLS patch cannot fix.
pub fn jit_syscalls(text: &[u8]) -> Vec<Syscall> {
    let present = syscalls(text);
    JIT_SYSCALLS
        .iter()
        .copied()
        .filter(|svc| present.contains(&svc.number))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `svc 0x4b` assembles to 0xD4000961.
    #[test]
    fn decodes_the_known_encoding() {
        assert_eq!(decode(0xd400_0961), Some(0x4b));
        assert_eq!(decode(0xd400_0021), Some(0x01));
        assert_eq!(decode(0xd400_0f01), Some(0x78));
    }

    #[test]
    fn rejects_non_svc_words() {
        assert_eq!(decode(0xd65f_03c0), None); // ret
        assert_eq!(decode(0xd53b_d061), None); // mrs x1, tpidrro_el0
        assert_eq!(decode(0xd400_0962), None); // svc opcode field is wrong
    }

    #[test]
    fn finds_jit_syscalls_and_ignores_the_rest() {
        let mut text = Vec::new();
        for word in [0xd65f_03c0u32, 0xd400_0961, 0xd400_0021, 0xd400_0ee1] {
            text.extend_from_slice(&word.to_le_bytes());
        }

        assert_eq!(syscalls(&text), BTreeSet::from([0x01, 0x4b, 0x77]));
        assert_eq!(
            jit_syscalls(&text),
            vec![
                Syscall::new(0x4b, "svcCreateCodeMemory"),
                Syscall::new(0x77, "svcMapProcessCodeMemory"),
            ]
        );
    }

    #[test]
    fn ignores_unaligned_and_trailing_bytes() {
        // The svc word sits at offset 2, so no aligned read sees it.
        let mut text = vec![0x00, 0x00];
        text.extend_from_slice(&0xd400_0961u32.to_le_bytes());
        text.push(0x00);
        assert!(jit_syscalls(&text).is_empty());
    }
}
