# Registry Segment Hashing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the exact domain-separated identity and segment hashes with independently calculated byte fixtures, as the first testable storage primitive.

**Architecture:** Pure hashing functions in the new registry-event-store library module; no filesystem or registry runtime changes. A fixed complete segment fixture verifies the normative 158-byte header and hash domain without relying on a production encoder to generate expected results. Header parsing, bounded body streaming, private storage, joint checkpoints, migration, and real-network validation remain separate required implementation slices under the parent specification.

**Tech Stack:** Existing Rust workspace, existing `sha2` dependency, built-in Rust tests; Python standard-library calculations used only to independently derive golden values.

This is an AI-assisted implementation plan. Parent: `docs/superpowers/specs/2026-09-06-registry-event-segments-design.md`, reviewed revision `56d13d8083be748fda54ad4cec6f2447f0b514f4d93b7f0e80d86331e87320c0`. Do not execute before independent design approval. This slice does not resolve the registry's full-snapshot performance defect by itself.

## Acceptance and boundaries

- Exact SHA-256 domains, NUL separator, little-endian u64 UTF-8 byte lengths, and lowercase fixture hashes match the parent format.
- Job and peer identities use different domains even for identical input.
- Strings are hashed as their exact UTF-8 bytes, not normalized text or character counts.
- Complete segment bytes include both header and body, without an additional length prefix.
- These functions calculate digests only; they do not claim to validate a segment, authorize an actor, or make storage durable.
- Existing dependencies only; no service restart, identity writes, deployment, migration, or modifications to frozen transport logic.
- Demonstrate assertion-level RED before implementing, then GREEN and independent specification/quality reviews. Implementer does not self-review or self-merge under project AGENTS rules.

## Task 1: Domain-separated hashes and independent golden segment

**Files:**

- Create: `src/registry_event_store.rs` (pure digest helpers and unit tests).
- Modify: `src/lib.rs` (one module declaration adjacent to existing out-of-line modules).
- Test: unit module in `src/registry_event_store.rs`.

- [x] Add the module declaration and these deliberately inert signatures so tests compile; do not implement hashing yet.

```rust
// src/lib.rs
pub mod registry_event_store;

// src/registry_event_store.rs: initial RED scaffolding
pub fn job_binding(_identity: &str) -> [u8; 32] { [0; 32] }
pub fn peer_binding(_identity: &str) -> [u8; 32] { [0; 32] }
pub fn segment_digest(_bytes: &[u8]) -> [u8; 32] { [0; 32] }
```

- [x] Append these tests. The golden complete file encodes store bytes 0 through 15, job `job-1`, Apple peer `agent-1`, no predecessor, first+last flags, one nonterminal `started` event with sequence 1 and empty payload. Its body has 39 bytes and its file has 197 bytes.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len()).step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn identity_domains_match_independent_vectors() {
        assert_eq!(hex(&job_binding("job-1")),
            "152b89d57e78a7a7475270aa99a54aad45409c77f90988ffa96e8813e0b26255");
        assert_eq!(hex(&peer_binding("agent-1")),
            "f01c81ae896053ba02fffce4efa1ca03cb5ba993cc7cfc9916e34deca2c55667");
        assert_ne!(job_binding("same"), peer_binding("same"));
    }

    #[test]
    fn identity_length_counts_utf8_bytes_without_normalization() {
        assert_eq!(hex(&job_binding("\u{e9}")),
            "bb92c81172aa135c0de3de5f455ccfac37d6912a6e58dc49a11365af225ccbf6");
        assert_ne!(job_binding("\u{e9}"), job_binding("e\u{301}"));
        assert_ne!(job_binding("a\0b"), job_binding("ab"));
    }

    #[test]
    fn complete_segment_matches_independent_golden_digest() {
        let bytes = unhex(concat!(
            "444c534547303031000102030405060708090a0b0c0d0e0f",
            "152b89d57e78a7a7475270aa99a54aad45409c77f90988ffa96e8813e0b26255",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "01f01c81ae896053ba02fffce4efa1ca03cb5ba993cc7cfc9916e34deca2c55667",
            "03010000000000000001000000000000000100000000000000000000000000000027000000",
            "010000000000000001000000000000000700000000000000737461727465640000000000000000"
        ));
        assert_eq!(bytes.len(), 158 + 39);
        assert_eq!(hex(&segment_digest(&bytes)),
            "90c170d10d11a5d05911de2c024d7e520831e08517de488aa9287eef531e6969");
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert_ne!(segment_digest(&changed), segment_digest(&bytes), "byte {index}");
        }
    }
}
```

- [x] Run `rtk cargo test --locked --lib registry_event_store -- --nocapture`. On Windows use the established MSVC developer shell and `E:/CodexBuild/devicelane-task10-ci` target directory. Require three failing assertions against all-zero hashes, not a missing module, malformed hex, or compiler error. Preserve terminal output before continuing.

- [x] Replace only the three inert functions with the following implementation; keep the tests unchanged.

```rust
use sha2::{Digest, Sha256};

fn identity_binding(domain: &[u8], identity: &str) -> [u8; 32] {
    let length = u64::try_from(identity.len())
        .expect("supported platforms have at most 64-bit string lengths");
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(length.to_le_bytes());
    hash.update(identity.as_bytes());
    hash.finalize().into()
}

/// Calculate the storage binding of an exact UTF-8 job identity.
pub fn job_binding(identity: &str) -> [u8; 32] {
    identity_binding(b"DeviceLane/event-job/v1", identity)
}

/// Calculate the storage binding of an exact UTF-8 Apple-agent identity.
pub fn peer_binding(identity: &str) -> [u8; 32] {
    identity_binding(b"DeviceLane/event-peer/v1", identity)
}

/// Hash complete segment bytes; this does not validate their structure or origin.
pub fn segment_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DeviceLane/event-segment/v1\0");
    hash.update(bytes);
    hash.finalize().into()
}
```

- [x] Rerun the same test command: require 3 PASS. Run `rtk cargo test --locked --lib`, `rtk cargo clippy --locked --lib --tests -- -D warnings`, `rtk cargo fmt --all -- --check`, and `rtk git diff --check`. Distinguish actual test completion from a shell wrapper that still holds output pipes; do not restart a live build due solely to an observation timeout.
- [x] Hand off the exact source diff and RED/GREEN logs for independent specification review, followed by quality review. Do not self-certify the security properties of these hashes.

Independent specification review: PASS. Independent quality review: READY, no Critical/Important/Minor findings. Both reviewers separately reproduced the fixed digests; root reran all 30 library tests and Clippy successfully. This approval is limited to the pure hashing module and its declaration.
- [ ] After both reviews approve, the controller may stage only the new module, its single declaration hunk, and the reviewed plan/spec documentation. `src/lib.rs` already contains unrelated uncommitted transport changes: never stage that entire file blindly. Commit this coherent slice only if the resulting index excludes those unapproved changes; otherwise keep it uncommitted until the broader transport review clears.

## Coverage handoff

This plan covers domain separation and one exact header/body golden fixture. It intentionally provides no header decoder, fragment writer, private-file adapter, runtime commit integration, migration, or scale claim. Those are still mandatory parts of the parent specification and must receive their own complete code-level tasks before implementation. The full DeviceLane product objective remains unchanged.
