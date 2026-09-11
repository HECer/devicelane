# Registry Segment Header Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Encode and validate the fixed segment header and reject invalid physical segment extents without copying the body.

**Architecture:** Add a focused codec submodule beneath the event-store module, re-exporting its small header/extent API. Existing hash helpers remain unchanged. This slice checks individual physical records; chain traversal, event reconstruction, authorization, private file I/O, and checkpoint durability remain required subsequent work.

**Tech Stack:** Rust standard library and the existing event-store digest helper for the independent golden test.

AI-assisted plan. Parent specification: `docs/superpowers/specs/2026-09-06-registry-event-segments-design.md` (independently reviewed, two wording corrections applied). Start only after the preceding hashing slice passes specification and quality review. Use the existing isolated `speechwalker-remote-builds` worktree; preserve all unrelated uncommitted transport changes. No deployment or live identity/service access.

## Acceptance

- Fixed 158-byte header offsets and little-endian integers exactly match the normative specification and independent 197-byte golden segment.
- Reject header lengths other than 158, wrong magic, origins outside 1–4, unknown flag bits, terminal nonfinal records, inconsistent first/index fields, nonfirst zero predecessors, non-Apple nonzero actor bindings, empty/oversized bodies, and short nonfinal bodies.
- Empty batches require zero first/last sequence, a single first+last part, and an eight-byte body. One-event batches require identical first/last sequence summaries. Larger legacy batches may retain gaps and stored sequence order; do not impose strict new-Apple sequencing here.
- A physical record is bounded to 158 + 524,288 bytes, must exactly match its body length, and returns a borrowed body slice. No record-body allocation or unchecked declared-length allocation.
- Header validation is not authentication, hash validation, event parsing, chain validation, or proof of durable storage. State that boundary in documentation.
- Tests first with observed assertion RED, then GREEN and independent two-stage review. No commits by the implementer.

## Task 1: Header codec and borrowed physical record view

**Files:**

- Create `src/registry_event_store/codec.rs`.
- Modify `src/registry_event_store.rs` only to declare/re-export the codec.
- Tests live in `src/registry_event_store/codec.rs`.

- [x] Add the constants and type below, plus inert methods with the same signatures returning `Err(invalid())`, and append the tests in the next step. The inert methods are only RED scaffolding, not a partially implemented decoder.

```rust
use std::io;

pub const HEADER_BYTES: usize = 158;
pub const MAX_BODY_BYTES: usize = 524_288;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentHeader {
    pub store_id: [u8; 16],
    pub job: [u8; 32],
    pub predecessor: [u8; 32],
    pub origin: u8,
    pub actor: [u8; 32],
    pub flags: u8,
    pub event_count: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub part_index: u64,
    pub body_length: u32,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid event segment header or extent")
}

// Initial RED methods: replace with the complete methods below after recording RED.
impl SegmentHeader {
    pub fn encode(&self) -> io::Result<[u8; HEADER_BYTES]> { Err(invalid()) }
    pub fn decode(_bytes: &[u8]) -> io::Result<Self> { Err(invalid()) }
}
pub fn decode_segment(_bytes: &[u8]) -> io::Result<(SegmentHeader, &[u8])> {
    Err(invalid())
}
```

In `src/registry_event_store.rs`, before its existing test module:

```rust
mod codec;
pub use codec::{HEADER_BYTES, MAX_BODY_BYTES, SegmentHeader, decode_segment};
```

- [x] Append this complete test module. Run the positive tests first so the inert implementation produces assertion-level RED; rejection tests alone would pass against a reject-everything implementation.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_event_store::{job_binding, peer_binding, segment_digest};

    fn header() -> SegmentHeader {
        SegmentHeader {
            store_id: std::array::from_fn(|index| index as u8),
            job: job_binding("job-1"), predecessor: [0; 32], origin: 1,
            actor: peer_binding("agent-1"), flags: 3, event_count: 1,
            first_sequence: 1, last_sequence: 1, part_index: 0, body_length: 39,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn body() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        bytes.extend_from_slice(&7_u64.to_le_bytes());
        bytes.extend_from_slice(b"started");
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes
    }

    #[test]
    fn header_matches_independent_complete_segment_digest() {
        let expected = header();
        let encoded = expected.encode().expect("valid header must encode");
        let mut file = encoded.to_vec();
        file.extend_from_slice(&body());
        assert_eq!(file.len(), 197);
        assert_eq!(hex(&segment_digest(&file)),
            "90c170d10d11a5d05911de2c024d7e520831e08517de488aa9287eef531e6969");
        assert_eq!(SegmentHeader::decode(&encoded).unwrap(), expected);
        let (decoded, view) = decode_segment(&file).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(view, body());
        assert_eq!(view.as_ptr(), file[HEADER_BYTES..].as_ptr());
    }

    #[test]
    fn maximum_body_and_integer_fields_round_trip() {
        let mut expected = header();
        expected.predecessor = [7; 32];
        expected.flags = 2;
        expected.part_index = u64::MAX;
        expected.event_count = u64::MAX;
        expected.first_sequence = u64::MAX;
        expected.last_sequence = 0;
        expected.body_length = MAX_BODY_BYTES as u32;
        let bytes = expected.encode().unwrap();
        assert_eq!(SegmentHeader::decode(&bytes).unwrap(), expected);
        let mut file = bytes.to_vec();
        file.resize(HEADER_BYTES + MAX_BODY_BYTES, 0);
        assert_eq!(decode_segment(&file).unwrap().1.len(), MAX_BODY_BYTES);
        file.push(0);
        assert!(decode_segment(&file).is_err());
    }

    #[test]
    fn empty_generic_terminal_and_full_nonfinal_parts_are_valid() {
        let mut empty = header();
        empty.origin = 3; empty.actor = [0; 32]; empty.flags = 7;
        empty.event_count = 0; empty.first_sequence = 0; empty.last_sequence = 0;
        empty.body_length = 8;
        assert_eq!(SegmentHeader::decode(&empty.encode().unwrap()).unwrap(), empty);
        let mut first = header();
        first.flags = 1; first.body_length = MAX_BODY_BYTES as u32;
        assert!(first.encode().is_ok());
        first.flags = 0; first.part_index = 1; first.predecessor = [1; 32];
        assert!(first.encode().is_ok());
    }

    #[test]
    fn malformed_header_fields_are_rejected() {
        let valid = header().encode().unwrap();
        let cases = [(0, 0), (88, 0), (88, 5), (121, 0x83), (121, 5),
            (121, 2), (146, 1), (88, 3), (154, 0), (157, 1)];
        for (offset, value) in cases {
            let mut bad = valid;
            bad[offset] = value;
            assert!(SegmentHeader::decode(&bad).is_err(), "offset {offset}: {value}");
        }
        for length in 0..HEADER_BYTES {
            assert!(SegmentHeader::decode(&valid[..length]).is_err());
        }
        let mut extra = valid.to_vec(); extra.push(0);
        assert!(SegmentHeader::decode(&extra).is_err());
        let mut bad = header(); bad.flags = 1;
        assert!(bad.encode().is_err());
        bad = header(); bad.flags = 2; bad.part_index = 1;
        assert!(bad.encode().is_err());
        bad = header(); bad.event_count = 0;
        assert!(bad.encode().is_err());
        bad = header(); bad.last_sequence = 2;
        assert!(bad.encode().is_err());
    }

    #[test]
    fn physical_extent_rejects_every_truncation_and_trailing_data() {
        let mut file = header().encode().unwrap().to_vec();
        file.extend_from_slice(&body());
        for length in 0..file.len() {
            assert!(decode_segment(&file[..length]).is_err(), "length {length}");
        }
        file.push(0);
        assert!(decode_segment(&file).is_err());
    }

    #[test]
    fn distinct_integer_fields_have_exact_little_endian_offsets() {
        let mut expected = header();
        expected.origin = 4;
        expected.actor = [0; 32];
        expected.predecessor = [7; 32];
        expected.flags = 2;
        expected.event_count = 0x0102030405060708;
        expected.first_sequence = 0x1112131415161718;
        expected.last_sequence = 0x2122232425262728;
        expected.part_index = 0x3132333435363738;
        expected.body_length = 0x010203;
        let encoded = expected.encode().unwrap();
        assert_eq!(&encoded[122..130], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&encoded[130..138], &[24, 23, 22, 21, 20, 19, 18, 17]);
        assert_eq!(&encoded[138..146], &[40, 39, 38, 37, 36, 35, 34, 33]);
        assert_eq!(&encoded[146..154], &[56, 55, 54, 53, 52, 51, 50, 49]);
        assert_eq!(&encoded[154..158], &[3, 2, 1, 0]);
        assert_eq!(SegmentHeader::decode(&encoded).unwrap(), expected);
    }
}
```

- [x] Run `rtk cargo test --locked --lib registry_event_store::codec -- --nocapture` in the established Windows MSVC developer shell with target `E:/CodexBuild/devicelane-task10-ci`. Record terminal failure caused by valid headers being rejected, not fixture/compiler problems. The previous hashing tests must still pass.

- [x] Replace the inert methods/functions with this implementation. Preserve constants/type/error helper and all tests. The fixed offsets are derived from the normative header table; no allocation occurs in decode.

```rust
impl SegmentHeader {
    fn validate(&self) -> io::Result<()> {
        let first = self.flags & 1 != 0;
        let last = self.flags & 2 != 0;
        let terminal = self.flags & 4 != 0;
        if !(1..=4).contains(&self.origin)
            || (self.origin != 1 && self.actor != [0; 32])
            || self.flags & !7 != 0 || (terminal && !last)
            || first != (self.part_index == 0)
            || (!first && self.predecessor == [0; 32])
            || self.body_length == 0 || self.body_length > MAX_BODY_BYTES as u32
            || (!last && self.body_length != MAX_BODY_BYTES as u32)
            || (self.event_count == 0 && (!first || !last || self.body_length != 8
                || self.first_sequence != 0 || self.last_sequence != 0))
            || (self.event_count == 1 && self.first_sequence != self.last_sequence)
        { return Err(invalid()); }
        Ok(())
    }

    /// Encode a locally consistent physical header, not a validated event chain.
    pub fn encode(&self) -> io::Result<[u8; HEADER_BYTES]> {
        self.validate()?;
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(b"DLSEG001");
        bytes[8..24].copy_from_slice(&self.store_id);
        bytes[24..56].copy_from_slice(&self.job);
        bytes[56..88].copy_from_slice(&self.predecessor);
        bytes[88] = self.origin;
        bytes[89..121].copy_from_slice(&self.actor);
        bytes[121] = self.flags;
        bytes[122..130].copy_from_slice(&self.event_count.to_le_bytes());
        bytes[130..138].copy_from_slice(&self.first_sequence.to_le_bytes());
        bytes[138..146].copy_from_slice(&self.last_sequence.to_le_bytes());
        bytes[146..154].copy_from_slice(&self.part_index.to_le_bytes());
        bytes[154..158].copy_from_slice(&self.body_length.to_le_bytes());
        Ok(bytes)
    }

    /// Validate exactly one physical header; identity and chain binding are separate.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != HEADER_BYTES || &bytes[..8] != b"DLSEG001" {
            return Err(invalid());
        }
        let header = Self {
            store_id: bytes[8..24].try_into().map_err(|_| invalid())?,
            job: bytes[24..56].try_into().map_err(|_| invalid())?,
            predecessor: bytes[56..88].try_into().map_err(|_| invalid())?,
            origin: bytes[88],
            actor: bytes[89..121].try_into().map_err(|_| invalid())?,
            flags: bytes[121],
            event_count: u64::from_le_bytes(bytes[122..130].try_into().map_err(|_| invalid())?),
            first_sequence: u64::from_le_bytes(bytes[130..138].try_into().map_err(|_| invalid())?),
            last_sequence: u64::from_le_bytes(bytes[138..146].try_into().map_err(|_| invalid())?),
            part_index: u64::from_le_bytes(bytes[146..154].try_into().map_err(|_| invalid())?),
            body_length: u32::from_le_bytes(bytes[154..158].try_into().map_err(|_| invalid())?),
        };
        header.validate()?;
        Ok(header)
    }
}

/// Validate the physical extent and borrow its body; no event/hash/authorization check.
pub fn decode_segment(bytes: &[u8]) -> io::Result<(SegmentHeader, &[u8])> {
    if !(HEADER_BYTES..=HEADER_BYTES + MAX_BODY_BYTES).contains(&bytes.len()) {
        return Err(invalid());
    }
    let header = SegmentHeader::decode(&bytes[..HEADER_BYTES])?;
    let body_length = usize::try_from(header.body_length).map_err(|_| invalid())?;
    let total = HEADER_BYTES.checked_add(body_length).ok_or_else(invalid)?;
    if bytes.len() != total { return Err(invalid()); }
    Ok((header, &bytes[HEADER_BYTES..]))
}
```

- [x] Rerun `rtk cargo test --locked --lib registry_event_store -- --nocapture`: require nine passing tests (three existing hashing plus six codec). Run full `rtk cargo test --locked --lib`, `rtk cargo clippy --locked --lib --tests -- -D warnings`, `rtk cargo fmt --all -- --check`, and `rtk git diff --check`. Formatting the new module is permitted; do not reformat unrelated files.
- [x] Request independent specification review, then independent quality review, including malformed-input panic safety and no-body-copy evidence. Implementer reports exact RED/GREEN output and does not self-review, commit, or deploy.

Review record: independent SPEC PASS and final QUALITY READY, no remaining Critical/Important/Minor findings, for `codec.rs` SHA-256 `de4c2774e75d98167164c17dc874d4bb6fd85784e99bcf070bd9ddef5a2e9fbf` and its parent re-exports. Root independently reran all 36 library tests, Clippy, and formatting successfully. The mutation described below was removed before final verification; no production mutation remains.

Quality-review correction: the initial five codec fixtures had identical count and first-sequence values. Prove the additional sixth test detects a symmetric offset swap by temporarily exchanging count/first offsets in both encode and decode: the initial eight event-store tests stay green, the new distinct-field test fails, and restoring the exact production implementation makes all nine pass. Retain no production mutation. The existing independent golden vector already detects a global LE-to-BE conversion because value 1 is not endian-invariant; do not misreport that as an uncovered global endianness defect.

## Parent coverage still open

This slice adds header encoding/decoding and per-record bounds. It does not prove event reconstruction, chain integrity, authenticated assignment, owner-private publication, single-writer locking, joint state/lease commit, downgrade safety, linear storage cost, or real Mac operation. Keep those parent acceptance gates open; no whole-store or product readiness claim follows from these nine tests.
