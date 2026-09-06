# Registry Fragment Writer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stream a logical event batch into bounded hash-linked physical segment bytes without a second whole-batch serialization buffer.

**Architecture:** A private `Write` adapter holds one header/body buffer and synchronously lends each completed segment to a fallible callback. The adapter delays emission of a full body until another byte arrives, so an exactly full final body is marked final without an empty extra segment. Persistence, authentication, checkpoint publication and recovery remain separate callers.

**Tech Stack:** Existing Rust standard I/O, `NetworkEvent`, `SegmentHeader`, `segment_digest` and `write_event_batch`; no dependencies.

AI-assisted implementation plan under the reviewed registry-event-segments design. Work in the existing `speechwalker-remote-builds` worktree. Parent hash/header/body primitives are committed through `222c84d`. Preserve unrelated transport edits and real user data.

## Acceptance and scope

- Each body is 1..=524288 bytes; every nonfinal body is exactly 524288. No total event-output cap.
- One reusable buffer has length/capacity bounded by 158+524288 bytes. It includes reserved header space; no intermediate full-body copy in production.
- First part links to the caller's previous committed tail. Subsequent parts link to the digest of the immediately preceding bytes and have checked increasing indices. The callback receives the digest and borrowed exact header/body bytes.
- Derive count/first/last summaries from the borrowed input events; do not trust caller-supplied summaries. Store/job/origin/actor remain identical throughout the batch. Terminal is set on final part only.
- Validate origin and actor before any callback. Preserve Unicode, legacy order and zero/max sequences. Do not add Apple authorization or sequence normalization here.
- Stop immediately on callback failure, return the original error, and return no successful tail. Already emitted parts may be orphans; this function never claims a commit or deletes them. The callback must durably publish private immutable bytes before returning success when used by storage integration.
- Tests reconstruct original events by concatenating validated test bodies only. That test collection is not the production buffering strategy. Full recovery-chain validation, private file publication, locks, metadata/lease transactions, migration and performance acceptance are not completed by this writer.

## Task 1: Streaming physical fragment writer

**Files:**

- Create `src/registry_event_store/fragments.rs` with implementation and unit tests.
- Modify `src/registry_event_store.rs` only to add `mod fragments; pub use fragments::{BatchBinding, write_event_segments};` before its tests.

- [x] Add the following types, inert function and tests. Assertion RED was verified in a corrective pass; see the process deviation recorded below.

```rust
use std::io::{self, Write};
use crate::network_processes::NetworkEvent;
use super::{HEADER_BYTES, MAX_BODY_BYTES, SegmentHeader, segment_digest, write_event_batch};

pub struct BatchBinding {
    pub store_id: [u8; 16],
    pub job: [u8; 32],
    pub predecessor: [u8; 32],
    pub origin: u8,
    pub actor: [u8; 32],
}

pub fn write_event_segments<F>(
    _binding: BatchBinding, _events: &[NetworkEvent], _terminal: bool, _emit: F,
) -> io::Result<[u8; 32]>
where F: FnMut([u8; 32], &[u8]) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::InvalidData, "fragment writer absent"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_event_store::{decode_segment, job_binding, peer_binding, read_event_batch};

    fn binding() -> BatchBinding {
        BatchBinding { store_id: std::array::from_fn(|i| i as u8),
            job: job_binding("job-1"), predecessor: [9;32], origin: 1,
            actor: peer_binding("agent-1") }
    }
    fn event(sequence: u64, kind: &str, payload: String) -> NetworkEvent {
        NetworkEvent { sequence, kind: kind.into(), payload }
    }
    fn collect(events: &[NetworkEvent], terminal: bool) -> Vec<Vec<u8>> {
        let mut parts = Vec::new();
        let mut previous = [9;32];
        let tail = write_event_segments(binding(), events, terminal, |digest, bytes| {
            assert_eq!(digest, segment_digest(bytes));
            assert!(bytes.len() <= HEADER_BYTES + MAX_BODY_BYTES);
            let (header, _) = decode_segment(bytes)?;
            assert_eq!(header.predecessor, previous);
            assert_eq!(header.part_index, parts.len() as u64);
            assert_eq!(header.flags & 1 != 0, parts.is_empty());
            assert_eq!(header.store_id, binding().store_id);
            assert_eq!(header.job, binding().job);
            assert_eq!(header.origin, 1);
            assert_eq!(header.actor, binding().actor);
            assert_eq!(header.event_count, events.len() as u64);
            assert_eq!(header.first_sequence, events.first().map_or(0, |e| e.sequence));
            assert_eq!(header.last_sequence, events.last().map_or(0, |e| e.sequence));
            previous = digest; parts.push(bytes.to_vec()); Ok(())
        }).unwrap();
        assert_eq!(tail, previous);
        let mut body = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let (header, bytes) = decode_segment(part).unwrap();
            let last = i + 1 == parts.len();
            assert_eq!(header.flags & 2 != 0, last);
            assert_eq!(header.flags & 4 != 0, last && terminal);
            if !last { assert_eq!(bytes.len(), MAX_BODY_BYTES); }
            body.extend_from_slice(bytes);
        }
        assert_eq!(read_event_batch(&mut body.as_slice(), body.len() as u64).unwrap(), events);
        parts
    }

    #[test]
    fn empty_and_exact_full_final_body_have_no_extra_part() {
        for terminal in [false, true] {
            let empty = collect(&[], terminal);
            assert_eq!(empty.len(), 1);
            assert_eq!(empty[0].len(), HEADER_BYTES + 8);
            // Count plus one event's three integers = 32 bytes, empty kind.
            let full = collect(&[event(7, "", "x".repeat(MAX_BODY_BYTES-32))], terminal);
            assert_eq!(full.len(), 1);
            assert_eq!(full[0].len(), HEADER_BYTES + MAX_BODY_BYTES);
        }
    }
    #[test]
    fn one_byte_overflow_and_large_legacy_event_round_trip() {
        let parts = collect(&[event(0, "", "x".repeat(MAX_BODY_BYTES-31))], true);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len(), HEADER_BYTES + 1);
        let events = [event(u64::MAX, "legacy", "é\0\"\n".repeat(300_000)),
            event(0, "", "e\u{301}".into())];
        assert!(collect(&events, true).len() >= 3);
    }
    #[test]
    fn length_prefix_and_unicode_can_cross_physical_boundary() {
        // Payload length starts at 24 + kind.len(), with four bytes in part 0.
        let kind = "k".repeat(MAX_BODY_BYTES-28);
        let prefix = collect(&[event(1, &kind, "z".into())], false);
        let (_, first) = decode_segment(&prefix[0]).unwrap();
        let (_, second) = decode_segment(&prefix[1]).unwrap();
        assert_eq!(&first[MAX_BODY_BYTES-4..], &[1,0,0,0]);
        assert_eq!(&second[..4], &[0,0,0,0]);
        // Payload starts at 32, placing the first UTF-8 byte last in part 0.
        let payload = format!("{}é", "x".repeat(MAX_BODY_BYTES-33));
        let unicode = collect(&[event(1, "", payload)], false);
        let (_, first) = decode_segment(&unicode[0]).unwrap();
        let (_, second) = decode_segment(&unicode[1]).unwrap();
        assert_eq!(first[MAX_BODY_BYTES-1], 0xc3);
        assert_eq!(second[0], 0xa9);
    }
    #[test]
    fn started_segment_retains_independent_golden_hash() {
        let mut source = binding(); source.predecessor = [0;32];
        let tail = write_event_segments(source, &[event(1,"started",String::new())], false,
            |_, bytes| { assert_eq!(bytes.len(),197); Ok(()) }).unwrap();
        let hex: String = tail.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex,"90c170d10d11a5d05911de2c024d7e520831e08517de488aa9287eef531e6969");
    }
    #[test]
    fn invalid_binding_is_rejected_before_emission() {
        for origin in [0,2,3,4,5] {
            let mut source = binding(); source.origin = origin;
            let mut calls = 0;
            assert!(write_event_segments(source, &[], false, |_,_| {calls+=1; Ok(())}).is_err());
            assert_eq!(calls,0);
        }
        for origin in [2,3,4] {
            let mut source = binding(); source.origin=origin; source.actor=[0;32];
            assert!(write_event_segments(source,&[],false,|_,_| Ok(())).is_ok());
        }
    }
    #[test]
    fn callback_failure_stops_without_a_successful_tail() {
        let events = [event(1,"","x".repeat(3*MAX_BODY_BYTES))];
        for (fail_at, kind) in [(1,io::ErrorKind::PermissionDenied),
            (2,io::ErrorKind::PermissionDenied),(4,io::ErrorKind::PermissionDenied),
            (2,io::ErrorKind::Interrupted)] {
            let mut calls=0;
            let error=write_event_segments(binding(),&events,true,|_,_| {
                calls+=1;
                if calls==fail_at { Err(io::Error::new(kind,"sink denied")) }
                else { Ok(()) }
            }).unwrap_err();
            assert_eq!(calls,fail_at);
            assert_eq!(error.kind(),kind);
            assert_eq!(error.to_string(),"sink denied");
        }
    }
}
```

- [x] Run `cargo test --locked --jobs 1 --lib registry_event_store::fragments -- --nocapture` in the established VS2022 developer shell with `CARGO_TARGET_DIR=E:/CodexBuild/devicelane-task10-ci`. Require assertion failures from inert behavior, not compiler errors. Use `rtk` prefix and `login:false`; never restart a live build on observation timeout.

- [x] Replace only the inert function with the implementation below; retain the type, imports and tests.

```rust
/// Emits bounded physical parts. The callback must publish each part privately
/// and immutably with required durability before returning success. A successful
/// tail is not a checkpoint commit; on failure prior emitted parts may be orphans.
pub fn write_event_segments<F>(
    binding: BatchBinding, events: &[NetworkEvent], terminal: bool, emit: F,
) -> io::Result<[u8;32]>
where F: FnMut([u8;32], &[u8]) -> io::Result<()> {
    let header = SegmentHeader {
        store_id: binding.store_id, job: binding.job, predecessor: binding.predecessor,
        origin: binding.origin, actor: binding.actor, flags: 3,
        event_count: u64::try_from(events.len()).map_err(|_| invalid())?,
        first_sequence: events.first().map_or(0, |e| e.sequence),
        last_sequence: events.last().map_or(0, |e| e.sequence),
        part_index: 0, body_length: 8,
    };
    // Validate binding before any callback; final extent is set when emitting.
    header.encode()?;
    let mut buffer = Vec::with_capacity(HEADER_BYTES + MAX_BODY_BYTES);
    buffer.resize(HEADER_BYTES, 0);
    let mut writer = FragmentWriter { header, terminal, buffer, emit, failure: None };
    if let Err(error) = write_event_batch(&mut writer, events) {
        return Err(writer.failure.take().unwrap_or(error));
    }
    writer.emit_part(true)
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid event fragment")
}

struct FragmentWriter<F> {
    header: SegmentHeader,
    terminal: bool,
    buffer: Vec<u8>,
    emit: F,
    failure: Option<io::Error>,
}

impl<F: FnMut([u8;32], &[u8]) -> io::Result<()>> FragmentWriter<F> {
    fn emit_part(&mut self, last: bool) -> io::Result<[u8;32]> {
        self.header.body_length = u32::try_from(self.buffer.len()-HEADER_BYTES)
            .map_err(|_| invalid())?;
        self.header.flags = u8::from(self.header.part_index==0)
            | (u8::from(last)<<1) | (u8::from(last && self.terminal)<<2);
        self.buffer[..HEADER_BYTES].copy_from_slice(&self.header.encode()?);
        let digest = segment_digest(&self.buffer);
        // Reject impossible next index before publishing a nonfinal part.
        let next = if last { self.header.part_index }
            else { self.header.part_index.checked_add(1).ok_or_else(invalid)? };
        (self.emit)(digest, &self.buffer)?;
        self.header.predecessor = digest;
        self.header.part_index = next;
        self.buffer.truncate(HEADER_BYTES);
        Ok(digest)
    }
}

impl<F: FnMut([u8;32], &[u8]) -> io::Result<()>> Write for FragmentWriter<F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() { return Ok(0); }
        if self.buffer.len()==HEADER_BYTES+MAX_BODY_BYTES {
            if let Err(error) = self.emit_part(false) {
                // write_all retries Interrupted. A callback error must instead
                // stop this append, even if publication may have occurred.
                self.failure = Some(error);
                return Err(io::Error::other("segment emission failed"));
            }
        }
        let count=bytes.len().min(HEADER_BYTES+MAX_BODY_BYTES-self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
```

- [x] Rerun focused tests and require six passing tests. Run full library tests, Clippy `--locked --lib --tests -- -D warnings`, `cargo fmt --all -- --check`, and `git diff --check`. Use VS2022 BuildTools (not VS18, whose SDK is incomplete). Format only the owned files if needed, not unrelated dirty files.
- [x] Independent specification review followed by quality review must verify lookahead behavior, buffer bound, callback error propagation, full hash links, empty/final semantics and exact boundary reconstruction. Implementer does not self-review, commit or deploy. Root stages only the two owned source files and this plan after review.

## Verification and process deviation

The first implementer attempt failed to execute the prescribed assertion-RED step: the ambient VS18 dependency build failed, and implementation proceeded without runtime RED. Root rejected that as TDD evidence, identified missing test assertions and API documentation, and required a corrective pass. With inert methods and the complete tests, VS2022 produced six runtime failures (`868d43`, exit 1), followed by six passing fragment tests after restoration (`5b3453`, exit 0). This does not make the original development order TDD-compliant.

The implementer reported 49 library tests and Clippy passing. Root independently ran the full library suite: 49 passed (`182696`, exit 0). Root also caught an edition-dependent formatter mismatch; formatting only the owned files for Rust 2024 resolved it, and the full format check passed (`76421f`, exit 0). Independent specification and quality reviews passed with no open findings after corrections. No runtime storage integration or live-service rollout was performed.

## Parent coverage and remaining work

This task covers writer-side physical fragmentation from the reviewed deterministic format, including lengths/Unicode boundaries and large legacy values. It does not claim corruption-safe cold loading, one-read-per-file recovery, private immutable publication, exclusive locks, compact joint checkpoints, handler integration, offline migration/downgrade, benchmark improvement or completion of the desktop/CLI product. Those requirements remain active and must be implemented before storage rollout.
