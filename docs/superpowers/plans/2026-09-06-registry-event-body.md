# Registry Event Body Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stream exact logical event batches to a writer and reconstruct them from a bounded reader without allocating from untrusted declared lengths.

**Architecture:** A separate event-body module works with existing `NetworkEvent` values and standard `Read`/`Write`. It is independent of physical fragmentation: the future segment layer supplies a concatenated, integrity-checked logical body and its checked byte length. This layer preserves event order and content but does not enforce Apple-specific sequence or actor rules.

**Tech Stack:** Rust standard I/O and existing `crate::network_processes::NetworkEvent`; no new dependencies.

AI-assisted plan under `docs/superpowers/specs/2026-09-06-registry-event-segments-design.md`. Do not implement concurrently with the header slice or before its independent reviews pass. No filesystem, identities, services, wire protocol, or live registry state changes in this task.

## Acceptance and ownership

- Encode LE-u64 event count followed by each LE-u64 sequence, LE-u64 UTF-8 kind length and bytes, LE-u64 UTF-8 payload length and bytes.
- Preserve zero/max sequence values, legacy gaps/order, empty strings, embedded NUL/newlines/quotes, and exact Unicode bytes without normalization.
- Writer borrows events; it does not clone them or serialize the full batch into an intermediate buffer. Propagate real write errors.
- Decoder receives a caller-provided exact logical extent, limits its reads to that extent, and rejects leftover bytes within it. It intentionally does not consume bytes belonging to a following extent in the same reader.
- Check the event-count lower bound (24 bytes per event after the count) and each string length against remaining bytes. Never reserve event or string capacity from a declared count/length; grow only as actual bytes/events are read. Use an 8-KiB scratch buffer for strings; UTF-8 validation occurs after reassembly, so a code point may cross scratch boundaries.
- Large legitimate legacy events remain supported; there is no arbitrary total-output cap. Decoder output memory remains proportional to recovered events, as the parent design explicitly hydrates histories.
- This is not physical-file validation, chain/hash verification, authentication, or durability. The caller must derive `encoded_length` by checked addition of validated physical body lengths.

## Task 1: Event-body streaming codec

**Files:**

- Create `src/registry_event_store/events.rs`.
- Modify `src/registry_event_store.rs` only with the module/re-exports shown below.
- Tests: unit module in `src/registry_event_store/events.rs`.

- [x] Add the module/re-export and inert signatures, then the complete tests below. Do not implement the codec before observing assertion RED on valid inputs.

```rust
// Parent event-store module, before its tests:
mod events;
pub use events::{read_event_batch, write_event_batch};

// New events.rs, RED scaffolding:
use crate::network_processes::NetworkEvent;
use std::io::{self, Read, Write};

pub fn write_event_batch<W: Write>(_writer: &mut W, _events: &[NetworkEvent]) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::InvalidData, "event body codec absent"))
}
pub fn read_event_batch<R: Read>(_reader: &mut R, _encoded_length: u64)
    -> io::Result<Vec<NetworkEvent>>
{
    Err(io::Error::new(io::ErrorKind::InvalidData, "event body codec absent"))
}
```

- [x] Append these tests. They use real in-memory I/O, including a fixed-size cursor that fails when exhausted, rather than a mock storage implementation.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn event(sequence: u64, kind: &str, payload: &str) -> NetworkEvent {
        NetworkEvent { sequence, kind: kind.into(), payload: payload.into() }
    }

    fn encode(events: &[NetworkEvent]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_event_batch(&mut bytes, events).expect("valid event body must encode");
        bytes
    }

    #[test]
    fn started_body_matches_independent_bytes() {
        let events = [event(1, "started", "")];
        let bytes = encode(&events);
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex,
            "010000000000000001000000000000000700000000000000737461727465640000000000000000");
        assert_eq!(read_event_batch(&mut bytes.as_slice(), 39).unwrap(), events);
    }

    #[test]
    fn empty_batch_is_exactly_one_count() {
        let bytes = encode(&[]);
        assert_eq!(bytes, [0; 8]);
        assert!(read_event_batch(&mut bytes.as_slice(), 8).unwrap().is_empty());
    }

    #[test]
    fn unicode_large_events_and_legacy_order_round_trip() {
        let large = "\u{e9}\0\"\n".repeat(300_000);
        let events = [event(u64::MAX, "\u{e9}", &large), event(0, "", "e\u{301}")];
        let bytes = encode(&events);
        assert!(bytes.len() > 2 * 524_288);
        assert_eq!(read_event_batch(&mut bytes.as_slice(), bytes.len() as u64).unwrap(), events);
    }

    #[test]
    fn every_truncation_and_internal_trailing_byte_is_rejected() {
        let bytes = encode(&[event(1, "started", "")]);
        for length in 0..bytes.len() {
            assert!(read_event_batch(&mut &bytes[..length], length as u64).is_err(), "{length}");
        }
        let mut extra = bytes; extra.push(0);
        assert!(read_event_batch(&mut extra.as_slice(), extra.len() as u64).is_err());
    }

    #[test]
    fn forged_lengths_counts_and_invalid_utf8_are_rejected() {
        let valid = encode(&[event(1, "x", "y")]);
        for offset in [0, 16, 25] {
            let mut bytes = valid.clone();
            bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(read_event_batch(&mut bytes.as_slice(), bytes.len() as u64).is_err());
        }
        for offset in [24, 33] {
            let mut bytes = valid.clone(); bytes[offset] = 0xff;
            assert!(read_event_batch(&mut bytes.as_slice(), bytes.len() as u64).is_err());
        }
    }

    #[test]
    fn logical_extent_does_not_consume_following_record() {
        let first = encode(&[event(7, "out", "one")]);
        let second = encode(&[event(8, "out", "two")]);
        let mut joined = first.clone(); joined.extend_from_slice(&second);
        let mut reader = Cursor::new(joined);
        assert_eq!(read_event_batch(&mut reader, first.len() as u64).unwrap(),
            [event(7, "out", "one")]);
        assert_eq!(reader.position(), first.len() as u64);
        assert_eq!(read_event_batch(&mut reader, second.len() as u64).unwrap(),
            [event(8, "out", "two")]);
    }

    #[test]
    fn real_short_writer_failure_is_propagated() {
        let mut space = [0_u8; 4];
        let error = write_event_batch(&mut Cursor::new(space.as_mut_slice()), &[]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }
}
```

- [x] Run `rtk cargo test --locked --lib registry_event_store::events -- --nocapture` with the established Windows VS2022 developer shell and target directory. Require positive tests to fail because the inert methods return errors, not a compiler or fixture problem. Preserve terminal RED output.

- [x] Replace the inert functions with this implementation, retaining the tests and imports. The only reusable reader buffer is the fixed scratch array in `read_string`; the returned event histories necessarily own their strings.

```rust
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid event batch body")
}

fn write_length<W: Write>(writer: &mut W, length: usize) -> io::Result<()> {
    let length = u64::try_from(length).map_err(|_| invalid())?;
    writer.write_all(&length.to_le_bytes())
}

/// Stream exact event values; sequence and actor policy are validated by the caller.
pub fn write_event_batch<W: Write>(writer: &mut W, events: &[NetworkEvent]) -> io::Result<()> {
    write_length(writer, events.len())?;
    for event in events {
        writer.write_all(&event.sequence.to_le_bytes())?;
        write_length(writer, event.kind.len())?;
        writer.write_all(event.kind.as_bytes())?;
        write_length(writer, event.payload.len())?;
        writer.write_all(event.payload.as_bytes())?;
    }
    Ok(())
}

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_string<R: Read>(reader: &mut io::Take<R>) -> io::Result<String> {
    let length = read_u64(reader)?;
    if length > reader.limit() { return Err(invalid()); }
    let mut remaining = length;
    let mut bytes = Vec::new();
    let mut scratch = [0; 8192];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(scratch.len() as u64)).map_err(|_| invalid())?;
        reader.read_exact(&mut scratch[..count])?;
        bytes.extend_from_slice(&scratch[..count]);
        remaining -= count as u64;
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}

/// Read exactly the supplied logical extent, leaving following reader bytes untouched.
/// The caller supplies a checked length from validated physical segment bodies.
/// This reconstructs values but does not authenticate or validate their event chain.
pub fn read_event_batch<R: Read>(reader: &mut R, encoded_length: u64)
    -> io::Result<Vec<NetworkEvent>>
{
    let mut bounded = reader.take(encoded_length);
    let count = read_u64(&mut bounded)?;
    if count > bounded.limit() / 24 { return Err(invalid()); }
    let mut events = Vec::new();
    for _ in 0..count {
        let sequence = read_u64(&mut bounded)?;
        let kind = read_string(&mut bounded)?;
        let payload = read_string(&mut bounded)?;
        events.push(NetworkEvent { sequence, kind, payload });
    }
    if bounded.limit() != 0 { return Err(invalid()); }
    Ok(events)
}
```

- [x] Rerun the event-body tests: require seven passing tests. Run all `registry_event_store` unit tests and the full library suite, then Clippy `--locked --lib --tests -- -D warnings`, fmt check, and diff check. Distinguish actual terminal processes from observation timeouts; do not restart a live build merely because output is delayed.
- [x] Obtain independent specification review, followed by quality review of length handling, exact format, reader boundaries, and allocation behavior. No implementer self-review, commit, or deployment. Preserve the existing uncommitted transport work.

## Verification record

Implemented against `ec44dbe`. The implementer reported seven assertion failures with inert methods, followed by seven passing body tests, sixteen event-store tests, and forty-three library tests. Root independently reran the full library suite: 43 passed, exit 0. Independent specification and quality reviews passed; the quality review's minor request to document checked physical-length addition and caller-owned integrity/durability checks was applied and re-reviewed. This verifies the codec only, not persistence integration or the scaling target. No live services were changed.

## Parent work still required

Integrating this codec with bounded physical fragments, validating chains and committed heads, publishing owner-private immutable files, enforcing single-writer locking, migrating legacy state, atomically committing metadata/leases, and demonstrating linear I/O all remain open. The full Windows/macOS/Linux desktop+CLI product and real Mac E2E goals are not reduced by this isolated codec plan.
