use std::io::{self, Write};

use super::{HEADER_BYTES, MAX_BODY_BYTES, SegmentHeader, segment_digest, write_event_batch};
use crate::network_processes::NetworkEvent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchBinding {
    pub store_id: [u8; 16],
    pub job: [u8; 32],
    pub predecessor: [u8; 32],
    pub origin: u8,
    pub actor: [u8; 32],
}

/// Streams a logical event batch into hash-linked physical segments.
///
/// The callback receives borrowed bytes and must publish owner-private,
/// immutable files with the required durability before returning `Ok(())`.
/// The writer itself does not provide filesystem privacy. A successful return
/// identifies the emitted tail; it does not checkpoint or commit that tail.
/// Callback failures stop immediately and already-emitted orphan segments
/// remain the caller's responsibility. This writer does not authenticate the
/// binding or establish recovery policy; those are caller responsibilities.
pub fn write_event_segments<F>(
    binding: BatchBinding,
    events: &[NetworkEvent],
    terminal: bool,
    emit: F,
) -> io::Result<[u8; 32]>
where
    F: FnMut([u8; 32], &[u8]) -> io::Result<()>,
{
    if !(1..=4).contains(&binding.origin) || (binding.origin != 1 && binding.actor != [0; 32]) {
        return Err(invalid_fragment());
    }
    let header = SegmentHeader {
        store_id: binding.store_id,
        job: binding.job,
        predecessor: binding.predecessor,
        origin: binding.origin,
        actor: binding.actor,
        flags: 0,
        event_count: u64::try_from(events.len()).map_err(|_| invalid_fragment())?,
        first_sequence: events.first().map_or(0, |event| event.sequence),
        last_sequence: events.last().map_or(0, |event| event.sequence),
        part_index: 0,
        body_length: 8,
    };
    let mut writer = FragmentWriter {
        header,
        terminal,
        buffer: Vec::with_capacity(HEADER_BYTES + MAX_BODY_BYTES),
        emit,
        failure: None,
    };
    writer.buffer.resize(HEADER_BYTES, 0);
    if let Err(error) = write_event_batch(&mut writer, events) {
        return Err(writer.failure.take().unwrap_or(error));
    }
    match writer.emit_part(true) {
        Ok(digest) => Ok(digest),
        Err(error) => Err(writer.failure.take().unwrap_or(error)),
    }
}

fn invalid_fragment() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid event fragment")
}

struct FragmentWriter<F> {
    header: SegmentHeader,
    terminal: bool,
    buffer: Vec<u8>,
    emit: F,
    failure: Option<io::Error>,
}

impl<F> FragmentWriter<F>
where
    F: FnMut([u8; 32], &[u8]) -> io::Result<()>,
{
    fn emit_part(&mut self, last: bool) -> io::Result<[u8; 32]> {
        let body_length = self
            .buffer
            .len()
            .checked_sub(HEADER_BYTES)
            .ok_or_else(invalid_fragment)?;
        self.header.body_length = u32::try_from(body_length).map_err(|_| invalid_fragment())?;
        self.header.flags = u8::from(self.header.part_index == 0)
            | (u8::from(last) << 1)
            | (u8::from(last && self.terminal) << 2);
        self.buffer[..HEADER_BYTES].copy_from_slice(&self.header.encode()?);
        let digest = segment_digest(&self.buffer);
        let next_index = if last {
            self.header.part_index
        } else {
            self.header
                .part_index
                .checked_add(1)
                .ok_or_else(invalid_fragment)?
        };
        if let Err(error) = (self.emit)(digest, &self.buffer) {
            self.failure = Some(error);
            return Err(io::Error::other("segment emission failed"));
        }
        self.header.predecessor = digest;
        self.header.part_index = next_index;
        self.buffer.truncate(HEADER_BYTES);
        Ok(digest)
    }
}

impl<F> Write for FragmentWriter<F>
where
    F: FnMut([u8; 32], &[u8]) -> io::Result<()>,
{
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.buffer.len() == HEADER_BYTES + MAX_BODY_BYTES {
            self.emit_part(false)?;
        }
        let available = HEADER_BYTES + MAX_BODY_BYTES - self.buffer.len();
        let count = bytes.len().min(available);
        self.buffer.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_event_store::{
        HEADER_BYTES, MAX_BODY_BYTES, decode_segment, job_binding, peer_binding, read_event_batch,
        segment_digest,
    };
    use std::io::{Cursor, ErrorKind};

    fn event(sequence: u64, kind: &str, payload: &str) -> NetworkEvent {
        NetworkEvent {
            sequence,
            kind: kind.to_owned(),
            payload: payload.to_owned(),
        }
    }

    fn binding() -> BatchBinding {
        BatchBinding {
            store_id: std::array::from_fn(|i| i as u8),
            job: job_binding("job-1"),
            predecessor: [9; 32],
            origin: 1,
            actor: peer_binding("agent-1"),
        }
    }

    fn collect(events: &[NetworkEvent], terminal: bool) -> (Vec<Vec<u8>>, [u8; 32]) {
        let b = binding();
        let mut parts = Vec::new();
        let tail = write_event_segments(b, events, terminal, |digest, bytes| {
            assert_eq!(digest, segment_digest(bytes));
            assert!(bytes.len() <= HEADER_BYTES + MAX_BODY_BYTES);
            let (header, body) = decode_segment(bytes).unwrap();
            assert_eq!(header.store_id, b.store_id);
            assert_eq!(header.job, b.job);
            assert_eq!(header.origin, b.origin);
            assert_eq!(header.actor, b.actor);
            assert_eq!(header.event_count, events.len() as u64);
            assert_eq!(
                header.first_sequence,
                events.first().map_or(0, |e| e.sequence)
            );
            assert_eq!(
                header.last_sequence,
                events.last().map_or(0, |e| e.sequence)
            );
            assert_eq!(
                header.predecessor,
                parts
                    .last()
                    .map_or(b.predecessor, |p: &Vec<u8>| segment_digest(p))
            );
            assert_eq!(header.part_index, parts.len() as u64);
            assert_eq!(header.flags & 1 != 0, parts.is_empty());
            if !parts.is_empty() {
                let previous = decode_segment(parts.last().unwrap()).unwrap().0;
                assert_eq!(header.predecessor, segment_digest(parts.last().unwrap()));
                assert_ne!(previous.part_index, header.part_index);
            }
            assert_eq!(body.len(), header.body_length as usize);
            parts.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(tail, segment_digest(parts.last().unwrap()));
        let mut body = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            let (header, bytes) = decode_segment(part).unwrap();
            assert_eq!(header.flags & 2 != 0, index + 1 == parts.len());
            assert_eq!(header.flags & 4 != 0, index + 1 == parts.len() && terminal);
            if index + 1 != parts.len() {
                assert_eq!(bytes.len(), MAX_BODY_BYTES);
            }
            body.extend_from_slice(bytes);
        }
        let body_len = body.len() as u64;
        assert_eq!(
            read_event_batch(&mut Cursor::new(body), body_len).unwrap(),
            events
        );
        (parts, tail)
    }

    #[test]
    fn empty_and_exact_full_final_body_have_no_extra_part() {
        for terminal in [false, true] {
            let (empty, _) = collect(&[], terminal);
            assert_eq!(empty.len(), 1);
            assert_eq!(empty[0].len(), HEADER_BYTES + 8);
        }
        let payload = "x".repeat(MAX_BODY_BYTES - 32);
        for terminal in [false, true] {
            let (full, _) = collect(&[event(7, "", &payload)], terminal);
            assert_eq!(full.len(), 1);
            assert_eq!(full[0].len(), HEADER_BYTES + MAX_BODY_BYTES);
        }
    }

    #[test]
    fn one_byte_overflow_and_large_legacy_event_round_trip() {
        let (parts, _) = collect(&[event(0, "", &"x".repeat(MAX_BODY_BYTES - 31))], true);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len(), 159);
        let events = [
            event(u64::MAX, "legacy", &"\u{e9}\0\"\n".repeat(300_000)),
            event(0, "", "e\u{301}"),
        ];
        let (parts, _) = collect(&events, true);
        assert!(parts.len() >= 3);
        let mut body = Vec::new();
        for p in &parts {
            body.extend_from_slice(decode_segment(p).unwrap().1);
        }
        let body_len = body.len() as u64;
        assert_eq!(
            read_event_batch(&mut Cursor::new(body), body_len).unwrap(),
            events
        );
    }

    #[test]
    fn length_prefix_and_unicode_can_cross_physical_boundary() {
        let (parts, _) = collect(&[event(1, &"k".repeat(MAX_BODY_BYTES - 28), "z")], true);
        assert_eq!(
            &decode_segment(&parts[0]).unwrap().1[MAX_BODY_BYTES - 4..],
            &[1, 0, 0, 0]
        );
        assert_eq!(&decode_segment(&parts[1]).unwrap().1[..4], &[0, 0, 0, 0]);
        let payload = format!("{}\u{e9}", "x".repeat(MAX_BODY_BYTES - 33));
        let (parts, _) = collect(&[event(1, "", &payload)], true);
        assert_eq!(*decode_segment(&parts[0]).unwrap().1.last().unwrap(), 0xc3);
        assert_eq!(decode_segment(&parts[1]).unwrap().1[0], 0xa9);
    }

    #[test]
    fn started_segment_retains_independent_golden_hash() {
        let mut b = binding();
        b.predecessor = [0; 32];
        let mut got = None;
        let tail = write_event_segments(b, &[event(1, "started", "")], false, |d, bytes| {
            assert_eq!(bytes.len(), 197);
            got = Some(d);
            Ok(())
        })
        .unwrap();
        assert_eq!(tail, got.unwrap());
        let hex: String = tail.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "90c170d10d11a5d05911de2c024d7e520831e08517de488aa9287eef531e6969"
        );
    }

    #[test]
    fn invalid_binding_is_rejected_before_emission() {
        for origin in [0, 2, 3, 4, 5] {
            let mut b = binding();
            b.origin = origin;
            let mut calls = 0;
            assert!(
                write_event_segments(b, &[], false, |_, _| {
                    calls += 1;
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(calls, 0);
        }
        for origin in [2, 3, 4] {
            let mut b = binding();
            b.origin = origin;
            b.actor = [0; 32];
            assert!(write_event_segments(b, &[], false, |_, _| Ok(())).is_ok());
        }
    }

    #[test]
    fn callback_failure_stops_without_a_successful_tail() {
        let events = [event(1, "", &"x".repeat(3 * MAX_BODY_BYTES))];
        for (fail_at, kind) in [
            (1, ErrorKind::PermissionDenied),
            (2, ErrorKind::PermissionDenied),
            (4, ErrorKind::PermissionDenied),
            (2, ErrorKind::Interrupted),
        ] {
            let mut calls = 0;
            let err = write_event_segments(binding(), &events, true, |_, _| {
                calls += 1;
                if calls == fail_at {
                    Err(io::Error::new(kind, "sink denied"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(err.kind(), kind);
            assert_eq!(err.to_string(), "sink denied");
            assert_eq!(calls, fail_at);
        }
    }
}
