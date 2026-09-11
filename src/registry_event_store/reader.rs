use std::collections::HashSet;
use std::io::{self, Read};

use super::{BatchBinding, HEADER_BYTES, decode_segment, read_event_batch, segment_digest};
use crate::network_processes::NetworkEvent;

#[derive(Debug, PartialEq, Eq)]
pub struct DecodedBatch {
    pub binding: BatchBinding,
    pub events: Vec<NetworkEvent>,
    pub terminal: bool,
    pub physical_bytes: u64,
    pub parts: u64,
}

/// Reconstructs one complete batch from its committed physical tail.
///
/// The loader must enforce owner-private, no-follow, regular-file and bounded
/// reads before allocating. This function validates bytes only; callers retain
/// responsibility for authentication, actor assignment, checkpointing,
/// recovery, and durability. Segment hashes do not authenticate a store an
/// attacker can control.
///
/// Traversal stops at part index zero. Its returned binding predecessor is
/// neither loaded nor validated; whole-history summaries and cross-batch
/// predecessor continuity remain caller responsibilities.
pub fn read_event_segment_batch<F>(
    store_id: [u8; 16],
    job: [u8; 32],
    tail: [u8; 32],
    mut load: F,
) -> io::Result<DecodedBatch>
where
    F: FnMut([u8; 32]) -> io::Result<Vec<u8>>,
{
    let mut current = tail;
    let mut seen = HashSet::new();
    let mut retained = Vec::new();
    let mut expected = None;
    let mut index = 0;
    let mut body_bytes = 0_u64;
    let mut physical_bytes = 0_u64;
    let mut parts = 0_u64;
    let preceding;

    loop {
        if !seen.insert(current) {
            return Err(invalid());
        }
        let bytes = load(current)?;
        let (header, body) = decode_segment(&bytes)?;
        if segment_digest(&bytes) != current || header.store_id != store_id || header.job != job {
            return Err(invalid());
        }
        physical_bytes = physical_bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        body_bytes = body_bytes
            .checked_add(u64::try_from(body.len()).map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        parts = parts.checked_add(1).ok_or_else(invalid)?;

        match &expected {
            None => {
                if header.flags & 2 == 0 {
                    return Err(invalid());
                }
                index = header.part_index;
                expected = Some(header.clone());
            }
            Some(expected) => {
                if header.origin != expected.origin
                    || header.actor != expected.actor
                    || header.event_count != expected.event_count
                    || header.first_sequence != expected.first_sequence
                    || header.last_sequence != expected.last_sequence
                    || header.part_index != index
                    || header.flags & 6 != 0
                {
                    return Err(invalid());
                }
            }
        }
        retained.push(bytes);
        if index == 0 {
            preceding = header.predecessor;
            break;
        }
        index = index.checked_sub(1).ok_or_else(invalid)?;
        current = header.predecessor;
    }

    retained.reverse();
    let expected = expected.ok_or_else(invalid)?;
    let mut reader = BodyReader {
        parts: retained,
        index: 0,
        offset: HEADER_BYTES,
    };
    let events = read_event_batch(&mut reader, body_bytes)?;
    if u64::try_from(events.len()).map_err(|_| invalid())? != expected.event_count
        || events.first().map_or(0, |event| event.sequence) != expected.first_sequence
        || events.last().map_or(0, |event| event.sequence) != expected.last_sequence
    {
        return Err(invalid());
    }
    Ok(DecodedBatch {
        binding: BatchBinding {
            store_id,
            job,
            predecessor: preceding,
            origin: expected.origin,
            actor: expected.actor,
        },
        events,
        terminal: expected.flags & 4 != 0,
        physical_bytes,
        parts,
    })
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid event segment batch")
}

struct BodyReader {
    parts: Vec<Vec<u8>>,
    index: usize,
    offset: usize,
}

impl Read for BodyReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while let Some(part) = self.parts.get(self.index) {
            if self.offset == part.len() {
                self.index = self.index.checked_add(1).ok_or_else(invalid)?;
                self.offset = HEADER_BYTES;
                continue;
            }
            let count = output.len().min(part.len() - self.offset);
            output[..count].copy_from_slice(&part[self.offset..self.offset + count]);
            self.offset += count;
            return Ok(count);
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_event_store::{
        HEADER_BYTES, MAX_BODY_BYTES, job_binding, peer_binding, segment_digest,
        write_event_segments,
    };
    use std::collections::{HashMap, HashSet};
    use std::io::ErrorKind;

    type PartFiles = HashMap<[u8; 32], Vec<u8>>;
    type PartChange = Box<dyn Fn(&mut Vec<u8>)>;

    fn binding() -> BatchBinding {
        BatchBinding {
            store_id: [7; 16],
            job: job_binding("job"),
            predecessor: [9; 32],
            origin: 1,
            actor: peer_binding("agent"),
        }
    }

    fn event(sequence: u64, kind: &str, payload: &str) -> NetworkEvent {
        NetworkEvent {
            sequence,
            kind: kind.to_owned(),
            payload: payload.to_owned(),
        }
    }

    fn encode(events: &[NetworkEvent], terminal: bool) -> (Vec<[u8; 32]>, PartFiles) {
        let mut order = Vec::new();
        let mut files = HashMap::new();
        write_event_segments(binding(), events, terminal, |hash, bytes| {
            order.push(hash);
            files.insert(hash, bytes.to_vec());
            Ok(())
        })
        .unwrap();
        (order, files)
    }

    fn read(tail: [u8; 32], files: &mut PartFiles) -> io::Result<DecodedBatch> {
        let b = binding();
        read_event_segment_batch(b.store_id, b.job, tail, |hash| {
            files
                .remove(&hash)
                .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "missing part"))
        })
    }

    fn replace_tail(
        tail: [u8; 32],
        files: &mut PartFiles,
        change: impl FnOnce(&mut Vec<u8>),
    ) -> [u8; 32] {
        let mut bytes = files.remove(&tail).unwrap();
        change(&mut bytes);
        let replacement = segment_digest(&bytes);
        files.insert(replacement, bytes);
        replacement
    }

    #[test]
    fn reconstructs_large_legacy_batch_once_per_part_and_stops_at_prior_tail() {
        let events = [
            event(u64::MAX, "legacy", &"\u{e9}\0\"\n".repeat(300_000)),
            event(0, "", "e\u{301}"),
        ];
        let (order, mut files) = encode(&events, true);
        let bytes: u64 = files.values().map(|part| part.len() as u64).sum();
        let mut seen = HashSet::new();
        let b = binding();
        let result = read_event_segment_batch(b.store_id, b.job, *order.last().unwrap(), |hash| {
            assert_ne!(hash, [9; 32]);
            assert!(seen.insert(hash));
            files
                .remove(&hash)
                .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "missing part"))
        })
        .unwrap();
        assert_eq!(result.events, events);
        assert_eq!(result.binding, b);
        assert!(result.terminal);
        assert_eq!(result.parts, order.len() as u64);
        assert_eq!(result.physical_bytes, bytes);
        assert_eq!(seen.len(), order.len());
    }

    #[test]
    fn empty_batches_and_both_boundary_splits_round_trip() {
        let cases = [
            vec![],
            vec![event(1, &"k".repeat(MAX_BODY_BYTES - 28), "z")],
            vec![event(
                1,
                "",
                &format!("{}\u{e9}", "x".repeat(MAX_BODY_BYTES - 33)),
            )],
        ];
        for terminal in [false, true] {
            for events in &cases {
                let (order, mut files) = encode(events, terminal);
                let result = read(*order.last().unwrap(), &mut files).unwrap();
                assert_eq!(result.events, *events);
                assert_eq!(result.terminal, terminal);
            }
        }
    }

    #[test]
    fn missing_middle_final_and_changed_bytes_are_rejected() {
        let events = [event(1, "", &"x".repeat(3 * MAX_BODY_BYTES))];
        let (order, files) = encode(&events, true);
        assert_eq!(order.len(), 4);
        for missing in [order[1], *order.last().unwrap()] {
            let mut changed = files.clone();
            changed.remove(&missing);
            let error = read(*order.last().unwrap(), &mut changed).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::NotFound);
            assert_eq!(error.to_string(), "missing part");
        }
        let mut changed = files.clone();
        changed.get_mut(&order[1]).unwrap()[HEADER_BYTES] ^= 1;
        assert!(read(*order.last().unwrap(), &mut changed).is_err());
    }

    #[test]
    fn nonfinal_tail_and_rehashed_inconsistent_batch_headers_are_rejected() {
        let events = [event(1, "", &"x".repeat(2 * MAX_BODY_BYTES))];
        let (order, files) = encode(&events, true);
        assert_eq!(order.len(), 3);
        let mut changed = files.clone();
        assert!(read(order[0], &mut changed).is_err());
        for offset in [8, 24, 89, 122, 130, 138, 146] {
            let mut changed = files.clone();
            let tail = replace_tail(*order.last().unwrap(), &mut changed, |bytes| {
                bytes[offset] ^= 1;
            });
            assert!(read(tail, &mut changed).is_err(), "offset {offset}");
        }
        let mut changed = files;
        let tail = replace_tail(*order.last().unwrap(), &mut changed, |bytes| {
            bytes[88] = 4;
            bytes[89..121].fill(0);
        });
        assert!(read(tail, &mut changed).is_err());
    }

    #[test]
    fn rehashed_body_corruption_and_forged_summaries_are_rejected() {
        let events = [event(1, "x", "y")];
        let (order, files) = encode(&events, false);
        let original = *order.last().unwrap();
        let mut mutations: Vec<PartChange> = vec![
            Box::new(|bytes| bytes[HEADER_BYTES + 33] = 0xff),
            Box::new(|bytes| {
                bytes[HEADER_BYTES..HEADER_BYTES + 8].copy_from_slice(&u64::MAX.to_le_bytes())
            }),
            Box::new(|bytes| {
                bytes[130..138].copy_from_slice(&2_u64.to_le_bytes());
                bytes[138..146].copy_from_slice(&2_u64.to_le_bytes());
            }),
            Box::new(|bytes| bytes.push(0)),
            Box::new(|bytes| {
                bytes.pop();
            }),
        ];
        for change in mutations.drain(..) {
            let mut changed = files.clone();
            let tail = replace_tail(original, &mut changed, change);
            assert!(read(tail, &mut changed).is_err());
        }
    }

    #[test]
    fn loader_errors_are_not_retried_and_oversized_parts_fail() {
        let mut calls = 0;
        let error = read_event_segment_batch([7; 16], job_binding("job"), [1; 32], |_| {
            calls += 1;
            Err(io::Error::new(ErrorKind::Interrupted, "loader interrupted"))
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(error.kind(), ErrorKind::Interrupted);
        assert_eq!(error.to_string(), "loader interrupted");
        let error = read_event_segment_batch([7; 16], job_binding("job"), [1; 32], |_| {
            Ok(vec![0; HEADER_BYTES + MAX_BODY_BYTES + 1])
        })
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }
}
