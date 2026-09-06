use std::io::{self, Read, Write};

use crate::network_processes::NetworkEvent;

/// Streams the canonical event batch body without buffering the full encoding.
///
/// The caller supplies any sequence/actor policy; this codec preserves event
/// order and does not authenticate or chain-validate the values.
pub fn write_event_batch<W: Write>(writer: &mut W, events: &[NetworkEvent]) -> io::Result<()> {
    write_u64(
        writer,
        u64::try_from(events.len()).map_err(|_| invalid_data())?,
    )?;
    for event in events {
        write_u64(writer, event.sequence)?;
        write_string(writer, &event.kind)?;
        write_string(writer, &event.payload)?;
    }
    Ok(())
}

/// Reads exactly one canonical event batch body from the supplied extent.
///
/// `encoded_length` must be the caller-checked sum of validated physical body
/// lengths. Any following bytes remain unread. Physical-file validation, hash
/// verification, authentication, segment-chain, and durability guarantees
/// remain caller responsibilities; this only reconstructs events.
pub fn read_event_batch<R: Read>(
    reader: &mut R,
    encoded_length: u64,
) -> io::Result<Vec<NetworkEvent>> {
    let mut reader = reader.take(encoded_length);
    let count = read_u64(&mut reader)?;
    if count > reader.limit() / 24 {
        return Err(invalid_data());
    }
    let mut events = Vec::new();
    for _ in 0..count {
        let sequence = read_u64(&mut reader)?;
        let kind = read_string(&mut reader)?;
        let payload = read_string(&mut reader)?;
        events.push(NetworkEvent {
            sequence,
            kind,
            payload,
        });
    }
    if reader.limit() != 0 {
        return Err(invalid_data());
    }
    Ok(events)
}

fn invalid_data() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid event body")
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_string<W: Write>(writer: &mut W, value: &str) -> io::Result<()> {
    let length = u64::try_from(value.len()).map_err(|_| invalid_data())?;
    write_u64(writer, length)?;
    writer.write_all(value.as_bytes())
}

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_string<R: Read>(reader: &mut io::Take<R>) -> io::Result<String> {
    let length = read_u64(reader)?;
    if length > reader.limit() {
        return Err(invalid_data());
    }
    let mut bytes = Vec::new();
    let mut remaining = length;
    let mut scratch = [0; 8192];
    while remaining != 0 {
        let chunk =
            usize::try_from(remaining.min(scratch.len() as u64)).map_err(|_| invalid_data())?;
        reader.read_exact(&mut scratch[..chunk])?;
        bytes.extend_from_slice(&scratch[..chunk]);
        remaining -= chunk as u64;
    }
    String::from_utf8(bytes).map_err(|_| invalid_data())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, ErrorKind};

    fn event(sequence: u64, kind: &str, payload: &str) -> NetworkEvent {
        NetworkEvent {
            sequence,
            kind: kind.to_owned(),
            payload: payload.to_owned(),
        }
    }

    fn encode(events: &[NetworkEvent]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_event_batch(&mut bytes, events).expect("event batch should encode");
        bytes
    }

    #[test]
    fn started_event_has_canonical_bytes_and_round_trips() {
        let events = [event(1, "started", "")];
        let encoded = encode(&events);
        assert_eq!(
            encoded,
            hex("010000000000000001000000000000000700000000000000737461727465640000000000000000")
        );
        assert_eq!(
            read_event_batch(&mut Cursor::new(encoded), 39).unwrap(),
            events
        );
    }

    #[test]
    fn empty_batch_has_only_zero_count() {
        let encoded = encode(&[]);
        assert_eq!(encoded, [0; 8]);
        assert!(
            read_event_batch(&mut Cursor::new(encoded), 8)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn large_unicode_nul_and_legacy_order_round_trip() {
        let large = "\u{e9}\0\"\n".repeat(300_000);
        let events = [event(u64::MAX, "\u{e9}", &large), event(0, "", "e\u{301}")];
        let encoded = encode(&events);
        assert!(encoded.len() > 2 * 524_288);
        assert_eq!(
            read_event_batch(&mut Cursor::new(&encoded), encoded.len() as u64).unwrap(),
            events
        );
    }

    #[test]
    fn truncation_and_trailing_extent_are_rejected() {
        let encoded = encode(&[event(1, "started", "")]);
        for length in 0..encoded.len() {
            assert!(read_event_batch(&mut Cursor::new(&encoded[..length]), length as u64).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(read_event_batch(&mut Cursor::new(trailing), 40).is_err());
    }

    #[test]
    fn impossible_lengths_and_invalid_utf8_are_rejected() {
        let valid = encode(&[event(1, "x", "y")]);
        for offset in [0, 16, 25] {
            let mut corrupted = valid.clone();
            corrupted[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(read_event_batch(&mut Cursor::new(corrupted), valid.len() as u64).is_err());
        }
        for offset in [24, 33] {
            let mut corrupted = valid.clone();
            corrupted[offset] = 0xff;
            assert!(read_event_batch(&mut Cursor::new(corrupted), valid.len() as u64).is_err());
        }
    }

    #[test]
    fn exact_extent_leaves_following_batch_unread() {
        let first = encode(&[event(7, "out", "one")]);
        let second = encode(&[event(8, "out", "two")]);
        let first_length = first.len();
        let second_length = second.len();
        let mut combined = first;
        combined.extend_from_slice(&second);
        let mut cursor = Cursor::new(combined);
        assert_eq!(
            read_event_batch(&mut cursor, first_length as u64).unwrap(),
            [event(7, "out", "one")]
        );
        assert_eq!(cursor.position(), first_length as u64);
        assert_eq!(
            read_event_batch(&mut cursor, second_length as u64).unwrap(),
            [event(8, "out", "two")]
        );
    }

    #[test]
    fn exhausted_writer_reports_write_zero() {
        let mut storage = [0u8; 4];
        let error = write_event_batch(&mut Cursor::new(storage.as_mut_slice()), &[]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WriteZero);
    }

    fn hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }
}
