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
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid event segment header or extent",
    )
}

impl SegmentHeader {
    fn validate(&self) -> io::Result<()> {
        let first = self.flags & 1 != 0;
        let last = self.flags & 2 != 0;
        let terminal = self.flags & 4 != 0;
        if !(1..=4).contains(&self.origin)
            || (self.origin != 1 && self.actor != [0; 32])
            || self.flags & !7 != 0
            || (terminal && !last)
            || first != (self.part_index == 0)
            || (!first && self.predecessor == [0; 32])
            || self.body_length == 0
            || self.body_length > MAX_BODY_BYTES as u32
            || (!last && self.body_length != MAX_BODY_BYTES as u32)
            || (self.event_count == 0
                && (!first
                    || !last
                    || self.body_length != 8
                    || self.first_sequence != 0
                    || self.last_sequence != 0))
            || (self.event_count == 1 && self.first_sequence != self.last_sequence)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Encodes a locally consistent header without validating the event chain.
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

    /// Decodes and validates the header, without checking identity or chain bindings.
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

/// Validates the header and physical extent, returning a borrowed body.
/// Does not validate events, hashes, or authentication.
pub fn decode_segment(bytes: &[u8]) -> io::Result<(SegmentHeader, &[u8])> {
    if !(HEADER_BYTES..=HEADER_BYTES + MAX_BODY_BYTES).contains(&bytes.len()) {
        return Err(invalid());
    }
    let header = SegmentHeader::decode(&bytes[..HEADER_BYTES])?;
    let body_length = usize::try_from(header.body_length).map_err(|_| invalid())?;
    let total = HEADER_BYTES.checked_add(body_length).ok_or_else(invalid)?;
    if bytes.len() != total {
        return Err(invalid());
    }
    Ok((header, &bytes[HEADER_BYTES..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_event_store::{job_binding, peer_binding, segment_digest};

    fn header() -> SegmentHeader {
        SegmentHeader {
            store_id: std::array::from_fn(|index| index as u8),
            job: job_binding("job-1"),
            predecessor: [0; 32],
            origin: 1,
            actor: peer_binding("agent-1"),
            flags: 3,
            event_count: 1,
            first_sequence: 1,
            last_sequence: 1,
            part_index: 0,
            body_length: 39,
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
        assert_eq!(
            hex(&segment_digest(&file)),
            "90c170d10d11a5d05911de2c024d7e520831e08517de488aa9287eef531e6969"
        );
        assert_eq!(SegmentHeader::decode(&encoded).unwrap(), expected);
        let (decoded, view) = decode_segment(&file).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(view, body());
        assert_eq!(view.as_ptr(), file[HEADER_BYTES..].as_ptr());
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
        assert_eq!(encoded[122..130], [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(encoded[130..138], [24, 23, 22, 21, 20, 19, 18, 17]);
        assert_eq!(encoded[138..146], [40, 39, 38, 37, 36, 35, 34, 33]);
        assert_eq!(encoded[146..154], [56, 55, 54, 53, 52, 51, 50, 49]);
        assert_eq!(encoded[154..158], [3, 2, 1, 0]);
        assert_eq!(SegmentHeader::decode(&encoded).unwrap(), expected);
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
        empty.origin = 3;
        empty.actor = [0; 32];
        empty.flags = 7;
        empty.event_count = 0;
        empty.first_sequence = 0;
        empty.last_sequence = 0;
        empty.body_length = 8;
        assert_eq!(
            SegmentHeader::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
        let mut first = header();
        first.flags = 1;
        first.body_length = MAX_BODY_BYTES as u32;
        assert!(first.encode().is_ok());
        first.flags = 0;
        first.part_index = 1;
        first.predecessor = [1; 32];
        assert!(first.encode().is_ok());
    }

    #[test]
    fn malformed_header_fields_are_rejected() {
        let valid = header().encode().unwrap();
        let cases = [
            (0, 0),
            (88, 0),
            (88, 5),
            (121, 0x83),
            (121, 5),
            (121, 2),
            (146, 1),
            (88, 3),
            (154, 0),
            (157, 1),
        ];
        for (offset, value) in cases {
            let mut bad = valid;
            bad[offset] = value;
            assert!(
                SegmentHeader::decode(&bad).is_err(),
                "offset {offset}: {value}"
            );
        }
        for length in 0..HEADER_BYTES {
            assert!(SegmentHeader::decode(&valid[..length]).is_err());
        }
        let mut extra = valid.to_vec();
        extra.push(0);
        assert!(SegmentHeader::decode(&extra).is_err());
        let mut bad = header();
        bad.flags = 1;
        assert!(bad.encode().is_err());
        bad = header();
        bad.flags = 2;
        bad.part_index = 1;
        assert!(bad.encode().is_err());
        bad = header();
        bad.event_count = 0;
        assert!(bad.encode().is_err());
        bad = header();
        bad.last_sequence = 2;
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
}
