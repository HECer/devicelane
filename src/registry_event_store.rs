use sha2::{Digest, Sha256};

/// Binds the exact UTF-8 bytes of a job identity without normalization.
///
/// SHA-256 covers `DeviceLane/event-job/v1`, a NUL byte, the UTF-8 byte
/// length as a little-endian u64, then the identity bytes.
pub fn job_binding(identity: &str) -> [u8; 32] {
    identity_binding(b"DeviceLane/event-job/v1", identity)
}

/// Binds the exact UTF-8 bytes of a peer identity without normalization.
///
/// SHA-256 covers `DeviceLane/event-peer/v1`, a NUL byte, the UTF-8 byte
/// length as a little-endian u64, then the identity bytes.
pub fn peer_binding(identity: &str) -> [u8; 32] {
    identity_binding(b"DeviceLane/event-peer/v1", identity)
}

fn identity_binding(domain: &[u8], identity: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(
        u64::try_from(identity.len())
            .expect("supported platforms have at most 64-bit string lengths")
            .to_le_bytes(),
    );
    hash.update(identity.as_bytes());
    hash.finalize().into()
}

/// Hashes `DeviceLane/event-segment/v1\0` followed by all supplied bytes,
/// without an additional length prefix.
///
/// This digest does not validate segment structure or authenticate its origin.
pub fn segment_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DeviceLane/event-segment/v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

mod codec;
pub use codec::{HEADER_BYTES, MAX_BODY_BYTES, SegmentHeader, decode_segment};

mod events;
pub use events::{read_event_batch, write_event_batch};

mod fragments;
pub use fragments::{BatchBinding, write_event_segments};

mod reader;
pub use reader::{DecodedBatch, read_event_segment_batch};

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn identity_domains_match_independent_vectors() {
        assert_eq!(
            hex(&job_binding("job-1")),
            "152b89d57e78a7a7475270aa99a54aad45409c77f90988ffa96e8813e0b26255"
        );
        assert_eq!(
            hex(&peer_binding("agent-1")),
            "f01c81ae896053ba02fffce4efa1ca03cb5ba993cc7cfc9916e34deca2c55667"
        );
        assert_ne!(job_binding("same"), peer_binding("same"));
    }

    #[test]
    fn identity_length_counts_utf8_bytes_without_normalization() {
        assert_eq!(
            hex(&job_binding("\u{e9}")),
            "bb92c81172aa135c0de3de5f455ccfac37d6912a6e58dc49a11365af225ccbf6"
        );
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
        assert_eq!(
            hex(&segment_digest(&bytes)),
            "90c170d10d11a5d05911de2c024d7e520831e08517de488aa9287eef531e6969"
        );
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert_ne!(
                segment_digest(&changed),
                segment_digest(&bytes),
                "byte {index}"
            );
        }
    }
}
