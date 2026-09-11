# Registry Batch Reader Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate and reconstruct one complete logical batch from its committed physical tail, reading each referenced part once.

**Architecture:** Traverse the physical predecessor links backwards, retaining validated bounded buffers. A forward reader over those buffers reconstructs events without a second concatenated body allocation. Return the preceding batch tail for the future whole-history loader.

**Tech Stack:** Existing Rust I/O, event codec, segment codec and SHA-256 helpers; no dependencies.

AI-assisted plan based on the reviewed registry event-segments design; baseline `f2afcfe`. This is one-batch integrity reconstruction, not whole-history authorization, private file access, checkpoint selection, migration, or durability. The complete product objective remains active.

## Acceptance

- The supplied tail must reference a last part. Validate each exact bounded physical extent before hashing. Compare full hash, expected store/job bindings, batch origin/actor/count/first/last, decrementing part index and first/last/terminal flags.
- Reject missing, changed, oversized, truncated, trailing, cross-batch or inconsistent parts. No events are returned on any error. Preserve loader errors without retry.
- Fetch each hash at most once. Never reserve from untrusted part index/count/length. Checked-add logical body and physical byte totals. Keep memory proportional to actual fetched data and reconstructed events; no second whole-body concatenation.
- Reassemble length prefixes and Unicode across physical boundaries, then validate exact event count and first/last sequence summaries. Preserve legacy order and content; do not impose Apple sequence continuity here.
- Return previous logical batch tail without fetching it. The caller must validate whole-history head summaries, actor authorization and predecessor continuity across batches.
- Loader contract: owner-private, nofollow, regular-file validation and bounded file reads are required before returning bytes. This module cannot supply filesystem security. Content hashes bind bytes but do not authenticate a store writable by an attacker.

## Task 1: Batch reconstruction

**Files:** create `src/registry_event_store/reader.rs`; parent `src/registry_event_store.rs` adds only `mod reader; pub use reader::{DecodedBatch, read_event_segment_batch};`.

- [x] Add imports, result type, inert public function and the tests below. Run the inert version in the prescribed VS2022 environment and require actual runtime assertion RED before implementing; a compiler failure is not RED.

```rust
use std::{collections::HashSet, io::{self, Read}};
use crate::network_processes::NetworkEvent;
use super::{BatchBinding, HEADER_BYTES, SegmentHeader, decode_segment,
    read_event_batch, segment_digest};

pub struct DecodedBatch {
    pub binding: BatchBinding,
    pub events: Vec<NetworkEvent>,
    pub terminal: bool,
    pub physical_bytes: u64,
    pub parts: u64,
}

pub fn read_event_segment_batch<F>(
    _store_id: [u8;16], _job: [u8;32], _tail: [u8;32], _load: F,
) -> io::Result<DecodedBatch>
where F: FnMut([u8;32]) -> io::Result<Vec<u8>> {
    Err(io::Error::new(io::ErrorKind::InvalidData,"batch reader absent"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::registry_event_store::{MAX_BODY_BYTES, job_binding, peer_binding, write_event_segments};

    fn binding() -> BatchBinding {
        BatchBinding { store_id:[7;16], job:job_binding("job"), predecessor:[9;32],
            origin:1, actor:peer_binding("agent") }
    }
    fn event(sequence:u64, kind:&str, payload:String) -> NetworkEvent {
        NetworkEvent { sequence, kind:kind.into(), payload }
    }
    fn encode(events:&[NetworkEvent],terminal:bool)->(Vec<[u8;32]>,HashMap<[u8;32],Vec<u8>>) {
        let mut order=Vec::new(); let mut files=HashMap::new();
        write_event_segments(binding(),events,terminal,|hash,bytes| {
            order.push(hash);files.insert(hash,bytes.to_vec());Ok(())
        }).unwrap(); (order,files)
    }
    fn read(tail:[u8;32],mut files:HashMap<[u8;32],Vec<u8>>)->io::Result<DecodedBatch> {
        read_event_segment_batch(binding().store_id,binding().job,tail,|hash| {
            files.remove(&hash).ok_or_else(||io::Error::new(io::ErrorKind::NotFound,"missing part"))
        })
    }
    fn replace_tail(files:&mut HashMap<[u8;32],Vec<u8>>,tail:[u8;32],edit:impl FnOnce(&mut Vec<u8>))->[u8;32] {
        let mut bytes=files.remove(&tail).unwrap();edit(&mut bytes);
        let hash=segment_digest(&bytes);files.insert(hash,bytes);hash
    }

    #[test]
    fn reconstructs_large_legacy_batch_once_per_part_and_stops_at_prior_tail() {
        let events=[event(u64::MAX,"legacy","é\0\"\n".repeat(300_000)),event(0,"","e\u{301}".into())];
        let (order,mut files)=encode(&events,true);
        let physical_bytes=files.values().map(|b|b.len() as u64).sum::<u64>();
        let mut seen=HashSet::new();
        let result=read_event_segment_batch(binding().store_id,binding().job,*order.last().unwrap(),|hash| {
            assert_ne!(hash,[9;32]);assert!(seen.insert(hash));Ok(files.remove(&hash).unwrap())
        }).unwrap();
        assert_eq!(result.events,events);assert_eq!(result.binding,binding());
        assert!(result.terminal);assert_eq!(result.parts,order.len() as u64);
        assert_eq!(result.physical_bytes,physical_bytes);assert_eq!(seen.len(),order.len());
    }
    #[test]
    fn empty_batches_and_both_boundary_splits_round_trip() {
        let cases=[Vec::new(),vec![event(1,&"k".repeat(MAX_BODY_BYTES-28),"z".into())],
            vec![event(1,"",format!("{}é","x".repeat(MAX_BODY_BYTES-33)))]];
        for events in cases { for terminal in [false,true] {
            let (order,files)=encode(&events,terminal);
            let result=read(*order.last().unwrap(),files).unwrap();
            assert_eq!(result.events,events);assert_eq!(result.terminal,terminal);
        }}
    }
    #[test]
    fn missing_middle_final_and_changed_bytes_are_rejected() {
        let (order,files)=encode(&[event(1,"","x".repeat(3*MAX_BODY_BYTES))],true);
        let tail=*order.last().unwrap();
        for hash in [order[1],tail] {
            let mut missing=files.clone();missing.remove(&hash);
            let error=read(tail,missing).err().unwrap();
            assert_eq!(error.kind(),io::ErrorKind::NotFound);assert_eq!(error.to_string(),"missing part");
        }
        let mut changed=files;changed.get_mut(&order[1]).unwrap()[HEADER_BYTES]^=1;
        assert!(read(tail,changed).is_err());
    }
    #[test]
    fn nonfinal_tail_and_rehashed_inconsistent_batch_headers_are_rejected() {
        let (order,files)=encode(&[event(1,"","x".repeat(2*MAX_BODY_BYTES))],true);
        assert!(read(order[0],files.clone()).is_err());
        let tail=*order.last().unwrap();
        // Header changes retain a valid content hash to exercise binding/chain validation.
        for offset in [8,24,89,122,130,138,146] {
            let mut changed=files.clone();
            let new_tail=replace_tail(&mut changed,tail,|bytes|bytes[offset]^=1);
            assert!(read(new_tail,changed).is_err(),"offset {offset}");
        }
        let mut changed=files;
        let new_tail=replace_tail(&mut changed,tail,|bytes| {bytes[88]=4;bytes[89..121].fill(0);});
        assert!(read(new_tail,changed).is_err());
    }
    #[test]
    fn rehashed_body_corruption_and_forged_summaries_are_rejected() {
        let (order,files)=encode(&[event(1,"x","y".into())],false);let tail=order[0];
        for mutation in 0..5 {
            let mut changed=files.clone();
            let new_tail=replace_tail(&mut changed,tail,|bytes| match mutation {
                0=>bytes[HEADER_BYTES+33]=0xff,
                1=>bytes[HEADER_BYTES..HEADER_BYTES+8].copy_from_slice(&u64::MAX.to_le_bytes()),
                2=>{bytes[130..138].copy_from_slice(&2u64.to_le_bytes());bytes[138..146].copy_from_slice(&2u64.to_le_bytes());},
                3=>bytes.push(0),
                _=>{bytes.pop();},
            });
            assert!(read(new_tail,changed).is_err(),"mutation {mutation}");
        }
    }
    #[test]
    fn loader_errors_are_not_retried_and_oversized_parts_fail() {
        let mut calls=0;
        let error=read_event_segment_batch([7;16],binding().job,[1;32],|_| {
            calls+=1;Err(io::Error::new(io::ErrorKind::Interrupted,"loader interrupted"))
        }).err().unwrap();
        assert_eq!(calls,1);assert_eq!(error.kind(),io::ErrorKind::Interrupted);
        assert_eq!(error.to_string(),"loader interrupted");
        assert!(read_event_segment_batch([7;16],binding().job,[1;32],|_|Ok(vec![0;HEADER_BYTES+MAX_BODY_BYTES+1])).is_err());
    }
}
```

- [x] Run `cargo test --locked --jobs 1 --lib registry_event_store::reader -- --nocapture` with `rtk`, `login:false`, VS2022 BuildTools imported and entered in the same PowerShell process, and `CARGO_TARGET_DIR=E:/CodexBuild/devicelane-task10-ci`. Require positive reconstruction assertions to fail at runtime. Stop and repair the command if compilation fails; do not proceed to implementation.

- [x] Replace the inert function with the following code, retaining imports/type/tests. Temporary metadata clones are bounded headers, not event-history clones.

```rust
/// Reconstructs one integrity-checked batch, without fetching its preceding batch.
/// The loader must validate private nofollow regular-file access and bound reads
/// before allocation. Whole-history heads, actor authorization, checkpoint and
/// durability policy remain caller-owned; hashes alone do not authenticate data.
pub fn read_event_segment_batch<F>(store_id:[u8;16],job:[u8;32],tail:[u8;32],mut load:F)
    ->io::Result<DecodedBatch>
where F:FnMut([u8;32])->io::Result<Vec<u8>> {
    let mut seen=HashSet::new();let mut parts=Vec::new();
    let mut current=tail;let mut expected:Option<SegmentHeader>=None;
    let mut index=0;let mut body_bytes=0u64;let mut physical_bytes=0u64;
    let preceding;
    loop {
        if !seen.insert(current) { return Err(invalid()); }
        let bytes=load(current)?;
        let (header,body)=decode_segment(&bytes)?;
        if segment_digest(&bytes)!=current || header.store_id!=store_id || header.job!=job {
            return Err(invalid());
        }
        if let Some(summary)=&expected {
            if header.origin!=summary.origin || header.actor!=summary.actor
                || header.event_count!=summary.event_count
                || header.first_sequence!=summary.first_sequence
                || header.last_sequence!=summary.last_sequence
                || header.part_index!=index || header.flags&6!=0 { return Err(invalid()); }
        } else {
            if header.flags&2==0 { return Err(invalid()); }
            index=header.part_index;expected=Some(header.clone());
        }
        body_bytes=body_bytes.checked_add(body.len() as u64).ok_or_else(invalid)?;
        physical_bytes=physical_bytes.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
        current=header.predecessor;
        parts.push(bytes);
        if index==0 { preceding=current;break; }
        index=index.checked_sub(1).ok_or_else(invalid)?;
    }
    let summary=expected.ok_or_else(invalid)?;
    let part_count=u64::try_from(parts.len()).map_err(|_|invalid())?;
    parts.reverse();
    let mut reader=BodyReader {parts,index:0,offset:HEADER_BYTES};
    let events=read_event_batch(&mut reader,body_bytes)?;
    if u64::try_from(events.len()).map_err(|_|invalid())?!=summary.event_count
        || events.first().map_or(0,|e|e.sequence)!=summary.first_sequence
        || events.last().map_or(0,|e|e.sequence)!=summary.last_sequence {return Err(invalid());}
    Ok(DecodedBatch {binding:BatchBinding {store_id,job,predecessor:preceding,
        origin:summary.origin,actor:summary.actor}, events,terminal:summary.flags&4!=0,
        physical_bytes,parts:part_count})
}
fn invalid()->io::Error {io::Error::new(io::ErrorKind::InvalidData,"invalid event segment batch")}
struct BodyReader {parts:Vec<Vec<u8>>,index:usize,offset:usize}
impl Read for BodyReader {
    fn read(&mut self,out:&mut[u8])->io::Result<usize> {
        if out.is_empty(){return Ok(0);}
        while let Some(part)=self.parts.get(self.index) {
            if self.offset==part.len(){self.index+=1;self.offset=HEADER_BYTES;continue;}
            let count=out.len().min(part.len()-self.offset);
            out[..count].copy_from_slice(&part[self.offset..self.offset+count]);
            self.offset+=count;return Ok(count);
        }
        Ok(0)
    }
}
```

- [x] Require six focused tests and the full library suite to pass; run Clippy `--locked --lib --tests -- -D warnings`, full format check and diff check. Format only owned files for edition 2024; do not mutate unrelated work.
- [x] Obtain independent specification review followed by quality review. No implementer self-review, commit or deployment. Root may stage only the two owned source files and this plan after review.

## Verification record

The inert implementation was executed with VS2022 before implementation: four positive reconstruction tests failed at runtime, while two rejection-only tests passed (exit 101). After implementation all six focused tests passed. The implementer completed the full library suite, Clippy and format checks. Root independently ran all 55 library tests (`4eb161`, exit 0), and reran the six reader tests after final documentation changes (`a76eb8`, exit 0). Independent specification and quality reviews passed; the minor request to explicitly document the unchecked prior-batch reference and whole-history responsibilities was applied and re-reviewed. No live state or services were changed.

## Remaining parent requirements

Whole-history traversal and committed-head summaries, caller actor policy, owner-private immutable file publication, opened-object validation, locking, compact joint metadata/lease checkpointing, offline cutover/downgrade, failure injection and measured linear I/O remain outstanding. The reader API is a foundation for these, not an alternative definition of product completion.
