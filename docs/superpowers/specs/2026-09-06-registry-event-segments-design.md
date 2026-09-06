# Registry event segments design

Status: independently approved for implementation planning on 2026-09-06; not a code, storage-rollout, or product-completion approval.

Review record: revision `56d13d8083be748fda54ad4cec6f2447f0b514f4d93b7f0e80d86331e87320c0` had no Critical or Important findings. The two Minor terminology corrections (job binding and derived lease-mirror persistence) were applied in revision `a31c0140f3359bd910cf836381ac0700c5750aa0b4d083d4235692eb24bc0b17`. The reviewed offline-upgrade, bounded-format, and joint-checkpoint decisions remain unchanged. Each implementation slice still requires test-first evidence and independent specification/quality review before rollout.

This is an AI-assisted engineering specification. It addresses one incomplete part of the existing DeviceLane product objective, not a replacement or reduced definition of product completion.

## Problem and evidence

The current registry embeds all event payloads in `DurableState.jobs`. Progress commits clone that state, serialize a complete checksummed snapshot, read and validate the previous snapshot, and atomically rewrite it. Heartbeats and other metadata-only operations also persist this payload-bearing state.

The explicit Windows debug-build benchmark `progress_snapshot_scaling_exposes_superlinear_checkpoint_work` produced:

| Payload | Progress commits | Logical snapshot writes | Logical previous-snapshot reads | Commit time | Unchanged heartbeat time |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 MiB | 5 | 3,479,110 B | 2,429,294 B | 464 ms | 141 ms |
| 8 MiB | 21 | 95,303,805 B | 86,908,885 B | 12,411 ms | 1,141 ms |
| 32 MiB | 76 | 1,307,161,001 B | 1,273,582,593 B | 173,071 ms | 4,356 ms |

These are checkpoint-length-based logical accounting and measured elapsed time, not physical OS I/O, allocation, or RSS measurements. The benchmark uses 64-KiB ASCII events, seven events per data batch, separate start and terminal commits, and reports every size before asserting the linear-work budget. The existing result is deliberately RED.

## Decision and alternatives

Use immutable, hash-linked per-job event segments and a compact schema-2 registry checkpoint containing committed event heads. Keep in-memory event history for current readers, but do not serialize or clone historical payloads during a commit.

A global framed write-ahead log would also eliminate payload rewrites, but requires shared-offset recovery, tail truncation, Windows append semantics, and eventual compaction. Those additional mechanisms are unnecessary for the current approximately 75 data segments per 32 MiB workload. An arbitrary small total-output cap is rejected: legitimate build logs must remain complete.

## Scope and invariants

- Preserve the existing public request/response schema, frame limits, sequence numbers, payload bytes, observer reads, retry budgets, and process execution semantics.
- Preserve assigned-agent checks, exact replay, the narrowly defined lost-start-ACK fallback, lease revocation/expiry behavior, and terminal durability before writer promotion.
- Do not alter identity certificates, private keys, trust records, installed services, or real user state while implementing and testing.
- Remove event payloads from every registry metadata checkpoint, including heartbeat, lease, cancel, dispatch, generic Run/Complete, and startup reconciliation.
- No historical event-payload clone per progress commit. Runtime history itself must not implement an implicit whole-history `Clone` used by commit staging.
- Retain existing logs across migration and fail closed on unsupported downgrade or corrupt committed storage.
- Audit growth across many jobs and fully lazy event reads are separate work. Neither permits payloads to re-enter the checkpoint.

## Components and data ownership

Keep handler integration in `src/bin/mesh-registry.rs`. Introduce a focused library module `src/registry_event_store.rs` with a narrow store API for immutable segment I/O, integrity validation, and head traversal. This permits crate-internal reuse of security primitives, which a binary-private module cannot access. Where necessary expose narrowly scoped crate-internal private-I/O adapters from the audit implementation; do not expose those helpers as general public APIs or change existing audit behavior. The public `write_private_atomic` helper replaces destinations and must not be reused as immutable publication. A separate private checkpoint/migration module under `src/bin/mesh-registry/` owns registry-specific compatibility and metadata transitions. Do not reorganize unrelated registry behavior.

Separate three representations:

1. A deserialize-only legacy representation with the existing fields, including `jobs`.
2. Compact V2 metadata containing all existing non-`jobs` fields, an opaque random `event_store_id`, per-job event heads, and the authoritative serialized lease book (excluding its runtime path).
3. Runtime state containing compact metadata and hydrated job histories. Only compact metadata and the lease book are cloned for staging.

A job head records the tail content hash, event count, sequence summary, and whether the committed history is terminal. Empty newly created jobs have an explicit empty head. A segment contains a segment-format version, store ID, job binding, predecessor hash, origin, event sequence summary, terminal status, and encoded event bytes. Its content hash covers all fields and payloads.

Origin distinguishes new Apple agent progress (with its assigned peer), registry-control events, generic completion, and migrated legacy history. Registry-control origin identifies locally generated transitions, including heartbeat dispatch rejection (`rejected/lease_inactive`) and cancellation before dispatch; it must not impersonate an assigned agent or a generic completion. A segment's job/stream identity is distinct from its producing actor. Generic and legacy histories without `job_agents` entries must not be given invented peer identities. New Apple agent appends remain subject to the current strict assignment check. Existing authorization for registry-control transitions is retained, and their event head and related pending/dispatch/cancel metadata commit atomically. A migrated completed history can retain legacy sequence gaps or non-Apple terminal kinds; preserve its exact stored events rather than interpreting it as a new Apple batch. A pending Apple history that cannot support the existing append rules fails closed rather than being renumbered or silently normalized.

Segment filenames derive only from validated content hashes, never raw job or peer identifiers. Store IDs and hash strings have a fixed validated grammar. The store sits beneath the registry identity directory at a fixed event-store location.

### Deterministic bounded segment format

Storage encoding is independent of the unchanged JSON wire protocol. A logical append batch is encoded as `u64 event_count`, followed by each event's `u64 sequence`, `u64 kind_byte_length`, UTF-8 kind bytes, `u64 payload_byte_length`, and UTF-8 payload bytes, in that order. All integers are unsigned little-endian with checked conversions and arithmetic. Strings retain their exact Unicode scalar sequence and UTF-8 bytes; no normalization, escaping, newline conversion, sorting, or deduplication is performed. This encoding has no maps or serializer-dependent field order.

Stream these bytes into physical segment bodies of at most 524,288 bytes. Every nonfinal body is exactly that size; the final body is nonempty. A logical event may cross any physical boundary, including inside a UTF-8 code point or length prefix. This is storage fragmentation only: reconstruction emits the original event, not fragments. There is no total log-size cap and no new rejection of a legacy event solely because it exceeds one body. A zero-event batch has the eight-byte zero count body; an initial empty job may instead have no segment at all.

Each physical segment has this fixed 158-byte header, immediately followed by the body, with no padding or trailing bytes:

| Field, in order | Bytes | Meaning |
| --- | ---: | --- |
| Magic/version | 8 | ASCII `DLSEG001` |
| Store ID | 16 | Random store identifier; checkpoint form is exactly 32 lowercase hex digits |
| Job binding | 32 | SHA-256 job identity digest defined below |
| Predecessor | 32 | Previous physical segment hash; all zero only for a new stream |
| Origin | 1 | 1 Apple agent, 2 registry control, 3 generic complete, 4 legacy |
| Actor binding | 32 | Peer digest for Apple agent; all zero for other origins |
| Flags | 1 | Bit 0 first part, bit 1 last part, bit 2 terminal history; all other bits zero |
| Batch event count | 8 | Count of logical events in this append, repeated in every part |
| First sequence | 8 | First stored event sequence, or zero for an empty batch |
| Last sequence | 8 | Last stored event sequence, or zero for an empty batch |
| Part index | 8 | Zero-based within this logical batch |
| Body byte length | 4 | Exact following body length, 1 through 524,288 |

The file hash is SHA-256 of ASCII `DeviceLane/event-segment/v1` followed by one NUL byte and the entire header/body bytes. The immutable filename is exactly its 64 lowercase hexadecimal digits plus `.seg`. Identity digests use SHA-256 of ASCII `DeviceLane/event-job/v1` or `DeviceLane/event-peer/v1`, one NUL byte, the identity UTF-8 byte length as little-endian u64, then its UTF-8 bytes. Raw identifiers remain in compact metadata; compare their computed digests when loading or appending. Hashes provide integrity/binding, not authenticity against a principal who can rewrite the whole owner-private store.

The first part links to the previously committed physical tail. Subsequent parts link to the immediately preceding part and increment the index by exactly one. Store, job, origin, actor, count, and sequence summaries must agree throughout a batch. First/last flags must match boundaries; only a final part may set the terminal flag. The checkpoint may reference only a last part. Intermediate part files are not commits. The reconstructed batch must consume its exact body stream, event count, and summaries with no trailing bytes. Completed legacy sequence gaps remain permitted as described above; summary fields do not renumber or sort them.

Readers reject oversized files before payload allocation, unknown versions/flags/origins, incorrect header/body lengths, arithmetic overflow, inconsistent part chains, invalid UTF-8 after reconstruction, and lengths exceeding the remaining committed body bytes. Do not reserve attacker-declared string or event capacity up front. Read each physical file at most once per cold load; keep validated bodies or a forward reconstruction index while traversing backwards. This slice already hydrates full histories, so recovery memory is proportional to committed history; it does not promise constant-memory history queries. Writers stream incoming or legacy event references through one bounded body buffer, not a second whole-history serialization buffer.

Golden byte/hash vectors must cover empty and nonempty batches, NUL/newline/quotes/non-ASCII payloads, sequence zero and u64 maximum, and identical content across Windows and Unix. Boundary tests split a length prefix and a multibyte character, and migrate a single legacy event larger than two body limits. Corruption tests cover mismatched actor/job/store, cross-batch splicing, missing middle/final parts, forged lengths/counts, extra trailing bytes, and a checkpoint referencing a nonfinal part. Byte accounting counts every physical file and its 158-byte header; the per-segment overhead acceptance gate refers to physical segments, not unbounded logical batches.

## Private storage boundary

Use existing platform ownership/permission primitives through narrow adapters, not unconditional calls to their current repair behavior. Apply the following explicit path-class policy:

- Fresh V2 store directories are created owner-private (0700 on Unix, current-owner restricted ACL on Windows) before any payload is written. Fresh files are owner-private (0600 on Unix or the corresponding restricted ACL). A directory creation race is treated as an existing-directory case, not permission to repair an unknown object.
- Existing V2 directories, segments, checkpoint/barrier files, backups, lock files, and staging files are validated without silent permission repair. Reject unsafe permissions, unexpected owners, symlinks/reparse points, and wrong file types. Existing audit directory helpers currently tighten modes/ACLs; the new adapter must perform strict validation first instead of inheriting that repair policy.
- Legacy V1 input is read-only migration input, not a V2 file. Require the expected owner, regular-file/non-reparse type, nofollow opening, integrity validation, and no unrelated-principal write access to the file or trusted containing identity directory. Broader legacy read permissions may be retained for compatibility; they are not copied to newly written files. Do not silently chmod or rewrite the only legacy source during validation.
- New compact checkpoints, migration barriers, private legacy backups, and all their temporary files use the same private/nofollow boundary as new segments. Replacing a legacy checkpoint during the reviewed cutover is an explicit mutable-checkpoint operation, not an exception permitting segment replacement.

Validate final components and the opened object, rather than trusting only an earlier pathname check. Do not follow attacker-controlled names into unrelated locations.

Create segment staging files privately with exclusive creation. Write bounded segment contents, sync the file, install the immutable final name without overwriting an existing file, and sync the parent directory with the established platform durability primitives. An existing candidate is reusable only after exact content/hash/binding validation. No truncating or replacing an immutable final segment on collision.

Unreferenced segments are ignored on recovery. Do not introduce garbage collection in this slice; retaining bounded test orphans and migration backups is preferable to unsafe deletion. Report orphan retention as an operational limitation.

## Commit protocol

Under the existing registry state coordination boundary:

1. Validate the authenticated caller, existing job, sequence continuity, duplicates, terminal placement, and lease/start conditions before mutation.
2. Stage only compact metadata and lease changes. Retain historical event payloads by reference.
3. Persist and sync the new immutable segment. If an identical orphan already exists, verify and reuse it.
4. Atomically persist the schema-2 checkpoint with the new head, all associated metadata deltas, and the staged lease book. This single checkpoint is the joint event/metadata/lease commit point.
5. Only after successful checkpoint persistence, update runtime metadata and leases together and append the new batch to runtime history, while retaining the coordination lock.
6. Persist the derived schema-1 lease mirror; only after success allow subsequent mutation/dispatch and send the ACK. On mirror failure enter a repair-required state, not a mixed old-lease/new-event runtime state.

Exact replay after an ambiguous failure repairs the derived lease mirror and re-persists the compact checkpoint when required before ACK, without another segment or event append. A terminal checkpoint committed before a mirror failure remains authoritative, including its lease transition. On restart load the joint checkpoint and its events before expiry or reconciliation; never import older lease rights from the mirror. Reconciliation remains a staged joint metadata transaction so the old writer is released only on durable terminal evidence or the existing authorized detach behavior.

Generic Complete must use the same segment-before-head discipline and atomically checkpoint its pending removal, artifact reference, audit entry, and new event head. Registry-generated rejection/cancellation events also use segment-before-head and atomically checkpoint their associated metadata transitions. Heartbeat/lease/cancel/dispatch operations that do not generate events persist compact metadata only. They must neither serialize runtime histories nor read event segments during a normal metadata-only checkpoint.

### Metadata and lease transaction matrix

One coordination boundary owns compact state and the lease book. Remove paths that mutate a live lease book or state before persistence, or acquire those locks in opposing order. A handler validates and computes its complete staged transition first, then uses the joint checkpoint commit above. No grant, dispatch response, successful lease response, or new externally visible inventory is published between staging and successful persistence. Failed validation discards request-specific deltas; any legitimate expiry maintenance is a separate committed transition.

The schema-1 `device-leases.json` becomes a derived compatibility/diagnostic mirror, not a second authority. Keep its envelope and fields compatible, but V2 startup never uses it to initialize lease rights. A missing mirror is recreated from the committed checkpoint; a checksum-valid stale mirror is replaced with the authoritative contents. An existing malformed, unsafe, or nonregular mirror fails closed and requires explicit repair rather than being silently overwritten. Failure to persist a valid mirror blocks new mutations and grants until repair succeeds. Read-only diagnostics can expose the jointly committed state and the repair error. No successful response is sent for the failed write, even though a durable checkpoint may already contain the transition.

Fresh initialization and offline legacy migration populate the joint lease snapshot before the first V2 checkpoint. Legacy lease loading is read-only: do not call the present `LeaseBook::load` implementation, which expires and persists as a side effect. Validate the legacy lease file/fallback and preserve its exact selected bytes privately before cutover; retain an absent lease file as an explicit empty legacy book only where existing legacy semantics permit that absence. After importing, apply expiry/reconciliation through the same staged transaction before opening the listener. No new lock-free persistence call may bypass the joint commit API.

| Handler/transition | Joint staged fields | Event-store I/O during normal commit |
| --- | --- | --- |
| Idle heartbeat / connected inventory refresh | Host/device owner mappings, pending-detach clearing, expiry effects | Zero |
| Inventory disappearance with an active writer | Pending detach/release; retain writer fencing until the existing terminal/detach rule permits removal | Zero |
| Inventory disappearance without a writer | Device mapping removal, release/queue promotion | Zero |
| Generic dispatch / Apple dispatch grant | Dispatch metadata and any writer reservation plus expiry effects; response issued only after commit | Zero |
| Dispatch rejected for inactive lease | Pending removal, rejection head, lease cleanup | New registry-control batch only |
| Acquire / queue / renew / release / revoke / disconnect / expiry | Active leases, waiting queue, next ID, pending release and writer fencing as applicable | Zero |
| Authorized AgentDetach | Device ownership removal and existing force-release/promotion transition together | Zero |
| Cancellation without a new event | Cancellation/pending metadata and applicable lease deltas | Zero |
| Predispatch terminal cancellation | Cancellation event head, pending/cancel metadata, applicable lease deltas | New registry-control batch only |
| Apple start/progress/terminal or generic Complete | Event head and all associated job/audit/artifact metadata plus lease snapshot | Incoming batch only; exact replay writes no segment |
| Startup expiry/reconciliation after history validation | Reconciled metadata and authoritative leases together | Zero additional segment I/O |

For every row inject failure before checkpoint publication, after publication before directory sync, after checkpoint durability before mirror update, during mirror update, and after both writes before response. Before publication the old pair is authoritative. Once the new checkpoint is durable the new pair is authoritative even when the mirror is old. An ambiguous checkpoint error (including directory-sync failure) fences mutation and reloads/revalidates the main/fallback selection under the store lock before continuing; it must never blindly restore an old runtime state and later overwrite a possibly committed transition. A selected old checkpoint yields the entire old pair; a selected new checkpoint yields the entire new pair. No recovery may combine fields from different generations. Power-loss durability claims require the platform sync primitive; ordinary process-kill tests alone are not proof of stable-media behavior.

Lost-response retries retain existing operation authorization and wire semantics; do not invent retry IDs or replay a device command. In particular, progress exact replay must acknowledge the same durable events without another queue promotion, while a non-idempotent lease operation may retain its existing post-commit response semantics. Tests assert both the response and the resulting writer/queue state. This joint-checkpoint decision intentionally replaces a two-file transaction/intent log: the small lease book was already cloned per transition, and embedding it does not reintroduce historical event payloads.

## Recovery

The compact checkpoint selects authoritative heads. Follow each reachable predecessor chain, validate content hashes and store/job/origin bindings, detect cycles and conflicting ranges, and reconstruct the committed ordered history. Enforce count and terminal summaries. Read and hash each referenced segment once per cold load. Ignore additional unreachable segment files.

Missing, corrupt, misbound, or structurally inconsistent referenced segments produce a stable recovery error and prohibit mutation. Do not fall back to an older valid checkpoint merely to hide corruption of a committed current checkpoint. Preserve current fallback rules for interrupted atomic replacement, extended explicitly for schema 2.

| Failure point | Required recovered state |
| --- | --- |
| Before immutable segment installation | Old committed head; no ACK |
| Segment installed, old checkpoint | Old head; orphan ignored or verified on retry |
| New checkpoint, old lease mirror | New events and leases from the joint checkpoint; repair mirror before grants/ACK |
| New checkpoint and lease, lost ACK | Exact replay; no duplicate events or promotion |
| Referenced data missing/corrupt | Recovery error; no successful mutation |

## Legacy migration and downgrade

Migration runs before accepting new requests. Read bare JSON or schema-1 data using the existing checksum and generation semantics. Preserve exact legacy bytes in a private backup outside all old loader search names. Materialize and verify all legacy event histories into a new store before changing the authoritative checkpoint.

### Exclusive writer and offline upgrade

Every V2 registry process acquires and holds an OS-backed exclusive identity-store lock before loading or mutating registry state, lease state, artifacts, or migration files. Contention fails startup without mutation. The lock is a fixed private file subject to the opened-object validation above; its continued existence is not evidence of a live owner, and it is not unlinked on release. Process termination releases the OS lock. Tests must use two actual processes, including abrupt owner termination, rather than only a thread-local mutex.

The legacy `7c73879` reader does not honor this lock. Therefore the lock does NOT make online migration safe. Legacy input at ordinary startup returns an actionable migration-required error without changing it. A dedicated `mesh-registry --identity <path> --migrate-event-store` command performs the upgrade and exits without opening a listener. Before this command, the deployment workflow must stop the old registry and disable its automatic restart, verify that its owned process has exited, and retain that quiescent state until migration and V2 validation finish. It must not terminate unrelated processes or claim that a free TCP port proves there is no writer. A direct operator invocation has the same explicit offline precondition. The command holds the new lock, but cannot technically exclude an independently started old binary; concurrent legacy writers are unsupported and must be stated in help and deployment diagnostics.

An interrupted migration is resumed only through that offline command while a V1 main is still authoritative. A V2 normal startup may recover a fully committed V2 checkpoint as specified below. Installer/service integration must implement the stop/upgrade/validate/start sequence before any real rollout; this specification does not authorize modifying installed services now.

Use a schema-2 envelope for registry metadata; do not publish schema 1 with empty `jobs`. Artifact and derived lease-mirror envelopes remain schema 1. The authoritative lease book is embedded in V2 as specified above. The old registry rejects schema 2 instead of silently loading an empty history.

Before installing the V2 main file, atomically establish valid V2 fallback/barrier files in the old loader's nonpartial `.retired` and `.previous` search locations. Eliminate any recoverable V1 `.next` from that search path by preserving it outside those names and replacing its role with verified V2 staging; do not delete the only legacy copy. Until the main replacement, a valid V1 main remains authoritative. The upgrade writer replaces main directly, rather than rotating V1 main back into a scanned fallback name. Sync each required file/directory transition.

The cutover checkpoint is serialized once. Both barriers and the staged replacement are complete byte-identical copies of that checkpoint, including its generation, store ID, metadata, and event heads; they are not marker-only files. Its generation is one greater than the selected legacy generation, with overflow rejected. The legacy source bytes and generation are fixed for this offline attempt. If legacy recovery initially selected a fallback because main was absent, first preserve the selected source privately and restore it as a valid V1 main using a synced direct atomic replacement. Only then establish V2 barriers. Never leave the only recoverable legacy source dependent on a barrier name being overwritten.

V2 checkpoint selection is deterministic:

- A present main is authoritative. Validate it; corruption is an error, not permission to choose an older fallback. A valid V1 main requires the offline migration command even if V2 barriers already exist.
- With main absent, validate the nonpartial `.retired` and `.previous` candidates. Invalid nonpartial candidates fail closed. A torn `.next` can be ignored; a complete `.next` must pass the same envelope and referenced-data validation before it is eligible.
- During cutover, both V2 barriers must agree byte-for-byte. A V1/V2 mixture is an interrupted pre-cutover upgrade requiring offline recovery from the preserved legacy source, not an automatic choice by highest generation. Once cutover is complete, all eligible fallback candidates must belong to the same V2 store. Select the highest valid generation; equal generations with differing bytes are corruption. Unselected lower-generation V2 candidates are not used to conceal invalid committed data.
- After selecting a V2 fallback, reconstruct and verify its referenced history before restoring main with a direct synced atomic replacement. Do not rotate a legacy file back into the fallback set. Do not accept requests until this completes.

Test cuts after private backup sync, legacy-main normalization, each barrier install and directory sync, V1 `.next` preservation, V2 staging sync, main replacement, and final directory sync. For each cut record the exact main/fallback bytes, selected schema/generation, whether normal startup or explicit offline resume is allowed, and the result of running the real old reader. In particular, a present V1 main before cutover may still be read by the old binary; after V2 main publication or its later loss, the old binary must reject successful state-mutating requests and cannot overwrite authoritative V2 data.

The real old binary may remain alive in recovery-error mode rather than fail with a startup exit code. It also unconditionally expires and persists its schema-1 lease file during startup, and may create an absent artifacts directory. These are explicit downgrade-test exceptions, not evidence that the new checkpoint was accepted. Verify that all authoritative V2 checkpoints, segments, private backups, identity/trust bytes, and existing artifact files remain unchanged. Precreate the artifacts container in the fixture. Record the old reader's lease-mirror rewrite, then stop that owned process and verify that V2 startup derives lease rights from its joint checkpoint and repairs the mirror, without granting rights introduced by the old process. Do not advertise a fully write-free legacy startup.

After main replacement, reload and verify V2 and its segment chains before opening the listener. Test every migration crash cut. Recovery may select the fully old or fully new state at the cut, never a partial or silently empty history. A missing main after cutover must not let an old binary recover a stale V1 fallback. Keep the private legacy backup for explicit recovery; automatic downgrade is not provided.

## Verification and acceptance

Use test-first changes and independent specification/code review for each coherent implementation slice. No deployment until the full storage slice is verified.

1. Preserve current agent, registry, CLI, artifact, lease, progress, and remote E2E regressions, including actual sender ACK-loss plus real registry restarts, real expiry/revoke, and the 840,200-byte CLI/artifact test. Keep existing test timeouts, including its 15-second overall completion deadline and 5-second individual CLI deadline; do not tighten them into a new total five-second requirement.
2. Run identical 1/8/32-MiB benchmark fixtures before and after. Report actual segment bytes plus logical checkpoint read/write totals, per-size elapsed time, batch count, and metadata-only heartbeat cost. Do not claim the old checkpoint-only counter proves total new-store work.
3. Cumulative committed segment bytes are at most encoded event bytes plus 2 KiB per segment. The compact state size and its prior-checkpoint read grow by no more than 4 KiB between 1 and 32 MiB for the same job set. No payload sentinel occurs in compact state.
4. Historical event-payload clone bytes per commit are zero, supported by representation and targeted instrumentation. Only the incoming batch may be cloned for runtime ownership.
5. Total logical event-store plus checkpoint I/O scales approximately linearly: 32/8 ratio at most 4.5 and 8/1 ratio at most 8.5 for the fixed fixture; report fixed metadata overhead separately. Use deterministic byte accounting for CI gates and same-build/same-filesystem elapsed comparisons as supporting evidence, not unexplained machine-specific absolute time limits.
6. After each size, execute 100 real idle heartbeats and a lease metadata operation. Require zero segment I/O and less than 4 KiB difference per metadata operation between 1 and 32 MiB. Include generic completion followed by heartbeats.
7. Cold load validates each referenced segment once and reconstructs exact kinds, sequence numbers, payloads, counts, and terminal state. Observer paging and artifact integrity remain unchanged.
8. Inject failures before/after segment installation, checkpoint replacement and directory sync, derived lease-mirror persistence, and ACK. Verify exact old/new state, replay idempotency, writer fencing, and corruption fail-closed behavior.
9. Migration tests cover bare JSON and schema-1 data, generic and Apple jobs, completed and pending histories, every backup/barrier/main-replacement crash cut, and private backup byte preservation. Legacy snapshot reads are one-time migration work, never repeated per new segment or heartbeat.
10. Test downgrade with the existing `7c73879` registry reader, both with V2 main present and main absent with V2 barriers. Require rejection of mutations and event-history reads rather than successful empty-job responses; startup exit is not required. Preserve authoritative V2 checkpoints/segments/backups, identity/trust bytes, and existing artifact files. Explicitly observe the legacy lease-mirror side effect and verify V2 restores the authoritative lease snapshot afterward, as specified above.
11. Windows and Unix private-store tests cover directory/file collisions, symlink/reparse components, nonregular files, unsafe owners/permissions, and immutable segment collisions. Verify normal fresh-store, retry, and restart behavior on both platforms.

## Implementation sequence

First finalize the existing bounded-paging and I/O-diagnostic reviews. Then implement the isolated segment primitive and its corruption/private-storage tests, the compact checkpoint/runtime separation, handler integration, and migration/downgrade cutover in separately reviewed steps. Finally repeat the measured scaling cases and real-network fault tests before any rollout. A detailed code-level implementation plan follows independent review of this specification.
