# DeviceLane Mesh Dashboard, Activity, Policy, and Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an accessible hybrid local/global DeviceLane dashboard that shows trustworthy device topology, live remote resource access, current agent-to-resource occupancy, explicit approvals and rules, and a privacy-bounded 30-day audit through equal UI and CLI clients.

**Architecture:** Add a versioned domain model and bounded event journal to the Rust daemon, then expose read models and commands through the existing authenticated local IPC. The daemon remains the sole authority for mesh credentials, policy decisions, audit persistence, and subscriptions; Tauri and `devicelane` consume the same cursor-based contract. Remote registry data is projected into a local cache with explicit freshness and reconnect states so loss of connectivity never fabricates availability or duplicates work.

**Tech Stack:** Rust 2024, serde JSON, authenticated named-pipe/Unix-socket IPC, append-only JSONL segments with authenticated export manifests, Tauri 2, React 19, TypeScript 5, Vitest/Testing Library, WCAG 2.2 AA semantics.

---

## Scope and acceptance criteria

- The overview distinguishes local-only and authorized whole-mesh scope, and renders hosts, attached devices, connection path, trust, capabilities, permissions, active work, pending approvals, and warnings.
- Status is never color-only. `offline`, `connecting`, `online`, `busy`, `attention_required`, and `remote_access_paused` have stable typed values, visible text, icons hidden from assistive technology, and accessible names.
- A remote resource access produces an ordered event showing principal, source client, target host/device, typed operation, resource class, decision/rule, timestamps, state, redacted output, and available process-tree metrics. Unknown metrics remain `unavailable`, never numeric zero.
- Events are acknowledged by cursor. Reconnect resumes after the last acknowledged sequence, preserves one activity ID and idempotency key, and never starts another job.
- The local event journal has fixed frame, batch, subscriber, memory, and disk bounds. Slow consumers receive `resync_required`; producers and policy enforcement cannot be blocked by UI backpressure.
- Offline hosts and devices remain visible with `last_seen_at`; stale leases are shown as uncertain until registry reconciliation and cannot authorize new work.
- Deny overrides allow, the most-specific matching rule wins within one effect, expired rules do not match, and high-risk operations require fresh target-host confirmation unless an explicit managed policy permits them.
- Audit metadata is append-only for the configured retention window (30 days by default), redacted before persistence, filterable, explicitly deletable with a deletion audit record, and exported with hashes. Audit persistence failure fails closed for new state-changing remote operations.
- Audit data never stores captured audio, screen pixels, keystrokes, arbitrary workspace contents, secrets, tokens, signing material, private keys, or unredacted environment values.
- UI and CLI invoke the same local IPC request types and return equivalent JSON objects and stable error codes.
- Existing `mesh-*` commands, protocol fixtures, daemon lifecycle, and older clients remain compatible; all additions are optional/versioned.

## File map and boundaries

- Create `src/dashboard/model.rs`: canonical IDs, topology, activity, resource, metric, approval, rule, audit, freshness, cursor, and page types only.
- Create `src/dashboard/event_log.rs`: bounded ordered live-event journal and subscription/resync behavior.
- Create `src/dashboard/topology.rs`: merge local/registry snapshots into a freshness-aware hybrid projection.
- Create `src/dashboard/policy.rs`: pure deny-overrides policy evaluation and high-risk classification.
- Create `src/dashboard/audit.rs`: redaction, append-only segmented persistence, retention, filtering, deletion records, and export manifests.
- Create `src/dashboard/service.rs`: application service joining topology, policy, event log, and audit; no transport/UI code.
- Create `src/dashboard/mod.rs`: narrow public exports.
- Modify `src/lib.rs`: export `dashboard`; retain existing wire types.
- Modify `src/local_ipc.rs`: additive protocol v1 minor negotiation, dashboard queries/actions, cursor pages, and stable errors.
- Modify `src/bin/devicelane-service.rs`: construct persistent dashboard service and bridge registry observations.
- Modify `src/bin/devicelane.rs`: equal CLI commands and JSON rendering.
- Create `tests/dashboard_contract.rs`, `tests/dashboard_event_log.rs`, `tests/dashboard_topology.rs`, `tests/dashboard_policy.rs`, `tests/dashboard_audit.rs`, `tests/dashboard_ipc.rs`, and `tests/dashboard_cli.rs`: focused Rust contracts and process tests.
- Modify `desktop/src/api.ts`: exact TypeScript mirror and typed daemon methods.
- Create `desktop/src/dashboard-model.ts`: exhaustive display mappings; no transport.
- Create `desktop/src/components/TopologyView.tsx`, `ActivityFeed.tsx`, `ResourceOccupancy.tsx`, `ApprovalPanel.tsx`, `PolicyRules.tsx`, `AuditHistory.tsx`, and `ScopeSwitcher.tsx`: focused accessible views.
- Modify `desktop/src/App.tsx` and `desktop/src/styles.css`: dashboard composition and responsive native shell.
- Create matching `*.test.tsx` files beside each component; test semantics, keyboard behavior, stale/offline states, and non-color cues.
- Create `tests/mesh_dashboard_e2e.rs`: Windows/client-to-Mac fixture/process vertical slice with reconnect and audit assertions.

## Typed contract invariants

All externally serialized structs use `#[serde(deny_unknown_fields)]`; enums use `snake_case`; timestamps are Unix milliseconds (`u64`); IDs are non-empty opaque strings validated at construction; resource names are typed enums, never free-form authorization strings. Use these canonical shapes consistently in every task:

```rust
pub struct DashboardSnapshot {
    pub revision: u64,
    pub generated_at_ms: u64,
    pub scope: DashboardScope,
    pub hosts: Vec<DashboardHost>,
    pub activities: Vec<ActivitySummary>,
    pub pending_approvals: Vec<ApprovalRequest>,
    pub warnings: Vec<DashboardWarning>,
}

pub enum DashboardScope { Local, Mesh }
pub enum Presence { Offline, Connecting, Online, Busy, AttentionRequired, RemoteAccessPaused }
pub enum Freshness { Live, Stale { last_seen_at_ms: u64 }, Unknown }
pub enum MetricValue { Available { value: u64 }, Unavailable { reason: String } }
pub enum ResourceClass {
    WorkspaceRead, WorkspaceWrite, ArtifactUpload, ArtifactDownload, DeviceLease,
    ApplicationInstall, ApplicationLaunch, Debugger, Signing, Microphone,
    ScreenCapture, NetworkEndpoint,
}
pub enum ActivityState { AwaitingApproval, Queued, Running, Reconnecting, Succeeded, Failed, Denied, Cancelled }
pub enum PolicyEffect { Allow, Deny }
pub enum ApprovalDecision { AllowOnce, AllowAndRemember, DenyOnce, DenyAndBlock }
```

`ActivityEvent` contains `activity_id`, `sequence`, `occurred_at_ms`, `principal_id`, `source_host_id`, `target_host_id`, optional `device_id`, `operation`, `resources`, `authorization`, `state`, optional redacted message, and metric snapshot. `EventCursor` is `(epoch, sequence)`; a daemon restart increments `epoch`, and a cursor from a discarded epoch returns `resync_required` plus a fresh snapshot revision.

### Task 1: Establish canonical dashboard contracts

**Files:**
- Create: `src/dashboard/model.rs`
- Create: `src/dashboard/mod.rs`
- Modify: `src/lib.rs`
- Create: `tests/dashboard_contract.rs`

- [ ] **Step 1: Write failing serialization and validation tests**

Create representative `DashboardSnapshot`, `DashboardHost`, `DashboardDevice`, `ActivityEvent`, `ResourceOccupancy`, `ApprovalRequest`, `PolicyRule`, and `AuditRecord` values. Round-trip JSON, reject unknown fields, empty IDs, duplicate resource classes, `peak_memory_bytes < current_memory_bytes`, terminal activities without `finished_at_ms`, and stale presence without `last_seen_at_ms`. Assert serialized values contain no `private_key`, `token`, `environment`, or workspace content field.

```rust
#[test]
fn metric_unavailability_is_not_serialized_as_zero() {
    let value = serde_json::to_value(MetricValue::Unavailable { reason: "observer_failed".into() }).unwrap();
    assert_eq!(value, serde_json::json!({"unavailable":{"reason":"observer_failed"}}));
    assert!(!value.to_string().contains(":0"));
}
```

- [ ] **Step 2: Verify RED**

Run `cargo test --test dashboard_contract`; expect compilation failure because `device_development_mesh::dashboard` does not exist.

- [ ] **Step 3: Implement the minimal validated model**

Define the file-map types plus `ValidatedId::parse`, `DashboardSnapshot::validate`, `ActivityEvent::validate`, and `PolicyRule::validate`. Use newtypes for host, device, activity, principal, rule, and operation IDs so they cannot be mixed. Keep existing `network_processes::{HostSnapshot, DeviceSnapshot, NetworkEvent}` unchanged and add explicit conversion functions in later tasks.

- [ ] **Step 4: Verify GREEN and compatibility**

Run `cargo test --test dashboard_contract --test protocol_contract --test local_ipc`; expect all tests to pass. Run `cargo fmt --all -- --check` and strict Clippy.

- [ ] **Step 5: Commit**

Commit `feat: define typed dashboard contracts` with only the four listed paths.

### Task 2: Build a bounded, resumable live-event journal

**Files:**
- Create: `src/dashboard/event_log.rs`
- Modify: `src/dashboard/mod.rs`
- Create: `tests/dashboard_event_log.rs`

- [ ] **Step 1: Write failing ordering and backpressure tests**

Test monotonic per-activity sequences, duplicate idempotency-key collapse, rejection of conflicting duplicates, a maximum 1,000 events or 8 MiB in memory (whichever is reached first), maximum 256 events/256 KiB per page, maximum 32 subscribers, and a 15-second idle subscription expiry. Fill beyond capacity and assert an old cursor returns `EventRead::ResyncRequired { oldest_available, snapshot_revision }`, not a partial gap. Assert a slow reader does not block `append` or policy decisions.

```rust
let page = journal.read(EventCursor { epoch: 7, sequence: 0 }, ReadLimit::default());
assert!(matches!(page, EventRead::Events { ref events, .. } if events.len() <= 256));
journal.rotate_epoch(8, 42);
assert!(matches!(journal.read(old_cursor, limit), EventRead::ResyncRequired { snapshot_revision: 42, .. }));
```

- [ ] **Step 2: Verify RED**

Run `cargo test --test dashboard_event_log`; expect missing `dashboard::event_log` symbols.

- [ ] **Step 3: Implement bounded append/read semantics**

Use one `VecDeque<ActivityEvent>` guarded by a short-held mutex, byte accounting from serialized size, and cursor acknowledgement stored per subscriber. Never hold the journal lock during IPC writes. Return `LimitExceeded`, `CursorAhead`, or `ResyncRequired` as stable typed results; do not silently truncate a logical event.

- [ ] **Step 4: Verify GREEN under load**

Run `cargo test --test dashboard_event_log -- --nocapture`; expected PASS including a deterministic 10,000-event producer/slow-consumer case under 5 seconds. Run Miri-compatible unit tests where available and strict Clippy.

- [ ] **Step 5: Commit**

Commit `feat: add bounded dashboard event journal`.

### Task 3: Project hybrid topology and explicit offline semantics

**Files:**
- Create: `src/dashboard/topology.rs`
- Modify: `src/dashboard/mod.rs`
- Create: `tests/dashboard_topology.rs`

- [ ] **Step 1: Write failing projection tests**

Test conversion from existing `HostSnapshot`/`DeviceSnapshot`, stable sorting, local host precedence, trust and connection-path display, capability/permission diagnostics, and device ownership. At heartbeat timeout, preserve the host/device with `Presence::Offline` and `Freshness::Stale`; at first contact use `Unknown`; on reconnect update the same IDs. Mark an active lease `Uncertain` while its owner is stale and reject it for new authorization until reconciliation.

- [ ] **Step 2: Verify RED**

Run `cargo test --test dashboard_topology`; expect missing `TopologyProjector`.

- [ ] **Step 3: Implement the projector**

Add `TopologyProjector::{observe_local, observe_registry, mark_disconnected, snapshot}`. Accept monotonic source revisions and ignore replays older than the stored revision. Compute `DashboardScope::Local` without a registry authorization and `Mesh` only after authenticated registry state is available; never infer trust merely from network reachability.

- [ ] **Step 4: Verify GREEN and old registry compatibility**

Run `cargo test --test dashboard_topology --test agent_registry --test network_device_leases`; expected PASS. Add a v1 fixture lacking dashboard fields and assert conversion yields `Freshness::Unknown` rather than failure.

- [ ] **Step 5: Commit**

Commit `feat: project hybrid mesh topology`.

### Task 4: Implement deny-overrides policy and target-host approvals

**Files:**
- Create: `src/dashboard/policy.rs`
- Modify: `src/dashboard/mod.rs`
- Create: `tests/dashboard_policy.rs`

- [ ] **Step 1: Write the policy decision matrix as failing tests**

Cover exact/wildcard principal, source, target, operation, resource set, optional device, expiry, user-presence flag, managed-policy origin, and disabled rules. Assert deny overrides every allow; otherwise highest specificity wins; ties use newest rule revision only within the same effect. Assert debugger, signing, keychain, screen, microphone, physical-device install, and DeviceLane policy/service changes require fresh target confirmation unless an explicit managed rule matches. Pairing alone yields `ApprovalRequired`.

```rust
assert_eq!(engine.evaluate(&request, now), PolicyDecision::Denied { rule_id: block.id.clone() });
assert_eq!(engine.evaluate(&high_risk, now), PolicyDecision::ApprovalRequired { reason: "fresh_target_confirmation".into() });
```

- [ ] **Step 2: Verify RED**

Run `cargo test --test dashboard_policy`; expect missing `PolicyEngine` dashboard implementation.

- [ ] **Step 3: Implement pure evaluation and approval transitions**

Implement `evaluate`, `create_approval`, and `decide`. Bind approval nonces to exact request digest, target host, expiry (maximum five minutes), and one use. `AllowAndRemember` creates the exact least-privilege rule; `DenyAndBlock` creates an exact deny. Reject decisions from source hosts or expired/non-target sessions.

- [ ] **Step 4: Verify GREEN and adversarial cases**

Run `cargo test --test dashboard_policy --test policy_leases`; expected PASS. Add property tests for rule-order independence and deny dominance, and assert malformed/unknown resource names fail before process creation.

- [ ] **Step 5: Commit**

Commit `feat: enforce dashboard access policies`.

### Task 5: Persist privacy-bounded audit history

**Files:**
- Create: `src/dashboard/audit.rs`
- Modify: `src/dashboard/mod.rs`
- Create: `tests/dashboard_audit.rs`

- [ ] **Step 1: Write failing redaction, retention, and recovery tests**

Use secrets in arguments, environment-looking strings, bearer tokens, paths, stdout/stderr, and artifact metadata. Assert redaction occurs before `append`; forbidden content never appears in raw segment bytes. Test default 30-day retention, configurable 1–365 days, UTC cutoff boundaries, maximum 64 MiB segments, maximum 256 records/1 MiB query pages, stable cursor filtering, crash-truncated tail recovery, corrupt committed segment fail-closed, and disk-full behavior blocking new state-changing remote operations.

```rust
store.append(raw_record_with("Authorization: Bearer secret"))?;
assert!(!std::fs::read(segment)?.windows(b"secret".len()).any(|w| w == b"secret"));
assert!(matches!(guard.may_start_remote_mutation(), Err(AuditUnavailable)));
```

- [ ] **Step 2: Verify RED**

Run `cargo test --test dashboard_audit`; expect missing `AuditStore`, `Redactor`, and `RetentionPolicy`.

- [ ] **Step 3: Implement append-only segmented storage**

Write restrictive per-user files using create-new semantics, length-prefix plus SHA-256 each record, fsync segment and directory on rotation, and atomically update a small index. Redact structured sensitive fields and configured literal secret values before serialization. Do not accept arbitrary regex from remote peers. Recovery may discard only an incomplete uncommitted tail and must record that repair.

- [ ] **Step 4: Implement filtering, deletion audit, and signed diagnostic export**

Filter by time, principal, source, target, device, operation, resource, decision, and result. Retention deletion writes a tombstone summary to the next segment before removing expired segments. Export canonical JSON plus a SHA-256 manifest; sign with the daemon identity through an injected signer that exposes no private bytes. Label an unsigned test export explicitly `signature_status: unavailable`, never `verified`.

- [ ] **Step 5: Verify GREEN and privacy acceptance**

Run `cargo test --test dashboard_audit`; inspect temporary raw files in the test and expect no forbidden fixture values. Run strict Clippy and `git diff --check`.

- [ ] **Step 6: Commit**

Commit `feat: add private retained audit journal`.

### Task 6: Compose dashboard service and authenticated IPC

**Files:**
- Create: `src/dashboard/service.rs`
- Modify: `src/dashboard/mod.rs`
- Modify: `src/local_ipc.rs`
- Modify: `src/bin/devicelane-service.rs`
- Create: `tests/dashboard_ipc.rs`

- [ ] **Step 1: Write failing local IPC contract tests**

Add requests `DashboardSnapshot { scope }`, `ActivityEvents { cursor, limit }`, `AcknowledgeEvents { subscriber_id, cursor }`, `PendingApprovals`, `DecideApproval`, `PolicyRules`, `PutPolicyRule`, `DeletePolicyRule`, `AuditQuery`, `AuditExport`, and `CancelActivity`. Assert protocol `1.0` still handles foundation requests, dashboard requests require negotiated minor capability, unknown fields fail, same-user OS authorization remains mandatory, and all existing 512 KiB frame limits apply.

- [ ] **Step 2: Verify RED**

Run `cargo test --test dashboard_ipc`; expect missing request variants.

- [ ] **Step 3: Implement the application service**

Define `DashboardService` methods matching the requests. Each mutation validates IDs and request version, authorizes local role, evaluates policy, durably audits the decision before starting work, then appends the live event. Cancellation is idempotent. Pausing rejects new jobs/approvals and accepts an explicit `ExistingJobs::Finish | Cancel` choice.

- [ ] **Step 4: Extend IPC additively and preserve bounds**

Increment `LocalProtocolVersion::CURRENT.minor`; advertise feature strings in status. Keep existing enum JSON unchanged. Return stable error codes including `feature_unavailable`, `permission_denied`, `approval_expired`, `audit_unavailable`, `cursor_ahead`, `resync_required`, and `limit_exceeded`; responses that would exceed 512 KiB must use a smaller page or fail before writing.

- [ ] **Step 5: Verify GREEN and disconnect recovery**

Run `cargo test --test dashboard_ipc --test local_ipc --test local_cli --test job_reconnect`; expected PASS. Restart the test daemon between event reads and assert durable activities reconcile to one ID, incomplete state becomes `Reconnecting`, and inconsistent state fails closed.

- [ ] **Step 6: Commit**

Commit `feat: expose dashboard through local IPC`.

### Task 7: Make the unified CLI an equal dashboard client

**Files:**
- Modify: `src/bin/devicelane.rs`
- Create: `tests/dashboard_cli.rs`
- Modify: `npm/README.md`
- Modify: `README.md`

- [ ] **Step 1: Write failing process tests**

Exercise `devicelane mesh status|watch`, `activities list|watch|cancel`, `approvals list|decide`, `policy list|put|delete`, and `audit list|export`, each with `--local`, `--json`, explicit `--endpoint`, bounded `--limit`, and cursor options. Compare parsed JSON to direct IPC responses. Assert daemon errors print structured JSON and exit nonzero, invalid enum/value combinations fail before IPC, and no command accepts raw shell input.

- [ ] **Step 2: Verify RED**

Run `cargo test --test dashboard_cli`; expect unknown command failures.

- [ ] **Step 3: Implement commands using only local IPC types**

Add no second policy/topology model to the CLI. `watch` acknowledges only after successful stdout write; broken pipes terminate without acknowledging unseen events. Human text includes state words and last-seen times. JSON output remains one documented object per query or NDJSON event for watch mode.

- [ ] **Step 4: Verify GREEN and legacy compatibility**

Run `cargo test --test dashboard_cli --test local_cli --test release_contract`; run `npm test` in `npm`; expect all PASS and legacy `mesh-cli` mappings unchanged.

- [ ] **Step 5: Commit**

Commit `feat: add mesh dashboard CLI commands`.

### Task 8: Build accessible topology and activity UI

**Files:**
- Modify: `desktop/src/api.ts`
- Create: `desktop/src/dashboard-model.ts`
- Create: `desktop/src/components/ScopeSwitcher.tsx`
- Create: `desktop/src/components/TopologyView.tsx`
- Create: `desktop/src/components/ActivityFeed.tsx`
- Create: `desktop/src/components/ResourceOccupancy.tsx`
- Create: `desktop/src/components/ScopeSwitcher.test.tsx`
- Create: `desktop/src/components/TopologyView.test.tsx`
- Create: `desktop/src/components/ActivityFeed.test.tsx`
- Create: `desktop/src/components/ResourceOccupancy.test.tsx`
- Modify: `desktop/src/App.tsx`
- Modify: `desktop/src/styles.css`

- [ ] **Step 1: Write failing component and accessibility tests**

Use fixture clients for local/mesh scope, all six presence states, stale hosts, reconnect/resync, unknown metrics, busy devices, leases, and long names. Assert landmark/headings/list semantics, accessible scope tabs, visible text plus icon per state, keyboard focus order, 44px targets, no status conveyed only by CSS class, polite live announcements for new events, and no announcement flood during a 100-event batch.

- [ ] **Step 2: Verify RED**

Run `npm test -- --run` in `desktop`; expect missing component modules.

- [ ] **Step 3: Mirror the Rust contract and add exhaustive display mappings**

Define exact discriminated unions in `api.ts`. In `dashboard-model.ts`, implement exhaustive `assertNever` mappings for labels, icons, sort order, and metric formatting; render `Unavailable` as “Nicht verfügbar: reason”, never `0`. Poll snapshots at a bounded interval and stream cursor pages with abort-on-unmount and exponential reconnect capped at 30 seconds.

- [ ] **Step 4: Implement the hybrid visual dashboard**

Compose scope switcher, host/device cards, connection path, capabilities/permissions, active job count, resource occupancy (`Agent/App → Host/Device/Workspace/Resource`), warnings, and event feed. On `resync_required`, fetch one fresh snapshot, reset the cursor once, and avoid duplicating existing event IDs. Preserve selection when a host becomes offline.

- [ ] **Step 5: Verify GREEN and responsive behavior**

Run `npm test -- --run`, `npm run typecheck`, and `npm run build`. Test 320%, 400%, reduced motion, high contrast, keyboard-only navigation, and widths 360/768/1440 using deterministic component assertions or Playwright if already added; expect no clipped controls or inaccessible hover-only information.

- [ ] **Step 6: Commit**

Commit `feat: visualize mesh topology and activity`.

### Task 9: Add approval, policy, and audit UI

**Files:**
- Create: `desktop/src/components/ApprovalPanel.tsx`
- Create: `desktop/src/components/PolicyRules.tsx`
- Create: `desktop/src/components/AuditHistory.tsx`
- Create: `desktop/src/components/ApprovalPanel.test.tsx`
- Create: `desktop/src/components/PolicyRules.test.tsx`
- Create: `desktop/src/components/AuditHistory.test.tsx`
- Modify: `desktop/src/App.tsx`
- Modify: `desktop/src/styles.css`
- Modify: `desktop/src-tauri/src/lib.rs`

- [ ] **Step 1: Write failing safety and interaction tests**

Assert approval cards show exact principal/source/target/operation/resources/risk/expiry and require confirmation for remembered/blocking rules. Destructive choices are not default-focused. Expired requests disable actions. Rule editing exposes specificity, effect, origin, expiry, and user-presence requirement. Audit filters are keyboard operable, pagination bounded, export reports signature status, and deletion requires scope plus retention explanation.

- [ ] **Step 2: Verify RED**

Run `npm test -- --run`; expect missing modules and commands.

- [ ] **Step 3: Add typed Tauri commands without credential exposure**

Bridge each new IPC operation in `desktop/src-tauri/src/lib.rs`. Commands accept typed request bodies, never identity paths or secrets, and pass daemon error codes to the UI. Emit native notifications only for target-local pending approvals; notification actions reopen the exact approval but do not approve outside the authenticated app session.

- [ ] **Step 4: Implement approval, rule, and audit flows**

Disable double submission, handle optimistic concurrency with rule revisions, announce success/failure, and refresh from daemon truth. Show deny precedence and managed-rule read-only state. Keep redacted log text in a selectable `<pre>` with a clear “redacted” label; never render HTML from event payloads.

- [ ] **Step 5: Verify GREEN**

Run desktop tests, typecheck, build, and `cargo test --manifest-path desktop/src-tauri/Cargo.toml`. Run an axe-compatible scan if available; otherwise retain explicit role/name/tab-order assertions and record the limitation in the verification report.

- [ ] **Step 6: Commit**

Commit `feat: add approvals policies and audit UI`.

### Task 10: Prove end-to-end safety, parity, and real-host behavior

**Files:**
- Create: `tests/mesh_dashboard_e2e.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `scripts/mac-hardware-gate.sh`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Write a failing vertical-slice test**

Start registry, Windows/client fixture, Mac/agent fixture, daemon, CLI, and UI bridge. Pair hosts; submit an operation requiring `WorkspaceRead` and `DeviceLease`; deny once; resubmit and allow once; observe exactly one running activity and occupancy edge; disconnect/reconnect; resume after cursor; finish; query audit. Assert matching IDs and decisions across direct IPC, CLI JSON, and Tauri bridge.

- [ ] **Step 2: Verify RED**

Run `cargo test --test mesh_dashboard_e2e`; expect missing complete integration behavior.

- [ ] **Step 3: Add deterministic failure-path gates**

Cover target offline before approval, disconnect after authorization, daemon restart, observer unavailable, event overflow/resync, audit disk failure, expired approval, deny-overrides conflict, stale lease, cancellation race, and old agent lacking optional dashboard messages. Each case must terminate, preserve one activity identity, and expose a stable actionable error rather than hang.

- [ ] **Step 4: Extend CI and the physical Mac gate**

Run Rust/unit/UI/contract suites on Windows, macOS, and Linux. The hardware gate against the paired Apple Silicon Mac must show Windows principal/source in the Mac approval, resource access in both live views, nonzero-or-unavailable metrics, disconnect recovery, terminal result, and the same redacted audit record on the target. Capture only redacted diagnostic metadata; do not upload local audit databases or private identity files.

- [ ] **Step 5: Run the complete quality gate**

On Windows with the VS developer shell and `CARGO_TARGET_DIR=E:\CodexBuild\devicelane-speechwalker`, run:

```powershell
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
Push-Location desktop
npm test -- --run
npm run typecheck
npm run build
Pop-Location
git diff --check
```

On macOS/Linux run the equivalent locked Rust and desktop commands plus platform lifecycle smoke tests. Expected: all PASS; no ignored dashboard security/privacy tests.

- [ ] **Step 6: Independent reviews and commit**

Dispatch an independent specification review, then a separate code-quality/security/privacy review. Resolve every Critical/Important finding with a new failing regression test and a separate fix commit. Commit the gate/docs change as `test: gate mesh dashboard behavior`.

## Final verification checklist

- [ ] A user can switch between local and authorized mesh scope without a terminal and can still perform the same workflow through `devicelane --json`.
- [ ] Every resource access is visible live and attributable to principal, source, target, operation, resources, policy decision, and one stable activity ID.
- [ ] Offline, reconnecting, stale, uncertain lease, unknown metric, approval-needed, and paused states are explicit and accessible.
- [ ] Event journal, IPC frames/pages, subscribers, memory, disk segments, and UI announcements have tested bounds and deterministic resync behavior.
- [ ] Default 30-day retention and deletion/export behavior are tested at boundary timestamps and after crash recovery.
- [ ] Raw audit files and exported fixtures contain none of the forbidden privacy data; absence of a watermark or credential is never treated as proof of human authorship or safety.
- [ ] Existing clients and network protocol fixtures pass unchanged; optional features negotiate cleanly with old agents.
- [ ] Real Windows-to-Mac validation passes before a production release is labeled complete.

