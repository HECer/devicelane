# Daemon-owned controller runtime

Status: Implementation contract, not an implemented or deployable controller.

This is the runtime prerequisite of `2026-09-06-daemon-pairing-session-design.md`, within the approved autonomous Desktop/CLI product scope. It does not replace the full pairing, persistence, policy or native-host acceptance gates.

## Decision and alternatives

Extract the committed standalone registry dispatcher into a reusable library runtime. The existing `mesh-registry` remains a compatibility wrapper. `devicelane-service` starts the same runtime in process, with a daemon-validated identity and an explicitly reserved normal-network listener. No additional packaged executable is needed.

A bundled registry child would require process supervision, authenticated readiness/control and separate trust-refresh coordination. A service worker subcommand avoids another executable but retains those lifecycle problems. Neither makes passing an identity directory sufficient proof of identity ownership. In-process reuse is the selected approach following independent architecture review.

Work starts from commit `fc14d71771d69abd1d87938e10ebf999cbaa9946` in `.worktrees/daemon-controller`. Uncommitted transport/event-storage changes in the other worktree are excluded. Existing serialized registry state and standalone CLI behavior must remain compatible.

## Ownership and startup

`--listen` continues to mean the local IPC endpoint. `--registry` continues to mean an outbound registry connection. A new explicit `--registry-listen` identifies the normal controller endpoint; it never selects local IPC or implicitly takes over a running standalone registry.

The service validates the role, numeric private/loopback address, state roots and exclusive state ownership, then reserves the requested TCP listener before creating credentials or opening stores that can write. No automatic port fallback is allowed. An occupied port must leave the existing endpoint, credentials, configuration and registry storage unchanged.

The runtime accepts the already bound listener, a daemon-owned validated transport authority, an explicit private state root, offline duration, explicit agent identity admission and worker limits. It does not generate credentials, infer identity paths, parse command-line arguments or run pairing on the normal dispatcher.

The standalone wrapper preserves its legacy identity/state location and existing CLI defaults. The daemon uses its own selected identity and separate registry-state subdirectory. Existing separately keyed installations require an explicit future adoption workflow; no implicit key copy, replacement, trust expansion or migration is introduced here.

## Identity and authorization

The controller identity comes from `SecureTransport::identity_id()`, not the directory basename or `machine_id()` caller label. The actual TLS server leaf must be byte-for-byte the daemon certificate advertised to the pairing session.

The daemon transport authority publishes validated normal-trust snapshots with a generation after serialized trust/revocation changes. Each new connection obtains the current snapshot. Dispatch must revalidate the authorization generation so an already established connection cannot retain revoked permission. Candidate-only pairing roots never enter normal RPC authorization.

An initial controlled runtime restart can provide the trust-refresh boundary only if it closes all prior connections, preserves the exact certificate, exposes downtime honestly and passes restart tests. A running immutable `Arc<SecureTransport>` that never sees persisted trust is not sufficient for pairing integration.

New daemon-controlled meshes use explicitly configured or confirmed agent certificate identities; the legacy standalone fallback identity `agent` is not an implicit authorization grant for new peers.

## Lifecycle and readiness

The handle reports actual bound address, certificate identity/digest, readiness and terminal failure. A cancellable accept loop has a fixed worker limit and tracked sockets/join handles. Admission stops before shutdown; active sockets are closed to interrupt TLS/reads, bounded in-flight persistence finishes, and workers are joined. Partial input must not extend absolute connection deadlines indefinitely.

Startup and listener/storage errors are returned as structured failures, not panics that leave the UI reporting a ready controller. Local dashboard state locks are never held over TLS, registry RPC or shutdown joins. A local-only workstation remains usable without a normal listener.

## Acceptance criteria

1. An actual `devicelane-service` controller process, using a pre-existing certificate/key, serves a real normal mTLS inventory request on `--registry-listen`. The observed server leaf equals those exact certificate bytes. A pretrusted client is allowed in this prerequisite test only; it does not prove pairing.
2. The controller reports the certificate-derived identity. A misleading directory name or caller label cannot change the identity reported for the network endpoint.
3. Occupied-port startup leaves the existing listener and prior credential/configuration/state bytes unchanged. It creates neither a replacement identity nor a fallback listener.
4. Stop/restart releases the port and preserves certificate/key/trust and compatible durable state. Idle, partial-handshake and established connections do not leave detached workers running after shutdown.
5. Explicit agent admission is enforced on agent-only normal RPC operations, including heartbeat and agent progress. Ordinary mutually trusted clients retain read access to inventory without being on the agent allowlist. An untrusted pairing candidate cannot make an inventory request before the required confirmations and persistence.
6. After a serialized trust update, fresh normal mTLS uses the new validated trust generation. Revocation fences existing connections before their next authorized dispatch. Session-local candidate roots never satisfy this check.
7. The existing standalone registry network, lease, artifact, recovery and CLI tests continue to pass without state-format changes.
8. Full create-mesh remains incomplete until two actual daemons pair, persist, restart and execute normal authorized inventory against this same confirmed endpoint, followed by installed Windows/Mac wizard and CLI tests.

## First test implementation task

Create `tests/daemon_controller.rs` with a real subprocess fixture for criterion 1. Use a private temporary root, unique local IPC endpoint, a seeded daemon identity whose certificate identity differs from its directory name, and one independently seeded mutually trusted client. Keep trust preparation entirely inside the owned fixture.

Start `CARGO_BIN_EXE_devicelane-service` with absolute identity/runtime/log paths, `--role registry`, `--registry-listen 127.0.0.1:<reserved-test-port>` and `--agent-peer fixture-agent`, distinct from the trusted inventory client `fixture-client`. Do not pass an outbound `--registry` merely to satisfy the old parser. Preserve `--listen` for the unique local IPC endpoint. A short-lived loopback reservation may choose a test port; if another process wins the bind race, report the actual startup error instead of killing it or silently choosing a replacement.

Bound startup to ten seconds, TCP connect/read/write operations to the remaining deadline and at most one second each. Capture bounded child diagnostics while draining both pipes. Use RAII kill/wait cleanup before deleting the temporary root. Assert that the service remains alive, complete normal mutual TLS, compare the peer certificate bytes, issue `Request::List`, and require an accepted typed `Response`. Verify the seeded certificate/key bytes are unchanged. This test must fail against the baseline service because controller startup/listening is absent; compilation errors or fixture setup failures are not accepted as the behavioral RED.

An `unknown argument --registry-listen` baseline exit proves absent configured-controller support; it must not be described as a successful daemon startup with an observed missing listener. Record the actual failure. The test is not ignored or weakened to accept a missing listener. Do not commit or publish a green-runtime claim while this test remains red. Production extraction follows the verified RED and must receive independent specification and quality reviews.

## Baseline evidence and limits

- Clean-worktree Windows baseline: 14 registry unit tests, 6 local CLI tests and 13 secure-transport tests passed (33 total).
- The latest hosted CI passed macOS, Ubuntu and npm jobs. Its Windows job failed two `remote_apple_e2e` tests: inventory became stale during execution, and lease validation reported a response timeout. The new runtime discovery tests passed there.
- The same clean source passed all three active `remote_apple_e2e` tests locally in 15.34 seconds; two subprocess-fixture tests were correctly ignored. This does not resolve the intermittent hosted failures or establish their cause.
- No production source has changed for this runtime yet. Existing installed services and keys have not been modified.

Provenance: AI-assisted design and test contract based on inspected committed source and independent architecture review. No human-authorship or security-certification claim.
