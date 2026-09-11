# Persistent Mesh Connection Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for inline execution with independent review. Follow the approved desktop product design and the user's autonomous execution instruction. Steps use checkbox syntax.

**Goal:** Make the installed daemon reconnect using durable user-selected mesh configuration, with UI and CLI sharing the same authenticated local API.

**Architecture:** The daemon owns a versioned public connection configuration in its identity directory. Configuration never contains private key material or changes trust merely by selecting an address. The inventory observer reads a generation-tagged configuration and discards results from obsolete generations. Pairing remains an explicit, target-confirmed trust operation.

**Tech Stack:** Rust, serde JSON, existing mTLS transport and OS-authenticated IPC, React/Tauri, existing per-user lifecycle scripts.

## Acceptance criteria

- A paired daemon restarted without `--registry` loads its saved connection and displays live registry inventory.
- No saved configuration means local-only operation. Invalid, oversized, unsupported-version, linked, or non-regular configuration is rejected with a structured diagnostic, never silently replaced.
- Endpoint and peer identifiers are bounded and validated. Saved input cannot change the daemon's identity path, executable, environment, or private keys.
- Explicit CLI connection overrides are transient and do not overwrite persisted settings.
- Settings changes require authenticated local user presence and an audit entry; remote mesh callers cannot change service configuration.
- UI and CLI show the same address, expected peer and connection state. Neither receives credential bytes.
- Switching or disconnecting never applies an old in-flight inventory result, redirects an existing job, or reports cached remote hosts as live.
- Installation/repair preserves configuration. Real installed Windows and macOS restarts prove the path; Linux receives native CI validation.

## Task 1: Reproduce missing startup persistence

Files: `tests/dashboard_registry_inventory.rs`.

- [ ] Extend the real registry/agent/service test after its first live snapshot: stop the service, write the following fixture into `client_path.join("connection.json")`, restart with the same identity/runtime/log arguments but no `--registry`, and require live inventory again.

```rust
serde_json::json!({
    "version": 1,
    "registry_address": address,
    "registry_peer_id": "registry"
})
```

- [ ] Run `cargo test --test dashboard_registry_inventory actual_service_observes_registry_inventory_and_recovers_after_disconnect --locked --jobs 1`. Expected RED: restarted daemon never projects the live remote host.

## Task 2: Implement the durable startup reader

Files: create `src/connection_config.rs`, export in `src/lib.rs`, integrate in `src/bin/devicelane-service.rs`, test in `tests/connection_config.rs`.

- [ ] Add failing tests for absent file, valid bounded JSON, unknown fields, unsupported version, invalid address/peer, oversized file and linked/non-regular input. Use a dedicated error enum rather than echoing untrusted JSON in diagnostics.
- [ ] Implement a bounded reader (4 KiB maximum) and strict version-1 schema. Preserve existing mTLS certificate verification and derive identity/client ID only from daemon-owned state.
- [ ] Resolve transient CLI override first; otherwise load the saved connection. Pass the expected peer to `RemoteExecutionConfig`, not a hardcoded replacement.
- [ ] Run the new unit tests and Task 1 process test; require GREEN and verify standalone local-only startup remains available.

## Task 3: Add configuration mutation and clients

Files: `src/connection_config.rs`, `src/local_ipc.rs`, `src/bin/devicelane.rs`, `desktop/src-tauri/src/main.rs`, `desktop/src/api.ts`, `desktop/src/App.tsx`, corresponding IPC/CLI/UI tests.

- [ ] Add failing API tests for authenticated read/update/disconnect, required local presence, audit failure, invalid input, atomic write failure and preservation of prior configuration.
- [ ] Implement atomic private-directory persistence and generation changes. Keep DNS/TLS outside the IPC lock; reject late results whose generation differs. Running jobs retain their original immutable configuration.
- [ ] Add typed CLI commands and a connection settings panel that displays expected identity and actual connection state. Configuration is not pairing: an untrusted peer remains unavailable until explicit pairing succeeds.
- [ ] Test keyboard operation, validation errors, failed persistence, disconnect, restart restoration and identical CLI/UI results.

## Task 4: Finish onboarding and installed verification

Files: desktop onboarding components, daemon pairing API, lifecycle integration tests and existing setup scripts only where the verified startup path requires changes.

- [ ] Connect the approved short-lived-code/visual-confirmation flow to daemon-owned credentials. Test expired codes, wrong identities and public-listener rejection before implementation.
- [ ] Test first install, repair and restart with durable configuration; retain local-only and CLI workflows.
- [ ] Run Rust tests, desktop tests/typecheck, formatting and Clippy. Obtain independent review before committing implementation.
- [ ] Build and install native artifacts, then verify Windows and Mac UI, status, autostart, pairing and a real remote job. Fake Apple tools do not satisfy these gates.

This plan covers connection/onboarding work only; it does not replace the full product requirements for resources, recipes, signing, packaging or real-host end-to-end verification.

Provenance: AI-assisted implementation plan, written from the repository's approved design and observed source state.
