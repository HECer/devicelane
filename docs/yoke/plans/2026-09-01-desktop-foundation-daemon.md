# DeviceLane Desktop Foundation and Daemon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an installable Tauri desktop shell and a durable per-user DeviceLane daemon on Windows, macOS, and Linux while preserving the existing CLI as an equal client.

**Architecture:** Extract stable daemon startup configuration and a versioned local IPC contract into focused Rust modules. The daemon owns identity and mesh state; CLI and Tauri connect through OS-protected local endpoints. Platform lifecycle scripts install the same daemon with autostart, status, repair, logs, and identity-preserving uninstall.

**Tech Stack:** Rust 2024, serde JSON, length-bounded newline IPC over Windows named pipes or Unix-domain sockets, Tauri 2, React/TypeScript frontend, PowerShell Scheduled Tasks, macOS LaunchAgent, Linux systemd user services.

---

## Acceptance criteria

- `devicelane-service` starts independently of the desktop window and exposes a versioned local status API.
- IPC identifies the local operating-system user, applies a 512 KiB request limit, rejects unknown request fields, and never returns private key bytes.
- `devicelane status --local --json` and the Tauri application display the same daemon snapshot.
- Windows, macOS, and Linux support idempotent install, repair, status, autostart toggle, log discovery, and identity-preserving uninstall.
- Desktop launch, close-to-tray, native notification, start-at-login setting, local pause switch, and diagnostic summary work without an active remote controller.
- Existing network CLI commands and protocol fixtures remain compatible.
- Installer assets are reproducible and release checks reject unsigned/unnotarized production declarations.

### Task 1: Review and harden the Windows controller lifecycle

**Files:**
- Existing commit: `f567ceee86751385ec144cc668852f5a43af925c`
- Review: `scripts/setup-windows.ps1`
- Review: `tests/bootstrap.rs`
- Review: `README.md`

- [ ] **Step 1: Run an independent spec review**

Verify the commit provides `--controller-install`, `--controller-status`, and `--controller-uninstall`, requires an explicit peer, stores only paths and public peer identifiers in the task definition, uses per-user identity/log locations, repairs idempotently, and preserves identity/logs on uninstall.

- [ ] **Step 2: Run an independent quality review**

Inspect quoting, Scheduled Task principal/trigger/action behavior, path canonicalization, error propagation, and uninstall scope. Report issues by severity with file and line.

- [ ] **Step 3: Fix reviewed issues with TDD**

For each accepted issue, add a failing assertion to `tests/bootstrap.rs`, verify RED with:

```powershell
Set-Item Env:CARGO_TARGET_DIR 'E:\CodexBuild\devicelane-speechwalker'
cargo test --test bootstrap
```

Then apply the minimal script/documentation change and verify GREEN.

- [ ] **Step 4: Verify and commit**

Run the focused test, PowerShell AST parse, `cargo fmt --all -- --check`, and `git diff --check`. Commit fixes only if required.

### Task 2: Define the local daemon contract

**Files:**
- Create: `src/local_ipc.rs`
- Create: `tests/local_ipc.rs`
- Modify: `src/lib.rs`
- Create: `src/bin/devicelane-service.rs`
- Modify: `Cargo.toml`

- [ ] **Step 1: Write failing contract tests**

Add tests that use the intended public API:

```rust
let request = LocalRequest::Status { version: LocalProtocolVersion { major: 1, minor: 0 } };
let encoded = serde_json::to_string(&request).unwrap();
let decoded: LocalRequest = serde_json::from_str(&encoded).unwrap();
assert_eq!(decoded, request);
assert!(serde_json::from_str::<LocalRequest>(r#"{"request":"status","version":{"major":1,"minor":0},"raw_command":"id"}"#).is_err());
```

Test `Status`, `PauseRemoteAccess`, `ResumeRemoteAccess`, `SetAutostart`, and `Diagnostics`; reject incompatible major versions, unknown fields, oversized frames, and unauthenticated peers; assert status snapshots contain public identity, role, endpoint, connection state, versions, and warnings but no private material.

- [ ] **Step 2: Verify RED**

Run `cargo test --test local_ipc`; expect compilation failure because `local_ipc` and `devicelane-service` do not exist.

- [ ] **Step 3: Implement the typed contract**

Define `LocalProtocolVersion`, `LocalRequest`, `LocalResponse`, `DaemonSnapshot`, `DaemonRole`, `ConnectionState`, and `DiagnosticItem` with `serde(deny_unknown_fields)`. Add a bounded line codec and an `Authorizer` trait whose platform implementation receives peer credentials rather than caller-supplied identity strings.

- [ ] **Step 4: Implement the service entrypoint**

Add arguments `--identity`, `--runtime-dir`, `--role`, `--registry`, `--listen`, `--agent-peer`, `--log-dir`, and `--foreground`. Validate absolute state paths before binding IPC. Start with local status/pause/diagnostics state and reuse existing secure transport types without moving private keys into responses.

- [ ] **Step 5: Verify GREEN and commit**

Run `cargo test --test local_ipc`, `cargo test --test protocol_contract`, formatting, and Clippy. Commit `feat: add versioned local daemon API`.

### Task 3: Connect the existing CLI to local IPC

**Files:**
- Create: `src/bin/devicelane.rs`
- Create: `tests/local_cli.rs`
- Modify: `Cargo.toml`
- Modify: `npm/package.json`
- Modify: `npm/README.md`

- [ ] **Step 1: Write a failing process test**

Start `devicelane-service` on a temporary local endpoint, run:

```text
devicelane status --local --json
devicelane remote-access pause --local
devicelane remote-access resume --local
devicelane diagnostics --local --json
```

Assert structured output matches direct IPC responses, invalid flags return nonzero without panic, and existing `mesh-cli` remains available.

- [ ] **Step 2: Verify RED**

Run `cargo test --test local_cli`; expect failure because the unified CLI binary does not exist.

- [ ] **Step 3: Implement minimal local commands**

Create a small argument parser following existing binary conventions. Resolve the platform default endpoint or explicit `--endpoint`, send one bounded typed request, print JSON with `--json`, and render concise text otherwise. Do not proxy raw shell input.

- [ ] **Step 4: Preserve npm compatibility**

Expose `devicelane`, `devicelane-service`, `devicelane-agent`, `devicelane-registry`, and legacy `mesh-*` aliases from the npm launcher. Update launcher tests or add deterministic package assertions.

- [ ] **Step 5: Verify GREEN and commit**

Run local CLI tests, stable help/version tests, npm package tests, formatting, and Clippy. Commit `feat: expose daemon status through unified CLI`.

### Task 4: Complete cross-platform daemon lifecycle

**Files:**
- Create: `scripts/setup-linux.sh`
- Create: `tests/linux_bootstrap.rs`
- Modify: `scripts/setup-mac.sh`
- Modify: `tests/mac_bootstrap.rs`
- Modify: `scripts/setup-windows.ps1`
- Modify: `tests/bootstrap.rs`
- Modify: `README.md`

- [ ] **Step 1: Add failing lifecycle tests**

Assert every platform supports install/repair, status, autostart enable/disable, logs, and uninstall; service definitions invoke `devicelane-service`; state and logs use per-user OS locations; uninstall preserves identity by default; rendered definitions contain no secrets.

- [ ] **Step 2: Verify RED**

Run `cargo test --test bootstrap --test mac_bootstrap --test linux_bootstrap`; expect missing Linux script/test and missing shared service lifecycle flags.

- [ ] **Step 3: Implement platform adapters**

Windows renders a Scheduled Task action for `devicelane-service`. macOS renders a per-user LaunchAgent with `KeepAlive` and controlled absolute paths. Linux renders a user systemd unit under `~/.config/systemd/user/devicelane.service` with `Restart=on-failure`, `NoNewPrivileges=true`, and explicit state/log directories; foreground fallback is documented when systemd is unavailable.

- [ ] **Step 4: Add autostart mutation through lifecycle adapters**

Implement idempotent enable/disable operations invoked by both scripts and the local daemon request. Status reports installed/running/autostart/log path without exposing command secrets.

- [ ] **Step 5: Verify GREEN and commit**

Run lifecycle tests, shell syntax checks, PowerShell AST parsing, formatting, Clippy, and full tests. Commit `feat: unify daemon lifecycle across platforms`.

### Task 5: Scaffold the Tauri desktop and shared status client

**Files:**
- Create: `desktop/package.json`
- Create: `desktop/src-tauri/Cargo.toml`
- Create: `desktop/src-tauri/tauri.conf.json`
- Create: `desktop/src-tauri/src/main.rs`
- Create: `desktop/src/api.ts`
- Create: `desktop/src/App.tsx`
- Create: `desktop/src/App.test.tsx`
- Create: `desktop/src/styles.css`
- Create: `desktop/index.html`
- Modify: `Cargo.toml`

- [ ] **Step 1: Write failing UI behavior tests**

Use a fake typed `DaemonClient` and assert the app renders daemon state, OS/architecture, role, warnings, autostart state, and paused state; pause/resume and autostart controls call typed methods; unavailable daemon renders a repair action; all controls have accessible names and keyboard operation.

- [ ] **Step 2: Verify RED**

Run `npm test -- --run` inside `desktop`; expect failure because the desktop project does not exist.

- [ ] **Step 3: Create the smallest Tauri shell**

Use React/TypeScript for one local status window. The Rust Tauri command layer calls `local_ipc` and returns serialized `DaemonSnapshot`; JavaScript never reads identity files. Add close-to-tray behavior, Show/Quit menu items, native error notification, and a single-instance guard.

- [ ] **Step 4: Implement the foundation screen**

Render connection state, local host summary, warnings, autostart toggle, pause/resume control, diagnostics button, and log location. Meet WCAG keyboard/focus requirements and avoid color-only state indicators.

- [ ] **Step 5: Verify GREEN and commit**

Run UI tests, TypeScript check, Tauri Rust tests, accessibility assertions, formatting, and Clippy. Commit `feat: add DeviceLane desktop foundation`.

### Task 6: Package and validate first-run installation

**Files:**
- Create: `.github/workflows/desktop-release.yml`
- Create: `scripts/desktop-release-smoke.ps1`
- Create: `scripts/desktop-release-smoke.sh`
- Create: `tests/desktop_distribution.rs`
- Modify: `desktop/src-tauri/tauri.conf.json`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Write failing distribution tests**

Assert release configuration declares Windows MSI, notarized/hardened macOS DMG inputs, Linux AppImage and deb, SHA-256 manifests, signature inputs, SBOM generation, and refusal to label unsigned artifacts as production.

- [ ] **Step 2: Verify RED**

Run `cargo test --test desktop_distribution`; expect missing workflow and packaging declarations.

- [ ] **Step 3: Implement deterministic packaging**

Build CLI/service/desktop from locked dependencies for each native runner, generate checksums and SBOM, and separate unsigned CI artifacts from signed production releases. Keep signing secrets only in runner secret stores or the Mac Keychain.

- [ ] **Step 4: Implement first-run smoke tests**

Install into temporary or runner-scoped locations, enable autostart, query local status through CLI and UI command bridge, restart the daemon, inspect logs, disable autostart, uninstall, and assert identity preservation.

- [ ] **Step 5: Verify and commit**

Run distribution contract tests and platform smoke tests available on the current host. Commit `build: package DeviceLane desktop foundation`.

## Final verification

- [ ] Run `cargo test --workspace` using `CARGO_TARGET_DIR=E:\CodexBuild\devicelane-speechwalker` on Windows.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- [ ] Run desktop unit, accessibility, and TypeScript tests.
- [ ] Upgrade the paired Apple Silicon Mac agent/service and prove local status survives closing the UI.
- [ ] Dispatch an independent full spec review followed by an independent code-quality/security review.
