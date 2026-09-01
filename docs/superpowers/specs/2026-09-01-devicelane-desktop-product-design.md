# DeviceLane Desktop Product Design

**Status:** Approved design

**Date:** 2026-09-01

## Purpose

DeviceLane will evolve from a developer-oriented command-line mesh into an installable cross-platform desktop product without replacing its CLI. Every installation provides an operating-system-integrated local status application, while authorized installations can also observe and control the wider mesh.

The product must make remote access visible. When a Windows client starts work on a Mac, both the live activity view and the retained audit history identify the requesting principal, source host, target host, recipe, resources, duration, resource consumption, result, and produced artifacts.

## Product decisions

- Use a hybrid topology. Every host has a local status application; authorized hosts may manage the complete mesh.
- Preserve the `devicelane` CLI as a stable, equal client of the same service APIs used by the desktop application.
- Build the desktop application with Tauri and the existing Rust core. Add platform-specific behavior for the tray, menus, notifications, permissions, autostart, packaging, and updates.
- Monitor only DeviceLane-related resource use in the first release, not every process on the computer.
- Authorize access through explicit rules. Known combinations of principal, client, recipe, target, and resource may run automatically. New or sensitive combinations require confirmation on the target host.
- Retain redacted audit metadata locally for 30 days by default. Never retain captured audio, screen contents, keystrokes, or arbitrary workspace file contents as audit data.

## System architecture

Each installation contains four product units:

1. `devicelane-service`, a Rust background daemon responsible for identity, pairing, mesh transport, inventory, jobs, policies, audit, artifacts, and resource observation.
2. `devicelane`, the cross-platform CLI and automation interface.
3. DeviceLane Desktop, a Tauri application for local status and authorized mesh management.
4. Platform integration packages for Windows, macOS, and Linux service lifecycle, autostart, notifications, permissions, secure storage, installers, and updates.

The daemon is the only unit that owns mesh credentials or executes work. UI and CLI connect through a versioned, locally authenticated IPC API. Closing the UI does not interrupt the daemon, jobs, leases, or transfers.

The existing network protocol remains compatible. New desktop and policy capabilities use versioned optional messages so an older CLI can continue to list hosts and use existing operations.

## Trust and local IPC

The daemon exposes IPC only to the current interactive user or an explicitly configured local administration group. Windows uses a named pipe, macOS uses a Unix-domain socket protected by filesystem ownership, and Linux uses a Unix-domain socket under the user runtime directory. Every request carries a short-lived session established from operating-system peer credentials; no reusable bearer token is written to disk.

Private keys remain in the platform's protected storage where available. Migration from existing filesystem identities is explicit, recoverable, and preserves the original until the protected copy has been validated. Neither UI nor CLI receives private-key bytes.

## Desktop information architecture

### Overview

The default screen shows:

- host cards with name, operating system, architecture, online state, trust state, version, and connection path;
- attached iPhones, simulators, Android devices, and emulators;
- active jobs, pending approvals, warnings, and unavailable capabilities;
- one-click entry points for pairing, diagnosis, pausing remote access, and settings.

The interface distinguishes `offline`, `connecting`, `online`, `busy`, `attention required`, and `remote access paused` through text and iconography, not color alone.

### Host and device detail

A host detail view presents its capabilities, toolchain versions, connected devices, active leases, workspace use, operating-system permissions, and repair actions. Device detail shows the owning host, connection type, availability, active lease, current operation, and supported actions.

### Live activities

Each activity records and displays:

- requesting principal and client host;
- target host and optional physical or virtual device;
- typed recipe or operation;
- workspace and resource classes, without workspace contents;
- authorization decision and matching rule;
- start time, duration, state, progress, redacted output, and terminal result;
- CPU time, current and peak memory, bytes transferred, and child-process count for the DeviceLane job process tree;
- produced artifact names, sizes, media types, and SHA-256 hashes.

Users can cancel an authorized running job, inspect its redacted event stream, download an artifact, or open the rule that allowed it. Reconnecting clients resume from the last acknowledged event rather than starting a second job.

### Access approvals and rules

When no rule permits an operation, the target host shows a native notification and an in-app approval panel. The choices are:

- allow once;
- allow this exact principal, source host, recipe, target, and resource combination in the future;
- deny once;
- deny and create a blocking rule.

Rules are deny-overrides, most-specific-first. A rule names principal identity, source peer, target host, recipe or operation capability, resource classes, optional device, expiry, and whether user presence is required. Pairing alone never grants unrestricted recipe execution.

High-risk operations always require a fresh target-host confirmation unless an administrator has installed an explicit managed policy. High-risk operations include new signing identities, keychain access, screen or microphone access, debugger attachment, installation on a physical device, and changes to DeviceLane policy or service configuration.

The overview provides an immediate `Pause remote access` control. Pausing rejects new jobs and approval requests while allowing the user to choose whether existing jobs finish or are cancelled.

### Audit history

Audit records are append-only within the retention window and contain structured metadata plus redacted logs. The UI filters by time, principal, source, target, device, recipe, resource, decision, and result. Users can export JSON or a signed diagnostic bundle.

The default retention period is 30 days. Users may shorten or extend it. Deletion is explicit, audited, and does not imply deletion of independently retained build artifacts. Audit storage never includes audio samples, screenshots captured by user applications, keystrokes, arbitrary file contents, access tokens, environment secrets, signing materials, or private keys.

## Resource observation

The daemon observes only processes it started for DeviceLane jobs and descendants attributable to that job. It samples CPU time, resident memory, transferred bytes, and process count at a bounded interval. Platform adapters use job objects on Windows, process groups and operating-system process accounting on macOS, and cgroups when available with process-group fallback on Linux.

Access to DeviceLane-managed resources is represented as structured events: workspace read/write, artifact upload/download, device lease, application install/launch, debugger session, signing request, microphone request, screen-capture request, and network endpoint use. DeviceLane does not claim visibility into unrelated processes or access performed outside its daemon.

## Typed recipes

Remote development uses locally installed, versioned recipes rather than a raw shell command. A recipe declares:

- an absolute executable path;
- fixed arguments;
- named, validated parameters and their allowed formats;
- a confined relative working directory;
- an environment-variable allowlist;
- resource classes required for policy evaluation;
- timeout and cancellation behavior;
- declared relative output paths and media types.

The public request names a recipe and parameters. It cannot supply an executable, shell expression, unrestricted arguments, arbitrary environment, absolute workspace path, or output path. Secrets referenced by recipes are resolved on the target host and never returned in events or audits.

SpeechWalker's macOS recipes cover dependency installation, tests, production build, packaging, signing, and notarization as separate policy-visible operations. Signing and notarization use credentials already stored on the Mac.

## Onboarding and pairing

The first-run wizard performs these steps:

1. choose local-only, agent, controller, or hybrid behavior, with hybrid recommended;
2. choose a human-readable host name;
3. enable or decline autostart;
4. inspect installed toolchains and operating-system permissions;
5. create a mesh or pair with an existing controller using a short-lived code and visual identity confirmation;
6. explain and request only permissions needed for enabled capabilities;
7. execute a harmless end-to-end connection test;
8. show the resulting local and remote access rules.

Pairing listeners are temporary and bound to a private LAN or VPN interface. The UI refuses public-internet exposure by default and explains how to use a private VPN.

## Native integration and packaging

### Windows

- Per-user background service initially uses a logon-triggered Scheduled Task; a system-service installation may be offered separately for managed environments.
- Desktop integration uses a tray icon, native notifications, named-pipe IPC, Windows Credential Manager or DPAPI-backed key storage, and a signed MSI or MSIX package.
- Install, repair, status, autostart, log collection, and uninstall are available in both UI and CLI/PowerShell.

### macOS

- The daemon runs as a per-user LaunchAgent in the active GUI session.
- The app uses menu-bar integration, native notifications, Unix-domain socket IPC, Keychain storage, and explicit checks for Accessibility, Input Monitoring, Screen Recording, Automation, Microphone, Developer Mode, and signing access.
- Distribution uses a signed, hardened, notarized DMG. The app never attempts to bypass Transparency, Consent, and Control prompts.

### Linux

- The daemon runs as a user-level systemd service where available, with a documented foreground fallback.
- The desktop uses tray/status-notifier support, desktop notifications, Unix-domain socket IPC, Secret Service storage when available, and portal-aware permissions.
- Distribution starts with AppImage and `.deb`; Flatpak is a later compatibility target because sandboxed device and developer-tool access requires additional design.

## Updates and compatibility

The application checks a signed update manifest and verifies package signatures and hashes before installation. Automatic download is configurable; installation always communicates whether running jobs must finish or stop. Daemon, UI, and CLI negotiate local IPC versions. A compatible older CLI remains usable when the daemon adds optional capabilities.

## Failure handling

- Loss of UI does not affect daemon work.
- Loss of mesh connectivity transitions jobs to reconnecting while retaining ordered events and idempotency keys.
- Daemon restart reconciles durable jobs, leases, approvals, and artifact transfers and fails closed when state is inconsistent.
- Missing operating-system permission produces a structured repair instruction and never silently degrades a sensitive action.
- Invalid recipe or policy input is rejected before process creation.
- Resource observer failure marks metrics unavailable but does not fabricate zero usage; policy enforcement and job isolation remain active.
- Audit persistence failure blocks new state-changing remote operations until storage is repaired.

## Delivery decomposition

The product is delivered as four separately testable subprojects:

1. **Desktop foundation and daemon:** service extraction, versioned local IPC, tray application, installers, autostart, status, repair, and update foundation.
2. **Mesh dashboard:** host/device inventory, visual topology, capability and permission diagnostics, and graphical pairing.
3. **Activities, resources, policy, and audit:** live job model, platform resource observers, approvals, rules, pause control, retention, filtering, and export.
4. **Development workflows:** typed recipes, redacted streaming, artifacts, SpeechWalker macOS build/sign/notarize workflows, and Windows/macOS/Linux release gates.

Each subproject receives its own implementation plan and acceptance tests. Public releases require the complete quality gate plus real Windows-to-Mac validation; simulator and fixture tests do not substitute for physical-device gates.

## Test strategy and release gates

- Rust unit tests cover protocol types, policy precedence, redaction, retention, validation, and state recovery.
- Contract tests ensure CLI and UI IPC clients receive the same state and errors.
- Process tests use real confined child processes for streaming, cancellation, timeout, and resource attribution.
- Tauri component tests cover state rendering and actions; accessibility tests enforce keyboard navigation, names, roles, contrast, and non-color status cues.
- Platform installer tests validate idempotent install, repair, status, autostart, upgrade, and uninstall while preserving identity unless explicitly removed.
- Integration tests cover pairing, reconnect, approvals, denial, audit records, artifact transfer, and mixed compatible versions.
- Real-host gates cover Windows controller to Apple Silicon Mac agent, GUI notification and approval, SpeechWalker build, application launch, logs, resource metrics, artifact return, signing, and notarization.
- Security review covers IPC authorization, key storage, recipe confinement, path traversal, symlink/junction escape, environment leakage, redaction, update verification, and denial precedence.

## Success criteria

A new user can install DeviceLane, enable autostart, pair two hosts, understand their connection and capabilities, approve or deny a first remote action, observe its live resource use, inspect its audit record, and retrieve its verified output without using a terminal. The same workflow remains scriptable through the CLI. Closing the desktop application does not interrupt the operation, and no remote action can execute outside a typed capability and an applicable authorization decision.
