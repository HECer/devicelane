# DeviceLane

**Develop on any computer. Build and test on every device.**

DeviceLane is a secure, self-hosted development mesh. It connects Windows, macOS, and Linux hosts with the iOS and Android devices attached to them, then exposes those capabilities to authorized clients over the network.

The primary use case is cross-platform mobile development: work from Windows while a Mac builds, signs, launches, tests, and diagnoses an iOS app; or work from macOS while a Windows or Linux host operates an Android device through ADB.

> [!IMPORTANT]
> DeviceLane is currently an **experimental developer preview**. Its automated protocol and integration tests are extensive, but the physical-iPhone release gate has not yet been completed. Do not expose its ports directly to the public internet.

## What it provides

- Remote process and tool execution on registered development hosts
- Discovery of connected iOS devices, simulators, Android devices, and emulators
- Apple workflows through Xcode, `xcodebuild`, `devicectl`, `simctl`, `xcresulttool`, `xctrace`, and `lldb-dap`
- Android workflows through ADB-capable agents
- Remote project workspaces with path confinement
- App build, install, launch, test, log, diagnostic, and artifact operations
- Exclusive device leases so concurrent clients cannot control the same device accidentally
- Reconnectable jobs with ordered events and request deduplication
- Mutual TLS identities, explicit one-time pairing, peer allowlists, and audit records

## How it works

```text
Developer / automation
        |
        | mesh-cli (mutual TLS)
        v
  mesh-registry  <------>  mesh-agent on macOS  <------>  Xcode / iPhone / Simulator
        |
        +--------------->  mesh-agent on Windows <----->  ADB / Android
        |
        +--------------->  mesh-agent on Linux   <----->  tools / Android
```

The registry is the control plane. Agents advertise host and device capabilities. Clients select a host and device, obtain a lease, submit a job, and receive ordered output, diagnostics, and artifacts. Platform-restricted work stays on the platform that can legally and technically perform it: iOS builds still execute on a Mac with Xcode.

## Current status

| Area | Status |
|---|---|
| Secure registry, agent, and CLI transport | Implemented |
| Pairing, identities, allowlists, and audit trail | Implemented |
| Remote jobs, reconnect, deadlines, and artifacts | Implemented |
| Apple discovery, build, install, launch, XCTest, diagnostics | Implemented and fixture/integration tested |
| macOS LaunchAgent bootstrap | Implemented |
| Physical iPhone end-to-end validation | `iPhone-Hardware-Gate` pending |
| Android adapter and ADB workflow | Protocol foundation present; `Android-Hardware-Gate` pending |
| Public-internet deployment | Not supported; use a trusted LAN or private VPN |

## Requirements

### All hosts

- Git
- A current stable Rust toolchain installed with [rustup](https://rustup.rs/)
- Network reachability between the controller and agents

### Apple development host

- macOS with full Xcode installed and selected
- Accepted Xcode license
- For physical devices: an unlocked and trusted iPhone, Developer Mode, and valid signing credentials

### Android development host

- Android SDK Platform Tools with `adb` available in `PATH`
- For physical devices: USB debugging enabled and the host authorized

## Quick start

### Install prebuilt commands

With Node.js 20 or newer, install the npm launcher. On first use it downloads the
matching GitHub Release binary and verifies its SHA-256 checksum:

```sh
npm install --global devicelane
devicelane --version
```

This provides `devicelane` (the client), `devicelane-agent`, and
`devicelane-registry`. Native archives and checksums are also available directly
from [GitHub Releases](https://github.com/HECer/devicelane/releases).

### Desktop installers

The desktop release produces a Windows MSI, a hardened and notarized macOS DMG, and Linux
AppImage and deb packages. Pull-request artifacts are explicitly named `unsigned-ci-*`; they are
short-lived test outputs and must not be redistributed as production builds. A production
candidate is emitted only by the protected manual workflow after native platform signing,
Apple notarization inputs, SHA-256 manifests, a CycloneDX SBOM, and a signed checksum bundle are
available.

Install production packages only into the platform installer's administrator-owned location.
DeviceLane checks the staged sidecar hash during packaging, but a hash check does not eliminate
time-of-check/time-of-use races in a writable install directory. The signed, non-user-writable
installation root is the security boundary. The per-user lifecycle tools preserve identity and
logs during repair and normal uninstall; delete those directories separately only when rotating
the device identity intentionally.

The native installer contains the desktop executable, `devicelane-service`, and the equal
`devicelane` CLI client. The lifecycle and smoke tooling resolves both command binaries below the
verified native installation root, rejects links/reparse points, and never substitutes a raw
`target/release` binary for an installed artifact.

Release builds pin the hosted runner image (`windows-2025`, `macos-15`, or `ubuntu-24.04`), its
exact image version, Rust 1.95.0, Node.js 22.20.0, every GitHub Action by commit, the native
Xcode/SDK or MSVC/WiX toolchain, Linux package versions, `Cargo.lock`, and
`desktop/package-lock.json`. Production aborts when an observed input differs from the protected
repository-variable pins. `SOURCE_DATE_EPOCH`, UTC, non-incremental compilation, and two clean
unsigned builds provide a reproducibility gate for unsigned payloads and configuration; their
normalized installed-file manifests must match before CI accepts an artifact. Native container
hashes are recorded where the format is deterministic.

The normalized comparison covers file-system semantics as well as bytes: entry type, executable
or Unix permission mode, symbolic-link target, macOS extended attributes, and relevant Windows
file attributes and ACL SDDL. Release files retain their bundle-relative paths during collection;
an attempted destination collision aborts the workflow.

Each artifact set includes `BUILD-INPUTS.txt` with the observed versions and input hashes. The
signed envelope is intentionally outside the unsigned payload comparison: signing services add
external timestamp and notarization evidence, so the signed MSI/DMG container need not be
bit-for-bit identical to its unsigned envelope. Production acceptance is not weakened: native
signature verification, the single-DMG notarization and stapling gates, checksums, SBOMs, and
signed checksum evidence must all succeed.

Each production platform has its own protected job. Credentials are unavailable while dependencies
and unsigned payloads are built, and are injected only into the individual import, signing, or
notarization step that needs them. Windows signing additionally pins the certificate subject and
thumbprint, selects that certificate explicitly, verifies the resulting Publisher, and removes the
temporary certificate and PFX. Linux package smoke tests exercise the packaged lifecycle script in
an isolated home/runtime with a process-backed systemd adapter and perform real `dpkg` install and
uninstall transactions on the hosted runner.

On macOS, the complete Tauri application and all build hooks finish without Apple credentials. The
validated `.app` is then processed only by native `codesign`, `hdiutil`, `notarytool`, and `stapler`
commands. Its temporary keychain is removed and the prior keychain search list restored before any
smoke or SBOM step. Build jobs have no OIDC token permission; a separate protected attestation job
receives only the already checked artifact digests and holds the minimal short-lived OIDC grant.
Real deb transactions additionally require the hosted-CI gate and refuse to alter an already
installed package.

### Build from source

The examples use port `7443` for normal mutual-TLS traffic and temporary ports `7444`/`7445` for initial pairing. Replace `CONTROLLER_HOST` with a private DNS name or LAN/VPN address reachable from the other host.

### 1. Build the controller on Windows

```powershell
git clone https://github.com/HECer/devicelane.git
cd devicelane
.\scripts\setup-windows.ps1
```

Start a temporary client-pairing listener:

```powershell
.\target\debug\mesh-registry.exe pair --listen 127.0.0.1:7444 --identity .mesh\registry
```

In a second terminal, pair the local CLI:

```powershell
.\target\debug\mesh-cli.exe pair --address 127.0.0.1:7444 --identity .mesh\cli
```

### 2. Pair and install a Mac agent

On the controller, temporarily permit inbound TCP `7445` **only from the Mac's private IP**, then run:

```powershell
.\target\debug\mesh-registry.exe pair --listen 0.0.0.0:7445 --identity .mesh\registry
```

On the Mac, from the cloned repository:

```sh
sh ./scripts/setup-mac.sh --controller CONTROLLER_HOST
```

The setup script builds release binaries, pairs the agent, installs a per-user LaunchAgent, validates the Apple toolchain, starts the service, and prints the exact registry command required for that agent. Close firewall port `7445` immediately after pairing.

### 3. Start the registry

Run the `NEXT_CONTROLLER_COMMAND` printed by the Mac installer. It has this form:

```powershell
.\target\debug\mesh-registry.exe --listen 0.0.0.0:7443 --identity .mesh\registry --offline-after-ms 5000 --agent-peer MAC_AGENT_ID
```

Allow TCP `7443` only from trusted clients and agents on your LAN or private VPN.

For a persistent per-user Windows controller, install or repair a Scheduled Task with the
explicit agent peer ID printed by the Mac installer:

```powershell
.\scripts\setup-windows.ps1 --controller-install `
  --agent-peer MAC_AGENT_ID `
  --controller-listen 0.0.0.0:7443 `
  --controller-identity "$env:LOCALAPPDATA\DeviceLane\registry\identity" `
  --controller-log-dir "$env:LOCALAPPDATA\DeviceLane\registry\logs"
.\scripts\setup-windows.ps1 --controller-status
.\scripts\setup-windows.ps1 --controller-uninstall
```

Installation and repair require explicit `--agent-peer`, `--controller-listen`,
`--controller-identity`, and `--controller-log-dir` values. The Scheduled Task launches a
PowerShell logging wrapper whose command contains only the deployed registry path and public
runtime arguments; private keys and pairing secrets remain in the identity directory. A repair
builds and stages a new per-user binary before briefly stopping and replacing the running
controller. Re-running `--controller-install` repairs the current user's task idempotently.
Uninstall removes only that user's task and preserves the deployed binary, identity, and logs.

Do not expose the registry to the public Internet. Permit inbound TCP `7443` in Windows
Firewall only from trusted private LAN subnets or VPN peers; keep the firewall rule disabled
until pairing is complete and remove temporary pairing-port rules immediately afterward.

### 4. Verify the mesh

```powershell
.\target\debug\mesh-cli.exe --registry CONTROLLER_HOST:7443 --identity .mesh\cli list --json
```

The result lists online hosts, their capabilities, and attached devices. A remote job can then target a specific `host_id`, `device_id`, and isolated workspace:

```powershell
.\target\debug\mesh-cli.exe --registry CONTROLLER_HOST:7443 --identity .mesh\cli run --json-request '{"principal_id":"developer-1","host_id":"MAC_AGENT_ID","device_id":"IPHONE_DEVICE_ID","workspace_id":"demo","request_id":"demo-1","manifest":[{"path":"README.txt","contents":"hello from DeviceLane"}]}'
```

## macOS operations

The macOS installer supports repeatable lifecycle commands:

```sh
sh ./scripts/setup-mac.sh --controller CONTROLLER_HOST             # install or repair
sh ./scripts/setup-mac.sh --controller CONTROLLER_HOST --status    # inspect service
sh ./scripts/setup-mac.sh --controller CONTROLLER_HOST --upgrade   # rebuild and upgrade
sh ./scripts/setup-mac.sh --controller CONTROLLER_HOST --uninstall # remove installed binaries/service
```

The unified `devicelane` client exposes the dashboard over authenticated local IPC. Commands include
`mesh status|watch`, `activities list|watch|cancel`, `approvals list|request|decide`,
`policy list|put|delete`, and `audit list|export`. Every daemon request requires `--local`;
`--json` returns stable JSON and activity watch returns NDJSON. Events are acknowledged only after
stdout accepts and flushes them. Administrative changes use typed approval and access flags; raw
shell commands and raw IPC JSON are not accepted.

The per-user DeviceLane daemon has an independent lifecycle and keeps its identity and logs when
uninstalled:

```sh
sh ./scripts/setup-mac.sh --install
sh ./scripts/setup-mac.sh --status
sh ./scripts/setup-mac.sh --autostart-disable
sh ./scripts/setup-mac.sh --autostart-enable
sh ./scripts/setup-mac.sh --logs
sh ./scripts/setup-mac.sh --uninstall
```

On Linux the equivalent commands use `scripts/setup-linux.sh`. The adapter installs a hardened
`systemd --user` unit. Where a user systemd session is unavailable, the script prints the exact
`devicelane-service --foreground` command for a session supervisor or terminal.

On Windows use `setup-windows.ps1` with `--service-install`, `--service-repair`,
`--service-status`, `--service-autostart-enable`, `--service-autostart-disable`, `--service-logs`,
or `--service-uninstall`. All three adapters use per-user state and log directories.

Diagnostics are written below `~/Library/Logs/DeviceDevelopmentMesh/diagnostics`. Identity and trust material remain below `~/Library/Application Support/DeviceDevelopmentMesh` and must never be shared.

## Security model

DeviceLane grants remote development capabilities and must be treated like privileged infrastructure.

- Pairing is explicit and creates local cryptographic identities.
- Normal traffic uses mutual TLS; an unpaired peer is rejected.
- Pairing listeners are temporary and should be firewall-scoped to one source host.
- The registry can restrict the exact agent peer IDs allowed to connect.
- Jobs are confined to declared workspace roots and validated manifests.
- Device leases serialize writers across clients.
- Sensitive runtime state lives under `.mesh/`, which is ignored by Git.

Recommended deployment:

1. Use a trusted LAN or a private VPN such as WireGuard/Tailscale.
2. Never forward registry or pairing ports directly from the public internet.
3. Keep signing keys, Apple credentials, device identities, `.mesh/`, and diagnostic bundles out of Git.
4. Restrict host firewalls to known client and agent addresses.
5. Review audit records and rotate identities after suspected compromise.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and operational guidance.

## Development and verification

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Apple bootstrap smoke test (macOS or a compatible POSIX environment):

```sh
sh ./scripts/mac-bootstrap-smoke
```

Physical-device results are deliberately separate from mock, simulator, and fixture tests. **Mocks gelten nicht als Nachweis** for either hardware gate. A hardware gate is only green after installation, launch, logs, and artifact return succeed on a real authorized device.

### DeviceLane dashboard release gate

The normal CI matrix runs the locked Rust workspace, the Tauri bridge, the React dashboard tests,
type checking, production frontend build, and lifecycle contract/smoke checks on Windows, macOS,
and Linux. That deterministic fixture coverage does not prove a physical Mac pass. A production
release additionally requires a real paired Windows-to-Mac run against the target Apple Silicon
Mac supplied as `<MAC_HOST>` at execution time; private LAN addresses do not belong in committed
release evidence.

Start the gate on the Mac before submitting the matching operation from Windows. The expected
operation must request both `workspace_read` and `device_lease`, be approved on the Mac, survive a
disconnect/reconnect, and reach a terminal state. The script refuses fixture mode and writes only
redacted metadata: identifiers and the controller address are stored as SHA-256 pseudonyms, while
raw local audit databases, identity files, bearer values, and private keys are never copied.

```sh
DEVICELANE_REAL_MESH_GATE=1 sh ./scripts/mac-hardware-gate.sh \
  --mesh-controller "<WINDOWS_CONTROLLER_HOST>:7443" \
  --mesh-endpoint "$TMPDIR/devicelane/devicelane.sock" \
  --windows-principal codex-windows \
  --windows-source-host windows-controller \
  --mesh-activity-id release-gate-20260902 \
  --device PHYSICAL_IPHONE_UDID \
  --team APPLE_TEAM_ID
```

The mesh gate is green only when it observes the Windows principal/source in a target-local
approval, live activity through the CLI stream, explicit nonzero-or-unavailable metrics,
`reconnecting` or `resync_required`, a terminal result, and the corresponding redacted audit
record. If SSH or the DeviceLane ports are unavailable, report the physical gate as blocked; never
replace it with a fixture pass.

For Yoke-managed work, `passes: true` is valid only when the mapped **story-spezifische Akzeptanzprüfung** also passes. The global quality gate additionally runs the complete workspace tests, Clippy with warnings denied, and the formatting check.

## Repository map

| Path | Purpose |
|---|---|
| `src/bin/mesh-registry.rs` | Registry/control-plane executable |
| `src/bin/mesh-agent.rs` | Remote host and device agent |
| `src/bin/mesh-cli.rs` | Client CLI |
| `src/lib.rs` | Protocol, transport, policy, device, job, and artifact implementation |
| `scripts/` | Windows/macOS bootstrap and hardware gates |
| `hardware/DeviceMeshGate/` | Minimal signed iOS hardware-gate application |
| `tests/` | Contract, security, integration, and platform tests |
| `.yoke/` | Yoke planning and acceptance-test metadata |
| `.agents/skills/` | Yoke/gstack-derived development-agent workflow skills |

## Machine-readable project facts

```yaml
project: DeviceLane
repository: https://github.com/HECer/devicelane
license: MIT
language: Rust
edition: "2024"
binaries:
  - mesh-registry
  - mesh-agent
  - mesh-cli
roles:
  registry: control plane, peer admission, routing, leases
  agent: host capabilities, device adapters, job execution, artifacts
  cli: pairing, discovery, diagnostics, job submission
platforms:
  controller: [windows, macos, linux]
  agent: [windows, macos, linux]
  mobile_targets: [ios, android]
transport: mutual TLS after explicit pairing
default_ports:
  registry: 7443
  cli_pairing: 7444
  agent_pairing: 7445
internet_exposure_supported: false
release_status: experimental
hardware_gates:
  physical_iphone: pending
  physical_android: pending
  windows_to_mac_dashboard: pending
```

## License and acknowledgements

DeviceLane is available under the [MIT License](LICENSE). Development workflow material derived from [gstack](https://github.com/garrytan/gstack) and [Yoke](https://github.com/HECer/yoke) remains MIT-licensed; see [NOTICE](NOTICE).
