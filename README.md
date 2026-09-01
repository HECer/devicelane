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
`--controller-identity`, and `--controller-log-dir` values. The Scheduled Task contains only
the registry executable and public runtime arguments; private keys and pairing secrets remain
in the identity directory. Re-running `--controller-install` repairs the current user's task
idempotently. Uninstall removes only that user's task and preserves identity and logs.

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
```

## License and acknowledgements

DeviceLane is available under the [MIT License](LICENSE). Development workflow material derived from [gstack](https://github.com/garrytan/gstack) and [Yoke](https://github.com/HECer/yoke) remains MIT-licensed; see [NOTICE](NOTICE).
