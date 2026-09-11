# Changelog

## Unreleased

- Added a Mesh dashboard end-to-end gate covering typed CLI/IPC/Tauri parity, bounded recovery and
  release checks on Windows, macOS, and Linux, plus a separate physical Windows-to-Mac evidence
  path that persists only pseudonymized, redacted metadata.
- Bound approved dashboard activities to the real mTLS registry, device-lease, and Apple execution
  path. The physical Mac gate now pins Darwin arm64 binaries by hash/version, requires an
  authenticated controller session, separates cursor resync from reconnect, and retains only one
  allow-listed redacted JSON record with a canonical audit digest.
- Bound the hardware-gate controller endpoint, peer, Windows SID-derived principal, certificate-
  derived source host, fresh Mac challenge, and expiry into a short-lived signed controller-session
  assertion. The Mac verifies it against the paired trust store and rejects mismatched parameters.
- Replaced free remote approval identity fields with a separately paired Windows client flow: the
  Windows process signs the exact access request and native SID, the mTLS registry attests that
  signature, and the target rejects unsigned or mismatched principal/source claims.
- Added stable fail-closed dashboard outcomes for offline targets, authenticated disconnects,
  daemon restarts, observer loss, event resync, audit-store failure, expired approvals,
  deny-overrides, stale leases, cancellation races, and incompatible older agents. Every outcome
  preserves the original activity ID and uses a typed, redacted message code.
- Added native DeviceLane desktop packaging for Windows MSI, notarized macOS DMG, and Linux
  AppImage/deb targets.
- Added locked native builds, SHA-256 manifests, CycloneDX SBOMs, checksum signatures, and
  separate unsigned CI artifacts that cannot be presented as production releases.
- Added runner-scoped first-run lifecycle smoke checks covering install, status, repair,
  autostart, logs, uninstall, and identity preservation.
- Hardened distribution validation so the installed MSI, DMG, AppImage, and deb payloads supply
  the desktop, service, and CLI used by the smoke; production signing runs only inside the
  protected release environment, while unsigned CI receives no release secrets.
- Pinned release runners, Rust, Node.js, actions, and dependency locks and added a build-input
  evidence manifest documenting the remaining native-toolchain reproducibility boundary.
- Added exact production image/native-tool drift gates, deterministic double-build payload
  comparison, strict macOS signature/notarization acceptance, and an elevated-only MSI install
  gate that cannot silently degrade to administrative extraction.
- Isolated production credentials per platform and signing step, bound Windows signing to the
  approved certificate identity, extended reproducibility checks to file-system security metadata,
  and replaced simulated Linux lifecycle markers with packaged-script and real deb transactions.
- Split Apple packaging into a credential-free Tauri build and isolated native signing/notarization
  phase, confined OIDC to a hook-free digest-attestation job, and made xattr/deb smoke handling
  root-relative and non-destructive.

## 0.1.0 — 2026-07-31

Initial experimental developer preview of DeviceLane.

- Secure mutual-TLS registry, agent, and CLI mesh
- Remote Apple build, simulator, device, test, log, and artifact workflows
- Device leasing, reconnectable jobs, audit records, and workspace confinement
- Windows, Linux, macOS Intel, and macOS Apple Silicon release binaries
- SHA-256 release manifest and checksum-verifying npm launcher
