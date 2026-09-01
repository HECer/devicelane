# Changelog

## Unreleased

- Added native DeviceLane desktop packaging for Windows MSI, notarized macOS DMG, and Linux
  AppImage/deb targets.
- Added locked native builds, SHA-256 manifests, CycloneDX SBOMs, checksum signatures, and
  separate unsigned CI artifacts that cannot be presented as production releases.
- Added runner-scoped first-run lifecycle smoke checks covering install, status, repair,
  autostart, logs, uninstall, and identity preservation.

## 0.1.0 — 2026-07-31

Initial experimental developer preview of DeviceLane.

- Secure mutual-TLS registry, agent, and CLI mesh
- Remote Apple build, simulator, device, test, log, and artifact workflows
- Device leasing, reconnectable jobs, audit records, and workspace confinement
- Windows, Linux, macOS Intel, and macOS Apple Silicon release binaries
- SHA-256 release manifest and checksum-verifying npm launcher
