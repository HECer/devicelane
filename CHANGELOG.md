# Changelog

## Unreleased

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

## 0.1.0 — 2026-07-31

Initial experimental developer preview of DeviceLane.

- Secure mutual-TLS registry, agent, and CLI mesh
- Remote Apple build, simulator, device, test, log, and artifact workflows
- Device leasing, reconnectable jobs, audit records, and workspace confinement
- Windows, Linux, macOS Intel, and macOS Apple Silicon release binaries
- SHA-256 release manifest and checksum-verifying npm launcher
