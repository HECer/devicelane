# Security policy

## Supported versions

DeviceLane is an experimental developer preview. Only the latest commit on the default branch receives security fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature on the repository's **Security** tab. Include the affected revision, impact, reproduction steps, and any suggested mitigation. Do not include real private keys, signing credentials, device identifiers, or diagnostic bundles.

## Operational boundaries

DeviceLane exposes privileged development and device-control functions. Deploy it only on a trusted private network or VPN. Do not expose ports `7443`, `7444`, or `7445` directly to the public internet.

Pairing ports must be opened only for the duration of pairing and restricted by host firewall to the intended peer. Treat `.mesh/`, macOS application-support data, audit records, and diagnostics as confidential. If identity material may have leaked, remove the affected trust relationship and create a new identity before reconnecting.

