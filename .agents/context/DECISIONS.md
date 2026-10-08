# Decisions

This file records durable product and architecture choices, not task-runner status.

## 2026-07-30 — Capability-based agent mesh

- Use a versioned agent/adapter protocol with a self-hosted control plane, outbound agent tunnels, a direct data plane, and relay fallback.
- Keep SSH and remote desktop as optional tools rather than the product core.
- Run Apple build, signing, and physical-device operations on a Mac through supported Apple tools.
- Require authenticated encrypted connections, deny-by-default capabilities, exclusive device leases, isolated workspaces, and audit records.

## 2026-09-06 — First-trust pairing

- Authenticate first trust with exact certificate pins and independent local fingerprint confirmation; a same-channel code echo is not proof of identity.
- Keep private keys and trust mutation in the daemon. Local clients receive typed operations and public status only.
- Grant peer identity trust separately from permission to run jobs or access protected operating-system resources.

## 2026-09-06 — Hardware support claims

- Treat hardware support as available only after verification on the relevant real device and host; fixture results alone do not establish installed-host support.

## 2026-10-08 — Pairing session authority boundary

- Validate the shared approval tuple against controller-owned invitation fields before opening a session. The in-memory session core only reports readiness after both peers confirm the exact tuple; TLS provenance, bearer-token replay protection, daemon-wide admission and restart fencing, local IPC authorization, audit, revocation revalidation, and trust mutation remain daemon responsibilities.
