# Desktop onboarding: verified pairing gaps

Date: 2026-09-06

Status: Source assessment and implementation acceptance criteria, not a completed implementation or security certification.

Authority: The approved `2026-09-01-devicelane-desktop-product-design.md` and Task 4 of `../plans/2026-09-05-persistent-mesh-connection.md`. This assessment preserves the full desktop/CLI product scope.

## Evidence and consequence

Inspected feature worktree at HEAD `07bb9bb996d93d7974ab6b4a3ccdb97053c39687`, including its existing uncommitted transport changes. No deployed identity, trust, configuration, or service was modified during this assessment.

| Current boundary | Source evidence | Consequence for onboarding |
| --- | --- | --- |
| Desktop connection editor | `desktop/src/components/ConnectionSettingsCard.tsx` explicitly requires an already paired peer; `desktop/src/api.ts` exposes connection settings but no pairing session | Saving an address cannot perform first pairing. Do not present it as a complete setup wizard. |
| Local daemon API | `src/local_ipc.rs`, `LocalRequest`, has connection read/set but no pairing start, candidate, confirm, cancel, or expiry state | Pairing needs a daemon-owned typed local API, not UI access to key files or a shell wrapper. |
| Service identity | `src/bin/devicelane-service.rs`, `run`, derives public identity from the identity directory basename | A readable host name must be distinct from stable cryptographic identity. Two default directories named `identity` cannot serve as globally unique host identities. Existing identities require explicit preservation/migration, not silent replacement. |
| Legacy listener | `src/bin/mesh-registry.rs`, `pair`, sends a generated code to the connecting socket, reads the echoed code and certificate, and immediately calls `accept_pairing` | The code is available to the same unauthenticated connector. Private binding limits exposure but does not prove the intended user selected that certificate. |
| Legacy connector | `src/bin/mesh-agent.rs`, initial `pair` branch, echoes the received code and subsequently calls `trust("registry", certificate)` | There is no user comparison or independently authenticated registry certificate in this branch. Do not call this branch from the new wizard unchanged. |
| Trust persistence | `src/lib.rs`, `secure_transport::SecureTransport::accept_pairing`, consumes the code and invokes `trust`; `trust` writes the peer certificate | The existing accept operation already changes persistent trust, rather than providing a harmless preview. Candidate display must happen before it. This write does not establish crash durability: `write_secret` truncates/writes without file or directory synchronization. |
| Settings authorization | `src/dashboard/service.rs`, `AdminMutation::ConnectionSet` and `apply_connection_change`, bind an approval to exact settings and audit before persistence | Reuse the authorization discipline, but a connection-setting approval is not permission to trust arbitrary certificates. Pairing needs its own exact candidate-bound mutation. |

The legacy listener also uses blocking `accept` and unbounded `read_line` without an overall pairing-session deadline. A ten-second code lifetime does not itself bound listener lifetime, memory consumption, or socket occupancy. `mesh-cli` repeats the same automatic code-echo and certificate-trust flow as `mesh-agent`.

An independent, bounded read-only security review confirmed that the legacy flow must not back the wizard unchanged. It also corrected the persistence/crash-durability distinction above. Existing post-pairing mTLS, certificate pinning, revocation and key-pair validation are reusable primitives, not proof that first trust is authenticated. No active-network attack was performed against deployed devices.

## Verified test boundary

Ran the current worktree with VS 2022 and target directory `E:/CodexBuild/devicelane-task10-ci`:

```text
cargo test -p devicelane --test pairing_listener --locked --jobs 1
3 passed; 0 failed; 0 ignored; process exit 0
```

The tests reject unsafe/missing bind addresses before identity creation and complete a loopback exchange by echoing the code supplied by the listener. The green result verifies those existing behaviors. It does not verify out-of-band authentication, visual confirmation, intended-peer authorization, or safe unattended first pairing.

CI run `34018793228` completed: macOS, Ubuntu and npm jobs succeeded; Windows failed in `dashboard_job_preserves_live_inventory_during_real_mesh_execution`, reporting `TargetOffline`. The same run also logged an artifact registration response timeout. These observations are separate from the onboarding gap; neither is explained or fixed by this assessment.

## Required integration acceptance criteria

1. A clean installation can create its own stable daemon-owned identity, choose a separate readable host name, and enter local-only mode without a registry. An existing identity is never overwritten merely because configuration is missing.
2. UI and CLI use the same authenticated local pairing-session API. Neither chooses a credential directory, receives private key bytes, or starts an unrestricted shell command. Remote mesh callers cannot invoke local trust confirmation.
3. Session creation requires an explicit local action. A temporary listener binds only to an explicitly selected allowed private/loopback interface. Validate before creating credentials or opening a socket; retain public, wildcard, malformed, and unsupported-address rejection tests.
4. The invitation and candidate exchange must authenticate the intended peers using a reviewed protocol. The legacy same-channel code echo is not an authentication proof. Do not invent cryptography or treat display of an unverified name as verification.
5. A candidate is pending, not trusted. Display the exact peer identity and certificate fingerprint to be confirmed; bind confirmation to the session, candidate certificate, requested role and intended controller connection. Changed certificates, stale sessions, reused confirmations and conflicting existing trust must fail closed.
6. Require the approved visual identity confirmation before granting trust. Pairing grants identity trust only, never blanket recipe execution, keychain access, developer permissions or policy authority.
7. Session expiry uses a monotonic deadline covering the entire lifecycle, including idle accept, handshake and candidate confirmation. Apply bounded frames, connection/read/write deadlines, retry/attempt limits and cancellation. Close the listener on cancellation, expiry and completion. Restart invalidates pending sessions.
8. Persist an audited trust decision before exposing an active mesh connection. An audit failure must prevent a new trust mutation. Report partial durable outcomes honestly; no false rollback or success when certificate/configuration writes are uncertain. No automatic replacement of an existing different certificate.
9. Network work must not hold the global IPC/daemon lock. Late results after cancellation, restart or connection changes cannot activate a superseded candidate. Existing jobs retain their original immutable connection.
10. UI and CLI expose the same pending/expired/rejected/confirmed/error states with safe structured errors, no invitation secrets in audit/logs, accessible keyboard confirmation, and retry guidance. Local-only operation remains available.
11. Two real daemon processes must prove first pairing, restart persistence and a harmless authenticated inventory exchange. Negative tests cover unsolicited peers, wrong invitation/identity, an active proxy substituting certificates despite a correct code, candidate substitution, expiry, replay, cancellation, malformed/oversized frames, audit failure and credential/configuration write failures. An unconfirmed or substituted candidate must leave both prior trust stores unchanged. Test doubles alone cannot satisfy this boundary.
12. Installed Windows and real Mac UI must complete the workflow without terminal pairing or manual key copies. Verify service restart/autostart and CLI parity. CI on macOS is not proof of the user's Mac installation; full resource, packaging and remote-build gates remain required.

## Next implementation boundary

Resolve the protocol and credential-ownership boundary with independent security review first. Then implement a single vertical pairing path spanning daemon session ownership, exact local approval, durable trust/configuration reconciliation, CLI and desktop confirmation, followed by real-process and installed-host tests. Do not ship an apparently complete wizard that simply invokes legacy pairing.

Provenance: AI-assisted source assessment and acceptance criteria. This document makes no human-authorship claim.
