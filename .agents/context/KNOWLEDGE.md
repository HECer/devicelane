# Knowledge

> Reusable gotchas, conventions, and learnings. Add a bullet whenever you discover
> something a future agent would waste time rediscovering.

- Pairing session roles should reuse `local_ipc::DaemonRole`; the shared tuple binds the controller and candidate roles together with both numeric endpoints.
- The pairing core's single-use flag belongs to one in-memory invitation binding; it does not replace token replay protection or a daemon-wide one-active-session manager.
