# Decisions

> Append-only ledger. The Yoke loop adds an entry per completed story; agents add
> entries for non-obvious calls made during interactive work. Newest at the bottom.

## 2026-07-30 – Capability-basierter Agenten-Mesh

- Gewählt: versioniertes Agenten-/Adapterprotokoll mit self-hosted Control Plane, ausgehenden Agenttunneln, direkter Datenebene und Relay-Fallback.
- Verworfen als Kern: reine SSH-Fassade und reiner Remote Desktop; beide bleiben optionale Escape Hatches.
- Apple-Operationen werden ausschließlich auf einem Mac über Xcode CLI, XCTest/XCUIAutomation, LLDB und Instruments ausgeführt.
- Der erste Yoke-Loop implementiert nur den sicheren plattformübergreifenden Vertikalkern mit Fake-Adaptern und Preflights. Echte Apple-/Android-Geräte folgen in getrennten Hardware-Gate-Phasen.
- Sicherheitsvorgabe: deny-by-default Capabilities, mTLS-Pairing, exklusive Leases, isolierte Workspaces und Audit ab dem ersten Vertikalschnitt.

## 2026-07-30 — STORY-1: Rust-Workspace und grüne plattformübergreifende Verifikation anlegen
codex implemented STORY-1

## 2026-07-30 — STORY-2: Versioniertes Capability- und Fehlerprotokoll definieren
codex implemented STORY-2

## 2026-07-30 — STORY-3: Maschinenidentität und lokales mTLS-Pairing implementieren
codex implemented STORY-3

## 2026-07-30 — STORY-4: Agent-Registry, Heartbeats und Capability-Snapshots bereitstellen
codex implemented STORY-4

## 2026-07-30 — STORY-5: Deny-by-default Policies und exklusive Leases erzwingen
codex implemented STORY-5

## 2026-07-30 — STORY-6: Isolierte Workspaces mit Pfadgrenzen und Manifesten verwalten
codex implemented STORY-6

## 2026-07-30 — STORY-7: Begrenzte Prozessausführung und sequenzierte Eventstreams anbieten
codex failed on STORY-7: Command failed: node C:\Users\HEC_e\AppData\Roaming\npm\node_modules\@hecer\yoke\dist\loop\watchdog.js --idle-ms=1200000 --pid-file=.yoke\worktrees\STORY-7\.yoke\runner.pid -- codex exec --dangerously-bypass-approvals-and-sandbox --json (runner exited non-zero but verify is green)

## 2026-07-30 — STORY-8: Reconnect und idempotente Jobwiederaufnahme implementieren
codex implemented STORY-8

## 2026-07-30 — STORY-9: Inhaltsadressierte Artefakte und wiederaufnehmbare Übertragung ergänzen
codex failed on STORY-9: Command failed: node C:\Users\HEC_e\AppData\Roaming\npm\node_modules\@hecer\yoke\dist\loop\watchdog.js --idle-ms=1200000 --pid-file=.yoke\worktrees\STORY-9\.yoke\runner.pid -- codex exec --dangerously-bypass-approvals-and-sandbox --json (runner exited non-zero but verify is green)

## 2026-07-30 — STORY-10: Plattformunabhängiges Device-Adapter-SDK und Fake-Adapter liefern
codex failed on STORY-10: Command failed: node C:\Users\HEC_e\AppData\Roaming\npm\node_modules\@hecer\yoke\dist\loop\watchdog.js --idle-ms=1200000 --pid-file=.yoke\worktrees\STORY-10\.yoke\runner.pid -- codex exec --dangerously-bypass-approvals-and-sandbox --json (runner exited non-zero but verify is green)

## 2026-07-30 — STORY-11: Apple- und Android-Preflight-Adapter ohne Hardwareabhängigkeit anlegen
codex implemented STORY-11

## 2026-07-30 — STORY-12: Sicheren Client-zu-Agent-Vertikalschnitt dokumentieren und beweisen
codex implemented STORY-12

## 2026-07-30 — Phase-1-Audit und Reparatur-Loop

Die Commits für STORY-7, STORY-9, STORY-10 und STORY-12 enthielten keine Implementierung. Pairing und Registry waren zudem nur In-Memory-Modelle. Ursache war ein globales Gate, das keine story-spezifische Akzeptanzprüfung verlangte. STORY-13 bis STORY-20 bilden den verbindlichen Reparatur-Loop; Phase 2 bleibt bis zum echten Mehrprozess- und TLS-Nachweis gesperrt.

## 2026-07-30 — STORY-17: Echter TLS-Transport

Der Yoke-Runner implementierte die Story testgetrieben, blockierte aber beim Windows-GNU-Native-Build wegen einer unvollständigen lokalen Binutils-Auflösung. Nach Reparatur der lokalen Toolchain wurde derselbe Working Tree mit 48 Tests, Clippy und rustfmt verifiziert und ohne Absenkung der Security-Akzeptanz abgeschlossen.

## 2026-07-30 — STORY-13: Verifikationsgate gegen leere Story-Abschlüsse härten
codex implemented STORY-13

## 2026-07-30 — STORY-14: Begrenzte reale Prozessausführung und sequenzierte Eventstreams liefern
codex implemented STORY-14

## 2026-07-30 — STORY-14: Begrenzte reale Prozessausführung und sequenzierte Eventstreams liefern
codex implemented STORY-14

## 2026-07-30 — STORY-15: Inhaltsadressierten Artefaktspeicher mit Resume implementieren
codex implemented STORY-15

## 2026-07-30 — STORY-16: Device-Adapter-SDK und vollständigen Fake-Adapter liefern
codex implemented STORY-16

## 2026-07-30 — STORY-18: Registry, Host-Agent und CLI als getrennte Netzwerkprozesse bereitstellen
codex implemented STORY-18

## 2026-07-30 — STORY-19: Reale Client-zu-Agent-Ende-zu-Ende-Strecke beweisen
codex implemented STORY-19

## 2026-07-30 — STORY-19: Reale Client-zu-Agent-Ende-zu-Ende-Strecke beweisen
codex implemented STORY-19

## 2026-07-30 — STORY-20: Reproduzierbare lokale Bedienung und Bootstrap dokumentieren
codex implemented STORY-20

## 2026-07-30 — STORY-21: Apple-Preflight und typisierte Toolausführung liefern
codex failed on STORY-21: Command failed: node C:\Users\HEC_e\AppData\Roaming\npm\node_modules\@hecer\yoke\dist\loop\watchdog.js --idle-ms=2700000 --pid-file=.yoke\runner.pid -- codex exec --dangerously-bypass-approvals-and-sandbox --json (runner exited non-zero but verify is green)

## 2026-07-30 — STORY-22: Physische Apple-Geräte und Simulatoren normalisiert erkennen
codex implemented STORY-22

## 2026-07-30 — STORY-23: Xcode-Projekte Schemes und Destinations entdecken
codex implemented STORY-23

## 2026-07-30 — STORY-24: Xcode Build und Test als resumierbaren Agent-Job ausführen
codex implemented STORY-24

## 2026-07-30 — STORY-25: iOS-Simulator Lifecycle und Entwicklungsautomation bereitstellen
codex implemented STORY-25

## 2026-07-31 — STORY-26: Physisches iPhone installieren starten stoppen und protokollieren
codex implemented STORY-26

## 2026-07-31 — STORY-27: XCTest XCUI und xcresult Artefakte integrieren
codex implemented STORY-27

## 2026-07-31 — STORY-28: Kontrollierte LLDB- und xctrace-Sessions liefern
codex implemented STORY-28

## 2026-07-31 — STORY-29: Mac-Agent mit einem Befehl installieren und betreiben
codex implemented STORY-29

## 2026-07-31 — STORY-30: Versionierten Remote-Apple-Jobvertrag liefern
codex implemented STORY-30

## 2026-07-31 — STORY-31: Apple-Operationen im entfernten Mac-Agent dispatchen
codex implemented STORY-31

## 2026-07-31 — STORY-32: Apple-Artefakte chunked über das Mesh übertragen
codex implemented STORY-32

## 2026-07-31 — STORY-33: Remote-Apple-Vertikalschnitt in getrennten Prozessen bestehen
codex failed on STORY-33: Command failed: node C:\Users\HEC_e\AppData\Roaming\npm\node_modules\@hecer\yoke\dist\loop\watchdog.js --idle-ms=2700000 --pid-file=.yoke\runner.pid -- codex exec --dangerously-bypass-approvals-and-sandbox --json (runner exited non-zero but verify is green)

## 2026-07-31 — STORY-33: Remote-Apple-Vertikalschnitt in getrennten Prozessen bestehen
codex failed on STORY-33: Command failed: node C:\Users\HEC_e\AppData\Roaming\npm\node_modules\@hecer\yoke\dist\loop\watchdog.js --idle-ms=2700000 --pid-file=.yoke\runner.pid -- codex exec --dangerously-bypass-approvals-and-sandbox --json (runner exited non-zero but verify is green)

## 2026-07-31 — STORY-34: Verteilte Geräte-Leases und Mehrclient-Steuerung liefern
codex failed on STORY-34: Command failed: node C:\Users\HEC_e\AppData\Roaming\npm\node_modules\@hecer\yoke\dist\loop\watchdog.js --idle-ms=2700000 --pid-file=.yoke\runner.pid -- codex exec --dangerously-bypass-approvals-and-sandbox --json (runner exited non-zero but verify is green)

## 2026-07-31 — STORY-34 unabhängiger Stop-the-Line-Audit

Der reine Signaturtest genügt nicht. Der erneute Loop muss echte mTLS-Prozesse
verwenden und zusätzlich verhindern, dass Observer `AgentDetach`, fremdes
`AppleCancel`/`AppleProgress` oder gefälschte Heartbeats senden. Geräte-Leases
müssen an den meldenden Agenten gebunden sein. Ein ablaufender Grant darf einen
wartenden Writer erst dann wirksam machen, wenn die vorherige mutierende
Toolausführung beendet oder nachweislich abgebrochen ist; zwei Toolprozesse für
dasselbe Gerät dürfen sich nie überlappen.
