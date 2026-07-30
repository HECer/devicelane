# Device Development Mesh

## Story-Verifikation

Ein Yoke-Status `passes: true` ist ungültig, solange die im Acceptance-Test-Katalog
zugeordnete story-spezifische Akzeptanzprüfung nicht grün ist. Das globale Gate
führt zusätzlich Workspace-Tests, Clippy ohne Warnungen und den rustfmt-Check aus.
