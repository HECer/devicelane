# Device Development Mesh

## Lokaler Bootstrap

Systemvoraussetzungen sind Git und Rust (via rustup). Für Apple-Operationen wird auf dem Mac vollständiges Xcode benötigt; für Android-Operationen müssen die Android SDK Platform Tools einschließlich `adb` im `PATH` liegen. Alle Netzwerkverbindungen in diesem Ablauf verwenden Loopback und nach dem Pairing TLS.

### Windows

In PowerShell einmalig und bei Bedarf erneut ausführen:

```powershell
.\scripts\setup-windows.ps1
```

Das Skript legt die lokalen Verzeichnisse idempotent an, baut alle drei Programme und gibt den JSON-Bericht von `mesh-cli doctor` aus.

### macOS

```sh
./scripts/setup-mac.sh
```

Das Skript darf beliebig oft wiederholt werden. Es legt fehlende Verzeichnisse an, baut den Workspace und prüft Rust, Netzwerk, Xcode, ADB, Zertifikate und Dateirechte.

### Linux

```sh
mkdir -p .mesh/registry .mesh/agent .mesh/cli .mesh/workspaces
cargo build --workspace
./target/debug/mesh-cli doctor --identity .mesh/cli
```

## Erster Remote-Job

Die folgenden Befehle zeigen den macOS-/Linux-Pfad `./target/debug/<name>`. Unter Windows wird jeweils `./target/debug/<name>` durch `.\target\debug\<name>.exe` ersetzt. Für einen entfernten Agenten muss die Registry an eine erreichbare Schnittstelle statt nur an Loopback gebunden werden; in den Agent- und CLI-Befehlen wird dann `127.0.0.1` durch den Registry-Host ersetzt. Pairing-Ports dürfen nur für den jeweiligen einmaligen Pairing-Vorgang erreichbar sein.

Zuerst Registry und CLI in zwei Terminals pairen:

```text
./target/debug/mesh-registry pair --listen 127.0.0.1:7444 --identity .mesh/registry
./target/debug/mesh-cli pair --address 127.0.0.1:7444 --identity .mesh/cli
```

Danach Registry und Agent genauso pairen:

```text
./target/debug/mesh-registry pair --listen 0.0.0.0:7445 --identity .mesh/registry
./target/debug/mesh-agent pair --address REGISTRY_HOST:7445 --identity .mesh/agent
```

Für dieses Agent-Pairing wird Port 7445 in der Host-Firewall ausschließlich für die IP des Agent-Hosts und nur für die Dauer der beiden Befehle freigegeben; danach wird er wieder geschlossen. `REGISTRY_HOST` ist der vom Agent-Host erreichbare DNS-Name oder die IP der Registry.

Registry starten:

```text
./target/debug/mesh-registry --listen 0.0.0.0:7443 --identity .mesh/registry --offline-after-ms 3000
```

Auf dem entfernten Host den Agenten starten (für Windows entsprechend `--os windows --arch x86_64` und ein Android-Gerät angeben):

```text
./target/debug/mesh-agent --registry 127.0.0.1:7443 --identity .mesh/agent --id mac-1 --os macos --arch aarch64 --capability process.start@1 --device iphone-1:ios:connected --heartbeat-ms 250 --workspace-root .mesh/workspaces
```

Vom Client Host prüfen und den ersten Job senden:

```text
./target/debug/mesh-cli --registry 127.0.0.1:7443 --identity .mesh/cli list --json
./target/debug/mesh-cli --registry 127.0.0.1:7443 --identity .mesh/cli run --json-request '{"principal_id":"developer-1","host_id":"mac-1","device_id":"iphone-1","workspace_id":"hello","request_id":"hello-1","manifest":[{"path":"README.txt","contents":"hello mesh"}]}'
```

Die Run-Antwort enthält Job-ID, sequenzierte Events, Exitstatus, Auditdaten und das erzeugte Artefakt. Unter PowerShell kann der JSON-Wert identisch in einfache Anführungszeichen gesetzt werden.

## Nachgelagerte Hardware-Gates

Das **iPhone-Hardware-Gate** ist erst bestanden, wenn Installation, Start, Logs und Artefaktrückgabe mit einem physisch angeschlossenen, entsperrten iPhone auf einem Mac mit Xcode, Developer Mode, gültigem Signing und bestätigtem Trust erfolgreich gelaufen sind.

Das **Android-Hardware-Gate** ist erst bestanden, wenn dieselbe Strecke mit einem physisch angeschlossenen, über `adb devices` als `device` autorisierten Android-Gerät erfolgreich gelaufen ist.

Mocks gelten nicht als Nachweis für eines dieser Hardware-Gates. Fake-Adapter, Simulatoren und Emulatoren bleiben Vorprüfungen und dürfen den Hardwarestatus nicht auf bestanden setzen.

## Story-Verifikation

Ein Yoke-Status `passes: true` ist ungültig, solange die im Acceptance-Test-Katalog zugeordnete story-spezifische Akzeptanzprüfung nicht grün ist. Das globale Gate führt zusätzlich Workspace-Tests, Clippy ohne Warnungen und den rustfmt-Check aus. Für STORY-20 ist `scripts/bootstrap-smoke` die zugeordnete Prüfung.
