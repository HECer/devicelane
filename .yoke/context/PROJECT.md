# Project — North Star

> Edit this file. It is the durable goal every Yoke agent reads before implementing.

## Goal
Ein sicherer, plattformübergreifender Device Development Mesh, über den Entwickler von Windows, macOS oder Linux aus Builds, Tests, Debugger, Logs, Dateien und an entfernte Hosts angeschlossene Mobilgeräte bedienen können. Der primäre Ablauf ist Windows → Mac → iPhone; derselbe Vertrag trägt Mac → Windows → Android und weitere Kombinationen.

## Constraints
- Apple-Builds, Codesigning und physische iOS-Geräte benötigen einen Mac mit vollständigem Xcode.
- Öffentliche, unterstützte Plattformwerkzeuge werden nicht durch private iOS-APIs oder Sicherheitsumgehungen ersetzt.
- Jede Netzwerkverbindung ist authentisiert und verschlüsselt; Autorisierung ist capability-basiert und deny-by-default.
- Der Yoke-Loop implementiert kleine, testbare Phasen; Hardwareunterstützung gilt erst nach echten Hardware-Gates als fertig.
- Windows, macOS und Linux müssen denselben Protokollkern ausführen können.

## Non-goals
- Kein öffentlich erreichbarer anonymer Remote-Root-Shell-Dienst.
- Keine Umgehung von Apple Trust, Developer Mode, Codesigning, Entitlements oder Gerätesperren.
- Kein Versprechen beliebiger iOS-System- oder Drittanbieter-App-Steuerung wie auf einem gerooteten Gerät.
- Kein vollständiger Remote Desktop und keine SaaS-Abrechnung im ersten Produktkern.

## Success criteria
- Windows kann einen Mac-Agenten entdecken, sicher pairen und einen isolierten Remote-Workspace bedienen.
- Der Mac kann eine iOS-App bauen, testen, auf einem angeschlossenen iPhone installieren/starten und Logs/Debugartefakte zurückliefern.
- Mac kann denselben Ablauf über einen Windows-Agenten und ADB für Android ausführen.
- Jobs überleben kurzzeitige Clientabbrüche; Dateien und Events werden ohne Lücken oder doppelte Seiteneffekte fortgesetzt.
- Zugriffe sind scoped, widerrufbar und vollständig auditierbar.
