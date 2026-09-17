# VEUX Non-GKI Universal Kernel

Multi-base Non-GKI kernel project for Xiaomi/POCO `veux` (SM6375) with ReSukiSU, SUSFS and AnyKernel3.

## Ziel

Dieses Repository entwickelt **keinen einzelnen Kernel, der beliebig auf jede 5.4.x-Basis geflasht werden soll**.

„Universal“ bedeutet hier:

- gemeinsame, wiederverwendbare 5.4-Kompatibilitätslogik,
- getrennte und echte Kernel-Lineages für relevante 5.4.x-Stände,
- ein gemeinsamer VEUX-spezifischer Integrationslayer,
- ReSukiSU + SUSFS als kontrolliert integrierte Funktionsschicht,
- reproduzierbare Builds und nachvollziehbare Audit-Ergebnisse,
- klare Trennung zwischen statischer Prüfung und echtem Gerätetest.

## Zielgerät

- Gerät: Xiaomi/POCO `veux`
- SoC: Qualcomm SM6375
- Kernel-Familie: Linux 5.4 Non-GKI
- Primäre Vendor-Basis: Android-13-kompatible VEUX/SM6375-Kernelquellen
- Packaging: AnyKernel3

## Geplante Kernel-Lineages

| Kernel | Rolle | Status |
|---|---|---|
| 5.4.259 | ältere relevante VEUX-Basis | PORT_REQUIRED |
| 5.4.268 | verbreitete Vendor-/Custom-ROM-Basis | PORT_REQUIRED |
| 5.4.274 | Referenz / P13 | DEVICE PASS |
| 5.4.290 | neuere VEUX-Basis | PORT_REQUIRED |
| 5.4.292 | erste neue Multibase-Ziellinie | PORT_REQUIRED |
| 5.4.300 | offizielle Linux-stable Portlinie | STATIC BOOT PATH PASS |
| 5.4.302 | offizielle Linux-stable Portlinie | STATIC BOOT PATH PASS |
| 5.4.275 | Sonderfall: Quellbasis aktuell unvollständig | DEFERRED |

5.4.191 ist bewusst nicht Bestandteil der aktuellen Zielmatrix.

## Architektur

Das Projekt folgt vier Ebenen:

1. **Common 5.4 Layer** – wiederverwendbare ReSukiSU/SUSFS-Integrationslogik.
2. **Lineage Layer** – nur die Abweichungen der jeweiligen Kernelversion bzw. Quellbasis.
3. **VEUX Layer** – gerätespezifische SM6375/VEUX-Anpassungen und Defconfig-Verträge.
4. **Validation & Packaging Layer** – reproduzierbare Prüfung, AnyKernel3 und Boot-Pfad-Audits.

Details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Verifizierungsprinzip

Ein erfolgreicher Compile-, Package- oder statischer Boot-Test ist **kein DEVICE PASS**.

Statusbegriffe werden strikt getrennt:

- `STATIC PASS`
- `PACKAGE PASS`
- `STATIC BOOT PATH PASS`
- `DEVICE PASS`

Nur ein realer, bestätigter Gerätetest darf als `DEVICE PASS` bezeichnet werden.

Weitere Regeln: [`docs/VALIDATION_RULES.md`](docs/VALIDATION_RULES.md)

## Aktueller Referenzstand

Die stabile Geräte-Referenz ist P13 auf Linux `5.4.274` mit ReSukiSU, SUSFS 2.3 und AnyKernel3.

P13 bleibt als Referenz unverändert und wird nicht durch spätere Portversuche überschrieben.

## Wichtige Projektregel

Versionsnummern werden nicht gefälscht oder per Localversion-Trick als andere Kernelbasis ausgegeben. Jede Lineage muss tatsächlich aus der jeweiligen Quellbasis hervorgehen.

## Noch keine CI-Workflows

Dieses Bootstrap enthält bewusst **keine GitHub-Actions-YAML**.

Automatisierung wird erst ergänzt, wenn der zugrunde liegende Inhalt und die Build-/Portlogik zuvor reproduzierbar verifiziert wurden.

## Referenzideen

Die Architektur orientiert sich unter anderem an dem sinnvollen Muster „gemeinsame Non-GKI-/SUSFS-Logik + gerätespezifische Fixes“, wie es in Community-Buildsystemen verwendet wird. Fremde Patches werden jedoch nicht blind übernommen, sondern semantisch gegen die jeweilige VEUX-Quellbasis geprüft.
