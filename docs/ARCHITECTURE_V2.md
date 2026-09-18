# Architektur – V2

## 1. Grundidee

VEUX besitzt mehrere reale Linux-5.4-Quellstände, die sich trotz gleicher Hauptlinie semantisch unterscheiden können.

Deshalb ist das Projekt **kein One-Image-Fits-All-Kernel**. Stattdessen wird möglichst viel nachweislich gemeinsame Logik zentral gepflegt, während echte Quellunterschiede pro Lineage getrennt behandelt werden.

Die Architektur übernimmt bewusst das sinnvolle Muster modularer Non-GKI-Buildsysteme:

- gemeinsame Build- und Integrationslogik,
- getrennte Kernelquellen und Defconfigs,
- gemeinsame Linux-5.4-Kompatibilität,
- zusätzliche Lineage- und Gerätefixes.

Im Unterschied zu toleranteren Community-Buildsystemen arbeitet dieses Projekt **fail-closed**:

- kritische Patches dürfen nicht still fehlschlagen,
- `.rej`- oder `.orig`-Dateien gelten als Fehler,
- ein erfolgreicher Compile ersetzt keine semantische Prüfung,
- ein statischer Test ersetzt keinen realen Gerätetest.

## 2. Layer-Modell

### A. Common 5.4 Layer

Der Common-Layer enthält nur Logik, die auf mehreren VEUX-5.4-Lineages nachweislich identisch oder semantisch gleich ist.

Dazu gehören insbesondere:

- ReSukiSU-Grundintegration,
- SUSFS-2.3-Grundlogik,
- gemeinsame Hook-Verträge,
- gemeinsame Konfigurationsprüfungen,
- Source- und Identity-Gates,
- strikt fehlschlagende Patch-Hilfen,
- Erkennung bereits vorhandener KernelSU-/SUSFS-Integrationen.

Dieser Layer darf keine versionsspezifischen Annahmen erzwingen.

Wenn eine Zielquelle von der gemeinsamen Semantik abweicht, gehört die Anpassung in den jeweiligen Lineage-Layer.

### B. Lineage Layer

Der Lineage-Layer enthält ausschließlich die Unterschiede einer konkreten Kernelbasis.

Geplante Lineages:

- `5.4.259`
- `5.4.268`
- `5.4.274`
- `5.4.290`
- `5.4.292`
- `5.4.300`
- `5.4.302`

`5.4.275` bleibt vorerst separat, bis eine vollständige und vertrauenswürdige Quellbasis feststeht.

Typische Aufgaben dieses Layers sind:

- abweichende Funktionssignaturen,
- verschobene Hooks,
- unterschiedliche VFS-/exec-/SELinux-Strukturen,
- versionsspezifische Backports,
- abweichende Defconfig-Abhängigkeiten,
- Quellunterschiede zwischen Vendor- und Custom-ROM-Lineages.

### C. VEUX Layer

Der VEUX-Layer enthält ausschließlich gerätespezifische Regeln für Xiaomi/POCO `veux` / SM6375.

Dazu gehören insbesondere:

- VEUX-Defconfig-Verträge,
- Qualcomm-/HOLI-/SM6375-Abhängigkeiten,
- Device-Tree- und DTBO-Verträge,
- Boot- und Vendor-Boot-Kompatibilität,
- VEUX-sichere AnyKernel3-Einstellungen,
- ROM-/Vendor-Basis-Kompatibilitätsregeln.

Gerätespezifische Anpassungen gehören nicht in den Common-Layer.

### D. Validation & Packaging Layer

Dieser Layer erzeugt keine fachliche Kompatibilität.

Er prüft und verpackt ausschließlich bereits bekannte und nachvollziehbare Zustände.

Geplant sind insbesondere:

- Source-Pin-Prüfung,
- Patch-Fail-Closed-Prüfung,
- Compile-Validierung,
- Kernelrelease- und Identitätsprüfung,
- AnyKernel3-Paketprüfung,
- ARM64-Header-Prüfung,
- Boot-v3-/AVB-/Ramdisk-Handoff-Audit,
- reproduzierbare Hashes,
- Audit-Berichte.

## 3. Repository-Struktur

```text
.
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── KERNEL_MATRIX.md
│   └── VALIDATION_RULES.md
├── common/
│   ├── README.md
│   ├── SELFTEST.md
│   ├── contracts/
│   └── scripts/
├── lineages/
│   ├── 5.4.259/
│   ├── 5.4.268/
│   ├── 5.4.274/
│   ├── 5.4.290/
│   ├── 5.4.292/
│   ├── 5.4.300/
│   └── 5.4.302/
├── device/
│   └── veux/
├── packaging/
│   └── anykernel3/
└── audit/
```

Verzeichnisse werden erst angelegt, wenn tatsächlicher Inhalt dafür existiert.

Leere Platzhalter sind nicht erforderlich.

## 4. ReSukiSU / SUSFS

Die aktuelle Geräte-Referenz nutzt ReSukiSU und SUSFS 2.3.

Wichtige Regeln:

- keine unkontrollierte Mischung verschiedener SUSFS-Generationen,
- Hooks semantisch prüfen statt nur Patch-Kontext passend zu machen,
- `module_load_filter` bleibt aus der aktuellen Referenzintegration ausgeschlossen,
- existierende KernelSU-/SUSFS-Reste in Zielquellen werden vor jeder Integration auditiert,
- doppelte Hooks sind Fehler,
- doppelte Kconfig- oder Makefile-Einbindungen sind Fehler,
- `patch ... || true` oder `git apply ... || true` sind in Masterpfaden verboten.

## 5. Referenzlinie P13

P13 auf Linux `5.4.274` bleibt die derzeitige Geräte-Referenz.

Bekannter Referenzstand:

- Kernel: `5.4.274-qgki-g82179e362f33`
- ReSukiSU: `7741f87849f7ad7cebf82bbb4c5b89880e61e37e`
- KSU/ReSukiSU: `35141`
- UAPI: `4`
- SUSFS: `2.3.0`
- `module_load_filter`: ausgeschlossen
- Status: `DEVICE PASS`

P13 bleibt immutable.

P13 ist Referenz für Verhalten und bekannte VEUX-Kompatibilität, aber kein universeller Quellpatch für jede andere Linux-5.4-Lineage.

## 6. Externe Kernel-Lineages

Für externe VEUX-/SM6375-Quellen gilt:

1. Quelle exakt pinnen.
2. Native Kernelidentität prüfen.
3. Defconfig prüfen.
4. Vorhandene KernelSU-/SUSFS-Integration auditieren.
5. Gemeinsam nutzbare Logik identifizieren.
6. Abweichungen getrennt pro Lineage behandeln.
7. Erst danach Build und Packaging durchführen.

Es gibt keinen Versionsspoofing-Pfad.

Eine Kernel-Lineage gilt nicht als portiert, nur weil eine passende Quelle gefunden wurde.

## 7. Erste geplante externe Ziellinie: 5.4.292

Aktuell bekannte Quellbasis:

- Repository: `UEDestroyer/kernel_xiaomi_veux`
- Branch: `main`
- Commit: `fb3bbb10bc0480282c01b88ccaf39c0145cd9f51`
- Defconfig: `veux_defconfig`
- Kernelbasis: `5.4.292`

Diese Quelle ist derzeit nur als geplante erste externe Ziellinie dokumentiert.

Der eigentliche Port gilt noch **nicht** als begonnen oder validiert.

Vor konkreten Änderungen werden zuerst:

1. Source-Pin und native Kernelidentität geprüft,
2. vorhandene KernelSU-/SUSFS-Reste auditiert,
3. die Quelle gegen den Common-5.4-Vertrag klassifiziert,
4. tatsächliche Lineage-Abweichungen dokumentiert.

Erst danach entstehen konkrete Patches für `lineages/5.4.292/`.

## 8. Statusdisziplin

Folgende Statusbegriffe bleiben strikt getrennt:

- `STATIC PASS`
- `PACKAGE PASS`
- `STATIC BOOT PATH PASS`
- `DEVICE PASS`

Keiner dieser Status darf automatisch aus einem anderen abgeleitet werden.

`DEVICE PASS` wird ausschließlich nach einem echten Gerätetest vergeben.

## 9. Leitprinzip

Das Projekt soll die **Modularität guter Non-GKI-Buildsysteme** übernehmen, aber deren Fehlertoleranz nicht kopieren.

Gemeinsame Logik wird zentralisiert.

Lineage-spezifische Abweichungen bleiben getrennt.

VEUX-spezifische Regeln bleiben getrennt.

Validierung bleibt fail-closed.
