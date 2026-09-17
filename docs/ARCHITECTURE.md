# Architektur

## 1. Grundidee

VEUX besitzt mehrere reale Linux-5.4-Quellstände, die sich trotz gleicher Hauptlinie semantisch unterscheiden können.

Deshalb ist das Projekt **kein One-Image-Fits-All-Kernel**. Stattdessen soll möglichst viel gemeinsame Logik zentral gepflegt werden, während echte Quellunterschiede pro Lineage getrennt behandelt werden.

## 2. Layer-Modell

### A. Common 5.4 Layer

Enthält nur Logik, die auf mehreren VEUX-5.4-Lineages nachweislich identisch oder semantisch gleich ist.

Beispiele:

- ReSukiSU-Grundintegration
- SUSFS-2.3-Grundlogik
- gemeinsame Hook-Verträge
- gemeinsame Konfigurationsprüfungen
- Patch-/Audit-Hilfen

Dieser Layer darf keine versionsspezifischen Annahmen erzwingen.

### B. Lineage Layer

Enthält die Unterschiede einer konkreten Kernelbasis.

Geplante Lineages:

- `5.4.259`
- `5.4.268`
- `5.4.274`
- `5.4.290`
- `5.4.292`
- `5.4.300`
- `5.4.302`

`5.4.275` bleibt vorerst separat, bis eine vollständige und vertrauenswürdige Quellbasis feststeht.

Typische Aufgaben dieses Layers:

- abweichende Funktionssignaturen,
- verschobene Hooks,
- unterschiedliche VFS-/exec-/SELinux-Strukturen,
- versionsspezifische Backports,
- abweichende Defconfig-Abhängigkeiten.

### C. VEUX Layer

Gerätespezifischer Vertrag für Xiaomi/POCO `veux` / SM6375.

Er umfasst insbesondere:

- VEUX-Defconfig,
- Qualcomm-/HOLI-/SM6375-Abhängigkeiten,
- Device-Tree-/DTBO-Vertrag,
- Boot-/Vendor-Boot-Kompatibilität,
- VEUX-sichere AnyKernel3-Einstellungen,
- ROM-/Vendor-Basis-Kompatibilitätsregeln.

### D. Validation & Packaging Layer

Dieser Layer erzeugt keine fachliche Kompatibilität, sondern prüft und verpackt bereits bekannte Zustände.

Er soll später enthalten:

- Source-Pin-Prüfung,
- Patch-Fail-Closed-Prüfung,
- Compile-Validierung,
- Kernelrelease-/Identitätsprüfung,
- AnyKernel3-Paketprüfung,
- ARM64-Header-Prüfung,
- Boot-v3-/AVB-/Ramdisk-Handoff-Audit,
- reproduzierbare Hashes und Audit-Berichte.

## 3. Zielstruktur des Repositories

Die spätere Repository-Struktur soll ungefähr so aussehen:

```text
.
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── KERNEL_MATRIX.md
│   └── VALIDATION_RULES.md
├── common/
│   ├── patches/
│   ├── hooks/
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

Die Verzeichnisse werden erst angelegt, wenn tatsächlicher Inhalt dafür existiert. Leere Platzhalter sind nicht notwendig.

## 4. ReSukiSU / SUSFS

Die aktuelle Referenzlinie nutzt ReSukiSU und SUSFS 2.3.

Wichtige Regeln:

- keine unkontrollierte Mischung verschiedener SUSFS-Generationen,
- Hooks semantisch prüfen statt nur Patch-Kontext passend zu machen,
- `module_load_filter` bleibt aus der aktuellen Referenzintegration ausgeschlossen,
- existierende KernelSU-/SUSFS-Reste in fremden Quellen werden vor Portierung auditiert,
- doppelte Hooks oder doppelte Kconfig-Einbindung sind Fehler.

## 5. Warum 5.4.292 zuerst

5.4.292 ist aktuell die nächste praktische Multibase-Ziellinie, weil:

- eine echte VEUX-Quellbasis vorhanden ist,
- `veux_defconfig` vorhanden ist,
- die Kernelidentität 5.4.292 echt ist,
- der frühere Feasibility-Test bereits `PORT_REQUIRED` festgestellt hat,
- damit ein realer semantischer Port statt Versionsspoofing möglich ist.

Die erste Aufgabe für 5.4.292 ist daher nicht „Build erzwingen“, sondern den **ersten reproduzierbaren Portkonflikt** zu bestimmen und sauber zu lösen.
