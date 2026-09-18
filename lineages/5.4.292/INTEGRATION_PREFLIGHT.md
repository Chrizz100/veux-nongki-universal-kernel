# VEUX 5.4.292 – ReSukiSU / SUSFS Integration Preflight

Stand: 2026-09-18

## 1. Zweck

Dieser Preflight legt die verifizierte Ausgangslage für die kontrollierte Integration
von ReSukiSU und SUSFS in die bereits grün gebaute VEUX-5.4.292-Baseline fest.

Er verändert **keinen Kernel-Quelltext** und ist **kein Integrations-PASS**.

Status dieses Dokuments:

- Native 5.4.292 Baseline: **GITHUB GREEN PASS**
- ReSukiSU/SUSFS Integration: **NOT STARTED**
- ReSukiSU/SUSFS Static Integration Pass: **NO**
- Package Pass: **NO**
- Static Boot Path Pass: **NO**
- Device Pass: **NO**

---

## 2. Verifizierte 5.4.292-Baseline

Kernelquelle:

- Repository: `UEDestroyer/kernel_xiaomi_veux`
- Commit: `fb3bbb10bc0480282c01b88ccaf39c0145cd9f51`
- Defconfig: `veux_defconfig`
- Kernelversion: `5.4.292`
- Kernelrelease: `5.4.292-veid-veux`
- Defconfig SHA-256:
  `a83099092fba60b5beaacc4f5b089f4f96e23d31148714dee0d539817f50f0d1`

Toolchain:

- AOSP Clang: `clang-r547379`
- Toolchain Commit:
  `d19c99c180cfa21504426915d765b5e7adf878b6`
- Clang: `20.0.0`
- Build ID: `13065274`
- LLVM Project Revision:
  `b718bcaf8c198c82f3021447d943401e3ab5bd54`

Green Baseline:

- Script: `lineages/5.4.292/BASELINE_BUILD_V3.sh`
- Script SHA-256:
  `22068e1b4504d14df1271e77465b0e662c4f4119199566878f48fbd9de8db0c2`
- GitHub Actions Run: `35317893402`
- Ergebnis: **SUCCESS**
- Image Größe: `33,792,512` Byte
- Image SHA-256:
  `450b544287d829893edc25fba88f1bd84698c77fc72068778c42a83f9590cede`

Die Baseline ist damit die unveränderte Referenz für alle folgenden
Integrationsdeltas.

---

## 3. Unveränderliche P13-Referenz

P13 bleibt immutable und dient ausschließlich als bekannte funktionierende
5.4-/VEUX-Referenz.

Bekannter Stand:

- Kernel: `5.4.274-qgki-g82179e362f33`
- ReSukiSU Commit:
  `7741f87849f7ad7cebf82bbb4c5b89880e61e37e`
- sichtbare ReSukiSU-Identität:
  `v4.2.0-rc1-7741f878-p13@ReSukiSU`
- KSU/ReSukiSU: `35141`
- UAPI: `4`
- SUSFS: `2.3.0`
- `module_load_filter`: **ausgeschlossen**
- bestätigter Host-Kernel-Source-Delta:
  - `fs/exec.c`
  - `include/linux/ksu_hook_contract.h`
- Status: **DEVICE PASS**

P13 beweist, dass ein VEUX-Linux-5.4-Kernel mit ReSukiSU und SUSFS 2.3.0
funktionieren kann.

P13 beweist **nicht**, dass sein minimaler Host-Source-Delta unverändert auf
5.4.292 oder auf einen neueren ReSukiSU-Commit übertragen werden kann.

---

## 4. Aktueller ReSukiSU-Upstream

Verifizierter aktueller `main`-Stand am 2026-09-18:

- Repository: `ReSukiSU/ReSukiSU`
- Branch: `main`
- Commit:
  `6ec8d9a8a8be30878c388504cacf8ae7849c757b`
- Commit-Datum: `2026-09-17`
- letzter Commit:
  `kernel: cherry-pick KernelSU-Next commit e21a3c5`

Vergleich mit dem P13-ReSukiSU-Pin:

- Basis:
  `7741f87849f7ad7cebf82bbb4c5b89880e61e37e`
- aktuell:
  `6ec8d9a8a8be30878c388504cacf8ae7849c757b`
- aktueller Stand ist **13 Commits voraus**

Aktuelles `kernel/Kbuild` bestätigt weiterhin:

- ReSukiSU Version: `v4.2.0`
- KSU Version: `35141`
- UAPI: `4`
- `RE_SUSFS_ENABLE ?= 1`
- `KSU_MANUAL_HOOK ?= 1`

Wichtig:

Der heutige ReSukiSU-Stand ist deshalb **nicht identisch** mit dem
P13-ReSukiSU-Pin, obwohl KSU-Version und UAPI weiterhin übereinstimmen.

Für die neue 5.4.292-Linie wird der aktuelle Commit

`6ec8d9a8a8be30878c388504cacf8ae7849c757b`

als **Update-Kandidat** verwendet, aber erst nach erfolgreichem
5.4.292-Kompatibilitätsaudit als Integrations-Pin freigegeben.

---

## 5. Aktueller ReSukiSU-Hook-Vertrag

Der aktuelle ReSukiSU-Baum enthält einen eigenen Inline-Hook-Check.

Bei Inline-Hook-Modus (`KSU_MANUAL_HOOK=0`) prüft dieser unter anderem
Hookflächen in:

- `fs/exec.c`
- `fs/open.c`
- `fs/read_write.c`
- `fs/stat.c`
- `fs/statfs.c`
- `fs/readdir.c`
- `fs/namespace.c`
- `fs/devpts/inode.c`
- `fs/input/input.c`
- `kernel/reboot.c`
- `kernel/ptrace.c`
- `kernel/sys.c`

Bei aktivem SUSFS kommen zusätzliche Kernel-Hookflächen hinzu, unter anderem in:

- `fs/d_path.c`
- `fs/notify/fdinfo.c`
- `fs/namespace.c`
- `fs/statfs.c`
- `fs/open.c`
- `fs/exec.c`
- `fs/stat.c`
- `fs/read_write.c`
- `fs/readdir.c`

Der aktuelle Kbuild setzt jedoch standardmäßig `KSU_MANUAL_HOOK ?= 1`.
Der vollständige Inline-Hook-Checker wird deshalb nicht automatisch in jedem
Integrationsmodus zum Pflichtpfad.

Folgerung:

Der P13-Delta von nur zwei Host-Kernel-Dateien darf nicht allein anhand der
heutigen Inline-Hook-Liste als unvollständig bewertet werden. P13 ist ein realer
DEVICE-PASS, während der aktuelle ReSukiSU-Baum mehrere Integrationsmodi
unterstützt.

Für 5.4.292 muss daher zuerst festgestellt werden, welcher aktuelle
ReSukiSU-Modus den P13-Vertrag sauber und reproduzierbar ersetzt.

---

## 6. SUSFS-Upstream und Linux 5.4

Der offizielle SUSFS-Upstream liegt bei `simonpunk/susfs4ksu`.

Verifiziert wurde:

- aktueller SUSFS-Gesamtstand führt Version `2.3.0`
- der offizielle Branch `kernel-5.4` steht dagegen weiterhin bei SUSFS `1.5.5`
- ein offizieller aktueller `kernel-5.4`-Branch mit SUSFS `2.3.0` wurde
  **nicht verifiziert**
- aktuelle 2.3.0-Entwicklung liegt auf neueren GKI-Linien

Der offizielle ältere `kernel-5.4`-Patch benutzt außerdem einen älteren
KernelSU/SUSFS-Hookstil und entspricht nicht direkt dem heutigen
ReSukiSU-Hookvertrag.

Daraus folgen zwei Verbote für die 5.4.292-Integration:

1. SUSFS `1.5.5` aus dem alten offiziellen `kernel-5.4`-Branch wird **nicht**
   als Ersatz für das gewünschte SUSFS `2.3.0` übernommen.
2. Ein moderner 5.10-/5.15-SUSFS-Patch wird **nicht blind** auf Linux 5.4.292
   angewendet.

P13 bleibt der Nachweis, dass ein kontrollierter SUSFS-2.3.0-Backport auf
VEUX/Linux 5.4 grundsätzlich möglich ist.

---

## 7. Integrationsentscheidung für 5.4.292

Die neue Linie wird in getrennten Stufen aufgebaut.

### Stufe A – ReSukiSU Host-Surface Audit

Noch ohne Patchanwendung:

1. exakte 5.4.292-Baseline erneut verifizieren
2. aktuelle ReSukiSU-Hookanforderungen gegen den 5.4.292-Quellbaum prüfen
3. P13-Hookvertrag als funktionierende Referenz danebenstellen
4. benötigten Integrationsmodus festlegen
5. unbekannte oder mehrdeutige Hooks als `PORT_REQUIRED` behandeln

Ergebnis darf nur sein:

- `COMPATIBLE`
- `PORT_REQUIRED`
- `BLOCKED`

Kein automatisches Erraten oder stilles Überspringen.

### Stufe B – ReSukiSU Integration

Erst nach Stufe A:

- ReSukiSU exakt pinnen
- keine `latest`-Abhängigkeit
- `module_load_filter` ausgeschlossen lassen
- Änderungen fail-closed anwenden
- keine Versions-/Localversion-Manipulation
- Identity Guard vor und nach der Integration

### Stufe C – SUSFS 2.3.0 Backport

SUSFS wird separat behandelt:

- 2.3.0-Kernlogik gegen Linux 5.4.292 portieren
- P13 als funktionierende 5.4-Referenz verwenden
- aktuelle SUSFS-Hookanforderungen einzeln prüfen
- keine fremde GKI-Patchdatei ungeprüft anwenden
- keine Rejects ignorieren oder löschen
- jeder Konflikt führt zu `PORT_REQUIRED`

### Stufe D – Compile

Ein Compile wird erst gestartet, wenn:

- Source Pin PASS
- Host-Surface Audit PASS bzw. alle Ports explizit aufgelöst
- `git apply --check` / äquivalente strikte Prüfungen PASS
- `git diff --check` PASS
- keine `.rej` / `.orig`
- Identity Guard PASS

### Stufe E – Packaging und Bootpfad

Erst nach erfolgreichem Compile:

- AnyKernel3 Package Audit
- Stock-Boot-v3-Vertrag
- Static Boot Path Audit
- danach realer VEUX-Gerätetest

---

## 8. Was ausdrücklich noch nicht bewiesen ist

Dieser Preflight beweist **nicht**:

- dass ReSukiSU `6ec8d9a8...` bereits auf 5.4.292 kompiliert
- dass SUSFS 2.3.0 bereits auf 5.4.292 portiert ist
- dass P13-Hooks unverändert übernommen werden können
- dass ein AK3-Paket erstellt wurde
- dass der Bootpfad bestanden wurde
- dass ein Gerät gebootet wurde

Der nächste technische Schritt ist deshalb ein **read-only
5.4.292 ReSukiSU Host-Surface Audit**.

---

## 9. Aktueller Status

```text
5.4.292_NATIVE_BASELINE=GITHUB_GREEN_PASS
5.4.292_IMAGE=PASS
5.4.292_IDENTITY_PRESERVED=PASS

P13_REFERENCE=DEVICE_PASS_IMMUTABLE

RESUKISU_LATEST_CANDIDATE=6ec8d9a8a8be30878c388504cacf8ae7849c757b
RESUKISU_UPDATE_DISTANCE_FROM_P13=13_COMMITS
RESUKISU_INTEGRATION=NOT_STARTED

SUSFS_TARGET=2.3.0
SUSFS_OFFICIAL_KERNEL_5_4_BRANCH=1.5.5
SUSFS_2_3_0_KERNEL_5_4_OFFICIAL_BRANCH=NOT_VERIFIED
SUSFS_INTEGRATION=NOT_STARTED

PACKAGE_PASS=NO
STATIC_BOOT_PATH_PASS=NO
DEVICE_PASS_5_4_292=NO
```

## 10. Quellenbasis

- `Chrizz100/veux-nongki-universal-kernel` – verifizierte 5.4.292-Baseline
- `ReSukiSU/ReSukiSU` – aktueller `main`-Stand und Kbuild/Hook-Checks
- `simonpunk/susfs4ksu` – offizieller SUSFS-Upstream und `kernel-5.4`
- immutable P13-DEVICE-PASS-Projektstand als lokale Integrationsreferenz
