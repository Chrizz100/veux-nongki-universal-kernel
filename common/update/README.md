# VEUX All-in-One V3: gemeinsame Engine

Aktuelle Reparatur: DTB-Prüfung und Fehlerdiagnose von Run 36308814641 auf main
c8effdf273804bd6f949da2c1af9e8feeea124d8. Die frühere Reparatur für Run
36306478920 bleibt enthalten.

## DTB-Reparatur vom 27.09.2026

Die bisherige Engine verglich jede Lineage mit dem Golden-DTB von 5.4.274.
Dieser feste Hash ist für 5.4.274, 5.4.300, 5.4.301 und 5.4.302 belegt und
bleibt für diese vier Quellen erhalten. Für 5.4.292 und 5.4.293 fehlt ein
entsprechender fester Hash in den historischen Verträgen.

Für diese beiden Quellen baut dieselbe Engine deshalb vor jeder Upstream-
Änderung eine DTB-Referenz aus der authentifizierten nativen Quelle mit deren
ursprünglicher Konfiguration und Toolchain. Das aktualisierte DTB muss exakt
denselben SHA-256 haben. Der Kandidat bestimmt niemals seinen eigenen Sollwert.
Die Auswahl erfolgt ausschließlich über Daten in source-recipes.json.

DTB-REFERENCE.json und DTB-CHECK.json dokumentieren Referenz, Soll- und Ist-Hash.
Fehlerartefakte behalten außerdem die Ergebnisdateien vorher erfolgreicher
Lineages. Die Schutzprüfungen und die Freigabe erst nach sechs Erfolgen bleiben
aktiv. Golden-Verträge und CURRENT_FLEET_V10 werden nicht verändert.

Verifizierter bisheriger CI-Stand aus Run 36308814641:

- 5.4.274: Compile, Package und Static PASS; DEVICE_PASS=NO.
- 5.4.292: Image-Build beendet, danach Abbruch an der DTB-Prüfung.
- Die vier späteren Lineages wurden nicht mehr ausgeführt.
- REPOSITORY_MUTATION=NO; keine Kernel-Artefakte veröffentlicht.
- VEUX-AllInOne-BLOCKED-36308814641 ist ein Diagnosearchiv, kein Flash-Paket.
  SHA-256: ec3b6da6b5f8997902681a1b901a36f7d531441707b55f0f53147095001b27b0.
  Es enthält keinen Ist-DTB-Hash. Eine tatsächliche DTB-Änderung ist damit
  weder nachgewiesen noch ausgeschlossen.

Für die aktuelle DTB-Reparatur: 21 Regressionstests erfolgreich, Python- und
Bash-Syntax, YAML 1.2 mit Duplicate-Key-Ablehnung sowie actionlint v1.7.12
erfolgreich (ohne optionales ShellCheck). Die neuen Tests simulieren den
Referenzcompiler; sie ersetzen keinen nativen DTB- oder vollständigen CI-Build.
Kein neuer GitHub-Run und kein Push durch diese Reparatur. 6/6 CI-PASS und neue
Gerätetests bleiben offen.

## Dateien und Zielordner

Alle Pfade sind relativ zum Hauptverzeichnis von
Chrizz100/veux-nongki-universal-kernel. Die ZIP-Ordnerstruktur beibehalten.

- `.github/workflows/veux-all-in-one-updater-v3.yml`
- `common/scripts/veux_update_engine.py`
- `common/scripts/test_veux_update_engine.py`
- `common/update/source-recipes.json`
- `common/update/golden-source-transform.py` (unveränderter bestehender Helfer)
- `common/update/susfs-legacy-to-04a9d713.patch`
- `common/update/tests/susfs-legacy-source.json.gz`
- `common/update/tests/susfs-relocated-statfs.json.gz`
- `common/update/README.md`

Die gzip-Dateien unverändert hochladen; die Tests entpacken sie selbst.
Bestehende gleichnamige Dateien ersetzen. Historische Workflows, Golden-Verträge,
Fleet-Verträge und Lineage-Profile bleiben erhalten.

## Änderungen

1. Der Quell-Tag `20240619` wird über einen expliziten Datenvertrag dem Commit
   `b2b7a3bbc36d120ee523ebc8d68e0f13a97df632` zugeordnet. Der Checkout prüft
   weiterhin die vollständige Commit-Identität und erhält `fetch-depth: 0`.
   Unbekannte Tags werden abgewiesen.
2. Ein gemeinsamer Patch migriert den anhand dreier SHA-256-Werte erkannten
   Legacy-SUSFS-Quellstand zur API von `04a9d713`. Anschließend integriert dieselbe
   Engine das Upstream-Delta. Es gibt keine sechs separaten Update-Engines.
3. Die Migration erhält die lokalen OPEN_REDIRECT-readlink-, statfs-, fdinfo-
   und ENOMEM-Anpassungen sowie die SRCU-/fsnotify-Kompatibilität für Linux 5.4.
   SUS_KSTAT-Aufrufe bekommen den neuen API-Selektor; auf 5.4 werden keine
   nicht vorhandenen `kstat.mnt_id`-Felder verwendet und keine privaten
   STATX-Bits an Userspace weitergereicht.
4. Änderungen an versetzten Host-Funktionen verwenden eindeutige, exakte
   Vorabbilder. Mehrdeutige oder abweichende Vorabbilder brechen ab.
5. Der gepinnte Clang-Transport akzeptiert sowohl das Quell-Arbeitsverzeichnis
   als auch RUNNER_TEMP; andere Ausgabeorte bleiben gesperrt. Ein Timeout
   kann zum bereits authentifizierten Mirror weiterführen.
6. Unsichtbare deaktivierte Kconfig-Unteroptionen dürfen in `.config` fehlen.
   Aktivierte kollidierende Hooks werden weiterhin abgewiesen.
7. Die Repository-Unverändertheitsprüfung läuft auch bei einem Jobfehler.
8. Die ReSukiSU-Ergebnisprüfung berücksichtigt das native LTO-Archiv
   `drivers/kernelsu/built-in.a` samt `core/init.o`.
9. Identische doppelte AVB-Properties des authentifizierten Basis-Images werden
   mit gleicher Anzahl erhalten. Widersprüchliche Werte werden abgewiesen.

## Prüfungen der vorherigen Reparatur

Lokaler Prüfstand vom 27.09.2026:

- 16 Regressionstests erfolgreich, auch aus dem entpackten Reparatur-ZIP in
  einer frischen Repository-Kopie.
- Workflow: YAML 1.2 mit Duplicate-Key-Ablehnung, Bash-Syntax und actionlint
  v1.7.12 erfolgreich; actionlint ohne optionales ShellCheck ausgeführt.
- Python-Syntax der Engine, Tests und des Golden-Helfers erfolgreich.
- 5.4.274: historische Quellrekonstruktion bis zur Build-Grenze, Golden-
  Transformation und neue Integration erfolgreich. Für diesen lokalen Replay
  wurden bereits vorhandene Vendor-/Toolchain-Transportdaten wiederverwendet;
  die historischen Commit-, Hash- und Quellprüfungen liefen weiterhin.
- 5.4.292: historische Quellrekonstruktion bis zur Build-Grenze, Integration
  und Kompilierung von SUSFS, stat, statfs, proc/fd, notify/fdinfo und NoMount
  erfolgreich. Kein vollständiger 5.4.292-Image-Build behauptet.
- 5.4.302: vollständiger Image-/DTB-Build erfolgreich, genau vier bekannte
  Basiswarnungen. AnyKernel-Paket reproduzierbar und CRC-/Image-Prüfung
  erfolgreich. Statischer Boot-Pfad mit AVB-Verifikation und identischem
  rohem/dekomprimiertem Ramdisk erfolgreich.
- Kein neuer GitHub-Run gestartet, kein Push und keine Stable-Promotion.
- 6/6 vollständige CI-Builds sowie neue Gerätetests sind noch offen.

5.4.302 Prüfdaten:

```text
kernelrelease=5.4.302-qgki-g82179e362f33
image_bytes=29911552
image_sha256=ffb9399b5877a55159faef9b786641fbe3b2351630e5d9093b17d5bd80433b7c
dtb_sha256=42728a6f3d48ae35ac6be4b14ea51bc8a323e77baec2ee544827487378f99d37
package_sha256=fb9ce931258f78e9caa4ff0828e6d4f39aa2aaf70a303c0e4dcf4213ecf8e7c6
static_boot_sha256=db480987ec220821f0317f20e38a1585add3e41f2f1ca9a98b996ff6b18d7ed1
DEVICE_PASS=NO
```
Die Unit-Tests benötigen Python 3, ruamel.yaml, Git und Bash. Der Workflow
installiert die Abhängigkeiten. Aus dem Repository-Hauptverzeichnis:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 common/scripts/test_veux_update_engine.py
```

Ein erfolgreicher lokaler Test ist kein GitHub-6/6-PASS und kein Device-PASS.
Der Workflow veröffentlicht sechs Kernel-Artefakte erst nach erfolgreicher
Bearbeitung aller sechs Quellen. Er schreibt keine Stable-Pins, Profile oder
Verträge auf main. `PROMOTION-READY.json` ist Prüfevidenz, keine durchgeführte
Promotion. Die bestehende CURRENT_FLEET_V10 bleibt bis zur gesonderten
Validierung und Übernahme unverändert.
