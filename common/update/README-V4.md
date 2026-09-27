# VEUX All-in-One Updater V4

Basis: der vollständig erfolgreiche V3-Lauf 36311911619 auf Commit
8b38173e013e84e56bfa58a486592b95f369ce29. V4 verwendet dieselben Build-, DTB-,
Paket- und Static-Boot-Prüfungen. Ein neuer V4-CI-Lauf ist noch erforderlich.

## Installation

Diese Dateien mit unveränderter Ordnerstruktur ins Repository übernehmen:

| Datei | Zielordner |
|---|---|
| veux-all-in-one-updater-v4.yml | .github/workflows/ |
| veux_update_engine.py | common/scripts/ |
| veux_release.py | common/scripts/ |
| test_veux_release.py | common/scripts/ |
| README-V4.md | common/update/ |

Die bestehende Engine ersetzen; die übrigen vier Dateien ergänzen. Bestehende
V3-Dateien, Tests, Quellrezepte, Testdaten und historische Workflows behalten.
Anschließend ausschließlich den neuen Workflow
**VEUX All-in-One Updater V4 - Publish and update sources** auf main starten.
V3 erhält dadurch keine automatische Repository-Übernahme.

## Ausgabe je Kernel

Beispiel für die bisher geprüften Komponentenstände:

`Kernel_5.4.274_ReSukiSU_35184_SUSFS_2.3.0_NoMount_20`

Die Namen werden aus den beim jeweiligen Lauf ermittelten Versionen erzeugt.
NoMount 20 bezeichnet exakt NOMOUNT_VERSION aus dem Kernel-Header. Es wird keine
unbelegte Umrechnung in eine semantische Modulversion vorgenommen.

Jedes GitHub-Artefakt enthält:

- `<Versionsname>_AnyKernel.zip`: Image, Installationsdateien und vorhandene Lizenz.
- `<Versionsname>_boot.img`: exakt das statisch geprüfte Boot-Image.
- `RESULT.json`: endgültige technische Ergebnisse und Quellenidentitäten.
- `SHA256SUMS.txt`: Prüfsummen der drei genannten Dateien.

Keine Arbeitsnotizen, Chatübergaben, internen Zwischenberichte oder KI-Hinweise
werden hinzugefügt. Technische Ergebnisse liegen außerhalb des flashbaren ZIPs.
Die Boot-Images verwenden die im bestehenden statischen Vertrag authentifizierte
Basis für veux / Android 13 Stock-Vendor. Die bisherige Prüfung von Header,
Partitiongröße, AVB, Kernel und roher/dekomprimierter Ramdisk bleibt erhalten.
Device-PASS wird nicht aus diesen Prüfungen abgeleitet.

Nach erfolgreicher Prüfung eines Kernels wird sein Artefakt sofort hochgeladen,
bevor der nächste Build beginnt. Scheitert ein späterer Build, bleiben bereits
hochgeladene Artefakte verfügbar; die Repository-Übernahme entfällt.

## Dauerhafte Repository-Übernahme

Erst nach sechs erfolgreichen Builds, Prüfungen und Uploads:

- `third_party/current/resukisu/`: normalisierte, gebaute ReSukiSU-Quellen.
- `third_party/current/susfs/`: zugehörige SUSFS-Kernelpatches und Lizenz.
- `third_party/current/nomount/`: zugehörige NoMount-Kernelquellen und Lizenz.
- `common/update/current/<Kernel>/`: authentifizierte Integrationsänderungen
  einschließlich Vorher-/Nachher-Hashes und Dateiinhalten.
- `common/upstream/<Komponente>/current.json`: genaue neue Komponentenreferenz.
- `common/contracts/CURRENT_BUILD.json`: aktive V4-Build-Referenz für alle sechs
  Kernel, Prüfergebnisse, Quellen-Hashes und Herkunftslauf; Device-PASS bleibt NO.

Folgende V4-Builds mit denselben Komponenten-Commits verwenden die gespeicherten
Integrationsänderungen. Vorabbilder, Quellrezept und Nutzdaten werden geprüft;
Abweichungen brechen ab. Bei neueren Upstream-Commits wird die gemeinsame
Integration erneut ausgeführt und erst nach Gesamterfolg ersetzt.

Golden, CURRENT_FLEET_V10 und die bisherigen third_party-Baselines bleiben als
historische Referenz für die Quellrekonstruktion unverändert. CURRENT_BUILD.json
bezeichnet den neuen V4-Stand; V10 wird nicht mit neuen Gerätefreigaben versehen.
Ältere eigenständige Workflows verwenden weiterhin ihre bisherigen Referenzen.

Der Workflow benötigt `contents: write`. Er schreibt einen Commit auf main mit
normalem Fast-Forward-Push. Wenn main während des Builds weitergelaufen ist,
wird die Übernahme gesperrt; vorhandene Artefakte bleiben erhalten. Es gibt keinen
Force-Push und keinen automatischen Merge über zwischenzeitliche Änderungen.
GitHub-Branch-Regeln werden nicht umgangen.

## Validierung dieser Änderung

- 21 bestehende Engine-Tests und 8 neue Release-Tests erfolgreich.
- Lokaler Git-Remote-Test prüft vollständige Übernahme und Push sowie Ablehnung
  bei beschädigtem Boot-Image oder gleichzeitig verändertem main.
- Replay-Test prüft identische Integration und Abbruch bei veränderten Nutzdaten.
- Pakettest prüft die erlaubten Installationsdateien und den Ausschluss von Notizen.
- YAML 1.2 ohne doppelte Schlüssel, Bash-/Python-Syntax und actionlint 1.7.12
  geprüft; actionlint ohne optionales ShellCheck.
- Kein vollständiger neuer Kernel-Build oder Gerätetest für V4 behauptet.

Lokale Regressionstests aus dem Repository-Hauptverzeichnis:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 common/scripts/test_veux_update_engine.py
PYTHONDONTWRITEBYTECODE=1 python3 common/scripts/test_veux_release.py
```
