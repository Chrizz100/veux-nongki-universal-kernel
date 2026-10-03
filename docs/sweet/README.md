# SWEET R4 – getrennte Ordner in der bestehenden Repo

R4 ersetzt das R3-Installationspaket. Keine neue Repo erforderlich.
Ziel: Chrizz100/veux-nongki-universal-kernel, zusätzlich zu den bestehenden VEUX-Dateien.

## Übernahme

Das ZIP entpacken und seine fünf Ordner mit vollständigen Pfaden in das
Repository-Stammverzeichnis übernehmen:
`.github`, `common`, `device`, `lineages`, `docs`.
Nicht die ZIP-Datei selbst als Repository-Datei hochladen und keinen zusätzlichen
SWEET-Wrapperordner darüberlegen. Vorhandene gleichnamige Verzeichnisse werden
zusammengeführt; vorhandene VEUX-Dateien bleiben erhalten. Kein VEUX-Ordner wird
verschoben, ersetzt oder gelöscht. Der Paketinhalt liegt ausschließlich unter
den SWEET-Unterpfaden und einer SWEET-Workflowdatei.

Die YAML muss direkt unter `.github/workflows/sweet-oem-source-audit.yml` liegen.
GitHub sucht Workflows unter `.github/workflows` im Stammverzeichnis.

Bereits R3 übernommen: Die gleichnamige SWEET-YAML wird durch die R4-YAML ersetzt.
Der alte Stammordner `sweet-oem-audit/` wird von R4 nicht mehr verwendet und muss
für den Lauf weder bearbeitet noch gelöscht werden. R3 und R4 nicht anschließend
wieder durcheinander überschreiben. Historische R3-Berichte in `history/r3/`
sind lediglich Belege, keine aktuelle Installationsanleitung.

## Manueller Lauf

Unter Actions den Eintrag „SWEET OEM Quellenpruefung R4“ wählen und einmal
„Run workflow“ starten. Der Workflow hat nur einen manuellen Trigger und
`contents: read`, keine Repo-Schreib- oder Flash-Schritte. Beide OEM-Quellen
werden unabhängig geprüft. Nur die SWEET-Unterpfade werden ausgecheckt.
Ausgaben landen im temporären Runnerbereich und anschließend in Artefakten
mit dem Präfix `SWEET-R4-`, nicht in den VEUX-Ausgabeordnern.

Die lokal gespeicherten Prüfresultate stehen unter `evidence/`.
Ein grüner Sammellauf ist kein Kernel-Green-Pass: den separaten
`critical_config_gate` in `report.json` lesen. Kernelbuild, AK3 und neue boot.img
sind weiterhin nicht Bestandteil dieses Prüfschritts.

## Zielstruktur

.github/workflows/sweet-oem-source-audit.yml
common/scripts/sweet/audit.py
common/update/sweet/tests/
device/sweet/reference/stock.config
lineages/sweet/source_lock.json
lineages/sweet/reference/
docs/sweet/

VEUX behält `device/veux/`, `lineages/5.4.*/`, seine Workflows, Skripte und
Updaterverträge. R4 registriert SWEET nicht in der bestehenden VEUX-Buildmatrix.

Quellprüfung zur Struktur: main-Snapshot c9a02ed301336400fd184eddd6144f2595b444b4.
Der betrachtete VEUX-Detektor sucht nur `lineages/*/build.yml`; das neue
SWEET-Verzeichnis enthält keine Datei dieses Namens auf dieser Ebene.
Die V4-Engine liest eine explizite VEUX-Flotten-/Quellliste statt alle Ordner
als Kernelstände zu behandeln. Eine vollständige Ausführung sämtlicher alter
VEUX-Workflows wurde für diese Strukturänderung nicht vorgenommen.

Es wurden keine Remote-Dateien geändert und keine Actions gestartet.
