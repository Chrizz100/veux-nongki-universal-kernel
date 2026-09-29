# Diag05 im regulären V4-Updater

Diese Korrekturen gelten ausschließlich für die authentifizierte 5.4.274-Quelle.
Der BQ2589x-Patch enthält die bisherigen Lifecycle-, Fehler- und
5-V-VINDPM-Korrekturen sowie die Diag05-Prüfung von Rückgabewerten in
Initialisierung und Adapter-Callbacks. Die USB-Spannungskorrektur bleibt enthalten.

## Referenz und Gerätetest

- Erfolgreicher Diag05-Build: https://github.com/Chrizz100/veux-nongki-universal-kernel/actions/runs/36518512103
- Referenz-Image SHA-256: `dc0bbb22143ea04a16e850707cf787d5dc9db36de4959383b58cca6eaf843df8`
- Referenz-AK3 SHA-256: `d7465ed9c997d9bc9f6da99aca85f4779e1ef09455f250ad9d168f2eeb4e927f`
- Gerätetest: 5.4.274 auf dem VEUX-Testgerät des Projektinhabers.
  Der gelieferte Bericht identifiziert den Diag05-Kernel im aktiven Boot-Image;
  Anstecken, Abziehen und erneutes Anstecken zeigen die erwarteten Ladezustände.
- Rückmeldung vom 29.09.2026: „Laden passt. Alles in Ordnung.“
  Dies ist eine Bestätigung des beobachteten Ladeverhaltens, keine pauschale
  Freigabe aller Fehlerpfade, Kernelvarianten oder Ladegeräte.

## Einbau

Das Paket wurde gegen `main` bei
`dfd3d2ebfae719ac7265d43ac5fa5b293908e367` geprüft.
Den enthaltenen Ordner `common/` mit dem vorhandenen Repo-Ordner zusammenführen:

- `common/scripts/veux_device_fixes.py` ersetzen.
- `common/scripts/test_veux_device_fixes.py` ersetzen.
- `common/device-fixes/5.4.274/charger-diag05/` vollständig hinzufügen.

Danach `.github/workflows/veux-all-in-one-updater-v4.yml` mit **Run workflow**
auf dem aktualisierten `main` neu starten. Die vorhandene YAML wird weiterverwendet.
Eine Wiederholung eines alten Runs verwendet dessen alten Workflow-Stand.

## Prüfungen und Geltungsbereich

V4 prüft Patch- und Testdateien, erzeugte Treiber sowie die zusätzlichen
Testreferenzen. Alle drei Treibertests müssen vor dem Build bestehen.
Getestet sind 76 BQ2589x-, 117 USB-Spannungs- und 1.101 I²C-Assertions.
Die Treiber werden erst nach bestandenen Tests übernommen. V4 prüft ihre
Hashes erneut nach dem Build und verlangt den Diag05-Nachweis zur Promotion.
Dies gilt sowohl für neue Upstream-Integrationen als auch für deren Wiederverwendung.

Die 47 lokalen Engine-, Release-, Device-Fix- und Transporttests bestehen.
Die bestehende V4-YAML besteht die Syntaxprüfung. Der erste reguläre V4-Build
mit dieser Anpassung steht noch aus. `CURRENT_BUILD.json` bleibt bis zu einer
erfolgreichen Promotion der Nachweis des vorherigen Builds.

USB_TYPE-Abfragen und der beobachtete schnelle Prozentanstieg sind separate
Prüfpunkte; dieses Paket enthält dafür keine zusätzlichen Änderungen.
Die übrigen fünf Kernelvarianten erhalten keine 5.4.274-Treiberpatches.
