# Diag08 im regulären V4-Updater

Dieser Patchsatz übernimmt die drei Treiber des erfolgreichen
[Diag08-Laufs 36698563062](https://github.com/Chrizz100/veux-nongki-universal-kernel/actions/runs/36698563062).
Alle kumulativen Diag07-Korrekturen bleiben erhalten. BQ2589x und wt_chg sind
bytegleich mit Diag07. Ausschließlich `sc8551_get_adc_data()` wird zusätzlich
geändert: den Fehler des ersten Registerzugriffs sofort zurückgeben und
ungültige Kanalnummern vor der Registerberechnung ablehnen.
Skalierung, erfolgreiche Messwerte, Ladepolitik und Stromlimits bleiben erhalten.

## Verifizierter Build

- Repo-Commit: `d4ef0b52386593b4142c5b6b7b69aa74159c518c`.
- Image SHA-256: `6b903f52b8139bf8a6f1c033581c4a6b0a93e6674b2e9f4be3453499f85d0603`.
- AK3 SHA-256: `5a5da465471af4a8cabeb1c599e107a34b77789a3dc430aeaf5423a5147423b3`.
- BQ-Treiber: `0aa9b1516a8a5fa2efe30b4cc9be56c03d030f7282e1b7ef8066615c9172c241`.
- WT-Treiber: `c8c785d03e2c723c9a23b89f7728e16ee3bb07e888e8cfc221ce406b6f73d1ef`.
- SC8551-Treiber: `035d1204b1a4796546c90ab1f448f9ba00889164c731719e3096e4fcafc5cd69`.
- Referenz-Komponenten: ReSukiSU 35187, SUSFS 2.3.0, NoMount Wire-Version 20.

Compile, Paket, DTB und Static-Boot bestanden. DTB unverändert zur Golden-
Referenz. Die zwei bisherigen Compilerwarnungen bleiben unverändert; keine
neue Warnung in den geänderten Treibern. Boot.img und AK3 enthalten dasselbe
Kernel-Image. Die 13 AK3-Dateien entsprechen Diag07; nur Image unterscheidet sich.

## Gerätevalidierung und Geltungsbereich

Diag08 wurde noch nicht auf dem Gerät bestätigt. `device=false` bleibt
bestehen. Ein erfolgreicher Build oder Static-Boot-Test ist kein Bootversuch
auf dem Telefon. Frühere Lade-/MTP-Bestätigungen gelten für ihre jeweiligen
Referenz-Builds. Die Diag07-Gerätebeobachtung steht im historischen Patchsatz.
Dieser Patchsatz gilt ausschließlich für 5.4.274.

## Integrationsprüfungen

V4 verlangt die drei exakten Treiber-Hashes sowie alle 3.622 C-Assertions:
BQ 76, I²C-Aufrufer 1.101, USB-Spannung 117, USB_TYPE 261,
Batteriespannung 468 und SC8551 1.599. Die Prüfung erfolgt vor dem Build;
Treiber-Hashes werden danach erneut geprüft. Die Patch-/Testdateien sind
identisch mit Diag08. Lediglich Buildreferenz und Kandidatenstatus werden
in den Metadaten aktualisiert; der Manifest-Hash ändert sich entsprechend.

Alte Diag04-/05-/06-/07-Nachweise werden für die Promotion abgewiesen.
`CURRENT_BUILD.json` bleibt bis zum tatsächlich erfolgreichen regulären Lauf
unverändert. Der reguläre Updater löst seine Upstream-Stände weiterhin selbst
auf; neue Upstream-Stände müssen alle vorhandenen Prüfungen erneut bestehen.

Workflow: `.github/workflows/veux-all-in-one-updater-v4.yml`.
Die bestehende YAML bleibt unverändert. Diagnose-Runner, Termux-Skripte und
Berichte werden nicht in die flashbare AK3 aufgenommen.
