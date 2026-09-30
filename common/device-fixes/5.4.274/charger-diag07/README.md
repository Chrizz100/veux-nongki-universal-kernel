# Diag07 im regulären V4-Updater

Dieser Patchsatz übernimmt die kumulativen Treiber des erfolgreichen
[Diag07-Laufs 36688871120](https://github.com/Chrizz100/veux-nongki-universal-kernel/actions/runs/36688871120).
Alle bisherigen BQ2589x-, USB-Spannungs- und USB_TYPE-Korrekturen bleiben enthalten.
Neu ist ausschließlich die Batteriespannungsabfrage in `batt_psy_get_prop()`:
eindeutige Auswahl des temperaturabhängigen Messkanals, Prüfung der
Leserückgabe und Schutz der mV-zu-µV-Umrechnung vor ungültigen Werten.
Ladepolitik, Temperaturgrenzen und Stromlimits bleiben unverändert.

## Referenz und Gerätebeobachtung

- Referenz-Image: `a2f474d9ce8e4b18a5867709aa77c48f3afa22780e33dae6919b5f8913386130`.
- BQ-Treiber: `0aa9b1516a8a5fa2efe30b4cc9be56c03d030f7282e1b7ef8066615c9172c241`.
- WT-Treiber: `c8c785d03e2c723c9a23b89f7728e16ee3bb07e888e8cfc221ce406b6f73d1ef`.
- Referenz-Komponenten: ReSukiSU 35187, SUSFS 2.3.0, NoMount Wire-Version 20.
- Gerätebericht vom 30.09.2026, SHA-256:
  `a05ee38007a1aa2549577f265f7b5df44328fbd410d78117ddbf213fcf105026`.

Die Image-Prüfsumme in der aktiven Bootpartition entspricht der Referenz.
17/17 Batteriespannungsabfragen waren erfolgreich und stimmten jeweils mit
mindestens einer unmittelbar davor oder danach gelesenen BMS-Messung überein.
Abziehen und Wiederanstecken zeigten die erwarteten USB-/Ladezustände.
Beobachtet wurden 27,7 bis 29,6 °C und eine Akkuanzeige von 69 auf 73 Prozent.
Dies bestätigt den beobachteten Normalbetrieb. Kälte-/Hitzezweige und
Lesefehler wurden ausschließlich auf dem Host simuliert. PC/MTP und
ausgeschaltetes Laden wurden in diesem Bericht nicht erneut geprüft.
Frühere Gerätebestätigungen gelten für ihre jeweiligen Referenz-Builds.

## Build und Grenzen

Der Einstieg `common/scripts/veux_release_device.py` verlangt diesen Patchsatz
bei neuer und wiederverwendeter Upstream-Integration. Vor dem Kompilieren
müssen 2.023 Assertions am tatsächlichen Treibercode bestehen:
BQ 76, I²C-Aufrufer 1.101, USB-Spannung 117, USB_TYPE 261 und Batteriespannung 468.
Payload- und Treiber-Hashes werden geprüft; nach dem Build erfolgt eine
erneute Treiberprüfung. Alte Diag04-/05-/06-Nachweise erfüllen die Promotion
nicht mehr. Die Patches gelten ausschließlich für Kernel 5.4.274.

`CURRENT_BUILD.json` bleibt der Nachweis des letzten regulären Builds, bis
ein neuer V4-Lauf Compile-, Paket-, DTB- und Static-Boot-Prüfungen bestanden hat.
Ein erfolgreicher Hosttest setzt weder `device=true` noch ersetzt er einen
Kernel-Build. SC8551-Änderungen gehören nicht zu diesem Patchsatz.

Workflow: `.github/workflows/veux-all-in-one-updater-v4.yml`.
Die bestehende YAML wird weiterverwendet. Diagnose-Runner und Termux-Skripte
werden nicht installiert; die AK3 enthält Kernel, Installationsdateien und Lizenz.
