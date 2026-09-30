# USB_TYPE-Korrektur im regulären 5.4.274-Updater

Der Patchsatz übernimmt die kumulativen Treiber aus dem erfolgreichen
[Diag06-Lauf 36615353847](https://github.com/Chrizz100/veux-nongki-universal-kernel/actions/runs/36615353847).
Die erzeugten C-Dateien stimmen bytegenau mit diesem Build überein.

## Enthaltene Änderungen

- Alle BQ2589x-Korrekturen aus Diag05: HiZ, VINDPM bei 5 V, I²C-Fehler,
  Initialisierung und Adapter-Callbacks, IRQ/Work/IIO-Lifecycle und Allokation.
- Vorhandene USB-Spannungsumrechnung von mV nach µV mit Fehlerweitergabe.
- USB_TYPE mit passenden Enum-Werten, registrierter Typenliste und getrenntem
  Abfragepfad ohne Aufruf der Ladepolitik aus `get_real_type()`.

Die temperaturabhängige Batteriespannungsanzeige wird hier nicht geändert.
Die Korrekturen betreffen ausschließlich Kernel 5.4.274.

## Referenz und Nachweise

- Build-Commit: `69e17f285e38a741a9a80c97645445e8edcbe003`.
- ReSukiSU 35187, SUSFS 2.3.0, NoMount Kernel-Wire-Version 20.
- Referenz-Image SHA-256: `04310cb851b5dd8cd3189ad84b8067ede1642ce9552c5c179deeedca26027a2f`.
- Referenz-AK3 SHA-256: `7568532564168a19f5741c775b08b8b70c9f07faf44c4838e3c6c68792f116c5`.
- BQ-Treiber SHA-256: `0aa9b1516a8a5fa2efe30b4cc9be56c03d030f7282e1b7ef8066615c9172c241`.
- WT-Treiber SHA-256: `e75f5c793d74311da59343eb46410563750b642e63fd70e1e1f2cabaad3d3e08`.

Der Gerätebericht vom 29.09.2026 identifiziert das Referenz-Image in der
aktiven Bootpartition. Alle 24 USB_TYPE-Abfragen waren erfolgreich:
PD/PPS beim Laden, Unknown nach Abziehen, PD und anschließend PPS nach dem
Wiederanstecken. Akkustand 79 auf 83 Prozent, Temperatur 29,4 bis 30,3 °C.
Am 30.09.2026 bestätigte der Projektinhaber Laden am PC, MTP-Erkennung und
Zugriff auf den Telefonspeicher. Dies ist eine Bestätigung dieses beobachteten
USB-/Ladeverhaltens, keine Freigabe sämtlicher Fehlerpfade oder anderer Geräte.
Ausgeschaltetes Laden wurde für Diag06 nicht erneut getestet; frühere
Bestätigungen bleiben auf ihre jeweiligen Builds begrenzt.

## Verwendung und Prüfungen

Der reguläre Einstieg `common/scripts/veux_release_device.py` wendet den
Patchsatz sowohl auf wiederverwendete als auch neue Upstream-Integrationen an.
Alle 1.555 Host-Assertions müssen vor dem Build bestehen: BQ 76, I²C-Aufrufer
1.101, USB-Spannung 117 und USB_TYPE 261. Quell- und Payload-Hashes werden
geprüft; nach dem Build werden die Treiber-Hashes erneut verglichen.

`reference_run` bezeichnet jetzt den erfolgreichen Diag06-Lauf. Dadurch
ändert sich der Manifest-Hash gegenüber dem damaligen Diagnosemanifest;
Patches, Treiber-Endstände und Hosttests bleiben identisch.

Ein neuer regulärer Build muss weiterhin Compile-, Paket-, DTB- und
Static-Boot-Prüfungen bestehen. Alte Diag04-/Diag05-Ergebnisse dürfen die
aktuelle Promotion nicht erfüllen. `CURRENT_BUILD.json` wird erst durch
einen erfolgreichen regulären Lauf aktualisiert. Gerätebestätigungen werden
nicht automatisch auf zukünftige Builds übertragen.

Workflow: `.github/workflows/veux-all-in-one-updater-v4.yml` über
**Run workflow** auf dem aktualisierten `main` starten.
Die Diagnose-Runner und Termux-Skripte gehören nicht zu diesem Patchsatz.
AK3 enthält weiterhin nur Kernel, Installationsdateien und Lizenz.
