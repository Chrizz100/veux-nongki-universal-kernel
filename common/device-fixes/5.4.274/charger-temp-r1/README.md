# VEUX 5.4.274: Temperatur-Fehlerbehandlung R1

Grundlage: charger-diag08 und Gerätebericht R3 vom 04.10.2026
(SHA256 im Manifest). Der Bericht zeigt einen PMIC-IIO-Timeout (-110),
gefolgt von der Ausgabe des alten CP-Master-Temperaturwertes.

Änderungen an wt_chg:
- Der Slave-Reader prüft seinen eigenen IIO-Kanal.
- Die beiden Temperatur-sysfs-Attribute geben bei Messfehlern den errno
  zurück. Erfolgreiche Werte behalten ihr bisheriges Format und ihre Einheit.
- Der Worker kennzeichnet fehlgeschlagene Messungen als unavailable. Er
  aktualisiert den Cache nur nach Erfolg und bearbeitet beide Kanäle unabhängig.
- Temperatur-Fehlermeldungen sind begrenzt. Die anschließende Laderegelung,
  Wakeup-Behandlung und erneute Planung des Workers bleiben bytegleich.

Alle Diag08-Ladefixes sind kumulativ enthalten. Die bisherigen Hosttests
bleiben erhalten; beim Batterie-Spannungstest werden nur der Hash für den
übrigen Quelltext und dessen Beschreibung angepasst. Die neuen C-Hosttests
prüfen 152 Bedingungen und können die drei alten Defekte reproduzieren.
Der verpflichtende RPM-Sleep-Fix und ConfigDiag10 bleiben separat aktiv.

Der neue Workflow baut nur 5.4.274 über den regulären Release-Worker. Er
ermittelt die aktuellen ReSukiSU-/SUSFS-/NoMount-Commits zu Beginn und
übernimmt die vorhandenen Integrations-, Compiler-, DTB-, Config-, Paket-
und statischen Bootprüfungen. Alle sechs V4-Kernellinien bleiben erhalten.
Zusätzliche Diagnoseartefakte werden nur bei Fehlschlag hochgeladen.

Dies repariert die Verarbeitung eines fehlgeschlagenen Temperatur-Reads.
Eine Beseitigung der ADC-Timeout-Ursache oder aller Suspend-Abbrüche ist
nicht nachgewiesen. Ein Kernelbuild ersetzt keinen Gerätetest. Das Manifest
enthält deshalb device_validation=not-performed und reference_run=not-built;
der neue tatsächliche Buildnachweis steht nach Erfolg in RESULT.json.

Der aktuelle Resolver erkennt UAPI 4 und das geprüfte UAPI 5 aus ReSukiSU
8770c7e3. Für UAPI 5 müssen der vollständige Header und die Services-
Eventfunktion exakt den geprüften Hashes entsprechen; 20 C-Prüfungen
sichern Start/Skip, Soft-Reboot-Reset und die bisherigen Events ab.
Unbekannte UAPI-Versionen oder geänderte Schnittstellen brechen den Build ab.
