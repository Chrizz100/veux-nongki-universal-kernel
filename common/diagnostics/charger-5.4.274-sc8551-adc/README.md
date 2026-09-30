# SC8551: ADC-Lesefehler, separater Kandidat für 5.4.274

Status: Fehler am Originalcode reproduziert; Korrektur auf dem Host geprüft.
Dieser Ordner wird vom regulären V4-Updater **nicht** angewendet. Diag07
bleibt der aktive, zuvor auf dem Gerät beobachtete Patchsatz. Es existiert
noch kein Kernel-Build oder Geräteergebnis für diesen SC8551-Kandidaten.

## Bestätigter Fehler

`sc8551_get_adc_data()` liest erst das obere, dann das untere Registerbyte.
Der zweite Zugriff überschreibt den Rückgabewert des ersten. Schlägt der
erste Zugriff fehl und gelingt der zweite, meldet die Originalfunktion Erfolg
und kann ein nicht initialisiertes oberes Byte verwenden. Die aktive
IIO-Abfrage kann dadurch ebenfalls Erfolg melden und ihren Messwertcache ändern.

Die Reproduktion injiziert einen fehlgeschlagenen Zugriff mit bewusst
gesetztem Ausgabebyte. Damit wird die falsche Erfolgsmeldung deterministisch
nachgewiesen, ohne im Test selbst uninitialisierten Speicher auszuwerten.
Die korrigierte Fassung wird zusätzlich mit unverändertem Fehlerausgabebyte
geprüft, entsprechend dem tatsächlichen I²C-Zugriff.

## Begrenzte Korrektur

- Rückgabewert des ersten Zugriffs sofort prüfen und den Fehler zurückgeben.
- Ungültige Kanalnummern vor Registerberechnung mit `-EINVAL` ablehnen.
- Zweiten Zugriff und bestehende Fehlerweitergabe beibehalten.
- Ausgabewert bei Fehler nicht als gültigen neuen Messwert übernehmen.

Nur die ADC-Lesefunktion wird geändert. Skalierung, erfolgreiche Messwerte,
Ladepolitik, Temperaturgrenzen und Stromlimits bleiben unverändert.
Der tatsächlich verwendete `sc_iio_read_raw()`-Pfad reicht negative Fehler
bereits weiter und aktualisiert seinen Cache nur bei Erfolg. Er wird im Test
unverändert aus dem echten Treiber kompiliert. Der alternative alte
power_supply-Pfad für Kernel unter 5.4 gehört nicht zum Geltungsbereich.

## Nachweise und weiterer Schritt

`candidate.json` enthält exakte Quell-, Patch- und Test-Hashes.
`test_sc8551_adc.py` kompiliert die echten ADC- und IIO-Funktionen mit UBSan.
Die korrigierte Fassung besteht 1.599 Assertions: neun ADC-Kanäle, sieben
IIO-Abfragen, beide Chipvarianten, Fehler beim ersten und zweiten Zugriff,
drei Fehlercodes, veränderte/unveränderte Fehlerausgaben und Kanalgrenzen.
Die erfolgreiche Skalierung wird zusätzlich am Originalcode geprüft.

Nach Anwendung des Patches auf die exakte Quelle:

```sh
python3 common/diagnostics/charger-5.4.274-sc8551-adc/test_sc8551_adc.py /pfad/zur/kernelquelle/drivers/power/supply/qcom/sc8551_charger.c
```

Zur Reproduktion am unveränderten Original denselben Befehl mit `--baseline`
verwenden. Der Test lehnt unbekannte Treiber- und Headerstände ab.

Der nächste Schritt ist die Einbindung in einen isolierten Build auf Basis
des kumulativen Diag07-Standes mit Compile-, Paket-, DTB- und Static-Boot-Prüfung.
Host-Ergebnisse ersetzen diesen Build nicht. Wiederholte normale
Strommessungen können den gezielt simulierten I²C-Fehler nicht nachweisen.
Kein Testskript oder Kandidatenmaterial gehört in eine flashbare AK3.
