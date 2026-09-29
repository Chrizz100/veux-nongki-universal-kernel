# Dauerhafte Geräte-Fixes

Der reguläre **VEUX All-in-One Updater V4** verwendet
`common/scripts/veux_release_device.py`. Dieser Einstieg übernimmt die
bewährten Integrations-, Build-, AK3- und Static-Boot-Prüfungen der bisherigen
Engine und ergänzt die gerätespezifischen Patches vor dem Kompilieren.

## 5.4.274

`5.4.274/charger-diag04/` enthält exakt die kumulativen Treiber-Patches aus
dem erfolgreichen Lauf **36502307601**:

- BQ2589x: HiZ-Puls entfernt, VINDPM-Erholung bei 5 V, I²C-Fehlerweitergabe,
  geordnetes Beenden von IRQ/Work/IIO und geprüfte Speicherallokation.
- wt_chg: USB-Spannung aus dem tatsächlich verwendeten Charge-Pump-Kanal,
  korrekte Umrechnung von mV nach µV und definierte Fehlerweitergabe.

Das Gerät hat mit diesem Diagnose-Build laut Rückmeldung normal geladen,
einschließlich Laden im ausgeschalteten Zustand. Diese Rückmeldung gilt
für diesen Build und wird nicht automatisch auf neue Builds übertragen.

Die Patches werden sowohl beim Wiederverwenden der gespeicherten Integration
als auch bei neuen ReSukiSU-/SUSFS-/NoMount-Ständen angewendet. SHA-256-Prüfungen
blockieren abweichende Treiber oder Patchdateien. Bereits exakt gepatchte
Dateien sind zulässig. Die tatsächlichen C-Funktionen werden vor dem Build
mit den übernommenen 76 BQ- und 117 USB-Prüfungen getestet.

`RESULT.json` enthält den Nachweis unter `device_fixes`. Die Übernahme nach
`CURRENT_BUILD.json` verlangt diesen Nachweis zusätzlich zu den bisherigen
sechs Compile-/Package-/Static-Boot-Ergebnissen. Ein älteres grünes Ergebnis
ohne die Patches ist dafür nicht ausreichend. Der bisherige Build-Nachweis
wird erst durch einen tatsächlich erfolgreichen neuen Lauf ersetzt.

Dieser Ordner liegt außerhalb von `common/update/current/`, das bei einer
Upstream-Übernahme ersetzt wird. Andere Kernelversionen erhalten diese
5.4.274-Patches nicht. Historische Diagnose-Workflows und deren hashgebundene
Engine bleiben unverändert.

Die AK3-ZIPs enthalten weiterhin nur Installationsdateien, Kernel und Lizenz.
Nachweise und Prüflogs werden außerhalb der flashbaren ZIPs gespeichert.

## Validierung der Integration

- 43 lokale Python-Tests für Engine, Release, Diagnose und Geräte-Fixes.
- Originaltreiber mit beiden echten Patches: erwartete End-Hashes sowie
  76 BQ- und 117 USB-Prüfungen bestanden.
- V4 mit actionlint geprüft.
- Ein vollständiger neuer Kernel-Build ist nach dieser Integration noch
  erforderlich; lokale Tests sind kein Geräte- oder Bootnachweis.
