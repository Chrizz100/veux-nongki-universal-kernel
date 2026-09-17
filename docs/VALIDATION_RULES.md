# Validierungsregeln

## 1. Statusbegriffe strikt trennen

Folgende Begriffe sind nicht austauschbar:

### STATIC PASS

Quellcode-/Patch-/Konfigurationsprüfung ohne realen Boot auf dem Zielgerät.

### PACKAGE PASS

Das erzeugte Paket ist strukturell vollständig und intern konsistent.

### STATIC BOOT PATH PASS

Der Kernel erfüllt definierte Boot-v3-/ARM64-/Ramdisk-/AVB-/Handoff-Verträge in einer statischen Repack-/Extraktionsprüfung.

### DEVICE PASS

Nur ein realer, bestätigter Boot und Funktionstest auf dem tatsächlichen VEUX-Gerät.

**STATIC PASS, PACKAGE PASS oder STATIC BOOT PATH PASS dürfen niemals als DEVICE PASS bezeichnet werden.**

## 2. Echte Kernelidentität

Verboten:

- künstliches Ändern von `VERSION`, `PATCHLEVEL` oder `SUBLEVEL`, um Kompatibilität vorzutäuschen,
- Localversion-Spoofing als Ersatz für eine echte Portierung,
- ein 5.4.274-Image als 5.4.292/300/302 auszugeben.

Jede Lineage muss tatsächlich aus ihrer jeweiligen Quellbasis entstehen.

## 3. Exakte Source-Pins

Jeder reproduzierbare Audit-/Buildstand muss mindestens festhalten:

- Repository,
- Branch oder Tag,
- exakten Commit-SHA,
- Defconfig,
- Toolchain-Pin,
- ReSukiSU-Pin,
- SUSFS-Stand,
- angewendete Zusatzpatches.

„Latest“ ist kein reproduzierbarer Pin.

## 4. Fail-Closed statt `|| true`

Kritische Patches dürfen nicht still fehlschlagen.

Nicht zulässig für Produktions-/Masterpfade:

```sh
patch -p1 < patchfile.patch || true
```

Stattdessen:

- Patch anwenden,
- Exitcode prüfen,
- `.rej`/`.orig` prüfen,
- erwartete Symbole/Hooks prüfen,
- bei Abweichung abbrechen.

## 5. Semantik vor Patch-Kontext

Ein Patch gilt nicht als korrekt, nur weil er ohne Reject angewendet wurde.

Zusätzlich wird geprüft:

- richtige Funktion,
- richtige Kontrollflussposition,
- korrekte Fehlerpfade,
- korrekte Lock-/Refcount-Semantik,
- keine doppelten Hooks,
- keine bereits vorhandene alternative Implementation.

## 6. P13 bleibt Referenz

P13 (`5.4.274`) ist die immutable DEVICE-PASS-Referenz.

Neue Portierungen dürfen P13 nicht still verändern oder überschreiben.

Vergleiche gegen P13 müssen klar zwischen:

- gemeinsamem Funktionsvertrag,
- versionsbedingter Abweichung,
- VEUX-spezifischer Abweichung

unterscheiden.

## 7. ReSukiSU / SUSFS

Aktueller Referenzvertrag:

- ReSukiSU UAPI 4
- SUSFS 2.3
- `module_load_filter` ausgeschlossen

Vor jeder Integration wird geprüft, ob die Zielquelle bereits KernelSU-/SUSFS-Code enthält.

Doppelte oder konkurrierende Integrationen sind Fehler.

## 8. AnyKernel3

Packaging darf die fachliche Gerätekompatibilität nicht künstlich verbreitern.

Für VEUX gilt:

- Device-Check nicht bewusst deaktivieren,
- kein generisches „flash anywhere“-Paket,
- Boot-Ziel eindeutig,
- Kernelpayload muss exakt dem auditierten Build entsprechen.

## 9. Boot-v3-Vertrag

Für die bekannte VEUX-HyperOS-/Android-13-Referenz wird beim statischen Boot-Pfad-Audit insbesondere geprüft:

- ARM64-Header plausibel,
- Boot Header v3,
- nur Kernelpayload ersetzen,
- Stock-Ramdisk byte-identisch erhalten,
- Alignment/Padding korrekt,
- eingebetteten AVB-Hashdescriptor korrekt regenerieren,
- `vendor_boot`, `dtbo` und top-level `vbmeta` unverändert lassen,
- Kernel und Ramdisk nach Repack erneut extrahieren und Hashes vergleichen.

Ein solcher Test bleibt trotzdem ein statischer Test.

## 10. Keine Workflow-YAML vor verifiziertem Inhalt

Neue oder angepasste GitHub-Actions-Workflows werden erst erstellt, wenn die zugrunde liegende Port-/Buildlogik bereits nachvollziehbar und reproduzierbar validiert wurde.

Die CI automatisiert einen bekannten Prozess. Sie ersetzt nicht die fachliche Verifikation.

## 11. Artefakte und Hashes

Für relevante Builds/Audits werden festgehalten:

- Dateiname,
- Dateigröße,
- SHA-256,
- Kernelrelease,
- Build-/Auditstatus,
- Source-Pins,
- Geräteteststatus.

## 12. Freigaberegel

Ein Kernel wird erst als testbares Flash-Artefakt behandelt, wenn mindestens Compile-, Package- und die vorgesehenen statischen Konsistenzprüfungen erfolgreich sind.

`DEVICE PASS` folgt ausschließlich nach echtem Gerätetest.
