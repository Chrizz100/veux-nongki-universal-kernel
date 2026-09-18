# VEUX Device Contract

## 1. Zweck

Dieser Vertrag definiert ausschließlich gerätespezifische Regeln für Xiaomi/POCO `veux` auf Qualcomm SM6375.

Er ist unabhängig von einer konkreten Linux-5.4-Lineage.

Der VEUX-Layer entscheidet nicht, wie ReSukiSU oder SUSFS semantisch in eine bestimmte Kernelversion portiert werden. Das gehört in `common/` und `lineages/<version>/`.

Dieser Vertrag beschreibt stattdessen, welche Bedingungen ein Kernel erfüllen muss, damit er als VEUX-Kandidat weiter geprüft werden darf.

---

## 2. Zielgerät

- Codename: `veux`
- Plattform: Qualcomm SM6375
- Kernel-Familie: Linux 5.4 Non-GKI
- Primärer Zielbereich: Android-13-kompatible VEUX/SM6375-Vendorbasen
- Architektur: ARM64
- Packaging-Ziel: AnyKernel3
- Referenz-Defconfig: `veux_defconfig`

Ein Build für eine andere Gerätefamilie darf nicht allein durch eine geänderte Gerätekennung als VEUX-kompatibel behandelt werden.

---

## 3. Defconfig-Vertrag

Eine Lineage muss ihre eigene echte VEUX-Defconfig verwenden.

Vor jedem Build wird mindestens geprüft:

1. `arch/arm64/configs/veux_defconfig` existiert.
2. Die Defconfig gehört zur gepinnten Quellbasis.
3. Ihr SHA-256 wird vor Änderungen protokolliert.
4. Common- und Lineage-Änderungen dürfen die Kernelidentität nicht unbeabsichtigt verändern.
5. Zusätzliche Konfigurationswerte werden nachvollziehbar und getrennt dokumentiert.

Eine Defconfig aus einer anderen Kernel-Lineage darf nicht ungeprüft kopiert werden.

Qualcomm-, HOLI- und SM6375-Abhängigkeiten werden aus der jeweiligen echten VEUX-Quelle übernommen und nicht aus einer generischen Linux-5.4-Konfiguration erfunden.

---

## 4. Kernelidentität

Jede Lineage behält ihre reale Kernelversion.

Verboten:

- `VERSION`, `PATCHLEVEL` oder `SUBLEVEL` künstlich ändern,
- `LOCALVERSION` als Ersatz für eine echte Portierung benutzen,
- einen 5.4.274-Kernel als 5.4.290/292/300/302 ausgeben,
- eine fremde Geräte-Lineage durch reine Namensänderung zu VEUX erklären.

Erlaubt ist nur eine zusätzliche nachvollziehbare Build-Kennung, sofern die echte Kernelbasis weiterhin eindeutig erkennbar bleibt.

---

## 5. P13-Gerätereferenz

Die aktuelle bekannte VEUX-Gerätereferenz ist P13.

Referenzstand:

- Kernel: `5.4.274-qgki-g82179e362f33`
- ReSukiSU commit: `7741f87849f7ad7cebf82bbb4c5b89880e61e37e`
- sichtbare ReSukiSU-Identität: `v4.2.0-rc1-7741f878-p13@ReSukiSU`
- KSU/ReSukiSU: `35141`
- UAPI: `4`
- SUSFS: `2.3.0`
- `module_load_filter`: ausgeschlossen
- Status: `DEVICE PASS`

P13 bleibt immutable.

P13 ist eine reale Funktions- und Gerätekompatibilitätsreferenz, aber kein Universalimage und kein Beweis dafür, dass identische Source-Hunks auf jeder anderen 5.4-Lineage korrekt sind.

---

## 6. Boot-v3-Vertrag

Für die bekannte Android-13-/HyperOS-VEUX-Basis gilt beim Boot-Image-Repack:

1. Boot Header v3 beibehalten.
2. Nur den Kernelpayload ersetzen.
3. Die Stock-Ramdisk byte-identisch erhalten.
4. Headerdaten außerhalb des Kernelpayloads nicht unnötig verändern.
5. Alignment und Padding korrekt erhalten.
6. Den eingebetteten AVB-Hashdescriptor beziehungsweise Footer passend zum neuen Kernelpayload regenerieren.
7. Nach dem Repack Kernel und Ramdisk erneut extrahieren.
8. Den extrahierten Kernel gegen das tatsächlich auditierte Build-Image prüfen.
9. Die extrahierte Ramdisk gegen die Stock-Ramdisk hashen und Byte-Gleichheit verlangen.

Ein statisch korrektes Repack ist nur `STATIC BOOT PATH PASS`, nicht `DEVICE PASS`.

---

## 7. Stock-Referenz für statische Boot-Prüfungen

Bekannte Referenz:

- ROM: `OS1.0.12.0.TKCMIXM`
- Android: 13
- Region: Global
- Stock boot SHA-256:
  `ac6522e4eed55782dd2ae61362e9d345d01a1f229c87333818511d5537fa79c5`
- Stock vendor_boot SHA-256:
  `583e1f4c0e09c2267cda88bd48a8b4f56cf5c5e034fbda7b25bd65aa86385425`
- Stock dtbo SHA-256:
  `e9f3bae2c5417ff297162f1e7d2652ee98b347488fdf091d61daa986fbfb7690`
- Stock vbmeta SHA-256:
  `62a5b1a94c2247c786e8148b9d9d0aea943b57b1034b3fd82d9cac9a85fcde97`
- Stock Ramdisk SHA-256:
  `0bc8b54373b5501818e8b252517419786db207771047b6def7ec9bc89beb607a`

Diese Hashes gelten nur für diese konkrete Referenzbasis.

Eine andere ROM-/Regional-/Vendor-Basis muss separat gepinnt und geprüft werden.

---

## 8. Unveränderte Begleitpartitionen

Beim bekannten Boot-v3-Pfad werden standardmäßig nicht verändert:

- `vendor_boot`
- `dtbo`
- top-level `vbmeta`

Falls eine zukünftige Lineage eine Änderung an einem dieser Bestandteile tatsächlich benötigt, ist dies kein normaler Common-Build mehr.

Dann wird dafür ein eigener VEUX-spezifischer Audit mit Begründung, Ausgangshash und Zielhash benötigt.

---

## 9. AnyKernel3-Vertrag

AnyKernel3 dient nur zum Verpacken eines bereits validierten VEUX-Kernelpayloads.

Regeln:

- Geräteprüfung für VEUX nicht absichtlich deaktivieren.
- Kein generisches `flash anywhere`.
- Keine automatische Erweiterung auf nicht geprüfte Geräte.
- Kernelpayload im Paket muss byte-identisch zum auditierten Build-Image sein.
- Paketinhalt und SHA-256 werden protokolliert.
- Ein erfolgreich erzeugtes ZIP ist nur `PACKAGE PASS`.

Packaging darf eine fehlende Source- oder Gerätekompatibilität nicht kaschieren.

---

## 10. Device Tree / DTBO

Device-Tree- und DTBO-Verhalten bleibt an die jeweilige echte VEUX-Quellbasis gebunden.

Regeln:

- keine fremden DTBs ungeprüft übernehmen,
- keine DTBO-Änderung nur deshalb vornehmen, weil ein anderes SM6375-Gerät sie benötigt,
- erzeugte DTB-/DTBO-Artefakte müssen zur verwendeten Lineage gehören,
- bestehende Stock-DTBO kann nur dann unverändert bleiben, wenn die jeweilige Kernel-Lineage diesen Vertrag nachweislich erfüllt.

---

## 11. Geräteprüfung vor Freigabe

Vor einem ersten Flash-Kandidaten müssen mindestens erfolgreich sein:

1. Source-Pin-Prüfung,
2. Native-Kernelversion-Prüfung,
3. Defconfig-Prüfung,
4. bestehende KernelSU-/SUSFS-Integration geprüft,
5. Common-/Lineage-Patches fail-closed angewendet,
6. Compile erfolgreich,
7. erzeugtes Kernelimage validiert,
8. Kernelrelease geprüft,
9. Package-Prüfung erfolgreich,
10. statischer Boot-Pfad-Vertrag erfolgreich.

Erst danach darf ein Artefakt als Gerätetest-Kandidat bezeichnet werden.

---

## 12. DEVICE PASS

`DEVICE PASS` darf ausschließlich nach einem echten VEUX-Gerätetest vergeben werden.

Mindestens zu bestätigen:

- Gerät bootet vollständig,
- Android erreicht den normalen Betriebszustand,
- Kernelrelease entspricht dem erwarteten Build,
- ReSukiSU startet wie vorgesehen,
- erwartete UAPI-Version stimmt,
- SUSFS-Funktionalität ist vorhanden,
- kein unmittelbar erkennbarer Regressionsfehler im normalen Gerätebetrieb.

Ein Compile-, Package-, Repack-, QEMU- oder anderer statischer Test darf niemals automatisch zu `DEVICE PASS` hochgestuft werden.

---

## 13. Leitregel

Der VEUX-Layer soll Gerätekompatibilität **enger und überprüfbarer** machen, nicht künstlich verbreitern.

Common-Code beantwortet:

> Was ist zwischen mehreren Linux-5.4-Lineages gemeinsam?

Der Lineage-Layer beantwortet:

> Was unterscheidet diese konkrete Kernelbasis?

Der VEUX-Layer beantwortet:

> Was muss unabhängig davon auf unserem tatsächlichen `veux` eingehalten werden?
