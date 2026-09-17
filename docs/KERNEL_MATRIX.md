# Kernel-Matrix

Stand: 17.09.2026

## Zielmatrix

| Kernel | Quellrolle | Aktueller Status | Nächster Schritt |
|---|---|---|---|
| 5.4.259 | echte VEUX/SM6375-Basis | PORT_REQUIRED | nach 5.4.268 analysieren |
| 5.4.268 | echte VEUX/SM6375-Basis | PORT_REQUIRED | nach 5.4.290 analysieren |
| 5.4.274 | P13-Referenz | DEVICE PASS | immutable Referenz |
| 5.4.290 | echte VEUX-Basis | PORT_REQUIRED | nach 5.4.292 analysieren |
| 5.4.292 | echte VEUX-Basis | PORT_REQUIRED | **aktuelle nächste Portlinie** |
| 5.4.300 | offizieller Linux-stable-Port aus P13 | STATIC BOOT PATH PASS | Gerätetest später |
| 5.4.302 | offizieller Linux-stable-Port aus P13 | STATIC BOOT PATH PASS | Gerätetest später |
| 5.4.275 | unvollständige Quellbasis | DEFERRED | Quelle ersetzen/reparieren |

## Nicht mehr in der aktiven Matrix

### 5.4.191

Aus dem aktiven Audit entfernt, weil diese Basis für das aktuelle Ziel zu selten und im Verhältnis zum Aufwand zu wenig relevant ist.

## Verifizierte Quellpins der älteren Multibase-Audits

### 5.4.259

- Repository: `TTTT55/kernel_xiaomi_sm6375`
- Branch: `old`
- Commit: `9d3f1c9fe21bf67186fe5813d5796ac2c9f6bb59`
- Defconfig: `veux_defconfig`

### 5.4.268

- Repository: `PixelExperience-Devices/kernel_xiaomi_sm6375`
- Branch: `fourteen`
- Commit: `889296971b88453d7ca9a1dd668a2381a7f4e9b7`
- Defconfig: `veux_defconfig`

### 5.4.290

- Repository: `AOSPA-SM6375/kernel_xiaomi_veux`
- Branch: `14`
- Commit: `a9fa7c8d1db5c8161922714cf69e53ef2d359745`
- Defconfig: `veux_defconfig`

### 5.4.292

- Repository: `UEDestroyer/kernel_xiaomi_veux`
- Branch: `main`
- Commit: `fb3bbb10bc0480282c01b88ccaf39c0145cd9f51`
- Defconfig: `veux_defconfig`

## P13-Referenz

Linux `5.4.274` bleibt die stabile Geräte-Referenz.

Bekannter Referenzstand:

- Kernel: `5.4.274-qgki-g82179e362f33`
- ReSukiSU: `7741f87849f7ad7cebf82bbb4c5b89880e61e37e`
- sichtbare Identität: `v4.2.0-rc1-7741f878-p13@ReSukiSU`
- KSU/ReSukiSU: `35141`
- UAPI: `4`
- SUSFS: `2.3.0`
- `module_load_filter`: ausgeschlossen
- Status: `DEVICE PASS`

P13 wird nicht als vermeintlich universelles Image für andere Kernelstände verwendet.

## 5.4.300 / 5.4.302

Diese Linien folgen einem anderen Portmodell als die externen VEUX-Basen:

- BASE = offizielles Linux-stable `v5.4.274`
- OURS = P13 VEUX 5.4.274
- THEIRS = offizielles Linux-stable `v5.4.300` bzw. `v5.4.302`

Semantische 3-Wege-Portierung statt Versionsänderung.

Beide Linien besitzen bereits einen statischen Boot-Pfad-PASS, aber noch keinen DEVICE PASS.

## 5.4.275 Sonderfall

Die bislang geprüfte 5.4.275-Quelle enthält eine Kconfig-Referenz auf `drivers/kernelsu/Kconfig`, während die referenzierte Datei im gepinnten Stand fehlt.

Damit ist bereits der native Ausgangszustand inkonsistent. Diese Basis wird nicht künstlich „grün repariert“, bevor eine vollständige Originalquelle feststeht.
