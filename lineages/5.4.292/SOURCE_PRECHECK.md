# VEUX 5.4.292 – Source Precheck Audit

## Auditstatus

`REMOTE SOURCE PRECHECK = PASS WITH FINDINGS`

Dieser Audit wurde gegen die exakt gepinnte Quelle durchgeführt:

- Repository: `UEDestroyer/kernel_xiaomi_veux`
- Commit: `fb3bbb10bc0480282c01b88ccaf39c0145cd9f51`
- Kernelbasis: `5.4.292`

Der Status ist bewusst **kein STATIC PASS und kein Build-PASS**.

Er bedeutet nur, dass die Quellstruktur remote geprüft und erste Integrations-/Packaging-Risiken klassifiziert wurden.

---

## 1. KernelSU / ReSukiSU / SUSFS

Im gepinnten Source-Tree wurden keine der typischen vorintegrierten KernelSU-Verzeichnisse gefunden:

```text
KernelSU/
drivers/kernelsu/
kernel/kernelsu/
```

Ebenso wurden im geprüften `drivers/Kconfig` keine KernelSU-Kconfig-Einbindungen gefunden.

Im geprüften `drivers/Makefile` wurden keine `CONFIG_KSU`-/KernelSU-Objekte gefunden.

Die Repository-Code-Suche lieferte keine Treffer für:

```text
CONFIG_KSU
SUSFS
kernelsu
```

### Bewertung

Aktueller Remote-Befund:

```text
PREEXISTING_KSU_INTEGRATION=NOT_DETECTED
PREEXISTING_SUSFS_INTEGRATION=NOT_DETECTED
KSU_KCONFIG_REFERENCE=NOT_DETECTED
KSU_DRIVER_MAKE_REFERENCE=NOT_DETECTED
```

Das ist ein guter Ausgangspunkt für eine kontrollierte Integration.

Es ersetzt noch nicht den späteren vollständigen lokalen Lauf von:

```text
common/scripts/audit_existing_integration.sh --expect-clean
```

---

## 2. Vorhandenes AnyKernel3

Die 5.4.292-Quelle enthält bereits:

```text
AnyKernel3/
```

Die enthaltene `anykernel.sh` konfiguriert:

```text
do.devicecheck=1
device.name1=veux
device.name2=peux
```

Der Device-Check ist damit grundsätzlich enger als ein generisches `flash anywhere`.

### Kritischer Unterschied zu unserem VEUX-Vertrag

Das vorhandene Script bearbeitet nicht nur `boot`.

Es führt zusätzlich einen eigenen `vendor_boot`-Pfad aus:

```text
block=vendor_boot
split_boot
override_cmdline
flash_boot
```

Dabei wird außerdem die Kernel-/Vendor-cmdline überschrieben.

Unser derzeitiger bekannter VEUX-Boot-v3-Vertrag sieht für die geprüfte Android-13-/HyperOS-Referenz dagegen vor:

```text
vendor_boot = unverändert
dtbo        = unverändert
vbmeta      = unverändert
```

### Entscheidung

```text
UPSTREAM_ANYKERNEL3_REUSE_AS_IS=NO
```

Das vorhandene AnyKernel3 wird nur als Quellreferenz betrachtet.

Unser späteres Packaging erhält einen eigenen VEUX-Vertrag unter:

```text
packaging/anykernel3/
```

---

## 3. Build-Script der 5.4.292-Quelle

Die Quelle enthält ein `build.sh`.

Der Build-Aufruf verwendet:

```text
ARCH=arm64
CC=clang
LD=ld.lld
LLVM=1
LLVM_IAS=1
CLANG_TRIPLE=aarch64-linux-android-
CROSS_COMPILE=aarch64-linux-android-
CROSS_COMPILE_ARM32=arm-linux-gnueabi-
DTC_FLAGS=-f
```

Der eigentliche Build wird mit `$1` als zusätzlichem Make-Argument ausgeführt.

Danach wird:

```text
veux.dtb
```

nach:

```text
veux_no.dtb
```

kopiert.

---

## 4. Toolchain-Befund

In der bisher geprüften Quelle ist kein reproduzierbarer Clang-Release-Pin dokumentiert.

Der vorhandene GitHub-Workflow installiert Build-Abhängigkeiten und führt anschließend nur:

```text
sh build.sh
```

aus.

Es wurde kein belastbarer `clang-rXXXXXX`-Pin aus dieser Quellbasis bestätigt.

### Entscheidung

```text
TOOLCHAIN_PIN=UNRESOLVED
```

Wir übernehmen für 5.4.292 nicht automatisch einen Toolchain-Pin aus einer anderen Lineage.

Der Toolchain-Pin wird separat geprüft.

---

## 5. Source-CI

Die Quelle enthält einen älteren GitHub-Actions-Workflow.

Er verwendet unter anderem:

```text
actions/checkout@v2
actions/setup-node@v1
node-version: 12
```

Dieser Workflow ist für unser neues Buildsystem keine Vorlage.

Wir übernehmen nur technisch relevante Quellinformationen.

Unsere spätere CI folgt ausschließlich dem bereits definierten fail-closed-Vertrag.

---

## 6. Defconfig und native Identität

Bereits separat bestätigt:

```text
VERSION=5
PATCHLEVEL=4
SUBLEVEL=292
CONFIG_LOCALVERSION="-qgki"
```

Damit gilt weiterhin:

```text
NATIVE_KERNEL_VERSION=5.4.292
VERSION_SPOOFING=NO
```

---

## 7. Ergebnis

Aktueller 5.4.292-Stand:

```text
SOURCE_PIN=VERIFIED
REMOTE_SOURCE_PRECHECK=PASS
NATIVE_KERNEL_VERSION=5.4.292
VEUX_DEFCONFIG=PRESENT

PREEXISTING_KSU_INTEGRATION=NOT_DETECTED
PREEXISTING_SUSFS_INTEGRATION=NOT_DETECTED

UPSTREAM_ANYKERNEL3=PRESENT
UPSTREAM_ANYKERNEL3_REUSE_AS_IS=NO

UPSTREAM_BUILD_SCRIPT=PRESENT
TOOLCHAIN_PIN=UNRESOLVED

RESUKISU_INTEGRATION=NOT_STARTED
SUSFS_INTEGRATION=NOT_STARTED
LINEAGE_PATCHES=NONE
COMPILE=NOT_RUN
PACKAGE=NOT_RUN
STATIC_BOOT_PATH=NOT_RUN
DEVICE_PASS=NO
```

---

## 8. Nächster Schritt

Als Nächstes wird der **5.4.292-Toolchain-Vertrag** ermittelt.

Dabei werden getrennt geprüft:

1. Hinweise aus der konkreten 5.4.292-Quellhistorie,
2. Android-/Vendor-Kompatibilität,
3. bereits auf VEUX erfolgreich verwendete Compilerstände,
4. reproduzierbare exakte Toolchain-Pins.

Erst nach dieser Prüfung wird eine Toolchain für 5.4.292 festgelegt.

Danach folgt die ReSukiSU-/SUSFS-Integrationsanalyse.
