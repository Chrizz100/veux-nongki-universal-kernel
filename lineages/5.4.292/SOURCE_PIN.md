# VEUX 5.4.292 – Source Pin

## Status

`SOURCE IDENTIFIED / PIN VERIFIED`

Dieser Status bedeutet nur:

- Repository erreichbar,
- Commit vorhanden,
- native Kernelversion aus dem gepinnten Makefile bestätigt,
- VEUX-Defconfig vorhanden.

Er bedeutet ausdrücklich noch nicht:

- ReSukiSU integriert,
- SUSFS integriert,
- Port begonnen,
- Compile PASS,
- PACKAGE PASS,
- STATIC BOOT PATH PASS,
- DEVICE PASS.

---

## Quellbasis

- Repository: `UEDestroyer/kernel_xiaomi_veux`
- Branch: `main`
- Commit: `fb3bbb10bc0480282c01b88ccaf39c0145cd9f51`
- Commit-Titel: `change README`
- Kernelbasis: `5.4.292`
- Architektur: `arm64`
- Defconfig: `arch/arm64/configs/veux_defconfig`

Der Commit selbst existiert und ist im Repository erreichbar.

---

## Native Kernelidentität

Der gepinnte Makefile enthält:

```text
VERSION = 5
PATCHLEVEL = 4
SUBLEVEL = 292
EXTRAVERSION =
NAME = Kleptomaniac Octopus
```

Damit ist die native Quellidentität dieser Basis:

```text
5.4.292
```

Für diese Lineage ist kein Versionsspoofing erforderlich oder zulässig.

---

## VEUX-Defconfig

Vorhandene Defconfig:

```text
arch/arm64/configs/veux_defconfig
```

Der Dateianfang enthält unter anderem:

```text
CONFIG_LOCALVERSION="-qgki"
CONFIG_NO_HZ=y
CONFIG_HZ_250=y
CONFIG_HIGH_RES_TIMERS=y
CONFIG_PREEMPT=y
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
```

Git-Blob-SHA der aktuell geprüften Defconfig:

```text
9cf92a129311045314d2d15b749c7ee378990cc2
```

Dieser Git-Blob-SHA ist **nicht** mit einem SHA-256-Dateihash gleichzusetzen.

Ein reproduzierbarer SHA-256 der vollständigen Defconfig wird beim ersten lokalen/CI-Source-Audit erzeugt.

---

## Makefile-Pin

Git-Blob-SHA des geprüften Makefiles:

```text
7159b6298ce1b25c800148c8fc7a320431710f6f
```

Auch dies ist ein Git-Blob-SHA und kein SHA-256.

---

## Herkunftshinweis

Der gepinnte Commit beschreibt das Repository als Fork von:

```text
Evolution-X-Devices/kernel_xiaomi_veux
```

Im README des Forks werden zusätzliche Änderungen wie weitere DRM-Layer-Unterstützung und zusätzliche Logs genannt.

Daraus folgt:

Diese Quelle wird für unser Projekt als konkrete reale VEUX-5.4.292-Lineage behandelt.

Sie wird **nicht** automatisch als unveränderte Evolution-X-Originalquelle betrachtet.

---

## Noch nicht festgelegt

Folgende Pins werden bewusst erst nach ihrer eigenen Prüfung ergänzt:

- Toolchain-Pin
- ReSukiSU-Pin für diese Lineage
- SUSFS-Pin für diese Lineage
- zusätzliche Lineage-Patches
- AnyKernel3-Pin
- DTB/DTBO-Buildvertrag dieser Lineage

Bis diese Punkte verifiziert sind, werden keine Werte geraten oder aus anderen Lineages übernommen.

---

## Nächster Audit-Schritt

Bevor irgendein Portpatch erstellt wird:

1. exakten Source-Pin lokal/CI reproduzieren,
2. `make kernelversion` gegen `5.4.292` prüfen,
3. vollständigen SHA-256 der `veux_defconfig` erfassen,
4. vorhandene KernelSU-/SUSFS-Reste mit dem Common-Audit prüfen,
5. bestehende Kconfig-/Makefile-Hooks klassifizieren,
6. erst danach entscheiden, was aus dem Common-5.4-Layer wiederverwendbar ist.

---

## Statusdisziplin

Aktueller Stand:

```text
SOURCE_PIN=VERIFIED
NATIVE_KERNEL_VERSION=5.4.292
VEUX_DEFCONFIG=PRESENT
RESUKISU_INTEGRATION=NOT_AUDITED
SUSFS_INTEGRATION=NOT_AUDITED
COMPILE=NOT_RUN
PACKAGE=NOT_RUN
STATIC_BOOT_PATH=NOT_RUN
DEVICE_PASS=NO
```
