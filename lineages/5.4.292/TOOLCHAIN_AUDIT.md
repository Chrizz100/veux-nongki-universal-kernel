# VEUX 5.4.292 – Toolchain Audit

## Status

`TOOLCHAIN FAMILY IDENTIFIED / REPRODUCIBLE PIN CANDIDATE FOUND / COMPILE VALIDATION PENDING`

Dieser Status bedeutet:

- die historisch für diese VEUX-Lineage vorgesehene Clang-Familie ist identifiziert,
- eine reproduzierbar adressierbare AOSP-Quelle für dieselbe Clang-Revision ist gefunden,
- der Kernel wurde damit in unserem neuen Projekt noch nicht kompiliert.

Damit ist dies ausdrücklich noch kein `STATIC PASS`.

---

## 1. Gepinnte Kernelquelle

- Repository: `UEDestroyer/kernel_xiaomi_veux`
- Commit: `fb3bbb10bc0480282c01b88ccaf39c0145cd9f51`
- Kernel: `5.4.292`
- Defconfig: `veux_defconfig`

---

## 2. Historischer Toolchain-Hinweis aus derselben VEUX-Lineage

Die Historie von `build.sh` enthält den Commit:

```text
3a1fdbaf826c926b9bc421e585d9a39560fcda70
build.sh: Use Updated Script
```

Dieser Build-Script-Stand setzt ausdrücklich:

```text
COMPILER_PATH="$HOME/clang-r547379/bin"
```

und klont die Toolchain bei Bedarf aus:

```text
https://gitlab.com/crdroidandroid/android_prebuilts_clang_host_linux-x86_clang-r547379.git
```

mit Branch:

```text
15.0
```

Der Build selbst verwendet:

```text
ARCH=arm64
CC=clang
CLANG_TRIPLE=aarch64-linux-gnu-
CROSS_COMPILE=aarch64-linux-gnu-
CROSS_COMPILE_ARM32=arm-linux-gnueabi-
LD=ld.lld
LLVM=1
LLVM_IAS=1
```

### Bewertung

`clang-r547379` ist damit kein frei erfundener Compiler für unser Projekt, sondern besitzt einen direkten historischen Bezug zur konkreten VEUX-Quelllinie.

---

## 3. Frühere Inkonsistenz im Build-Script

Im Diff des historischen Build-Scripts ist erkennbar, dass ein älterer Stand für die sichtbare Compiler-Zeichenkette noch auf:

```text
clang-r510928
```

verwies, während der tatsächliche `PATH` bereits auf:

```text
clang-r547379
```

gesetzt wurde.

Der spätere Script-Stand beseitigte diese Inkonsistenz und ermittelt den Compilernamen direkt aus:

```text
$COMPILER_PATH/clang --version
```

### Konsequenz

Für unseren Audit gilt ausschließlich der tatsächlich verwendete Compilerpfad.

Eine alte `KBUILD_COMPILER_STRING`-Anzeige wird nicht als Toolchain-Pin gewertet.

---

## 4. Aktueller Source-Stand

Im derzeit gepinnten Commit `fb3bbb10...` enthält `build.sh` keinen Download und keinen exakten Toolchain-Pin mehr.

Es setzt nur die Buildparameter für einen bereits im `PATH` vorhandenen Clang.

Daher gilt:

```text
CURRENT_SOURCE_EXACT_TOOLCHAIN_COMMIT=NOT_PINNED
```

Der historische Hinweis auf `clang-r547379` bleibt aber erhalten.

---

## 5. Offizielle AOSP-Referenz für clang-r547379

AOSP enthält `clang-r547379` im Repository:

```text
platform/prebuilts/clang/host/linux-x86
```

Ein reproduzierbar adressierbarer Commit, der `clang-r547379/` enthält, ist:

```text
b2f65ea82667366e23657e4999751180e4030f5b
```

AOSP beschreibt diese Revision als:

```text
clang-r547379
LLVM 20.0.0
```

### Reproduzierbarer Kandidat

Für unser Projekt wird deshalb zunächst folgender Kandidat dokumentiert:

```text
TOOLCHAIN_FAMILY=clang-r547379
TOOLCHAIN_LLVM_VERSION=20.0.0
TOOLCHAIN_SOURCE=AOSP platform/prebuilts/clang/host/linux-x86
TOOLCHAIN_SOURCE_COMMIT=b2f65ea82667366e23657e4999751180e4030f5b
TOOLCHAIN_DIRECTORY=clang-r547379
```

---

## 6. Warum nicht einfach den crDroid-Branch pinnen?

Die historische VEUX-Lineage klonte den crDroid-Branch:

```text
15.0
```

Ein Branchname allein ist für unser Projekt kein ausreichender reproduzierbarer Pin.

Ohne einen bestätigten exakten Commit dieses Mirrors würde ein später veränderter Branch denselben Buildnamen mit anderem Inhalt liefern können.

Deshalb wird der crDroid-Verweis als **historische Herkunftsinformation** behandelt.

Für reproduzierbare Tests verwenden wir einen exakten Commit.

---

## 7. Verhältnis zur bisherigen P13-Toolchain

Die bisherige P13-/ältere GEN1-Arbeit verwendete eine ältere Android-Clang-Familie.

Dieser Stand wird nicht automatisch auf 5.4.292 übertragen.

Ebenso wird `clang-r547379` nicht allein deshalb als endgültig freigegeben, weil ein historisches VEUX-Script ihn verwendete.

Die neue 5.4.292-Lineage muss ihren eigenen Compile-Nachweis erbringen.

---

## 8. Geplanter erster Compile-Vertrag

Der erste kontrollierte 5.4.292-Build soll mit folgenden Grundwerten erfolgen:

```text
ARCH=arm64
DEFCONFIG=veux_defconfig

CC=clang
LD=ld.lld
LLVM=1
LLVM_IAS=1

CLANG_TRIPLE=aarch64-linux-gnu-
CROSS_COMPILE=aarch64-linux-gnu-
CROSS_COMPILE_ARM32=arm-linux-gnueabi-
```

Toolchain-Kandidat:

```text
clang-r547379
AOSP commit b2f65ea82667366e23657e4999751180e4030f5b
```

Vor einem vollständigen Kernel-Build werden mindestens geprüft:

1. `clang --version`
2. `ld.lld --version`
3. Toolchain-Verzeichnis und Commit-Pin
4. Source-Commit
5. native `make kernelversion`
6. Defconfig-Hash
7. unveränderte Kernelidentität

---

## 9. Noch keine endgültige Freigabe

Aktueller Status:

```text
TOOLCHAIN_FAMILY=clang-r547379
TOOLCHAIN_HISTORICAL_VEUX_EVIDENCE=YES
TOOLCHAIN_REPRODUCIBLE_AOSP_SOURCE=YES
TOOLCHAIN_REPRODUCIBLE_PIN_CANDIDATE=YES

TOOLCHAIN_COMPILE_TEST=NOT_RUN
TOOLCHAIN_BUILD_PASS=NO
TOOLCHAIN_FINAL_APPROVAL=PENDING
```

Der Kandidat wird erst nach einem reproduzierbaren nativen 5.4.292-Compile als endgültiger Toolchain-Pin übernommen.

---

## 10. Nächster Schritt

Vor ReSukiSU/SUSFS wird zunächst ein **native 5.4.292 baseline build** vorgesehen.

Dieser Baseline-Build verändert die Kernelquelle nicht.

Ziel:

```text
5.4.292 original source
+ veux_defconfig
+ clang-r547379 candidate
= native compile baseline
```

Erst wenn diese Baseline reproduzierbar funktioniert, beginnt die ReSukiSU-/SUSFS-Integration.

Damit lässt sich später eindeutig unterscheiden zwischen:

- Fehler der Originalquelle,
- Toolchain-Fehler,
- ReSukiSU-Integrationsfehler,
- SUSFS-Portfehler,
- Packaging-Fehler.
