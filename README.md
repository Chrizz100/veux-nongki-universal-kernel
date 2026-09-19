# VEUX ReSukiSU + SUSFS Kernel Builds

Custom 5.4 kernel builds for **Xiaomi / POCO `veux` (SM6375)** with **ReSukiSU**, **SUSFS** and **AnyKernel3** packaging.

## Supported platform

The currently validated target platform is:

* **Device:** Xiaomi / POCO `veux` (SM6375)
* **Android:** **Android 13**
* **ROM / vendor base:** **Xiaomi / POCO stock ROM / stock vendor**
* **ReSukiSU:** **35157** / `3d1185d8`
* **UAPI:** **4**
* **SUSFS:** **2.3.0**
* **Module-load-filter:** excluded

> \\\*\\\*Important:\\\*\\\* These kernels are validated for the Android 13 stock-vendor environment used by this project.
> Android 11, Android 12 and Android 14 are currently \\\*\\\*untested and unsupported\\\*\\\* unless a build is explicitly validated for that platform.

## Stock kernel vs. stock-vendor compatibility

These builds must not all be described as Xiaomi stock kernels.

* **5.4.274** is the lineage closest to the original VEUX vendor-kernel base used by this project.
* **5.4.292, 5.4.293, 5.4.300 and 5.4.302** are newer VEUX-compatible Linux 5.4 lineages / stable ports.
* The newer kernel versions were **not released by Xiaomi as official VEUX stock kernels**.
* They are built and validated to remain compatible with the **VEUX Android 13 stock ROM / stock vendor environment**.

Kernel version alone is therefore not a compatibility guarantee.

## Available builds

|Kernel|ReSukiSU|UAPI|SUSFS|Target|Validation|
|-|-|-:|-:|-|-|
|**5.4.274**|35157 / `3d1185d8`|4|2.3.0|A13 stock vendor|**DEVICE PASS**|
|**5.4.292**|35157 / `3d1185d8`|4|2.3.0|A13 stock vendor|**STATIC BOOT PASS**|
|**5.4.293**|35157 / `3d1185d8`|4|2.3.0|A13 stock vendor|**STATIC BOOT PASS**|
|**5.4.300**|35157 / `3d1185d8`|4|2.3.0|A13 stock vendor|**STATIC BOOT PASS**|
|**5.4.302**|35157 / `3d1185d8`|4|2.3.0|A13 stock vendor|**STATIC BOOT PASS**|

## Validation status

### 5.4.274 

This build has been tested on real VEUX hardware and passed:

* Build
* Packaging
* Static boot-image validation
* Flash
* Device boot
* ReSukiSU Built-in
* Kernel driver version 35157 / UAPI 4
* Root runtime
* SUSFS 2.3.0 runtime
* Session-keyring runtime
* SELinux enforcing

This is currently the **real-device validated reference build**.

### 5.4.292 / 5.4.293 / 5.4.300 / 5.4.302

These builds passed:

* Build
* Packaging
* Static Android Boot v3 validation
* Ramdisk-preservation validation
* AVB hash-descriptor recalculation / verification
* ReSukiSU 35157 integration checks
* UAPI 4 checks
* SUSFS 2.3.0 integration checks

**Real-device validation is still pending for these kernel versions.**

A **STATIC BOOT PASS** is not the same as a **DEVICE PASS**.

Static validation verifies the generated boot image structure and the known VEUX Android 13 boot layout. A DEVICE PASS requires the kernel to be flashed and successfully booted on real VEUX hardware.

## Installation

1. Make sure the device is **VEUX (SM6375)**.
2. Make sure the installed ROM/vendor environment is the supported **Android 13 stock ROM / stock vendor base**.
3. Keep a known-good boot image or recovery / rollback method available.
4. Download the matching **AnyKernel3 ZIP** or `boot.img` from the release.
5. Verify its SHA-256 checksum against the published checksum.
6. Flash only the file matching the intended installation method.
7. Reboot and verify:

   * kernel version
   * ReSukiSU status
   * ReSukiSU driver version / UAPI
   * SUSFS version
   * root functionality

## Important

* **VEUX / SM6375 only**
* **Validated target: Android 13 stock ROM / stock vendor**
* Android 11, Android 12 and Android 14 are currently **not validated**
* A custom ROM may use a compatible vendor base, but that does **not** automatically make it supported
* Kernel version alone is not a compatibility guarantee
* 5.4.292 / 5.4.293 / 5.4.300 / 5.4.302 should be treated as test builds until real-device validation is completed
* Do not describe 5.4.292 / 5.4.293 / 5.4.300 / 5.4.302 as official Xiaomi stock-kernel releases

## Disclaimer

Flashing a custom kernel modifies the device boot environment. Keep a working recovery / rollback method available before installing.

Use these builds only on the intended VEUX / SM6375 target and only with a compatible Android 13 vendor environment unless another platform has been explicitly validated.

