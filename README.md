# VEUX ReSukiSU + SUSFS Kernel Builds

Custom Linux 5.4 kernel builds for **Xiaomi / POCO `veux` (SM6375)** with **ReSukiSU**, **SUSFS** and **AnyKernel3** packaging.

## Available builds

| Kernel | ReSukiSU | UAPI | SUSFS | Validation |
|---|---|---:|---:|---|
| **5.4.274** | 35154 / `6ec8d9a8` | 4 | 2.3.0 | **DEVICE PASS** |
| **5.4.292** | 35154 / `6ec8d9a8` | 4 | 2.3.0 | **STATIC BOOT PASS** |
| **5.4.300** | 35141 / `7741f878` | 4 | 2.3.0 | **STATIC BOOT PASS** |
| **5.4.302** | 35141 / `7741f878` | 4 | 2.3.0 | **STATIC BOOT PASS** |

## Validation status

### 5.4.274
The P14 build has been tested on real VEUX hardware and passed:
- Build
- Packaging
- Flash
- Device boot
- ReSukiSU Built-in
- Root
- SUSFS runtime
- Session-keyring runtime

### 5.4.292 / 5.4.300 / 5.4.302
These builds passed build/package/static boot-path validation.

**Real-device validation is still pending.**

A static boot-path pass is not the same as a real device boot pass.

## Installation

1. Make sure the device is **VEUX**.
2. Keep a known-good boot image or recovery method available.
3. Download the matching AnyKernel3 ZIP from the GitHub Release.
4. Verify its SHA-256 checksum against `SHA256SUMS.txt`.
5. Flash the ZIP using a compatible recovery or AnyKernel3-compatible installer.
6. Reboot and verify kernel, ReSukiSU and SUSFS status.

## Important

- **VEUX only**
- Kernel version alone is not a compatibility guarantee.
- 5.4.292 / 5.4.300 / 5.4.302 should be treated as test builds until real-device validation is completed.

## Checksums

See [`SHA256SUMS.txt`](SHA256SUMS.txt).

## Disclaimer

Flashing a custom kernel modifies the device boot environment. Keep a working recovery/rollback method available before installing.
