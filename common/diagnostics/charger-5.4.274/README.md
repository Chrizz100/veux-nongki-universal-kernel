# VEUX 5.4.274 ChargerDiag01

Separate charging experiment based on the validated repository commit
`6dcf3369f27f2306bde876fd8ce06a7df3fb559d` (build run `36319804763`).
ReSukiSU 35184, SUSFS 2.3.0 and NoMount 20 stay pinned to the existing snapshots.

The only kernel source change removes the five-line HiZ pulse in
`drivers/power/supply/qcom/bq2589x_charger.c:bq2589x_monitor_workfunc`.
The stock 5.4.274 binary does not contain this pulse. Device logs show repeated
adapter detection/removal after a PD transition from fast charging to 5 V, with
VINDPM still at 8.5 V. Removing this pulse tests one suspected reset mechanism;
it does not implement the stock driver's full PD/BC1.2 coordination or change
the remaining VINDPM threshold. It is not yet a demonstrated off-mode fix.

## Run

Workflow: `.github/workflows/veux-charger-diagnostic-5.4.274.yml`.
It runs on changes to its files on branch
`diagnose/veux-5.4.274-charger-hiz`; it also supports `workflow_dispatch`.
The workflow token only has read access to repository contents. No promotion,
upstream resolution, fleet update or Golden modification occurs.

The runner restores the authenticated 5.4.274 recipe, replays the current source
overlay, verifies the exact driver preimage, applies the pinned patch, verifies
its postimage, then reuses the existing compile, warning, DTB, package and static
boot gates. Changed baseline files, components or patch bytes stop the build.

## Outputs

Artifact: `Kernel_5.4.274_ReSukiSU_35184_SUSFS_2.3.0_NoMount_20_ChargerDiag01`

- `..._AnyKernel.zip`: Image, AK3 installation files and licenses only.
- `..._boot.img`: statically verified image using the established boot contract.
- `RESULT.json` and `SHA256SUMS.txt`: provenance and file checksums outside AK3.

Source/build logs are uploaded separately as
`VEUX-5.4.274-ChargerDiag01-Reports-<run id>`.
Static PASS checks structure, kernel, ramdisk and AVB; it cannot verify actual
booting, charging, temperature behavior or the charger's user interface.

## Device comparison after a successful build

Install the diagnostic AK3 using the same installation method as the current
kernel. Retain a known working recovery path and the previous kernel package.
Use the same charger and cable. Check normal boot first, then off-mode charging,
and then normal charging through the transition near a full battery. Stop the
test if charging behaves abnormally. Capture fresh logs with the existing
`veux_ladeberichte.sh` collector after returning to Android. Keep the untouched
archive so timestamps and pstore can distinguish this test from older boots.

Device PASS remains false until the phone has actually passed these checks.
