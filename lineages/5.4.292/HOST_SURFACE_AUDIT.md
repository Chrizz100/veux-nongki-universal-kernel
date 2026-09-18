# VEUX 5.4.292 – ReSukiSU Host-Surface Audit

Stand: 2026-09-18

## Status

```text
SOURCE_PIN=fb3bbb10bc0480282c01b88ccaf39c0145cd9f51
KERNEL=5.4.292
BASELINE_GITHUB_GREEN_PASS=YES
BASELINE_RUN=35317893402

RESUKISU_CANDIDATE=6ec8d9a8a8be30878c388504cacf8ae7849c757b
RESUKISU_MODE=MANUAL_HOOK
HOST_SURFACE=PORT_REQUIRED

RESUKISU_INTEGRATION=NOT_YET_RUN
SUSFS_INTEGRATION=NOT_STARTED
PACKAGE_PASS=NO
STATIC_BOOT_PATH_PASS=NO
DEVICE_PASS_5_4_292=NO
```

## 1. Upstream-Pin

Aktueller verifizierter ReSukiSU-main-Stand:

`6ec8d9a8a8be30878c388504cacf8ae7849c757b`

Der Stand liegt 13 Commits vor der P13-Referenz
`7741f87849f7ad7cebf82bbb4c5b89880e61e37e`.

Für diese 5.4.292-Linie wird kein `latest` zur Buildzeit verwendet.
Der verifizierte Commit wird exakt gepinnt.

## 2. Gewählter Hook-Modus

Für Linux 5.4 wird `CONFIG_KSU_MANUAL_HOOK=y` verwendet.

Nicht verwendet:

- `CONFIG_KSU_TRACEPOINT_HOOK`
- `CONFIG_KSU_SUSFS` in der ersten ReSukiSU-Stufe

Begründung:

- ReSukiSU kennzeichnet Tracepoint Syscall Redirect für GKI2 / Kernel 5.10+.
- Linux 5.4 muss daher zunächst über den Manual-Hook-Pfad integriert werden.
- SUSFS 2.3.0 wird separat portiert und erst danach als eigene Stufe bewertet.

Die Auto-Hooks bleiben zunächst aktiviert:

- `CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK=y`
- `CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK=y`
- `CONFIG_KSU_MANUAL_HOOK_AUTO_INPUT_HOOK=y`

Damit sind auf 5.4 keine manuellen Quellpatches für setresuid, sys_read oder
input_event erforderlich, solange die Auto-Hook-Prüfungen bestehen.

## 3. Zwingende Manual-Hook-Flächen

### fs/exec.c — PORT_REQUIRED

Die 5.4.292-Quelle besitzt die passende 3.14+-Struktur:

`static int do_execveat_common(int fd, struct filename *filename, ...)`

Der aktuelle Quellstand enthält dort noch keinen ReSukiSU-Hook.

Einzubinden:

- `ksu_handle_execveat`
- `ksu_handle_post_execveat`

Der Post-Hook ist beim aktuellen ReSukiSU-Dokumentationsstand Teil des
bevorzugten 3.14+-Pfads und muss nach dem eigentlichen Exec-Aufruf laufen.

Status: `PORT_REQUIRED`, strukturell kompatible Einfügestelle vorhanden.

### fs/open.c — PORT_REQUIRED

Vorhanden:

`SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)`

Einzubinden:

`ksu_handle_faccessat(&dfd, &filename, &mode, NULL)`

Status: `PORT_REQUIRED`, passende 4.19+-Einfügestelle vorhanden.

### fs/stat.c — PORT_REQUIRED

Vorhandene passende Pfade:

- `newfstatat`
- `newfstat`
- `fstat64` / 32-bit-Kompatibilität
- `fstatat64` / 32-bit-Kompatibilität

Einzubinden:

- `ksu_handle_stat`
- `ksu_handle_newfstat_ret`
- `ksu_handle_fstat64_ret` im vorhandenen STAT64-Pfad

Status: `PORT_REQUIRED`.

32-bit/compat darf nicht stillschweigend ausgelassen werden, weil VEUX ARM64
gleichzeitig Android-32-bit-Kompatibilität besitzen kann.

### kernel/reboot.c — PORT_REQUIRED

Vorhanden:

`SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd, void __user *, arg)`

Einzubinden:

`ksu_handle_sys_reboot(magic1, magic2, cmd, &arg)`

Status: `PORT_REQUIRED`, passende 3.11+-Einfügestelle vorhanden.

## 4. Auto-Hook-Voraussetzungen

Die 5.4.292-LSM-Struktur besitzt die für ReSukiSU benötigten Hookflächen:

- `task_fix_setuid`
- `file_permission`
- `key_permission`

`security_add_hooks()` ist in dieser Quelle als Drei-Argument-Variante vorhanden.

Damit ist der ReSukiSU-LSM-Autohook-Pfad grundsätzlich mit der Quelle
vereinbar.

Zusätzlich zeigt der grüne Baseline-Build, dass `security/keys/*` tatsächlich
mitgebaut wird. Der aktuelle ReSukiSU-Commit, der den Keyring-Pfad für alte
Kernel erweitert, ist damit nicht allein wegen fehlender KEYS-Unterstützung
blockiert.

Status: `COMPATIBLE`, endgültiger Beweis erst durch Compile.

## 5. SELinux Static-Symbol-Fläche

Die 5.4.292-Quelle besitzt `struct selinux_state`.

Damit entfallen die alten bedingten 4.17--Exporte für:

- `selinux_status_page`
- `selinux_status_lock`
- `sel_mutex`
- `policy_rwlock`

Falls `CONFIG_KALLSYMS_ALL` nicht aktiviert wird, benötigt ReSukiSU jedoch
weiterhin externe Sichtbarkeit für:

- `write_op`
- `sel_handle_status_ops`

Die Quelle definiert aktuell:

- `static ssize_t (*const write_op[])(...)`
- `static const struct file_operations sel_handle_status_ops`

Für den minimalen Port wird **nicht** pauschal `CONFIG_KALLSYMS_ALL`
eingeschaltet. Stattdessen wird nur `static` an diesen beiden Definitionen
entfernt; `const` bleibt erhalten.

Status: `PORT_REQUIRED`.

## 6. ReSukiSU-Einbindung

Der offizielle `kernel/setup.sh` wird für unseren Masterpfad **nicht direkt
verwendet**.

Grund:

Sein Commit-Checkout enthält einen Fallback der Form:

`git checkout "$1" || echo "[-] Checkout default branch"`

Damit könnte ein fehlgeschlagener Pin unbemerkt auf dem Default-Branch
weiterlaufen. Das widerspricht unserem fail-closed-Vertrag.

Unsere Integration muss stattdessen:

1. ReSukiSU-Repository initialisieren/holen.
2. exakt `6ec8d9a8a8be30878c388504cacf8ae7849c757b` auschecken.
3. `git rev-parse HEAD` exakt vergleichen.
4. erst dann `drivers/kernelsu` verknüpfen.
5. `drivers/Makefile` und `drivers/Kconfig` mit exakt einem Eintrag ergänzen.
6. Duplikate als Fehler behandeln.

Offizielles Layout bleibt erhalten:

- `drivers/kernelsu -> <ReSukiSU>/kernel`
- `drivers/Makefile`: `obj-$(CONFIG_KSU) += kernelsu/`
- `drivers/Kconfig`: `source "drivers/kernelsu/Kconfig"`

## 7. module_load_filter — BLOCKED UNTIL REMOVED

Unser P13-Vertrag schließt `module_load_filter` ausdrücklich aus.

Der aktuelle ReSukiSU-Stand bindet die Funktion jedoch fest ein:

- `kernel/Kbuild` baut `feature/module_load_filter.o`
- `kernel/core/init.c` inkludiert dessen Header
- `kernel/core/init.c` definiert den Parameter `block_modules`
- `kernelsu_init()` ruft `ksu_module_load_filter_hook_init()` auf
- `kernelsu_exit()` ruft `ksu_module_load_filter_hook_exit()` auf

Damit darf der aktuelle Upstream nicht unverändert in unseren Master.

Vor dem ersten ReSukiSU-Compile muss ein enger ReSukiSU-Delta ausschließlich
diese Kernel-Funktion entfernen:

1. `feature/module_load_filter.o` nicht bauen
2. Header-Include entfernen
3. `ksu_block_modules` und `block_modules`-Modulparameter entfernen
4. Init-Aufruf entfernen
5. Exit-Aufruf entfernen

Die übrigen ReSukiSU-Funktionen bleiben unverändert.

Userspace-Dateien, die den Parameter für den LKM-Pfad vorbereiten, sind für
unseren eingebauten Non-GKI-Kernel nicht Teil des Kernel-Objektpfads. Sie
werden in dieser ersten Kernel-Stufe nicht als Vorwand für zusätzliche
Userspace-Änderungen benutzt.

Status: `PORT_REQUIRED`.

## 8. Konfiguration

Die native `veux_defconfig` wird nicht dauerhaft umgeschrieben.

Nach `make veux_defconfig` wird die erzeugte `.config` kontrolliert gesetzt auf:

```text
CONFIG_KSU=y
CONFIG_KSU_MANUAL_HOOK=y
CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK=y
CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK=y
CONFIG_KSU_MANUAL_HOOK_AUTO_INPUT_HOOK=y
# CONFIG_KSU_TRACEPOINT_HOOK is not set
# CONFIG_KSU_SUSFS is not set
```

Danach:

`make olddefconfig`

Damit bleibt die native Defconfig-Identität als Baseline-Referenz unverändert.

## 9. Fail-closed Bedingungen

Der Integrationslauf muss abbrechen bei:

- Source Commit ungleich dem Pin
- ReSukiSU Commit ungleich dem Pin
- vorhandener KSU/SUSFS-Integration
- mehrdeutiger oder fehlender Patch-Ankerstelle
- bereits vorhandenen ReSukiSU-Hooks
- doppelter Makefile/Kconfig-Einbindung
- verbliebenem `module_load_filter` im Kernel-Objektpfad
- `.rej` oder `.orig`
- `git diff --check` Fehler
- Identity-Guard-Verletzung
- unerwartetem Hook-Modus
- unerwartetem Kernelrelease

Keine Fehlerunterdrückung mit `|| true`.

## 10. Ergebnis

```text
HOST_SURFACE_AUDIT=PASS
INTEGRATION_CLASS=PORT_REQUIRED

EXECVE_SURFACE=PORT_REQUIRED
FACCESSAT_SURFACE=PORT_REQUIRED
STAT_SURFACE=PORT_REQUIRED
REBOOT_SURFACE=PORT_REQUIRED
AUTO_LSM_HOOK_SURFACE=COMPATIBLE
SELINUX_STATIC_EXPORT_SURFACE=PORT_REQUIRED
MODULE_LOAD_FILTER_EXCLUSION=PORT_REQUIRED

READY_FOR_FAIL_CLOSED_INTEGRATION_SCRIPT=YES
READY_FOR_COMPILE_PASS=NO
READY_FOR_SUSFS_2_3_0=NO
```

Der nächste Schritt ist ein fail-closed ReSukiSU-Integrationsscript mit
Fixture-Selbsttest. Erst nach dessen eigener Prüfung wird über eine
Ausführungsumgebung entschieden.
