# VEUX 5.4.292 – SUSFS 2.3.0 Backport Preflight

Stand: 2026-09-18

## 1. Ausgangsbasis

Bestätigte grüne Basis:

- Kernel: 5.4.292-veid-veux
- Source: UEDestroyer/kernel_xiaomi_veux
- Source Commit: fb3bbb10bc0480282c01b88ccaf39c0145cd9f51
- ReSukiSU Commit: 6ec8d9a8a8be30878c388504cacf8ae7849c757b
- ReSukiSU Compile: GREEN PASS
- GitHub Run: 35333478955
- Image SHA-256:
  b1518659449ceec8bcb03f842ce313a19c2b33d64a693a6d71f1c3f2e16e004b
- module_load_filter: EXCLUDED
- SUSFS: NOT YET INTEGRATED
- Package Pass: NO
- Static Boot Path Pass: NO
- Device Pass: NO

Diese Basis bleibt Referenz und wird nicht überschrieben.

## 2. Aktueller offizieller SUSFS-Upstream

Offizieller Upstream:

- Projekt: simonpunk/susfs4ksu
- Hosting: GitLab
- Project ID: 56471372

Aktueller moderner Zweig:

- Branch: gki-android13-5.15
- SUSFS_VERSION im aktuellen `susfs.h`: v2.3.0
- zuletzt sichtbarer Branch-HEAD (Kurz-SHA): 415e4143
- letzter sichtbarer Kernel-Commit:
  `kernel & KernelSU: Fix [ksu_driver_su] being wrongly installed before su session`

Wichtig:

Der vollständige 40-stellige SHA dieses aktuellen 2.3.0-Branch-HEADs ist vor
einer echten Integration noch fail-closed zu ermitteln. Ein Kurz-SHA wird
nicht als Build-Pin akzeptiert.

## 3. Offizieller Linux-5.4-Zweig

Offizieller SUSFS-5.4-Branch:

- Branch: kernel-5.4
- HEAD:
  76affd70abf61d77feb0a132f61365d6848505df
- Datum: 2025-02-23
- letzter Commit:
  `kernel: Remove support for Shamiko`
- Modulversion im 5.4-Zweig: 1.5.5

Damit existiert weiterhin kein offizieller aktueller SUSFS-2.3.0-Zweig für
Linux 5.4.

## 4. 2.3.0 ist kein Drop-in für den alten 5.4-Port

Die aktuelle 2.3.0-Datei `kernel_patches/fs/susfs.c` umfasst rund 1443 Zeilen;
die offizielle 5.4-Variante rund 851 Zeilen.

Die Implementierung hat sich substanziell geändert.

Beispiele:

### SUS_PATH

2.3.0:

- verwendet `inode->i_mapping->flags`
- verwendet `AS_FLAGS_SUS_PATH`
- behandelt FUSE-Inodes explizit
- nutzt SRCU / RCU für Pfadlisten
- hat versionsabhängige UID-Ermittlung für 5.15 / 6.6 / ältere Kernel

alter 5.4-Zweig:

- markiert Pfade im Wesentlichen über ältere inode/task-state Mechanismen
- basiert auf der alten 1.5.x-Hookarchitektur

### OPEN_REDIRECT

2.3.0:

- Ziel und Redirect werden inode/dev-basiert gespeichert
- besitzt `uid_scheme`
- Reverse-Lookup wird mitgeführt
- speichert zusätzlich spoofed mount/statfs Informationen
- nutzt SRCU und Mutex

alter 5.4-Zweig:

- arbeitet mit Pfadstrings und `INODE_STATE_OPEN_REDIRECT`
- deutlich einfacheres Hashtable-Modell
- andere ABI und Hook-Semantik

### Userspace-ABI

2.3.0:

- SUSFS_VERSION = v2.3.0
- viele Calls verwenden `void __user **user_info`
- liefert Fehlercodes in den Übergabestrukturen zurück
- besitzt Feature-/Variant-/Version-Abfragen
- unterstützt moderne Features wie AVC-log-spoofing und aktuelle Feature-Discovery

Folgerung:

`kernel-5.4` darf nur als 5.4-Struktur-/Hook-Referenz benutzt werden.
Sein `susfs.c` darf nicht als 2.3.0 ausgegeben oder unverändert übernommen werden.

## 5. ReSukiSU-Hookmodus für SUSFS

Der aktuelle ReSukiSU-Kconfig verwendet eine `choice` für:

- KSU_TRACEPOINT_HOOK
- KSU_MANUAL_HOOK
- KSU_SUSFS

Diese Modi sind gegenseitig exklusiv.

Die grüne ReSukiSU-V2-Basis wurde mit:

`CONFIG_KSU_MANUAL_HOOK=y`

gebaut.

Für SUSFS muss der nächste Compile auf:

`CONFIG_KSU_SUSFS=y`

wechseln.

Damit ist ein entscheidender Punkt geklärt:

Die bisherigen Manual-Hook-Quelländerungen können zwar im Source stehen,
werden aber unter `CONFIG_KSU_MANUAL_HOOK` nicht aktiv sein. Für SUSFS müssen
die vom ReSukiSU-Inline-Checker verlangten aktiven SUSFS/inline Hooks vorhanden
sein.

## 6. ReSukiSU SUSFS Inline-Hook-Vertrag

Der aktuelle ReSukiSU-Stand prüft im SUSFS-Modus unter anderem folgende
aktive Kernel-Hooks:

- kernel/sys.c:
  - `ksu_handle_setresuid`
- fs/exec.c:
  - `ksu_handle_execveat`
- fs/open.c:
  - `ksu_handle_faccessat`
- fs/read_write.c:
  - `ksu_handle_sys_read`
- fs/stat.c:
  - `ksu_handle_stat`
- kernel/reboot.c:
  - `ksu_handle_sys_reboot`
- drivers/input/input.c:
  - `ksu_handle_input_handle_event`

Zusätzlich werden veraltete/incompatible Hooks explizit abgelehnt, darunter:

- `ksu_vfs_read_hook`
- `ksu_input_hook`
- `ksu_execveat_hook`
- `ksu_init_rc_hook`

Der Checker warnt außerdem, wenn diese Dateien nur den
`CONFIG_KSU_MANUAL_HOOK`-Guard enthalten.

## 7. Konsequenz für unsere 5.4.292-Linie

Der SUSFS-Port darf nicht einfach auf `RESUKISU_INTEGRATE_V2.py` aufsetzen und
nur `CONFIG_KSU_SUSFS=y` einschalten.

Notwendig ist ein eigener SUSFS-Portschritt, der:

1. die grüne ReSukiSU-V2-Basis reproduziert,
2. den SUSFS-2.3.0-Upstream exakt pinnt,
3. `fs/susfs.c`, `include/linux/susfs.h` und benötigte aktuelle Header aus
   2.3.0 übernimmt,
4. die 5.4-spezifischen Kernel-Hookstellen anhand des offiziellen 5.4-Zweigs
   portiert,
5. dabei die 2.3.0-Datenstrukturen und ABI beibehält,
6. ReSukiSU-spezifische Änderungen getrennt portiert,
7. `CONFIG_KSU_MANUAL_HOOK` deaktiviert,
8. `CONFIG_KSU_SUSFS` aktiviert,
9. die vollständigen ReSukiSU Inline-Hook-Gates erfüllt,
10. `module_load_filter` weiterhin ausgeschlossen hält.

## 8. Upstream-KernelSU-Patch ist nicht direkt anwendbar

Der aktuelle SUSFS-2.3.0-Patch `10_enable_susfs_for_ksu.patch` ist gegen
offizielles KernelSU aufgebaut und verändert unter anderem:

- KernelSU Kbuild
- KernelSU Kconfig
- core/init
- adb_root
- sucompat
- setuid handling
- SELinux integration
- supercall handling

Unser ReSukiSU-Baum hat bereits eigene, abweichende Implementierungen dieser
Bereiche.

Deshalb gilt:

`10_enable_susfs_for_ksu.patch` darf NICHT direkt auf ReSukiSU angewendet
werden.

Stattdessen wird die für SUSFS benötigte Semantik manuell und fail-closed auf
den gepinnten ReSukiSU-Stand übertragen.

## 9. Portierungsstrategie

### Phase S1 – Read-only Surface Audit

Prüfen:

- alle 2.3.0-Kerneldateien/Headers
- alle 5.4-Hookanker
- benötigte struct-Erweiterungen
- benötigte inode/mount/task/thread Flags
- FUSE-Kompatibilität
- cmdline/bootconfig hook
- uname hook
- stat/statfs hooks
- mount-id/group-id Logik
- open_redirect
- AVC log spoofing
- ReSukiSU supercall ABI

Ergebnis je Fläche:

- COMPATIBLE
- PORT_REQUIRED
- BLOCKED

### Phase S2 – SUSFS Core Backport

Erst nach S1:

- 2.3.0-Core übernehmen
- 5.4-Kompatibilität gezielt ergänzen
- keine 1.5.5-Core-Datei als Ersatz verwenden

### Phase S3 – ReSukiSU SUSFS Adapter

- aktuelle ReSukiSU-API verwenden
- keine offiziellen-KernelSU-Dateien blind ersetzen
- module_load_filter weiterhin ausgeschlossen
- Hookmodus auf `KSU_SUSFS`
- alte Manual-Hooks nur dort entfernen/umbauen, wo sie mit dem
  Inline-Hook-Vertrag kollidieren

### Phase S4 – Compile

Compile erst nach:

- exakten Pins
- Port-Audit PASS
- Delta-Guard PASS
- `git diff --check` PASS
- keine `.rej` / `.orig`
- Inline-Hook-Checker PASS
- Identity Guard PASS

## 10. Aktueller Status

```text
5.4.292_RESUKISU_GREEN_BASE=PASS
SUSFS_TARGET_VERSION=2.3.0
SUSFS_OFFICIAL_HOST=GITLAB
SUSFS_2_3_BRANCH=gki-android13-5.15
SUSFS_2_3_VISIBLE_HEAD_SHORT=415e4143
SUSFS_2_3_FULL_SHA=REQUIRED_BEFORE_INTEGRATION

SUSFS_5_4_BRANCH=kernel-5.4
SUSFS_5_4_HEAD=76affd70abf61d77feb0a132f61365d6848505df
SUSFS_5_4_VERSION=1.5.5

DIRECT_5_4_1_5_5_USE=FORBIDDEN
DIRECT_5_15_PATCH_ON_5_4=FORBIDDEN
DIRECT_OFFICIAL_KSU_PATCH_ON_RESUKISU=FORBIDDEN

SUSFS_2_3_0_BACKPORT=PORT_REQUIRED
READY_FOR_SURFACE_AUDIT=YES
READY_FOR_SUSFS_COMPILE=NO
PACKAGE_PASS=NO
STATIC_BOOT_PATH_PASS=NO
DEVICE_PASS=NO
```
