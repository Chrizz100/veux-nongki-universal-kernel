# Common 5.4 Integration Contract

## Muss-Bedingungen

1. Repository und Commit exakt gepinnt.
2. Native Kernelversion stimmt.
3. VEUX-Defconfig vorhanden.
4. Bestehendes KernelSU/SUSFS vorher auditieren.
5. Kernelidentitätsdateien vor Common-Patches sichern.
6. Kritische Patches fail-closed.

## Verboten

- `patch ... || true` / `git apply ... || true`
- Löschen von Rejects, um Fehler zu verstecken
- Versionsspoofing
- doppelte Kconfig/Makefile-Einbindung
- doppelte SUSFS-Hooks
- automatisches Überschreiben unbekannter bestehender Integrationen

## ReSukiSU-Referenz

- Commit `7741f87849f7ad7cebf82bbb4c5b89880e61e37e`
- UAPI 4
- KSU/ReSukiSU 35141
- SUSFS 2.3.0
- `module_load_filter`: ausgeschlossen

Diese Werte sind Referenz, nicht der Beweis, dass ein identischer Patch auf jeder Lineage korrekt ist.
