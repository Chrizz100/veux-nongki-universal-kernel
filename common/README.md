# Common 5.4 Layer

Wiederverwendbare, kernelversionsübergreifende Prüf- und Integrationslogik für VEUX/Linux 5.4.

## Werkzeuge

- `verify_source_pin.sh` — exakter Commit, `make kernelversion`, Defconfig und Defconfig-Hash.
- `audit_existing_integration.sh` — erkennt vorhandenes KernelSU/SUSFS, Doppel-Einbindungen und den ausgeschlossenen `module_load_filter`.
- `apply_patch_strict.sh` — fail-closed Patch-Anwendung mit `git apply --check`, echter Anwendung, `git diff --check` und `.rej/.orig`-Kontrolle.
- `identity_guard.sh` — schützt Makefile/localversion/setlocalversion/Defconfig vor unbeabsichtigten Common-Layer-Änderungen.

Lineage-Abweichungen gehören nach `lineages/<version>/`, nicht in einen immer größeren Universalpatch.
