# SWEET: Quellen und Kernelstände

`source_lock.json` enthält die zwei festen offiziellen OEM-Quellstände für den
Quellen-/Kconfig-Vergleich. `reference/` enthält die zugehörigen unveränderten
OEM-Defconfigs. Beide Quellen deklarieren 4.14.180; die hochgeladene Stock-Binärdatei
trägt 4.14.190. R4 behauptet keine fertig rekonstruierte 4.14.190-Quelle.

In diesem Ordner gibt es bewusst KEINE `build.yml` direkt unter `lineages/sweet/`.
Der vorhandene VEUX-Detektor sucht `lineages/*/build.yml` und akzeptiert nur VEUX
mit 5.4-Versionen. Die bestehenden `lineages/5.4.*/` bleiben unverändert.
Künftige SWEET-Buildprofile benötigen ihren eigenen, SWEET-spezifischen Einstieg.
