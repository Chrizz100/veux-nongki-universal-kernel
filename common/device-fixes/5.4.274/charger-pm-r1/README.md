# VEUX 5.4.274: WT-Suspend-Koordination R1

Ausgangspunkt ist der tatsächlich geflashte Build 37206832975. Dessen
wt_chg.c hat SHA256 107cbc7bc8c1816f9821bcef8a201ef2977c948e5acd171ec2b7a4c4c1650ce4.
Im Folgebericht vom 04.10.2026 tritt die CP-Master-Temperaturabfrage mit
ADC-Timeout noch nach „Freezing remaining freezable tasks ... done“ auf.
Die bereits korrigierte Fehlerbehandlung meldet dabei korrekt unavailable.

Die Änderung ersetzt ausschließlich acht Aufrufe für batt_chg_work durch
queue_delayed_work(system_freezable_wq, ...): Erststart, Selbstplanung,
Property-/IIO-Schreibpfade und Watchdog. Alle Intervalle, ADC-Lesefunktionen,
Ladeentscheidungen, Temperaturgrenzen und Wakeup-Quellen bleiben bytegleich.
Andere WT-Arbeiten bleiben unverändert. Die BQ2589x- und SC8551-Korrekturen
sowie RPM-Sleep und ConfigDiag10 bleiben erhalten.

Im festgelegten Vendor-Kernel b2b7a3bbc36d120ee523ebc8d68e0f13a97df632
verwendet schedule_delayed_work die nicht einfrierbare system_wq.
system_freezable_wq hat WQ_FREEZABLE. Vor dem Geräte-Suspend wartet der
Freezer auf laufende Arbeiten dieser Queue; neu eingereihte Arbeiten
bleiben bis zum Auftauen zurückgestellt. Die Geräte werden vor dem
Auftauen wieder aufgenommen. Das gilt auch für einen abgebrochenen Suspend.
CONFIG_FREEZER=y ist im Gerätebericht und der bisherigen Konfiguration
vorhanden. Der vorhandene ConfigDiag10-Buildgate verlangt weiterhin exakt
dieselbe tatsächliche Konfiguration.

Primärquellen am genannten Commit:
- include/linux/workqueue.h: schedule_delayed_work, system_freezable_wq
- kernel/workqueue.c: freeze_workqueues_begin/busy, thaw_workqueues
- kernel/power/process.c: freeze_kernel_threads, thaw_processes
- kernel/power/suspend.c: suspend_prepare, suspend_devices_and_enter,
  suspend_finish

Der neue test_wt_pm.py kehrt ausschließlich diese acht Queue-Änderungen um
und verlangt danach den vollständigen Hash des geflashten WT-Treibers.
Zwölf Negativfälle prüfen insbesondere jeden einzeln vergessenen Einstieg
sowie unerlaubte Änderungen an Intervallen und Ladegrenzen. Die vorhandenen
Temperatur- und Spannungstests behalten ihre bisherigen Assertions und
Scope-Hashes; sie verwenden dazu die so authentifizierte Ausgangsfassung.
Die tatsächlichen getesteten Messfunktionen sind bytegleich. Die übrigen
C-Treibertests bleiben unverändert.

Die Hostprüfung ist kein ausgeführter Suspend-Test und kein Kernelbuild.
Die Korrektur beseitigt den gefundenen ungeschützten Scheduling-Pfad;
ob damit die beobachteten ADC-Timeouts verschwinden, muss der nächste
Kernelbuild mit anschließendem Gerätetest zeigen. Andere ADC-Ursachen
und Suspend-Abbrüche sind damit nicht ausgeschlossen. BMS-Lesefehler und
andere Hintergrundarbeiten sind noch nicht abschließend untersucht.

Der zugehörige Workflow verwendet ausschließlich die bereits festgelegten
Root-Komponenten aus VEUX_STABILIZATION_R1.json. Alle sechs V4-Linien,
Golden-Referenzen und vorhandenen Workflows bleiben erhalten.
