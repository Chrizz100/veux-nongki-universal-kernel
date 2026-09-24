# VEUX upstream sources

This directory is the machine-readable authority for external kernel components.

Tracked components:
- ReSukiSU
- SUSFS
- NoMount

`stable.commit` is the build pin. A newer remote commit is only a candidate.
The scheduled upstream watcher may detect and test newer commits, but it never
silently replaces the stable pin.

`third_party/<component>/` is a source snapshot for repository evidence and
review. The build system must authenticate the exact upstream commit before use.
Snapshots are not release artifacts and are never copied into Clean AK3 or
boot.img outputs.
