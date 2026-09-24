# Pinned upstream source snapshots

The folders in this directory are generated from the exact stable commits in
`common/upstream/*/manifest.yml`.

They exist for review, traceability and diff inspection. They are not release
payloads. Clean AK3 ZIPs and boot.img files must never contain this directory,
build logs, CI evidence or development files.

Use the manual workflow `VEUX Upstream Snapshot Sync V1` to refresh snapshots
after an approved stable pin changes.
