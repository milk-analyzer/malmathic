# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-08-30

First public release.

- Triage of a live volume, a machine from WinRE, or a disk image (`dd`, VDI, VMDK snapshot chains), reading NTFS and the registry hives in-process.
- Parsers for `$MFT`, the USN journal, Amcache, ShimCache, prefetch, PCA, UserAssist, scheduled tasks, run keys, Startup shortcuts, Defender's log and quarantine, the recycle bin, mark-of-the-web, and PE structure with pefile-compatible imphash and Rich header.
- Evidence scoring as log-likelihood ratios over a per-machine prior, with `explain` for the reasoning behind every weight.
- Sample recovery from the live file, quarantine, recycle bin, shadow copies, deleted `$MFT` clusters, index slack, orphaned records, the unused tail of a reused `$MFT` record, and record images still in `$LogFile`, each labelled by how it was verified; `--deep` carves free space by recorded digest, or by the name an image carries inside itself when nothing ever hashed it.
- Offline Authenticode and catalog verification against pinned roots.
- Report redaction for sharing: `--redact` and `malmathic redact`.
- The case directory defaults to `cases\<volume>-<time>` on the drive holding the exe; a double-click launch shows it and waits for Enter or another path.
- Python bindings `pymalmathic`.
- Tests that pin the no-execution, no-mounting and no-network properties, the read-only image readers, and the audited dependency list.

[0.1.0]: https://github.com/milk-analyzer/malmathic/releases/tag/v0.1.0
