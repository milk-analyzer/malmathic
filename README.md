# malmathic

Offline malware triage for infected Windows machines: reads raw NTFS and the registry hives itself, ranks candidate files by evidence, recovers the sample's bytes. Never mounts, executes or transmits anything.

[![CI](https://github.com/milk-analyzer/malmathic/actions/workflows/ci.yml/badge.svg)](https://github.com/milk-analyzer/malmathic/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/milk-analyzer/malmathic)](https://github.com/milk-analyzer/malmathic/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.94+](https://img.shields.io/badge/rust-1.94%2B-orange.svg)](Cargo.toml)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](#install)

**English** · [Русский](README.ru.md) · [简体中文](README.zh-CN.md)

## Features

- Runs on a live elevated system, from a WinRE console against a machine that will not boot, or against a disk image (`dd`, VDI, VMDK with snapshot chains).
- Parses `$MFT`, the USN journal, Amcache, ShimCache, prefetch, PCA, UserAssist, scheduled tasks, run keys and Startup shortcuts, Defender's log and quarantine, the recycle bin, mark-of-the-web and PE structure (imphash, Rich header) in-process — no Windows API on the analysis path, so locked files and unmounted hives are read anyway.
- Scores candidates as log-likelihood ratios over a per-machine prior; every evidence row is printed with its weight, and `malmathic explain` shows the reasoning behind each.
- Recovers the sample from the live file, Defender's quarantine, the recycle bin, a shadow copy, deleted `$MFT` clusters, index slack, orphaned records, the unused tail of a reused `$MFT` record, or a record image still in `$LogFile` — and labels each recovery `VERIFIED`, `UNVERIFIED` or `PARTIAL`.
- With `--deep`, carves free space by digest, and for a file no artifact ever hashed, by the name the image carries inside itself (its debug directory or export table).
- Verifies Authenticode and catalog signatures offline against pinned roots.
- Redacts reports for sharing (`--redact`, `malmathic redact`).
- Python bindings (`pymalmathic`) for the parsers, PE analysis and image reading.

## Install

Download `malmathic.exe` for x86-64 or ARM64 from [Releases](https://github.com/milk-analyzer/malmathic/releases): one static file, about 4 MB, no runtime.

From source: Rust 1.94+ with the MSVC toolchain, `cargo build --release`.

Reading an attached volume needs administrator rights (WinRE is already privileged). Reading an image needs none.

## Usage

```
malmathic                                   triage the Windows volume it finds; case in cases\ on the tool's drive
malmathic --out D:\case                     case directory of your choosing
malmathic --image disk.vmdk --out D:\case   disk image; --out is required
malmathic --redact                          also write report.redacted.*
malmathic explain <feature>                 the weight behind a feature id
malmathic redact D:\case\report.json        pseudonymise an existing report
```

Started by double-click (`Run as administrator`), it shows the case directory and waits for Enter or another path.

Exit codes: `0` — the analysis ran and the case was written (a negative result is a result); `1` — stopped early (not elevated, no Windows volume, refused placement) or a report could not be written; `diag` and `redact` use `2` for a usage error or a refused output path.

### Flags

| Flag | |
| --- | --- |
| `-o, --out <DIR>` | Case directory. Default `cases\<volume>-<time>` on the drive holding the exe; required with `--image`. Refused when it already holds a result, lies inside the source tree or in the exe's own folder (for an exe in a drive root, that root itself), or — with `--deep` — on the volume being read. |
| `--overwrite-case` | Replace an existing case directory. |
| `--volume <V>` | Volume to analyze: a drive letter or part of a volume GUID. |
| `--image <FILE>` | Disk image instead of a device; detected by header, no privileges. Do not mount it first. |
| `--list-volumes` | List volumes and what was found on them (stderr), then exit. |
| `--list-snapshots` | With `--image`: print the VMDK snapshot chain, then exit. |
| `--no-samples` | Recover and hash, but write no malware into the case directory. |
| `--deep` | Also carve unallocated clusters for candidates with no bytes, matching a recorded hash or the name the image carries inside itself. Slow. |
| `--acquire-top <N>` | At most N top candidates to recover (default 10), only those over the reporting threshold. |
| `--verify-top <N>` | Verify code signatures this far down the list (default 200). |
| `--redact` | Also write `report.redacted.txt` and `report.redacted.json`. |
| `--json` | Print the JSON report to stdout instead of the text one. |
| `--quiet` | No per-stage progress on stderr. |
| `--pause`, `--no-pause` | Force or forbid waiting for Enter at the end (`--no-pause` also skips the case-directory question); by default only when the window would close. |

### Subcommands

| Command | |
| --- | --- |
| `explain [FEATURE...]` | The weight table, or one row: meaning, the reasoning behind the weight, benign rate. |
| `redact <REPORT.JSON> [--out FILE] [--overwrite] [--keep-urls]` | Writes `<name>.redacted.json` and `.txt`: users become `user1`…, machines `host1`…, SID domains, volume ids and serials are renumbered, e-mail and IP addresses masked, URLs cut to their host, the case path dropped. Same name, same pseudonym throughout. |
| `diag mft [PATH] [--record N] [--children]` | One `$MFT` record with every ancestor; finds stale parent references. |
| `diag attribute-lists [--follow]` | Census of records carrying an `$ATTRIBUTE_LIST`. |
| `diag lzx-capture --out <FILE> [--overwrite] [--mount ROOT] [--all-algorithms] [--limit N]` | Capture Compact-OS streams beside their plaintext (WinRE). |
| `diag lzx-describe <FILE>` | Describe such a capture. |

### Case directory

| Path | |
| --- | --- |
| `report.txt`, `report.json` | Ranked candidates with evidence and weights, volume-level findings, coverage of what could not be read. |
| `report.redacted.txt`, `report.redacted.json` | Pseudonymised copies. Attach these to issues. |
| `sample/C<id>.bin` | Recovered bytes of a ranked candidate — live malware; your antivirus will quarantine it, which is expected. Absent with `--no-samples`. |
| `sample/unranked/` | Recoveries the ranking cannot reach: deleted records that still hold a runlist, vanished scratch-directory executables, names from index slack, below-threshold carves. Capped at 64 files or 256 MB. |

## Guarantees enforced by tests

- No process creation, library loading, mounting or network API in the shipped sources; the single `DeviceIoControl` is a length query; `Cargo.lock` matches an audited dependency list.
- Image readers hold no writable handle; with `--deep`, a case directory on the volume being read is refused.
- `imphash` and Rich-header hashes match `pefile` rule for rule, frozen ordinal tables and packed-sample heuristics included; checked against `pefile` by the Python tests.
- Every parser survives truncated, self-referential, size-lying and all-zero input.

## Limitations

- Weights are expert estimates, not fitted to a labelled corpus; every report says so.
- The prior is one in the machine's candidate count: evidence that convicts on a small machine may not on a large one.
- Validly signed malware scores down; a stolen certificate defeats the strongest negative weight.
- A deleted file with no recorded hash can still be found by the name its own PE headers carry, but nothing then confirms the bytes are that file's rather than another copy of the same program.
- Attributes recovered from record slack or `$LogFile` are bound to a path by a leftover name alone; a matching digest is what turns that into proof, and usually there is none.
- Disk and registry only: no processes, memory or network, and no disinfection.
- On a live system a user-mode rootkit can filter what it reads; WinRE and images avoid that.
- Windows only.

## Python bindings

```
cd bindings\python
pip install maturin pefile
maturin build --release
pip install target\wheels\pymalmathic-0.1.0-cp39-abi3-win_amd64.whl
```

```python
import pymalmathic as mm
mm.parse_amcache(hive)          # parse_shimcache, parse_prefetch, parse_tasks, parse_defender_log, parse_persistence, parse_recycle_bin, analyze_pe
mm.imphash(pe); mm.imports(pe); mm.rich_header(pe)
img = mm.Image("disk.vmdk"); img.list_dir("\\Users"); img.read_file(path, max_bytes=64 << 20)
```

A separate cargo workspace, so PyO3 never enters the audited dependency tree. One `abi3` wheel for CPython 3.9+, with type stubs. Parsers return observation dicts in the shape of `report.json`.

## Development

| Crate | |
| --- | --- |
| `mm-core` | Candidates, observations, paths, hashes, LZX and Xpress decoders |
| `mm-raw` | NTFS: `$MFT`, indexes and slack, USN journal, shadow copies, WOF |
| `mm-env` | Volumes, `dd`/VDI/VMDK images, snapshot chains, read-only file type, the Win32 layer |
| `mm-harvest` | Artifact parsers, PE, imphash, Rich header, mass-encryption detection |
| `mm-sign` | Authenticode and catalog verification, pinned roots |
| `mm-score` | Candidate graph, zones, features, weight table, incident window, baseline |
| `mm-report` | Report model, text rendering, redaction |
| `malmathic` | Pipeline, acquisition chain, CLI, diagnostics |
| `bindings/python` | `pymalmathic` |

```
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The reasoning behind every weight is in [`crates/mm-score/rules/weights.toml`](crates/mm-score/rules/weights.toml). See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE). Derived source and dependency licences, including the imphash ordinal tables taken from [pefile](https://github.com/erocarrera/pefile) (MIT, Ero Carrera), are listed in [NOTICE](NOTICE).
