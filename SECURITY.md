# Security

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: <https://github.com/milk-analyzer/malmathic/security/advisories/new>. Do not open a public issue. State the version, the environment (live, WinRE or `--image`) and, if a specific file triggers the problem, its SHA-256 and origin rather than the file itself. Expect an acknowledgement within seven days.

## Scope

malmathic parses attacker-controlled bytes from infected machines. Any input that makes it execute code, mount a filesystem, write to the volume it analyses, transmit data, panic, or run without bound is a vulnerability. These properties are pinned by `crates/malmathic/tests/no_execution_no_mounting.rs` and the hostile-input tests of each parser.

## Supported versions

The latest release.
