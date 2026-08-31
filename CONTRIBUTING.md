# Contributing

## Build and test

```
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cd bindings\python && cargo clippy --all-targets -- -D warnings && maturin build --release
```

Tests that open `\\.\C:` need an elevated shell and skip otherwise. `MM_VM_DIR` and `MM_SPLIT_VM_DIR` point the snapshot-chain tests at real VMDKs, `MM_CASE_JSON` enables the ignored reference-machine tests, `MM_TEST_IMAGE` enables the Python `Image` tests. The measured-machine tests in `crates/mm-score/tests/measured_machines.rs` read report datasets from a `VM_TESTS/` directory that is not published; they are ignored by default and run with `cargo test -- --ignored` where the datasets exist.

## Conventions

- Rust sources carry no comments. Reasoning goes into names, types and tests; the reasoning behind a weight goes into `crates/mm-score/rules/weights.toml`.
- Several tests assert on the source text itself (the no-execution audit, the weight-table checks). Read `crates/malmathic/tests/no_execution_no_mounting.rs` and the tests in `crates/mm-score/src/weights.rs` before restructuring, and keep files LF (`.gitattributes` enforces it).
- No new dependency without reading its source for process execution, library loading, mounting and network access, then updating `crates/malmathic/tests/audited-dependencies.txt`. The audit test compares `Cargo.lock` against that list. `bindings/python` is a separate workspace so that PyO3 stays out of it.
- A change to scoring or recovery comes with a test on a synthetic volume (`crates/malmathic/src/testimage.rs`). Describe real-world cases with redacted reports (`--redact`), never with samples.
- Clippy clean at `-D warnings`, all tests green; CI builds the release binary for x86-64 and cross-builds it for ARM64.
