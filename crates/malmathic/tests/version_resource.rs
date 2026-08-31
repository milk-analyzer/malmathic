#![cfg(all(windows, target_env = "msvc"))]

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root is two levels above this crate")
        .to_path_buf()
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn the_binary_this_run_built_names_itself_to_windows() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_malmathic")).expect("the binary this run built");

    assert_eq!(
        mm_harvest::pe::has_version_resource(&bytes),
        Some(true),
        "malmathic scores an executable that carries no version resource, and Windows falls \
         back to showing the file name where a description belongs. Its own binary must not \
         be that file"
    );

    for stated in [
        "malmathic.exe",
        "The malmathic authors",
        "Copyright (c) 2026 The malmathic authors",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_DESCRIPTION"),
    ] {
        let wanted = utf16(stated);
        assert!(
            bytes.windows(wanted.len()).any(|window| window == wanted),
            "the version resource does not carry {stated:?}"
        );
    }
}

#[test]
fn the_copyright_windows_shows_is_the_one_the_licence_states() {
    let licence = std::fs::read_to_string(workspace_root().join("LICENSE"))
        .expect("LICENSE must be readable");
    let stated = licence
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("Copyright"))
        .expect("the licence states a copyright line");

    let script = std::fs::read_to_string(workspace_root().join("crates/malmathic/build.rs"))
        .expect("build.rs must be readable");
    assert!(
        script.contains(&format!("const COPYRIGHT: &str = \"{stated}\";")),
        "build.rs stamps a copyright into every binary; it says something other than the \
         licence's {stated:?}"
    );
}
