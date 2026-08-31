use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root is two levels above this crate")
        .to_path_buf()
}

fn shipped_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let crates = workspace_root().join("crates");
    let entries = std::fs::read_dir(&crates).expect("crates/ must be readable");
    for entry in entries.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            collect_rs(&src, &mut out);
        }
        let build = entry.path().join("build.rs");
        if build.is_file() {
            out.push(build);
        }
    }
    out.sort();
    assert!(out.len() > 20, "the scan found only {} files; it is not finding the tree", out.len());
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

struct Line {
    number: usize,
    text: String,
}

fn code_lines(path: &Path) -> Vec<Line> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    let mut in_block = false;
    for (i, raw) in text.lines().enumerate() {
        let mut line = raw.to_string();
        if in_block {
            match line.find("*/") {
                Some(end) => {
                    line = line[end + 2..].to_string();
                    in_block = false;
                }
                None => continue,
            }
        }
        if let Some(start) = line.find("/*") {
            let head = line[..start].to_string();
            match line[start..].find("*/") {
                Some(end) => line = format!("{head}{}", &line[start + end + 2..]),
                None => {
                    in_block = true;
                    line = head;
                }
            }
        }
        if let Some(start) = line.find("//") {
            line = line[..start].to_string();
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(Line { number: i + 1, text: trimmed.to_string() });
    }
    out
}

fn relative(path: &Path) -> String {
    let root = workspace_root();
    path.strip_prefix(&root).unwrap_or(path).display().to_string().replace('\\', "/")
}

fn offences(needles: &[&str], allowed: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for file in shipped_sources() {
        let rel = relative(&file);
        if allowed.contains(&rel.as_str()) {
            continue;
        }
        for line in code_lines(&file) {
            for needle in needles {
                if line.text.contains(needle) {
                    out.push(format!("{rel}:{} contains {needle}: {}", line.number, line.text));
                }
            }
        }
    }
    out
}

#[test]
fn the_audit_reads_the_build_scripts_too() {
    let scanned = shipped_sources();
    assert!(
        scanned.iter().any(|path| path.ends_with("build.rs")),
        "a build script runs on whatever machine builds this tool, so it is the one file that \
         could execute something without any shipped source saying so. The audit below must \
         read it, or the guarantee this file exists to keep has a blind spot"
    );
}

#[test]
fn nothing_in_the_shipped_tree_can_execute_anything() {
    let found = offences(
        &[
            "std::process::Command",
            "process::Command",
            "Command::new(",
            "CreateProcessA",
            "CreateProcessW",
            "CreateProcessAsUser",
            "ShellExecute",
            "WinExec",
            "libloading",
            "LoadLibrary",
            "GetProcAddress",
            "dlopen",
            "dlsym",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
        ],
        &[],
    );
    assert!(
        found.is_empty(),
        "malmathic must not be able to execute anything. Found:\n  {}",
        found.join("\n  ")
    );
}

#[test]
fn the_only_foreign_code_linked_is_ntdlls_compressor_and_it_is_test_only() {
    let found = offences(&["extern \"", "#[link(name"], &["crates/malmathic/src/compact_os.rs"]);
    assert!(
        found.is_empty(),
        "a new foreign-function binding appeared; establish what it does before allowing it:\n  {}",
        found.join("\n  ")
    );

    let source =
        std::fs::read_to_string(workspace_root().join("crates/malmathic/src/compact_os.rs"))
            .expect("compact_os.rs");
    assert!(
        source.contains("#[link(name = \"ntdll\")]"),
        "the allowlisted binding should still be ntdll's compressor"
    );
    for forbidden in ["CreateProcess", "LoadLibrary", "WinExec", "ShellExecute"] {
        assert!(!source.contains(forbidden), "compact_os.rs must not declare {forbidden}");
    }

    let main = std::fs::read_to_string(workspace_root().join("crates/malmathic/src/main.rs"))
        .expect("main.rs");
    let lines: Vec<&str> = main.lines().map(str::trim).collect();
    let gated = lines.windows(2).any(|w| w[0] == "#[cfg(test)]" && w[1] == "mod compact_os;");
    assert!(gated, "compact_os must stay behind #[cfg(test)] so no foreign call ships");
}

#[test]
fn nothing_in_the_shipped_tree_can_mount_a_filesystem() {
    let found = offences(
        &[
            "SetVolumeMountPoint",
            "DeleteVolumeMountPoint",
            "DefineDosDevice",
            "AttachVirtualDisk",
            "OpenVirtualDisk",
            "CreateVirtualDisk",
            "FSCTL_",
            "IOCTL_",
            "DeviceIoControl",
            "NtCreateFile",
            "ZwCreateFile",
            "MountVolume",
            "SetupDiGetClassDevs",
        ],
        &["crates/mm-env/src/win.rs"],
    );
    assert!(
        found.is_empty(),
        "malmathic must never ask Windows to interpret a filesystem for it. Found:\n  {}",
        found.join("\n  ")
    );
}

#[test]
fn the_only_ioctl_asks_a_device_for_its_length() {
    let path = workspace_root().join("crates/mm-env/src/win.rs");
    let codes: BTreeSet<String> = code_lines(&path)
        .iter()
        .flat_map(|l| {
            l.text
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| w.starts_with("IOCTL_") || w.starts_with("FSCTL_"))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        codes,
        BTreeSet::from(["IOCTL_DISK_GET_LENGTH_INFO".to_string()]),
        "win.rs must issue exactly one control code, and it must be the length query"
    );

    let image_modules = [
        "crates/mm-env/src/image.rs",
        "crates/mm-env/src/vdi.rs",
        "crates/mm-env/src/vmdk.rs",
        "crates/mm-env/src/readonly.rs",
    ];
    for module in image_modules {
        let full = workspace_root().join(module);
        if !full.exists() {
            continue;
        }
        for line in code_lines(&full) {
            let win32 = line.text.contains("windows::Win32")
                || line.text.contains("use crate::win")
                || line.text.contains("crate::win::")
                || line.text.contains("win::VolumeDevice");
            assert!(
                !win32,
                "{module}:{} reaches the Win32 layer; the image path must not: {}",
                line.number, line.text
            );
        }
    }
}

#[test]
fn nothing_in_the_shipped_tree_can_reach_the_network() {
    let found = offences(
        &[
            "std::net",
            "TcpStream",
            "TcpListener",
            "UdpSocket",
            "reqwest",
            "hyper::",
            "ureq",
            "WinHttp",
            "InternetOpen",
            "WSAStartup",
            "socket2",
        ],
        &["crates/mm-harvest/src/imphash_ordinals.rs"],
    );
    assert!(found.is_empty(), "malmathic is offline by design. Found:\n  {}", found.join("\n  "));
}

#[test]
fn the_winsock_names_in_the_ordinal_table_are_data_and_nothing_else() {
    let path = workspace_root().join("crates/mm-harvest/src/imphash_ordinals.rs");
    let lines = code_lines(&path);
    assert!(lines.len() > 400, "the table looks empty: {} lines", lines.len());

    let is_arm = |text: &str| {
        let Some((ordinal, rest)) = text.split_once(" => \"") else { return false };
        let Some(name) = rest.strip_suffix("\",") else { return false };
        ordinal.parse::<u16>().is_ok()
            && !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    let mut signatures = 0;
    let mut arms = 0;
    for line in &lines {
        let text = line.text.as_str();
        let allowed = match text {
            "pub(super) fn ws2_32(ordinal: u16) -> Option<&'static str> {"
            | "pub(super) fn oleaut32(ordinal: u16) -> Option<&'static str> {" => {
                signatures += 1;
                true
            }
            "Some(match ordinal {" | "_ => return None," | "})" | "}" => true,
            _ => {
                let arm = is_arm(text);
                arms += usize::from(arm);
                arm
            }
        };
        assert!(
            allowed,
            "the ordinal table is exempt from the offline scan because it holds data only;              line {} is not a lookup arm: {text}",
            line.number
        );
    }
    assert_eq!(signatures, 2, "the table declares exactly two lookup functions");
    assert!(arms > 400, "expected the table to be mostly match arms, found {arms}");
}

#[test]
fn the_image_reading_modules_contain_no_write_path() {
    let modules = [
        "crates/mm-env/src/image.rs",
        "crates/mm-env/src/vdi.rs",
        "crates/mm-env/src/vmdk.rs",
        "crates/mm-env/src/snapshots.rs",
        "crates/mm-env/src/readonly.rs",
        "crates/mm-env/src/reader.rs",
    ];
    let forbidden = [
        "File::create",
        "fs::write",
        "fs::remove",
        "create_dir",
        "write_all",
        "set_len",
        "set_permissions",
        "OpenOptions::new().write",
        ".write(true)",
        ".append(true)",
        ".truncate(true)",
        ".create(true)",
    ];

    let mut scanned = 0;
    let mut found = Vec::new();
    for module in modules {
        let path = workspace_root().join(module);
        if !path.exists() {
            continue;
        }
        scanned += 1;
        let text = std::fs::read_to_string(&path).expect("a module");
        let shipped = match text.find("#[cfg(test)]") {
            Some(at) => &text[..at],
            None => &text[..],
        };
        let temp = std::env::temp_dir().join(format!(
            "mm-audit-{}-{}",
            std::process::id(),
            module.replace(['/', '\\'], "-")
        ));
        std::fs::write(&temp, shipped).expect("staging the shipped half of the module");
        for line in code_lines(&temp) {
            for needle in forbidden {
                if line.text.contains(needle) {
                    found
                        .push(format!("{module}:{} contains {needle}: {}", line.number, line.text));
                }
            }
        }
        let _ = std::fs::remove_file(&temp);
    }

    assert!(scanned >= 4, "only {scanned} image modules were found; the list is stale");
    assert!(
        found.is_empty(),
        "the image-reading modules must have no write path at all. Found:\n  {}",
        found.join("\n  ")
    );
}

#[test]
fn the_reading_modules_hold_no_writable_handle() {
    let modules = [
        "crates/mm-env/src/image.rs",
        "crates/mm-env/src/vdi.rs",
        "crates/mm-env/src/vmdk.rs",
        "crates/mm-env/src/snapshots.rs",
    ];
    let mut scanned = 0;
    let mut found = Vec::new();
    for module in modules {
        let path = workspace_root().join(module);
        if !path.exists() {
            continue;
        }
        scanned += 1;
        let text = std::fs::read_to_string(&path).expect("a module");
        let shipped = match text.find("#[cfg(test)]") {
            Some(at) => &text[..at],
            None => &text[..],
        };
        let temp = std::env::temp_dir().join(format!(
            "mm-audit-ro-{}-{}",
            std::process::id(),
            module.replace('/', "-")
        ));
        std::fs::write(&temp, shipped).expect("staging");
        for line in code_lines(&temp) {
            let owns_a_file = line.text.contains("std::fs::File")
                || line.text.contains("File::open(")
                || line.text.contains(": File")
                || line.text.contains("file: File")
                || line.text.contains("&mut File")
                || line.text.contains("(File)");
            if owns_a_file
                && !line.text.contains("ReadOnlyFile")
                && !line.text.contains("ImageFile")
            {
                found.push(format!("{module}:{} {}", line.number, line.text));
            }
        }
        let _ = std::fs::remove_file(&temp);
    }
    assert!(scanned >= 3, "only {scanned} reading modules were found; the list is stale");
    assert!(
        found.is_empty(),
        "an image-reading module holds a writable std::fs::File. Use mm_env::ReadOnlyFile, \
         which cannot be written through. Found:\n  {}",
        found.join("\n  ")
    );
}

#[test]
fn the_read_only_file_type_is_present_and_is_read_only() {
    use std::io::Read;

    let path = std::env::temp_dir().join(format!("mm-audit-ro-{}.bin", std::process::id()));
    std::fs::write(&path, b"EVIDENCE").expect("a scratch file");

    let mut f = mm_env::ReadOnlyFile::open(&path).expect("opening read-only");
    let mut got = Vec::new();
    f.read_to_end(&mut got).expect("reading");
    assert_eq!(got, b"EVIDENCE");
    drop(f);

    struct Probe<T>(std::marker::PhantomData<T>);
    trait MaybeWrite {
        fn writable(&self) -> bool {
            false
        }
    }
    impl<T> MaybeWrite for Probe<T> {}
    impl<T: std::io::Write> Probe<T> {
        #[allow(dead_code)]
        fn writable(&self) -> bool {
            true
        }
    }
    assert!(Probe::<std::fs::File>(std::marker::PhantomData).writable(), "the probe is broken");
    assert!(
        !Probe::<mm_env::ReadOnlyFile>(std::marker::PhantomData).writable(),
        "ReadOnlyFile has gained a Write impl"
    );

    assert_eq!(std::fs::read(&path).unwrap(), b"EVIDENCE");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_only_bytes_that_leave_an_image_land_in_the_case_directory() {
    let acquire = std::fs::read_to_string(workspace_root().join("crates/malmathic/src/acquire.rs"))
        .expect("acquire.rs");
    assert!(
        acquire.contains("format!(\"{}.bin\", candidate.id)"),
        "recovered samples must be named <id>.bin; if that changed, the README is now wrong"
    );

    let candidate =
        std::fs::read_to_string(workspace_root().join("crates/mm-core/src/candidate.rs"))
            .expect("candidate.rs");
    assert!(
        candidate.contains("write!(f, \"C{:03}\", self.0)"),
        "a candidate id must render as C###; if that changed, the README is now wrong"
    );

    let writes: Vec<String> = code_lines(&workspace_root().join("crates/malmathic/src/acquire.rs"))
        .iter()
        .filter(|l| l.text.contains("std::fs::write"))
        .map(|l| format!("{}: {}", l.number, l.text))
        .collect();
    assert_eq!(
        writes.len(),
        1,
        "acquisition should write bytes in exactly one place; found {writes:#?}"
    );
}

#[test]
fn nothing_writes_a_case_directory_without_asking_casedir_first() {
    let main = std::fs::read_to_string(workspace_root().join("crates/malmathic/src/main.rs"))
        .expect("main.rs");

    assert!(
        main.contains("fn write_case(case: &casedir::Plan,"),
        "write_case must take a Plan, which only casedir::prepare_case can produce; \
         taking a &Path again would restore the defect this test exists for"
    );

    let prepared = main.matches("casedir::prepare_case(").count();
    assert_eq!(
        prepared, 2,
        "exactly two run paths write a case (live/WinRE and --image) and both must \
         prepare it; found {prepared} call(s)"
    );

    let (shipped, _) = main
        .split_once("#[cfg(test)]\nmod tests {")
        .expect("main.rs still ends in its own test module");
    assert!(
        !shipped.contains("malmathic-case"),
        "no run path may hard-code a case directory; the live default is proposed by \
         casedir::suggest_case and, at a window of its own, confirmed at the console"
    );
    let suggested = shipped.matches("casedir::suggest_case(").count();
    assert_eq!(
        suggested, 1,
        "only suggest_output_dir may propose a case directory; found {suggested}"
    );
    let (_, from_run_image) = shipped
        .split_once("fn run_image(")
        .expect("run_image is still where the image path starts");
    let run_image_body = from_run_image.split("\nfn ").next().unwrap_or(from_run_image);
    assert!(
        run_image_body.contains("casedir::image_needs_out("),
        "an --image run with no --out must be refused inside run_image, not defaulted"
    );
    assert!(
        !run_image_body.contains("casedir::suggest_case("),
        "the image path must never be offered the live default; \
         its only fallback is casedir::beside_the_image"
    );
    assert!(
        run_image_body.contains("casedir::beside_the_image("),
        "the image path's fallback is beside the image"
    );

    let diag = std::fs::read_to_string(workspace_root().join("crates/malmathic/src/diag.rs"))
        .expect("diag.rs");
    assert!(
        diag.contains("casedir::guard_file("),
        "diag's --out must obey the same clobber and placement rules as a case"
    );
    assert!(
        diag.contains("refuses_to_write_onto("),
        "and must keep refusing the volume it is reading"
    );
}

#[test]
fn the_dependency_tree_is_the_one_that_was_audited() {
    let lock = std::fs::read_to_string(workspace_root().join("Cargo.lock")).expect("Cargo.lock");
    let mut present: BTreeSet<String> = BTreeSet::new();
    for line in lock.lines() {
        if let Some(rest) = line.strip_prefix("name = \"") {
            if let Some(name) = rest.strip_suffix('"') {
                present.insert(name.to_string());
            }
        }
    }
    assert!(present.len() > 100, "the lock file parse found only {} packages", present.len());

    let recorded_text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/audited-dependencies.txt"),
    )
    .expect("tests/audited-dependencies.txt");
    let recorded: BTreeSet<String> = recorded_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();

    let added: Vec<&String> = present.difference(&recorded).collect();
    let removed: Vec<&String> = recorded.difference(&present).collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "the dependency tree changed since it was audited.\n  \
         new, and unaudited: {added:?}\n  gone: {removed:?}\n\
         Read the new crates' sources for process execution, runtime library loading, \
         filesystem mounting and network access, then update \
         crates/malmathic/tests/audited-dependencies.txt. Do not update it first."
    );
}
