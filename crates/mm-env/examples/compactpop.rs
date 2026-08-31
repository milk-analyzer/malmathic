#[cfg(windows)]
fn main() {
    use std::collections::BTreeMap;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::FSCTL_GET_EXTERNAL_BACKING;
    use windows::Win32::System::IO::DeviceIoControl;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn backing(path: &str, unopenable: &mut u64) -> Option<(u32, u32)> {
        let w = wide(path);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(w.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        };
        let handle = match handle {
            Ok(handle) => handle,
            Err(_) => {
                *unopenable += 1;
                return None;
            }
        };
        let mut buf = [0u8; 64];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_GET_EXTERNAL_BACKING,
                None,
                0,
                Some(buf.as_mut_ptr().cast()),
                buf.len() as u32,
                Some(&mut returned),
                None,
            )
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        ok.ok()?;
        if returned < 16 {
            return None;
        }
        let provider = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        let algorithm = u32::from_le_bytes(buf[12..16].try_into().ok()?);
        Some((provider, algorithm))
    }

    fn is_executable(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        [".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".efi", ".com"]
            .iter()
            .any(|e| lower.ends_with(e))
    }

    fn algorithm_name(provider: u32, algorithm: u32) -> &'static str {
        if provider == 1 {
            return "WIM";
        }
        if provider != 2 {
            return "other provider";
        }
        match algorithm {
            0 => "XPRESS4K",
            1 => "LZX",
            2 => "XPRESS8K",
            3 => "XPRESS16K",
            _ => "unknown algorithm",
        }
    }

    #[derive(Default)]
    struct Tally {
        files: u64,
        executables: u64,
        compressed_files: u64,
        compressed_executables: u64,
    }

    let roots: Vec<String> = {
        let given: Vec<String> = std::env::args().skip(1).collect();
        if given.is_empty() {
            vec![
                r"C:\Windows".into(),
                r"C:\Program Files".into(),
                r"C:\Program Files (x86)".into(),
                r"C:\ProgramData".into(),
                r"C:\Users".into(),
            ]
        } else {
            given
        }
    };

    let mut total = Tally::default();
    let mut unopenable = 0u64;
    let mut by_algorithm: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut by_directory: BTreeMap<String, u64> = BTreeMap::new();
    let mut compressed_exes: Vec<(String, &'static str)> = Vec::new();
    let started = std::time::Instant::now();

    for root in &roots {
        let mut stack = vec![std::path::PathBuf::from(root)];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let Ok(kind) = entry.file_type() else { continue };
                if kind.is_symlink() {
                    continue;
                }
                if kind.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                let path = entry.path();
                let Some(text) = path.to_str() else { continue };
                let name = entry.file_name().to_string_lossy().to_string();
                let exe = is_executable(&name);
                total.files += 1;
                if exe {
                    total.executables += 1;
                }
                if total.files % 25_000 == 0 {
                    eprintln!(
                        "  {} files, {} compressed ({:.0?})",
                        total.files,
                        total.compressed_files,
                        started.elapsed()
                    );
                }
                let Some((provider, algorithm)) = backing(text, &mut unopenable) else { continue };
                total.compressed_files += 1;
                *by_algorithm.entry(algorithm_name(provider, algorithm)).or_default() += 1;
                if let Some(parent) = path.parent().and_then(|p| p.to_str()) {
                    *by_directory.entry(parent.to_ascii_lowercase()).or_default() += 1;
                }
                if exe {
                    total.compressed_executables += 1;
                    compressed_exes.push((text.to_string(), algorithm_name(provider, algorithm)));
                }
            }
        }
    }

    println!("roots: {}", roots.join(", "));
    println!("files                   {}", total.files);
    println!("executables             {}", total.executables);
    println!("compressed files        {}", total.compressed_files);
    println!("compressed executables  {}", total.compressed_executables);
    println!("could not be opened     {unopenable}");
    println!("elapsed                 {:.1?}", started.elapsed());
    println!("\nby algorithm:");
    for (name, n) in &by_algorithm {
        println!("  {name:<16} {n}");
    }
    println!("\ncompressed executables, in full:");
    for (path, algorithm) in compressed_exes.iter().take(200) {
        println!("  [{algorithm}] {path}");
    }
    println!("\ndirectories holding compressed files (top 40):");
    let mut dirs: Vec<_> = by_directory.into_iter().collect();
    dirs.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    for (dir, n) in dirs.iter().take(40) {
        println!("  {n:>6}  {dir}");
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("compactpop measures a live Windows machine");
}
