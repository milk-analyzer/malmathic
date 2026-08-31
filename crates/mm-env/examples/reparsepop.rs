#[cfg(not(windows))]
fn main() {
    eprintln!("reparsepop reads reparse points through Win32; it only runs on Windows");
    std::process::exit(2);
}

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
    use windows::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
    use windows::Win32::System::IO::DeviceIoControl;

    const MAX_REPARSE: usize = 16 * 1024;

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn reparse_bytes(path: &str) -> Option<Vec<u8>> {
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
        }
        .ok()?;
        let mut buf = vec![0u8; MAX_REPARSE];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_GET_REPARSE_POINT,
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
        buf.truncate(returned as usize);
        Some(buf)
    }

    fn tag_name(tag: u32) -> &'static str {
        match tag {
            0xA000_0003 => "MOUNT_POINT (junction / volume mount)",
            0xA000_000C => "SYMLINK",
            0x8000_0017 => "WOF (Compact OS)",
            0x9000_001A => "CLOUD (OneDrive)",
            0x8000_001B => "APPEXECLINK (Store alias)",
            0x8000_0014 => "WCI (container layer)",
            0xA000_0019 => "PROJFS",
            0x8000_0023 => "AF_UNIX socket",
            _ => "unrecognised",
        }
    }

    fn hex(bytes: &[u8], limit: usize) {
        for (i, chunk) in bytes.iter().take(limit).collect::<Vec<_>>().chunks(16).enumerate() {
            print!("    {:04x} ", i * 16);
            for b in chunk {
                print!("{:02x} ", b);
            }
            for _ in chunk.len()..16 {
                print!("   ");
            }
            print!(" |");
            for b in chunk {
                let c = **b;
                print!("{}", if (0x20..0x7f).contains(&c) { c as char } else { '.' });
            }
            println!("|");
        }
        if bytes.len() > limit {
            println!("    ... {} more bytes", bytes.len() - limit);
        }
    }

    fn describe(buf: &[u8]) {
        let Some(tag) = buf.get(0..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())) else {
            println!("  buffer too short to hold a tag");
            return;
        };
        let declared = buf.get(4..6).map(|b| u16::from_le_bytes(b.try_into().unwrap()));
        println!("  tag 0x{tag:08X}  {}", tag_name(tag));
        println!("  declared data length {declared:?}, buffer holds {} bytes", buf.len());
        if tag != 0xA000_0003 && tag != 0xA000_000C {
            return;
        }
        let head = 8usize;
        let read16 = |at: usize| -> Option<usize> {
            buf.get(at..at + 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()) as usize)
        };
        let (Some(sub_off), Some(sub_len), Some(print_off), Some(print_len)) =
            (read16(head), read16(head + 2), read16(head + 4), read16(head + 6))
        else {
            println!("  data too short for the name header");
            return;
        };
        let flags = if tag == 0xA000_000C {
            buf.get(head + 8..head + 12).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        } else {
            None
        };
        let path_buffer = head + if tag == 0xA000_000C { 12 } else { 8 };
        println!(
            "  substitute +{sub_off} len {sub_len}, print +{print_off} len {print_len}, \
             flags {flags:?}, path buffer starts at +{path_buffer}"
        );
        for (label, off, len) in
            [("substitute", sub_off, sub_len), ("print     ", print_off, print_len)]
        {
            let start = path_buffer + off;
            match buf.get(start..start + len) {
                Some(slice) => {
                    let units: Vec<u16> =
                        slice.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                    println!("    {label} = {:?}", String::from_utf16_lossy(&units));
                }
                None => println!("    {label} = <runs past the buffer>"),
            }
        }
    }

    let mut dumps: Vec<String> = Vec::new();
    let mut censuses: Vec<String> = Vec::new();
    let mut verify = false;
    let mut all = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dump" => dumps.extend(args.next()),
            "--census" => censuses.extend(args.next()),
            "--verify" => verify = true,
            "--all" => all = true,
            other => eprintln!("ignoring unrecognised argument {other}"),
        }
    }
    if dumps.is_empty() && censuses.is_empty() {
        eprintln!("usage: reparsepop --dump <path> [--dump <path>] [--census <dir>] [--verify]");
        std::process::exit(2);
    }

    for path in &dumps {
        println!("\n{path}");
        match reparse_bytes(path) {
            Some(buf) => {
                hex(&buf, 128);
                describe(&buf);
                if verify {
                    match mm_raw::reparse::parse(&buf) {
                        Some(link) => println!("  mm_raw::reparse::parse -> {link:?}"),
                        None => println!("  mm_raw::reparse::parse -> None"),
                    }
                }
            }
            None => println!("  not a reparse point, or could not be opened"),
        }
    }

    for root in &censuses {
        let mut tags: BTreeMap<u32, usize> = BTreeMap::new();
        let mut examples: BTreeMap<u32, String> = BTreeMap::new();
        let mut seen = 0usize;
        let mut stack = vec![std::path::PathBuf::from(root)];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata() else { continue };
                seen += 1;
                let path = entry.path();
                let is_link = {
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
                    let Ok(sym) = entry.path().symlink_metadata() else { continue };
                    sym.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                };
                if is_link {
                    if let Some(buf) = reparse_bytes(&path.to_string_lossy()) {
                        if let Some(tag) =
                            buf.get(0..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                        {
                            *tags.entry(tag).or_default() += 1;
                            examples
                                .entry(tag)
                                .or_insert_with(|| path.to_string_lossy().into_owned());
                            if all {
                                let link = mm_raw::reparse::parse(&buf);
                                println!(
                                    "  0x{tag:08X}	{}	{}",
                                    path.to_string_lossy(),
                                    link.map(|l| l.substitute).unwrap_or_default()
                                );
                            }
                        }
                    }
                    continue;
                }
                if meta.is_dir() && stack.len() < 4096 {
                    stack.push(path);
                }
            }
        }
        println!("\ncensus of {root}: {seen} entries");
        for (tag, count) in &tags {
            println!(
                "  0x{tag:08X} {:<38} {count:>6}   e.g. {}",
                tag_name(*tag),
                examples.get(tag).map(String::as_str).unwrap_or("")
            );
        }
        if tags.is_empty() {
            println!("  no reparse points");
        }
    }
}
