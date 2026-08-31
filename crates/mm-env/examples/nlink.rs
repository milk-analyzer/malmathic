#[cfg(windows)]
fn main() {
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };

    let mut args = std::env::args().skip(1);
    let (Some(list), Some(out_path)) = (args.next(), args.next()) else {
        eprintln!("usage: nlink <paths.txt> <out.tsv>");
        std::process::exit(2);
    };
    let text = std::fs::read_to_string(&list).expect("read list");
    let mut out = std::io::BufWriter::new(std::fs::File::create(&out_path).expect("create out"));
    let mut ok = 0usize;
    let mut failed = 0usize;

    for line in text.lines() {
        let path = line.trim().trim_start_matches('\u{feff}');
        if path.is_empty() {
            continue;
        }
        let wide: Vec<u16> =
            std::ffi::OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        };
        let Ok(handle) = handle else {
            failed += 1;
            let _ = writeln!(out, "{path}\t?");
            continue;
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let links = if unsafe { GetFileInformationByHandle(handle, &mut info) }.is_ok() {
            ok += 1;
            info.nNumberOfLinks
        } else {
            failed += 1;
            0
        };
        unsafe {
            let _ = CloseHandle(handle);
        };
        let _ = writeln!(out, "{path}\t{links}");
    }
    let _ = out.flush();
    eprintln!("read link counts for {ok} files, {failed} failed");
}

#[cfg(not(windows))]
fn main() {
    eprintln!("windows only");
}
