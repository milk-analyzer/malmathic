#[cfg(windows)]
fn main() {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::NTSTATUS;
    use windows::Win32::Storage::FileSystem::GetCompressedFileSizeW;

    windows::core::link!("ntdll.dll" "system" fn RtlGetCompressionWorkSpaceSize(
        f: u16, compress: *mut u32, fragment: *mut u32) -> NTSTATUS);
    windows::core::link!("ntdll.dll" "system" fn RtlCompressBuffer(
        f: u16, src: *const u8, src_len: u32, dst: *mut u8, dst_len: u32,
        chunk: u32, out_len: *mut u32, workspace: *mut core::ffi::c_void) -> NTSTATUS);

    fn compress_chunk(format: u16, data: &[u8]) -> Option<usize> {
        let mut ws = 0u32;
        let mut frag = 0u32;
        if unsafe { RtlGetCompressionWorkSpaceSize(format, &mut ws, &mut frag) }.0 != 0 {
            return None;
        }
        let mut workspace = vec![0u64; (ws as usize).div_ceil(8)];
        let mut out = vec![0u8; data.len() + 65536];
        let mut written = 0u32;
        let status = unsafe {
            RtlCompressBuffer(
                format,
                data.as_ptr(),
                data.len() as u32,
                out.as_mut_ptr(),
                out.len() as u32,
                4096,
                &mut written,
                workspace.as_mut_ptr().cast(),
            )
        };
        if status.0 != 0 {
            return None;
        }
        Some(written as usize)
    }

    fn predicted_on_disk(format: u16, data: &[u8], chunk: usize) -> Option<u64> {
        let chunks = data.len().div_ceil(chunk);
        let table = (chunks.saturating_sub(1)) * 4;
        let mut total = table;
        for piece in data.chunks(chunk) {
            let compressed = compress_chunk(format, piece)?;
            total += compressed.min(piece.len());
        }
        Some(((total as u64).div_ceil(4096)) * 4096)
    }

    fn on_disk(path: &str) -> u64 {
        let w: Vec<u16> =
            std::ffi::OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
        let mut high = 0u32;
        let low = unsafe { GetCompressedFileSizeW(PCWSTR(w.as_ptr()), Some(&mut high)) };
        (u64::from(high) << 32) | u64::from(low)
    }

    let mut args = std::env::args().skip(1);
    let scratch = args.next().expect("usage: wofpin <scratch dir> [file]");
    let source = args.next().unwrap_or_else(|| r"C:\Windows\System32\notepad.exe".to_string());
    let data = std::fs::read(&source).expect("read the sample");
    println!("sample {source}: {} bytes\n", data.len());

    std::fs::create_dir_all(&scratch).expect("scratch dir");

    println!("what `compact /c /exe:` actually stored:");
    let algorithms: [(&str, usize); 4] =
        [("XPRESS4K", 4096), ("XPRESS8K", 8192), ("XPRESS16K", 16384), ("LZX", 32768)];
    let mut measured = Vec::new();
    for (name, chunk) in algorithms {
        let copy = format!("{scratch}/{name}.bin");
        std::fs::write(&copy, &data).expect("write copy");
        let status = std::process::Command::new("compact.exe")
            .args(["/c", &format!("/exe:{name}"), &copy])
            .output();
        let stored = on_disk(&copy);
        println!(
            "  {name:<10} chunk {chunk:>5}  on disk {stored:>9}  ({})",
            if status.is_ok() { "compact ran" } else { "compact FAILED" }
        );
        measured.push((name, chunk, stored));
    }

    println!("\npredicted on-disk size, by ntdll format and chunk size:");
    println!("  (a cell equal to the measured number above is a match)");
    print!("{:>8}", "format");
    for (name, _, stored) in &measured {
        print!("{:>18}", format!("{name}={stored}"));
    }
    println!();
    for engine in [0u16, 0x0100] {
        for format in 2u16..9 {
            let combined = format | engine;
            print!("{:>8}", format!("{format}/{:x}", engine >> 8));
            for (_, chunk, stored) in &measured {
                match predicted_on_disk(combined, &data, *chunk) {
                    Some(p) if p == *stored => print!("{:>18}", format!("{p} MATCH")),
                    Some(p) => print!("{p:>18}"),
                    None => print!("{:>18}", "-"),
                }
            }
            println!();
        }
    }
}

#[cfg(not(windows))]
fn main() {}
