#[cfg(windows)]
fn main() {
    use windows::Win32::Foundation::NTSTATUS;

    windows::core::link!("ntdll.dll" "system" fn RtlGetCompressionWorkSpaceSize(
        f: u16, compress: *mut u32, fragment: *mut u32) -> NTSTATUS);
    windows::core::link!("ntdll.dll" "system" fn RtlCompressBuffer(
        f: u16, src: *const u8, src_len: u32, dst: *mut u8, dst_len: u32,
        chunk: u32, out_len: *mut u32, workspace: *mut core::ffi::c_void) -> NTSTATUS);

    const XPRESS_HUFF: u16 = 4;

    fn compress(data: &[u8]) -> Option<Vec<u8>> {
        let mut ws = 0u32;
        let mut frag = 0u32;
        if unsafe { RtlGetCompressionWorkSpaceSize(XPRESS_HUFF, &mut ws, &mut frag) }.0 != 0 {
            return None;
        }
        let mut workspace = vec![0u64; (ws as usize).div_ceil(8)];
        let mut out = vec![0u8; data.len() + 65536];
        let mut written = 0u32;
        let status = unsafe {
            RtlCompressBuffer(
                XPRESS_HUFF,
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
        out.truncate(written as usize);
        Some(out)
    }

    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    for source in [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\System32\drivers\ntfs.sys",
        r"C:\Windows\win.ini",
        r"C:\Windows\System32\license.rtf",
    ] {
        let Ok(bytes) = std::fs::read(source) else { continue };
        for (index, piece) in bytes.chunks(32768).enumerate().take(24) {
            cases.push((format!("{source} chunk {index}"), piece.to_vec()));
        }
    }
    cases.push(("all zeroes".into(), vec![0u8; 32768]));
    cases.push(("one byte".into(), vec![0x41]));
    cases.push(("two distinct bytes".into(), vec![0x41, 0x42]));
    cases.push(("repeating pair".into(), b"ab".repeat(16384)));
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let noise: Vec<u8> = (0..32768)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 33) as u8
        })
        .collect();
    cases.push(("pseudo-random".into(), noise));

    let mut checked = 0usize;
    let mut failed = 0usize;
    let mut refused = 0usize;
    for (name, plain) in &cases {
        let Some(stream) = compress(plain) else {
            println!("SKIP  {name}: ntdll refused to compress it");
            refused += 1;
            continue;
        };
        if stream.len() >= plain.len() {
            refused += 1;
            continue;
        }
        let got = mm_core::xpress::decompress(&stream, plain.len());
        if got == *plain {
            checked += 1;
        } else {
            failed += 1;
            let first = got
                .iter()
                .zip(plain)
                .position(|(a, b)| a != b)
                .unwrap_or(got.len().min(plain.len()));
            println!(
                "FAIL  {name}: {} bytes in, {} out, want {}, first difference at {first}",
                stream.len(),
                got.len(),
                plain.len()
            );
        }
    }
    println!(
        "\n{checked} real Microsoft-produced Xpress Huffman streams decoded byte-identically, \
         {failed} did not, {refused} were not compressible and are stored raw by WOF"
    );
    if failed > 0 {
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {}
