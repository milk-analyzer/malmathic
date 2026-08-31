#[cfg(windows)]
fn main() {
    use windows::Win32::Foundation::NTSTATUS;

    windows::core::link!("ntdll.dll" "system" fn RtlGetCompressionWorkSpaceSize(
        f: u16, compress: *mut u32, fragment: *mut u32) -> NTSTATUS);
    windows::core::link!("ntdll.dll" "system" fn RtlCompressBuffer(
        f: u16, src: *const u8, src_len: u32, dst: *mut u8, dst_len: u32,
        chunk: u32, out_len: *mut u32, workspace: *mut core::ffi::c_void) -> NTSTATUS);
    windows::core::link!("ntdll.dll" "system" fn RtlDecompressBufferEx(
        f: u16, dst: *mut u8, dst_len: u32, src: *const u8, src_len: u32,
        out_len: *mut u32, workspace: *mut core::ffi::c_void) -> NTSTATUS);

    let path = std::env::args().nth(1).unwrap_or_else(|| r"C:\Windows\System32\notepad.exe".into());
    let data = std::fs::read(&path).expect("read the sample");
    println!("{path}: {} bytes", data.len());

    for engine in [0u16, 0x0100] {
        for format in 2u16..9 {
            for chunk in [4096u32, 8192, 16384, 32768] {
                let combined = format | engine;
                let mut ws_size = 0u32;
                let mut frag = 0u32;
                if unsafe { RtlGetCompressionWorkSpaceSize(combined, &mut ws_size, &mut frag) }.0
                    != 0
                {
                    continue;
                }
                let mut workspace = vec![0u64; (ws_size as usize).div_ceil(8)];
                let mut out = vec![0u8; data.len() + data.len() / 8 + 65536];
                let mut written = 0u32;
                eprintln!("  try format {format} engine {engine:#06x} chunk {chunk} ws {ws_size} frag {frag}");
                let status = unsafe {
                    RtlCompressBuffer(
                        combined,
                        data.as_ptr(),
                        data.len() as u32,
                        out.as_mut_ptr(),
                        out.len() as u32,
                        chunk,
                        &mut written,
                        workspace.as_mut_ptr().cast(),
                    )
                };
                if status.0 != 0 {
                    println!(
                        "format {format} engine 0x{engine:04x} chunk {chunk}: compress 0x{:08x}",
                        status.0 as u32
                    );
                    continue;
                }
                let mut back = vec![0u8; data.len()];
                let mut got = 0u32;
                let d = unsafe {
                    RtlDecompressBufferEx(
                        combined,
                        back.as_mut_ptr(),
                        back.len() as u32,
                        out.as_ptr(),
                        written,
                        &mut got,
                        workspace.as_mut_ptr().cast(),
                    )
                };
                let identical = d.0 == 0 && got as usize == data.len() && back == data;
                println!(
                    "format {format} engine 0x{engine:04x} chunk {chunk:>5}: {written:>8} bytes  \
                     round-trip {}",
                    if identical { "IDENTICAL" } else { "FAILED" }
                );
            }
        }
    }
}

#[cfg(not(windows))]
fn main() {}
