#[cfg(windows)]
fn main() {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        BackupRead, CreateFileW, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING, WIN32_FIND_STREAM_DATA,
    };

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn open(path: &str, extra: FILE_FLAGS_AND_ATTRIBUTES) -> windows::core::Result<HANDLE> {
        let w = wide(path);
        unsafe {
            CreateFileW(
                PCWSTR(w.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | extra,
                None,
            )
        }
    }

    for path in std::env::args().skip(1) {
        println!("== {path}");

        let w = wide(&path);
        let mut data = WIN32_FIND_STREAM_DATA::default();
        unsafe {
            match FindFirstStreamW(
                PCWSTR(w.as_ptr()),
                FindStreamInfoStandard,
                (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
                None,
            ) {
                Ok(find) => loop {
                    let name = String::from_utf16_lossy(&data.cStreamName)
                        .trim_end_matches(char::from(0))
                        .to_string();
                    println!("   stream {name} ({} bytes)", data.StreamSize);
                    if FindNextStreamW(find, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast())
                        .is_err()
                    {
                        break;
                    }
                },
                Err(e) => println!("   FindFirstStreamW: {e:?}"),
            }
        }

        for (label, extra) in [
            ("stream", FILE_FLAGS_AND_ATTRIBUTES(0)),
            ("stream+reparse", FILE_FLAG_OPEN_REPARSE_POINT),
        ] {
            let stream_path = format!("{path}:WofCompressedData");
            match open(&stream_path, extra) {
                Ok(handle) => {
                    let mut buf = vec![0u8; 4096];
                    let mut read = 0u32;
                    let r = unsafe {
                        windows::Win32::Storage::FileSystem::ReadFile(
                            handle,
                            Some(buf.as_mut_slice()),
                            Some(&mut read),
                            None,
                        )
                    };
                    println!(
                        "   {label}: opened, read {r:?} {read} bytes {:02x?}",
                        &buf[..read.min(32) as usize]
                    );
                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                }
                Err(e) => println!("   {label}: {e:?}"),
            }
        }

        match open(&path, FILE_FLAGS_AND_ATTRIBUTES(0)) {
            Err(e) => println!("   BackupRead: could not open file: {e:?}"),
            Ok(handle) => {
                let mut context: *mut core::ffi::c_void = std::ptr::null_mut();
                let mut buf = vec![0u8; 1 << 16];
                loop {
                    let mut got = 0u32;
                    let ok = unsafe {
                        BackupRead(handle, &mut buf[..20], &mut got, false, true, &mut context)
                    };
                    if ok.is_err() || got < 20 {
                        break;
                    }
                    let id = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                    let size = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                    let name_len = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
                    let mut name = String::new();
                    if name_len > 0 && name_len <= buf.len() {
                        let mut n = 0u32;
                        let _ = unsafe {
                            BackupRead(
                                handle,
                                &mut buf[..name_len],
                                &mut n,
                                false,
                                true,
                                &mut context,
                            )
                        };
                        let units: Vec<u16> = buf[..n as usize]
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|c| u16::from_le_bytes(*c))
                            .collect();
                        name = String::from_utf16_lossy(&units);
                    }
                    println!("   BackupRead: stream id {id} name {name:?} size {size}");
                    let mut low = 0u32;
                    let mut high = 0u32;
                    let _ = unsafe {
                        windows::Win32::Storage::FileSystem::BackupSeek(
                            handle,
                            (size & 0xffff_ffff) as u32,
                            (size >> 32) as u32,
                            &mut low,
                            &mut high,
                            &mut context,
                        )
                    };
                }
                let mut got = 0u32;
                let _ = unsafe { BackupRead(handle, &mut [], &mut got, true, true, &mut context) };
                unsafe {
                    let _ = CloseHandle(handle);
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn main() {}
