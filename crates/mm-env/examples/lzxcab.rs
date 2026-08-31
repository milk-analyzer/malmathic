#[cfg(windows)]
fn main() {
    use std::path::PathBuf;
    use std::process::Command;

    let input =
        std::env::args().nth(1).unwrap_or_else(|| r"C:\Windows\System32\notepad.exe".into());
    let scratch = std::env::temp_dir().join("mm-env-lzxcab");
    let _ = std::fs::remove_dir_all(&scratch);
    if let Err(e) = std::fs::create_dir_all(&scratch) {
        eprintln!("cannot create {}: {e}", scratch.display());
        return;
    }

    let plain = scratch.join("sample.bin");
    let bytes = match std::fs::read(&input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {input}: {e}");
            return;
        }
    };
    if std::fs::write(&plain, &bytes).is_err() {
        eprintln!("cannot write the working copy");
        return;
    }
    println!("{input}: {} bytes", bytes.len());
    println!();
    println!("{:<18} {:>12}  expand round-trip", "window", "cab bytes");

    for window in [15u32, 16, 17, 18, 19, 20, 21] {
        let cab: PathBuf = scratch.join(format!("w{window}.cab"));
        let out = scratch.join(format!("out{window}"));
        let _ = std::fs::remove_dir_all(&out);
        if std::fs::create_dir_all(&out).is_err() {
            continue;
        }

        let made = Command::new("makecab.exe")
            .args(["/D", "CompressionType=LZX", "/D", &format!("CompressionMemory={window}")])
            .arg(&plain)
            .arg(&cab)
            .output();
        let made = match made {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                println!("{:<18} {:>12}  makecab failed: {}", window, "-", o.status);
                continue;
            }
            Err(e) => {
                println!("{window:<18} makecab could not be run: {e}");
                continue;
            }
        };
        drop(made);

        let cab_len = std::fs::metadata(&cab).map(|m| m.len()).unwrap_or(0);
        let expanded = Command::new("expand.exe")
            .arg(&cab)
            .arg("-F:*")
            .arg(format!("{}\\", out.display()))
            .output();
        let verdict = match expanded {
            Ok(o) if o.status.success() => {
                let got = std::fs::read_dir(&out)
                    .ok()
                    .and_then(|mut d| d.next())
                    .and_then(|e| e.ok())
                    .and_then(|e| std::fs::read(e.path()).ok());
                match got {
                    Some(back) if back == bytes => "SHA-256 IDENTICAL".to_string(),
                    Some(back) => format!("DIFFERENT ({} bytes back)", back.len()),
                    None => "nothing was extracted".to_string(),
                }
            }
            Ok(o) => format!("expand failed: {}", o.status),
            Err(e) => format!("expand could not be run: {e}"),
        };
        println!("{window:<18} {cab_len:>12}  {verdict}");
    }

    println!();
    println!(
        "window 15 is 32,768 bytes — the window WOF LZX uses. These are real \n\
         Microsoft LZX streams with known plaintext: a codec oracle. They are NOT \n\
         WOF-framed, which is the half that still has no fixture. See mm_raw::wof."
    );
    let _ = std::fs::remove_dir_all(&scratch);
}

#[cfg(not(windows))]
fn main() {}
