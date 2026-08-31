use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    modified: Option<SystemTime>,
    readonly: bool,
    digest: Option<String>,
}

fn fingerprint(path: &Path, hash: bool) -> std::io::Result<Fingerprint> {
    let meta = std::fs::metadata(path)?;
    let digest = if hash { Some(checksum_of(path)?) } else { None };
    Ok(Fingerprint {
        len: meta.len(),
        modified: meta.modified().ok(),
        readonly: meta.permissions().readonly(),
        digest,
    })
}

fn checksum_of(path: &Path) -> std::io::Result<String> {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut file = mm_env::ReadOnlyFile::open(path)?;
    let mut acc = OFFSET;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for byte in &buf[..n] {
            acc ^= u64::from(*byte);
            acc = acc.wrapping_mul(PRIME);
        }
    }
    Ok(format!("fnv1a64:{acc:016x}"))
}

fn survey(dir: &Path, hash: bool) -> BTreeMap<PathBuf, Fingerprint> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Ok(f) = fingerprint(&path, hash) {
                out.insert(path, f);
            }
        }
    }
    out
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let hash = args.iter().any(|a| a == "--checksum");
    args.retain(|a| a != "--checksum");

    let Some(image) = args.first().map(PathBuf::from) else {
        eprintln!(
            "usage: imagesafe [--checksum] <image>\n\n\
             Opens the image the way `malmathic --image` does, reads it, and proves\n\
             that nothing beside it on the host changed."
        );
        std::process::exit(2);
    };
    let dir = image.parent().unwrap_or(Path::new(".")).to_path_buf();

    println!("image     {}", image.display());
    println!("directory {}", dir.display());
    println!(
        "mode      {}\n",
        if hash { "size + mtime + a checksum of every byte" } else { "size + mtime" }
    );

    print!("surveying before … ");
    let started = Instant::now();
    let before = survey(&dir, hash);
    println!("{} files in {:.1} s", before.len(), started.elapsed().as_secs_f64());
    if before.is_empty() {
        eprintln!("nothing to survey; is the path right?");
        std::process::exit(1);
    }

    println!("\nopening the image …");
    let started = Instant::now();
    let partitions = match mm_env::find_ntfs_partitions(&image) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("could not open the image: {e}");
            report(&before, &survey(&dir, hash));
            std::process::exit(1);
        }
    };
    println!(
        "  {} NTFS partition(s) found in {:.2} s",
        partitions.len(),
        started.elapsed().as_secs_f64()
    );

    for partition in &partitions {
        let started = Instant::now();
        let mut file = match mm_env::ImageFile::open(&image) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("  offset {:<14} could not be reopened: {e}", partition.offset);
                continue;
            }
        };
        let mut sector = [0u8; 512];
        let ok = file.seek(SeekFrom::Start(partition.offset)).is_ok()
            && file.read_exact(&mut sector).is_ok();
        let label = if ok && &sector[3..11] == b"NTFS    " { "NTFS" } else { "unrecognised" };

        let mut read = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        while read < 64 << 20 {
            match file.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => read += n as u64,
            }
        }
        let volume = mm_env::open_partition(&image, *partition)
            .map(|v| {
                format!(
                    "serial {:016x}, {}",
                    v.serial(),
                    if v.is_windows_install() { "Windows installation" } else { "no Windows" }
                )
            })
            .unwrap_or_else(|e| format!("not openable as a volume: {e}"));

        println!(
            "  offset {:<14} {label}, {} MB read in {:.2} s\n  {:<21} {volume}",
            partition.offset,
            read >> 20,
            started.elapsed().as_secs_f64(),
            ""
        );
    }

    println!("\nthe handle: mm_env::ReadOnlyFile, which has no Write impl and whose Windows");
    println!("            access mask is FILE_GENERIC_READ (no FILE_WRITE_DATA).");

    print!("\nsurveying after … ");
    let started = Instant::now();
    let after = survey(&dir, hash);
    println!("{} files in {:.1} s\n", after.len(), started.elapsed().as_secs_f64());

    if report(&before, &after) {
        println!(
            "\nUNCHANGED. Every file in the directory has the same length, the same\n\
             modification time{} after the read as before it.",
            if hash { " and the same checksum over every byte" } else { "" }
        );
    } else {
        eprintln!("\nSOMETHING CHANGED. Do not use this build against evidence.");
        std::process::exit(1);
    }
}

fn report(before: &BTreeMap<PathBuf, Fingerprint>, after: &BTreeMap<PathBuf, Fingerprint>) -> bool {
    let mut clean = true;
    for (path, was) in before {
        match after.get(path) {
            None => {
                println!("GONE      {}", path.display());
                clean = false;
            }
            Some(now) if now != was => {
                println!("CHANGED   {}", path.display());
                if now.len != was.len {
                    println!("            length  {} → {}", was.len, now.len);
                }
                if now.modified != was.modified {
                    println!("            modified {:?} → {:?}", was.modified, now.modified);
                }
                if now.digest != was.digest {
                    println!("            checksum {:?} → {:?}", was.digest, now.digest);
                }
                clean = false;
            }
            Some(_) => {}
        }
    }
    for path in after.keys() {
        if !before.contains_key(path) {
            println!("NEW       {}", path.display());
            clean = false;
        }
    }
    clean
}
