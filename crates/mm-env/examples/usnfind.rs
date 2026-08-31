use std::path::PathBuf;

use mm_env::image::{find_ntfs_partitions, open_partition};
use mm_raw::usn::{read_journal, record_fate};
use ntfs_core::usn::UsnReason;

fn reasons(mask: u32) -> String {
    let all = [
        (UsnReason::FILE_CREATE, "FILE_CREATE"),
        (UsnReason::FILE_DELETE, "FILE_DELETE"),
        (UsnReason::DATA_EXTEND, "DATA_EXTEND"),
        (UsnReason::DATA_OVERWRITE, "DATA_OVERWRITE"),
        (UsnReason::DATA_TRUNCATION, "DATA_TRUNCATION"),
        (UsnReason::RENAME_NEW_NAME, "RENAME_NEW_NAME"),
        (UsnReason::RENAME_OLD_NAME, "RENAME_OLD_NAME"),
        (UsnReason::BASIC_INFO_CHANGE, "BASIC_INFO_CHANGE"),
        (UsnReason::SECURITY_CHANGE, "SECURITY_CHANGE"),
        (UsnReason::CLOSE, "CLOSE"),
    ];
    let named: Vec<&str> =
        all.iter().filter(|(bit, _)| mask & bit.bits() != 0).map(|(_, name)| *name).collect();
    if named.is_empty() {
        format!("0x{mask:08x}")
    } else {
        named.join("|")
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(image) = args.first() else {
        eprintln!("usage: usnfind <image> <name-substring> [more…]");
        std::process::exit(2);
    };
    let wanted: Vec<String> = args[1..].iter().map(|s| s.to_lowercase()).collect();
    if wanted.is_empty() {
        eprintln!("usage: usnfind <image> <name-substring> [more…]");
        std::process::exit(2);
    }
    let path = PathBuf::from(image);
    let parts = find_ntfs_partitions(&path).expect("scanning the image for NTFS");
    for p in parts {
        let Ok(vol) = open_partition(&path, p) else { continue };
        if !vol.is_windows_install() {
            continue;
        }
        let j = read_journal(&vol);
        let w = j.window();
        println!("volume @{}  {} journal record(s)", p.offset, j.records.len());
        println!("  window {:?} .. {:?}", w.first_time, w.last_time);
        for want in &wanted {
            let hits: Vec<_> =
                j.records.iter().filter(|r| r.filename.to_lowercase().contains(want)).collect();
            println!("\n  === {want}: {} row(s)", hits.len());
            for r in hits.iter().take(60) {
                println!(
                    "    usn {:>10}  {}  entry {}/{}  parent {}  {}  {}",
                    r.usn,
                    r.timestamp.format("%Y-%m-%d %H:%M:%S%.3fZ"),
                    r.mft_entry,
                    r.mft_sequence,
                    r.parent_mft_entry,
                    r.filename,
                    reasons(r.reason.bits()),
                );
            }
            let mut seen: Vec<(u64, u16)> =
                hits.iter().map(|r| (r.mft_entry, r.mft_sequence)).collect();
            seen.sort_unstable();
            seen.dedup();
            for (entry, sequence) in seen {
                println!("    fate  {}", record_fate(&vol, entry, sequence).describe(entry));
            }
        }
    }
}
