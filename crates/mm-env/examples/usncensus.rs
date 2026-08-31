use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use mm_env::image::{find_ntfs_partitions, open_partition};
use mm_raw::usn::{read_journal, record_fate, RecordFate};
use ntfs_core::usn::UsnReason;

fn main() {
    for a in std::env::args().skip(1) {
        let path = PathBuf::from(&a);
        println!("=== {}", path.display());
        let Ok(parts) = find_ntfs_partitions(&path) else {
            println!("  unreadable");
            continue;
        };
        for p in parts {
            let Ok(vol) = open_partition(&path, p) else { continue };
            if !vol.is_windows_install() {
                continue;
            }

            let j = read_journal(&vol);
            let w = j.window();
            println!("  @{} verdict {:?}", p.offset, j.verdict());
            println!("    $Max {:?}", j.max);
            println!(
                "    allocated {} KiB, sparse {} KiB  (sparse:allocated = {:.1}:1)",
                j.allocated_bytes / 1024,
                j.sparse_bytes / 1024,
                j.sparse_bytes as f64 / j.allocated_bytes.max(1) as f64
            );
            println!(
                "    read {} KiB in {:?}, truncated {:?}",
                j.bytes_read / 1024,
                j.elapsed,
                j.truncated.as_ref().map(|t| t.describe())
            );
            println!("    records {}", j.records.len());
            println!("    usn window {:?} .. {:?}", w.first_usn, w.last_usn);
            println!("    date window {:?} .. {:?}", w.first_time, w.last_time);

            let mut names: HashSet<String> = HashSet::new();
            let mut exec_names: HashSet<String> = HashSet::new();
            let mut deletes = 0usize;
            let mut creates = 0usize;
            let mut exec_deletes: HashMap<String, usize> = HashMap::new();
            let mut reasons: HashMap<&'static str, usize> = HashMap::new();

            let is_exec = |n: &str| {
                let n = n.to_lowercase();
                [".exe", ".dll", ".sys", ".scr", ".com", ".ps1", ".bat"]
                    .iter()
                    .any(|s| n.ends_with(s))
            };

            for r in &j.records {
                names.insert(r.filename.to_lowercase());
                if is_exec(&r.filename) {
                    exec_names.insert(r.filename.to_lowercase());
                }
                if r.reason.contains(UsnReason::FILE_DELETE) {
                    deletes += 1;
                    if is_exec(&r.filename) {
                        *exec_deletes.entry(r.filename.to_lowercase()).or_default() += 1;
                    }
                }
                if r.reason.contains(UsnReason::FILE_CREATE) {
                    creates += 1;
                }
                for (label, flag) in [
                    ("FILE_CREATE", UsnReason::FILE_CREATE),
                    ("FILE_DELETE", UsnReason::FILE_DELETE),
                    ("DATA_EXTEND", UsnReason::DATA_EXTEND),
                    ("DATA_OVERWRITE", UsnReason::DATA_OVERWRITE),
                    ("DATA_TRUNCATION", UsnReason::DATA_TRUNCATION),
                    ("RENAME_OLD_NAME", UsnReason::RENAME_OLD_NAME),
                    ("RENAME_NEW_NAME", UsnReason::RENAME_NEW_NAME),
                    ("CLOSE", UsnReason::CLOSE),
                    ("SECURITY_CHANGE", UsnReason::SECURITY_CHANGE),
                    ("BASIC_INFO_CHANGE", UsnReason::BASIC_INFO_CHANGE),
                ] {
                    if r.reason.contains(flag) {
                        *reasons.entry(label).or_default() += 1;
                    }
                }
            }

            println!("    distinct names {} (executables {})", names.len(), exec_names.len());
            println!("    creates {creates} deletes {deletes}");
            let mut rc: Vec<_> = reasons.into_iter().collect();
            rc.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            println!("    reasons {rc:?}");

            let t = std::time::Instant::now();
            let mut seen: HashSet<(u64, u16)> = HashSet::new();
            let (mut same, mut freed, mut realloc, mut unknown) = (0usize, 0usize, 0usize, 0usize);
            let mut examples: Vec<String> = Vec::new();
            for r in &j.records {
                if !seen.insert((r.mft_entry, r.mft_sequence)) {
                    continue;
                }
                match record_fate(&vol, r.mft_entry, r.mft_sequence) {
                    RecordFate::SameFile => same += 1,
                    RecordFate::Freed => freed += 1,
                    RecordFate::Reallocated { .. } => {
                        realloc += 1;
                        if examples.len() < 6 && is_exec(&r.filename) {
                            let f = record_fate(&vol, r.mft_entry, r.mft_sequence);
                            examples.push(format!("{}: {}", r.filename, f.describe(r.mft_entry)));
                        }
                    }
                    RecordFate::Unknown { .. } => unknown += 1,
                }
            }
            println!(
                "    distinct (entry,seq) {}: same {} freed {} REALLOCATED {} unknown {} in {:?}",
                seen.len(),
                same,
                freed,
                realloc,
                unknown,
                t.elapsed()
            );
            println!("    executables named in a FILE_DELETE: {} distinct", exec_deletes.len());
            let mut ed: Vec<_> = exec_deletes.into_iter().collect();
            ed.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            for (n, c) in ed.iter().take(12) {
                println!("      {c:5}  {n}");
            }
            for e in &examples {
                println!("    {e}");
            }
        }
    }
}
