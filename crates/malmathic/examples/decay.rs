use std::collections::HashMap;
use std::io::{BufWriter, Write};

use ntfs_core::usn::UsnReason;

const BITMAP_RECORD: u64 = 6;
const MAX_BITMAP_BYTES: usize = 512 * 1024 * 1024;
const ATTR_DIRECTORY: u32 = 0x10;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    Recoverable,
    ClustersGone,
    RecordGone,
    StillThere,
    Unknown,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Recoverable => "RECOVERABLE",
            Outcome::ClustersGone => "CLUSTERS_GONE",
            Outcome::RecordGone => "RECORD_GONE",
            Outcome::StillThere => "STILL_THERE",
            Outcome::Unknown => "UNKNOWN",
        }
    }
}

fn bit(bits: &[u8], cluster: u64) -> Option<bool> {
    let byte = usize::try_from(cluster / 8).ok()?;
    Some(bits.get(byte)? & (1 << (cluster % 8)) != 0)
}

fn is_executable(name: &str) -> bool {
    let lower = name.to_lowercase();
    [".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".ps1", ".bat", ".cmd", ".vbs", ".js"]
        .iter()
        .any(|e| lower.ends_with(e))
}

struct Row {
    hours: f64,
    entry: u64,
    when: String,
    executable: bool,
    outcome: Outcome,
    name: String,
    free: u64,
    reused: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(image) = args.first() else {
        eprintln!("usage: decay <image> [--tsv out.tsv]");
        std::process::exit(2);
    };
    let tsv = args.iter().position(|a| a == "--tsv").and_then(|i| args.get(i + 1)).cloned();
    let read_back = args.iter().any(|a| a == "--read");
    let mut bytes_read: u64 = 0;

    let partitions = mm_env::find_ntfs_partitions(std::path::Path::new(image))
        .expect("scanning the image for NTFS");
    let mut chosen = None;
    for partition in &partitions {
        if let Ok(volume) = mm_env::open_partition(std::path::Path::new(image), *partition) {
            if volume.is_windows_install() {
                chosen = Some(volume);
                break;
            }
            if chosen.is_none() {
                chosen = Some(volume);
            }
        }
    }
    let Some(volume) = chosen else {
        eprintln!("no readable NTFS in {image}");
        std::process::exit(1);
    };

    let bitmap = volume
        .read_record_capped(BITMAP_RECORD, MAX_BITMAP_BYTES)
        .ok()
        .filter(|b| b.iter().any(|byte| *byte != 0));
    if bitmap.is_none() {
        eprintln!("$Bitmap could not be read; every cluster answer will be UNKNOWN");
    }

    let journal = mm_raw::usn::read_journal(&volume);
    let window = journal.window();
    let Some(end) = window.last_time else {
        eprintln!("the journal carries no timestamps");
        std::process::exit(1);
    };
    eprintln!(
        "journal: {} records, {:?} .. {:?}",
        journal.records.len(),
        window.first_time,
        window.last_time
    );

    let mut seen: HashMap<(u64, u16), ()> = HashMap::new();
    let mut rows: Vec<Row> = Vec::new();
    let mut cache: HashMap<u64, Option<(bool, u16)>> = HashMap::new();

    for record in &journal.records {
        if !record.reason.intersects(UsnReason::FILE_DELETE) {
            continue;
        }
        if record.file_attributes.bits() & ATTR_DIRECTORY != 0 {
            continue;
        }
        if seen.insert((record.mft_entry, record.mft_sequence), ()).is_some() {
            continue;
        }
        let hours = (end - record.timestamp).num_milliseconds() as f64 / 3_600_000.0;
        let executable = is_executable(&record.filename);

        let header = *cache.entry(record.mft_entry).or_insert_with(|| {
            volume
                .fs()
                .read_record(record.mft_entry)
                .ok()
                .and_then(|b| ntfs_core::MftRecordHeader::parse(&b).ok())
                .filter(|h| &h.signature == b"FILE" && h.is_base_record())
                .map(|h| (h.is_in_use(), h.sequence_number))
        });

        let (outcome, free, reused) = match header {
            None => (Outcome::Unknown, 0, 0),
            Some((true, now)) if now == record.mft_sequence => (Outcome::StillThere, 0, 0),
            Some((true, _)) => (Outcome::RecordGone, 0, 0),
            Some((false, now)) if now.wrapping_sub(record.mft_sequence) > 1 => {
                (Outcome::RecordGone, 0, 0)
            }
            Some((false, _)) => {
                let runs = volume.data_runs(record.mft_entry);
                match &bitmap {
                    None => (Outcome::Unknown, 0, 0),
                    Some(bits) => {
                        let mut free = 0u64;
                        let mut reused = 0u64;
                        for run in &runs {
                            let Some(lcn) = run.lcn else { continue };
                            for cluster in lcn..lcn.saturating_add(run.length) {
                                match bit(bits, cluster) {
                                    Some(true) => reused += 1,
                                    Some(false) => free += 1,
                                    None => {}
                                }
                            }
                        }
                        if reused == 0 {
                            if read_back {
                                match volume.read_record_capped(record.mft_entry, 64 << 20) {
                                    Ok(b) if !b.is_empty() => {
                                        bytes_read += b.len() as u64;
                                        (Outcome::Recoverable, free, reused)
                                    }
                                    _ => (Outcome::Unknown, free, reused),
                                }
                            } else {
                                (Outcome::Recoverable, free, reused)
                            }
                        } else {
                            (Outcome::ClustersGone, free, reused)
                        }
                    }
                }
            }
        };
        rows.push(Row {
            hours,
            entry: record.mft_entry,
            when: record.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            executable,
            outcome,
            name: record.filename.clone(),
            free,
            reused,
        });
    }

    eprintln!("{} distinct file deletions", rows.len());
    if read_back {
        eprintln!("{bytes_read} bytes read back from the records called RECOVERABLE");
    }

    let buckets: [(f64, f64, &str); 7] = [
        (0.0, 1.0, "< 1 h"),
        (1.0, 2.0, "1 - 2 h"),
        (2.0, 4.0, "2 - 4 h"),
        (4.0, 8.0, "4 - 8 h"),
        (8.0, 16.0, "8 - 16 h"),
        (16.0, 24.0, "16 - 24 h"),
        (24.0, f64::INFINITY, "> 24 h"),
    ];

    for (title, only_exe) in [("ALL DELETED FILES", false), ("DELETED EXECUTABLES ONLY", true)] {
        println!("\n== {title} ==  age = from the deletion to the end of the journal");
        println!(
            "{:<10} {:>7} {:>12} {:>14} {:>12} {:>12} {:>8} {:>9}",
            "age",
            "n",
            "RECOVERABLE",
            "CLUSTERS GONE",
            "RECORD GONE",
            "STILL THERE",
            "UNKNOWN",
            "recov %"
        );
        let show = |mine: Vec<&Row>, label: &str| {
            if mine.is_empty() {
                return;
            }
            let count = |o: Outcome| mine.iter().filter(|r| r.outcome == o).count();
            println!(
                "{:<10} {:>7} {:>12} {:>14} {:>12} {:>12} {:>8} {:>8.1}%",
                label,
                mine.len(),
                count(Outcome::Recoverable),
                count(Outcome::ClustersGone),
                count(Outcome::RecordGone),
                count(Outcome::StillThere),
                count(Outcome::Unknown),
                100.0 * count(Outcome::Recoverable) as f64 / mine.len() as f64
            );
        };
        for (lo, hi, label) in buckets {
            show(
                rows.iter()
                    .filter(|r| (!only_exe || r.executable) && r.hours >= lo && r.hours < hi)
                    .collect(),
                label,
            );
        }
        show(rows.iter().filter(|r| !only_exe || r.executable).collect(), "TOTAL");
    }

    if let Some(path) = tsv {
        let file = std::fs::File::create(&path).expect("creating the output");
        let mut w = BufWriter::with_capacity(1 << 20, file);
        let _ = writeln!(
            w,
            "hours_before_capture\twhen\tmft_entry\texecutable\toutcome\tname\tclusters_free\tclusters_reused"
        );
        for r in &rows {
            let _ = writeln!(
                w,
                "{:.4}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                r.hours,
                r.when,
                r.entry,
                r.executable,
                r.outcome.label(),
                r.name,
                r.free,
                r.reused
            );
        }
        w.flush().unwrap();
        eprintln!("wrote {path}");
    }
}
