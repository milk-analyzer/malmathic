use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use mm_sign::catalog::CatalogIndex;
use mm_sign::{TrustStore, Verdict};

const CATROOT: &str = r"C:\Windows\System32\CatRoot";

const NAMES: [&str; 8] = [
    "EmbeddedValid",
    "CatalogValid",
    "Unsigned",
    "Invalid",
    "Expired",
    "Untrusted",
    "Unknown",
    "ReadError",
];

fn collect_cats(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_cats(&path, out);
        } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("cat")) {
            out.push(path);
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(list), Some(unsigned_out)) = (args.next(), args.next()) else {
        eprintln!("usage: unsignedpop <paths.txt> <out.tsv>");
        std::process::exit(2);
    };

    let trust = TrustStore::embedded();
    let now = mm_sign::now();

    let started = Instant::now();
    let mut cats = Vec::new();
    collect_cats(std::path::Path::new(CATROOT), &mut cats);
    cats.sort();
    let mut index = CatalogIndex::new();
    for path in &cats {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let Ok(bytes) = std::fs::read(path) else { continue };
        let _ = index.add(&name, &bytes, &trust, now);
    }
    eprintln!(
        "catalog index: {} catalogs, {} members, {:.1} MB, built in {:.1}s",
        index.catalogs().len(),
        index.member_count(),
        index.memory_bytes() as f64 / 1e6,
        started.elapsed().as_secs_f64()
    );

    let Ok(text) = std::fs::read_to_string(&list) else {
        eprintln!("could not read {list}");
        std::process::exit(2);
    };
    let paths: Vec<&str> = text
        .lines()
        .map(|l| l.trim().trim_start_matches('\u{feff}'))
        .filter(|l| !l.is_empty())
        .collect();
    eprintln!("verifying {} files", paths.len());

    let next = AtomicUsize::new(0);
    let unsigned_lines: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let tally: Mutex<[usize; 8]> = Mutex::new([0; 8]);
    let done = AtomicUsize::new(0);

    let scan = Instant::now();
    let threads = std::env::var("UNSIGNEDPOP_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut local = [0usize; 8];
                let mut local_unsigned = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= paths.len() {
                        break;
                    }
                    let path = paths[i];
                    let bytes = match std::fs::read(path) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            local[7] += 1;
                            continue;
                        }
                    };
                    let verdict = mm_sign::verify_file_at(&bytes, &trust, &index, now);
                    let slot = match &verdict {
                        Verdict::Valid { .. } => 0,
                        Verdict::CatalogValid { .. } => 1,
                        Verdict::Unsigned => 2,
                        Verdict::Invalid { .. } => 3,
                        Verdict::Expired { .. } => 4,
                        Verdict::Untrusted { .. } => 5,
                        Verdict::Unknown { .. } => 6,
                    };
                    local[slot] += 1;
                    let created = std::fs::metadata(path)
                        .and_then(|m| m.created())
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let modified = std::fs::metadata(path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    local_unsigned.push(format!(
                        "{path}\t{}\t{}\t{created}\t{modified}",
                        bytes.len(),
                        NAMES[slot]
                    ));
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_multiple_of(5000) {
                        eprintln!("  {n} / {} ({:.0}s)", paths.len(), scan.elapsed().as_secs_f64());
                    }
                }
                let mut t = tally.lock().unwrap();
                for (a, b) in t.iter_mut().zip(local) {
                    *a += b;
                }
                unsigned_lines.lock().unwrap().extend(local_unsigned);
            });
        }
    });

    let t = tally.lock().unwrap();
    let names = NAMES;
    let total: usize = t.iter().sum();
    eprintln!("\nscanned {total} files in {:.1}s", scan.elapsed().as_secs_f64());
    for (name, count) in names.iter().zip(t.iter()) {
        eprintln!("  {name:<14} {count:>8}  {:.3}%", *count as f64 * 100.0 / total.max(1) as f64);
    }

    let mut lines = unsigned_lines.lock().unwrap().clone();
    lines.sort();
    let mut out = std::io::BufWriter::new(std::fs::File::create(&unsigned_out).unwrap());
    for line in &lines {
        let _ = writeln!(out, "{line}");
    }
    let _ = out.flush();
    eprintln!("wrote {} rows to {unsigned_out}", lines.len());
}
