use std::time::Instant;

use mm_env::{BlockReader, CacheStats};
use mm_raw::Volume;
use mm_sign::catalog::{CatalogIndex, CATROOT_DIRECTORIES, MAX_CATALOG_BYTES};
use mm_sign::TrustStore;

const VARIANTS: &[(&str, bool, bool, usize)] = &[
    ("path/8", false, false, 8),
    ("path/64", false, false, 64),
    ("path/512", false, false, 512),
    ("record/8", true, false, 8),
    ("record-order/8", true, true, 8),
    ("record-order/64", true, true, 64),
    ("record-order/256", true, true, 256),
];

#[derive(Default)]
struct Outcome {
    seconds: f64,
    read_seconds: f64,
    files: usize,
    bytes: u64,
    members: usize,
    catalogs: usize,
    cache: CacheStats,
}

fn report(label: &str, o: &Outcome) {
    println!("{label}");
    println!(
        "  wall clock          {:.1} s   (reading {:.1} s, parsing+verifying {:.1} s)",
        o.seconds,
        o.read_seconds,
        o.seconds - o.read_seconds
    );
    println!("  catalogs read       {} ({:.1} MB)", o.files, o.bytes as f64 / 1e6);
    println!("  indexed             {} catalogs, {} members", o.catalogs, o.members);
    println!(
        "  block lookups       {} hits / {} misses = {:.4} hit rate ({} conflict evictions)",
        o.cache.hits,
        o.cache.misses,
        o.cache.hit_rate().unwrap_or(0.0),
        o.cache.conflicts
    );
    println!(
        "  device              {} reads, {:.1} MB — {:.1}x amplification over the {:.1} MB wanted",
        o.cache.device_reads,
        o.cache.device_bytes as f64 / 1e6,
        if o.bytes > 0 { o.cache.device_bytes as f64 / o.bytes as f64 } else { 0.0 },
        o.bytes as f64 / 1e6,
    );
    println!();
}

fn is_catalog(name: &str) -> bool {
    name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(".cat")
}

#[cfg(windows)]
fn main() {
    let mut args = std::env::args().skip(1);
    let device = args.next().unwrap_or_else(|| r"\\.\C:".to_string());
    let wanted: Vec<String> = args.collect();

    let trust = TrustStore::embedded();
    let now = mm_sign::now();

    for &(label, by_record, sorted, blocks) in VARIANTS {
        if !wanted.is_empty() && !wanted.iter().any(|w| w == label) {
            continue;
        }

        let raw = match mm_env::win::VolumeDevice::open(&device) {
            Ok(d) => d,
            Err(err) => {
                eprintln!("could not open {device}: {err} — raw access needs Administrator");
                std::process::exit(2);
            }
        };
        let reader = BlockReader::with_block_count(raw, blocks);
        let counters = reader.counters();
        let volume = match Volume::open(reader, &device) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("{device}: {err}");
                std::process::exit(2);
            }
        };

        let before = counters.snapshot();
        let started = Instant::now();
        let mut index = CatalogIndex::new();
        let (mut files, mut bytes, mut read_ns) = (0usize, 0u64, 0u128);

        for directory in CATROOT_DIRECTORIES {
            let mut entries: Vec<_> = volume
                .list_directory_entries(directory)
                .into_iter()
                .filter(|e| is_catalog(&e.name))
                .collect();
            if sorted {
                entries.sort_by_key(|e| e.record);
            }
            for entry in entries {
                let read_started = Instant::now();
                let got = if by_record {
                    volume.read_record_capped(entry.record, MAX_CATALOG_BYTES)
                } else {
                    let path = format!("{}\\{}", directory.trim_end_matches('\\'), entry.name);
                    volume.read_capped(&path, MAX_CATALOG_BYTES)
                };
                read_ns += read_started.elapsed().as_nanos();
                let Ok(b) = got else { continue };
                files += 1;
                bytes += b.len() as u64;
                let _ = index.add(&entry.name, &b, &trust, now);
            }
        }

        report(
            label,
            &Outcome {
                seconds: started.elapsed().as_secs_f64(),
                read_seconds: read_ns as f64 / 1e9,
                files,
                bytes,
                members: index.member_count(),
                catalogs: index.catalogs().len(),
                cache: counters.snapshot().since(before),
            },
        );
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("catprofile reads a raw Windows volume and only runs on Windows");
}
