use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use mm_harvest::pe;

fn zone_of(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    let after_drive = lower.split_once(':').map(|(_, rest)| rest).unwrap_or(&lower);
    if after_drive.starts_with("\\windows\\winsxs") {
        "component store"
    } else if after_drive.starts_with("\\windows\\system32")
        || after_drive.starts_with("\\windows\\syswow64")
    {
        "system directory"
    } else if after_drive.starts_with("\\windows\\temp") {
        "Windows temp"
    } else if after_drive.starts_with("\\windows") {
        "Windows directory"
    } else if after_drive.starts_with("\\programdata") {
        "ProgramData"
    } else if after_drive.starts_with("\\program files") {
        "Program Files"
    } else if after_drive.starts_with("\\users") {
        let rest: Vec<&str> = after_drive.split('\\').filter(|s| !s.is_empty()).collect();
        let tail = rest.get(2..).map(|t| t.join("\\")).unwrap_or_default();
        if tail.starts_with("appdata\\local\\temp") {
            "user temp"
        } else if tail.starts_with("appdata") {
            "user AppData"
        } else if tail.starts_with("downloads") {
            "user Downloads"
        } else {
            "user profile"
        }
    } else {
        "elsewhere"
    }
}

#[derive(Default, Clone, Copy)]
struct Tally {
    native: usize,
    native_none: usize,
    managed: usize,
    unknown: usize,
    entry_outside: usize,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(list) = args.next() else {
        eprintln!("usage: verpop <paths.txt> [out.tsv]");
        std::process::exit(2);
    };
    let rows_out = args.next();

    let Ok(text) = std::fs::read_to_string(&list) else {
        eprintln!("could not read {list}");
        std::process::exit(2);
    };
    let paths: Vec<&str> = text
        .lines()
        .map(|l| l.trim().trim_start_matches('\u{feff}'))
        .filter(|l| !l.is_empty())
        .collect();
    eprintln!("reading {} files", paths.len());

    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let tallies: Mutex<BTreeMap<&'static str, Tally>> = Mutex::new(BTreeMap::new());
    let rows: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let started = Instant::now();
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut local: BTreeMap<&'static str, Tally> = BTreeMap::new();
                let mut local_rows = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= paths.len() {
                        break;
                    }
                    let path = paths[i];
                    let Ok(bytes) = std::fs::read(path) else { continue };
                    let zone = zone_of(path);
                    let slot = local.entry(zone).or_default();

                    if pe::is_managed_assembly(&bytes) {
                        slot.managed += 1;
                        local_rows.push(format!("{path}\t{zone}\tmanaged\t-"));
                    } else {
                        match pe::has_version_resource(&bytes) {
                            None => {
                                slot.unknown += 1;
                                local_rows.push(format!("{path}\t{zone}\tunknown\t-"));
                            }
                            Some(true) => {
                                slot.native += 1;
                                local_rows.push(format!("{path}\t{zone}\tnative\thas"));
                            }
                            Some(false) => {
                                slot.native += 1;
                                slot.native_none += 1;
                                local_rows.push(format!("{path}\t{zone}\tnative\tnone"));
                            }
                        }
                        if pe::entry_point_is_inside_a_section(&bytes) == Some(false) {
                            slot.entry_outside += 1;
                        }
                    }
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_multiple_of(20000) {
                        eprintln!(
                            "  {n} / {} ({:.0}s)",
                            paths.len(),
                            started.elapsed().as_secs_f64()
                        );
                    }
                }
                let mut t = tallies.lock().unwrap();
                for (zone, slot) in local {
                    let entry = t.entry(zone).or_default();
                    entry.native += slot.native;
                    entry.native_none += slot.native_none;
                    entry.managed += slot.managed;
                    entry.unknown += slot.unknown;
                    entry.entry_outside += slot.entry_outside;
                }
                rows.lock().unwrap().extend(local_rows);
            });
        }
    });

    let t = tallies.lock().unwrap();
    println!("\nread {} files in {:.1}s\n", paths.len(), started.elapsed().as_secs_f64());
    println!(
        "{:<20} {:>8} {:>8} {:>9} {:>8} {:>8} {:>8}",
        "zone", "native", "no ver", "rate", "managed", "unknown", "EP out"
    );
    let mut all = Tally::default();
    for (zone, slot) in t.iter() {
        println!(
            "{:<20} {:>8} {:>8} {:>8.2}% {:>8} {:>8} {:>8}",
            zone,
            slot.native,
            slot.native_none,
            100.0 * slot.native_none as f64 / slot.native.max(1) as f64,
            slot.managed,
            slot.unknown,
            slot.entry_outside
        );
        all.native += slot.native;
        all.native_none += slot.native_none;
        all.managed += slot.managed;
        all.unknown += slot.unknown;
        all.entry_outside += slot.entry_outside;
    }
    println!(
        "{:<20} {:>8} {:>8} {:>8.2}% {:>8} {:>8} {:>8}",
        "ALL",
        all.native,
        all.native_none,
        100.0 * all.native_none as f64 / all.native.max(1) as f64,
        all.managed,
        all.unknown,
        all.entry_outside
    );

    let offered: Tally = ["system directory", "component store"]
        .iter()
        .filter_map(|z| t.get(z))
        .fold(Tally::default(), |mut acc, s| {
            acc.native += s.native;
            acc.native_none += s.native_none;
            acc
        });
    println!(
        "\nthe two zones `no_version_resource` is offered in: {} of {} native PE images \
         carry none - {:.2}%",
        offered.native_none,
        offered.native,
        100.0 * offered.native_none as f64 / offered.native.max(1) as f64
    );

    if let Some(out) = rows_out {
        let mut rows = rows.lock().unwrap().clone();
        rows.sort();
        let mut file = std::io::BufWriter::new(std::fs::File::create(&out).unwrap());
        for row in &rows {
            let _ = writeln!(file, "{row}");
        }
        let _ = file.flush();
        eprintln!("wrote {} rows to {out}", rows.len());
    }
}
