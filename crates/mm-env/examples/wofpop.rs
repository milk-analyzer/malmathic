use std::collections::BTreeMap;
use std::time::Instant;

use mm_raw::{wof, Volume};

const ZONES: &[(&str, &str)] = &[
    ("Defender platform", "\\programdata\\microsoft\\windows defender\\platform"),
    ("drivers", "\\windows\\system32\\drivers"),
    ("System32", "\\windows\\system32"),
    ("WinSxS", "\\windows\\winsxs"),
    ("Windows (other)", "\\windows"),
    ("Program Files", "\\program files"),
    ("everywhere else", ""),
];

#[derive(Default)]
struct Tally {
    files: usize,
    compressed: usize,
    bytes: u64,
    by_algorithm: BTreeMap<&'static str, usize>,
    read_ok: usize,
    read_failed: usize,
    looked_like_a_pe: usize,
    not_a_pe: usize,
}

fn zone_of(key: &str) -> &'static str {
    for (name, prefix) in ZONES {
        if prefix.is_empty() || key.starts_with(prefix) {
            return name;
        }
    }
    "everywhere else"
}

fn main() {
    let mut args = std::env::args().skip(1);
    let device = args.next().unwrap_or_else(|| r"\\.\C:".to_string());
    let mut dump: Option<String> = None;
    while let Some(arg) = args.next() {
        if arg == "--dump" {
            dump = args.next();
        }
    }

    let file = match std::fs::File::open(&device) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("could not open {device}: {err}");
            eprintln!("raw volume access needs Administrator; from WinRE it is the only way in");
            std::process::exit(2);
        }
    };
    let volume = match Volume::open(file, &device) {
        Ok(volume) => volume,
        Err(err) => {
            eprintln!("{device}: {err}");
            std::process::exit(2);
        }
    };
    println!("{device}: {:?}, windows install: {}", volume.kind(), volume.is_windows_install());

    if let Some(path) = dump {
        dump_stream(&volume, &path);
        return;
    }

    let started = Instant::now();
    let mut totals = Tally::default();
    let mut zones: BTreeMap<&'static str, Tally> = BTreeMap::new();
    walk(&volume, "", 0, &mut totals, &mut zones);
    let elapsed = started.elapsed().as_secs_f64();

    println!("\nwalked {} files in {elapsed:.1}s", totals.files);
    if totals.files == 0 {
        eprintln!("the walk found no files at all, which is a failure of this harness");
        std::process::exit(1);
    }
    println!(
        "Compact OS: {} files ({:.1}% of what was walked), {:.1} MB uncompressed",
        totals.compressed,
        100.0 * totals.compressed as f64 / totals.files as f64,
        totals.bytes as f64 / 1e6
    );
    if totals.compressed == 0 {
        println!("\nThis machine has Compact OS off. `compact /CompactOs:query` will say so.");
        println!(
            "The defect this measures cannot occur here; measure on a machine that has it on."
        );
        return;
    }

    println!("\nby algorithm");
    for (name, count) in &totals.by_algorithm {
        println!(
            "  {name:<22} {count:>7}  {:>5.1}%",
            100.0 * *count as f64 / totals.compressed as f64
        );
    }
    let lzx = totals.by_algorithm.get("LZX").copied().unwrap_or(0);
    println!(
        "\nLZX is {lzx} files, {:.1}% of the compressed population and {:.2}% of the volume — \n\
         that is the share this build still cannot read.",
        100.0 * lzx as f64 / totals.compressed as f64,
        100.0 * lzx as f64 / totals.files as f64
    );

    println!("\nby zone");
    println!("  {:<22} {:>8} {:>8} {:>7}", "zone", "files", "compact", "share");
    for (name, _) in ZONES {
        let Some(t) = zones.get(name) else { continue };
        if t.files == 0 {
            continue;
        }
        println!(
            "  {name:<22} {:>8} {:>8} {:>6.1}%",
            t.files,
            t.compressed,
            100.0 * t.compressed as f64 / t.files as f64
        );
    }

    println!("\nreading them back through Volume::read_capped");
    println!("  read and reassembled   {}", totals.read_ok);
    println!("  refused (UNKNOWN)      {}", totals.read_failed);
    println!("  .exe/.dll/.sys with MZ {}", totals.looked_like_a_pe);
    println!("  .exe/.dll/.sys without {}", totals.not_a_pe);
    if totals.not_a_pe > 0 {
        eprintln!("\na Compact-OS executable that read back without an MZ is a decoder bug");
        std::process::exit(1);
    }
    if totals.read_ok == 0 {
        eprintln!("\nfound compressed files and read none of them back");
        std::process::exit(1);
    }
}

fn walk(
    volume: &Volume<std::fs::File>,
    prefix: &str,
    depth: usize,
    totals: &mut Tally,
    zones: &mut BTreeMap<&'static str, Tally>,
) {
    if depth > 12 {
        return;
    }
    for entry in volume.list_directory_entries(prefix) {
        let key = format!("{prefix}\\{}", entry.name).to_lowercase();
        let backing = volume.wof_backing(entry.record);

        let children = volume.list_directory_entries(&key);
        if !children.is_empty() {
            walk(volume, &key, depth + 1, totals, zones);
            continue;
        }

        totals.files += 1;
        let zone = zones.entry(zone_of(&key)).or_default();
        zone.files += 1;

        let Some((backing, size)) = backing else { continue };
        totals.compressed += 1;
        totals.bytes += size;
        zone.compressed += 1;
        *totals.by_algorithm.entry(backing.algorithm_name()).or_default() += 1;

        match volume.read_record_capped(entry.record, 64 * 1024 * 1024) {
            Ok(bytes) => {
                totals.read_ok += 1;
                let executable = [".exe", ".dll", ".sys"].iter().any(|e| key.ends_with(e));
                if executable {
                    if bytes.starts_with(b"MZ") {
                        totals.looked_like_a_pe += 1;
                    } else {
                        totals.not_a_pe += 1;
                        println!("  NOT A PE after decompression: {key} ({size} bytes declared)");
                    }
                }
            }
            Err(_) => totals.read_failed += 1,
        }
    }
}

fn dump_stream(volume: &Volume<std::fs::File>, path: &str) {
    let Some(record) = volume.resolve(&path.to_lowercase()) else {
        eprintln!("{path} does not resolve on this volume");
        std::process::exit(2);
    };
    let Some((backing, size)) = volume.wof_backing(record) else {
        println!("{path} is not Compact-OS compressed");
        return;
    };
    println!("{path}");
    println!(
        "  provider {} ({}), algorithm {} ({}), uncompressed {size} bytes",
        backing.provider,
        if backing.is_file_provider() { "file" } else { "other" },
        backing.algorithm,
        backing.algorithm_name()
    );
    let Some(chunk_size) = backing.chunk_size() else {
        println!("  no chunk size for this algorithm; nothing more to show");
        return;
    };
    let chunks = (size as usize).div_ceil(chunk_size);
    println!("  chunk size {chunk_size}, {chunks} chunks, table {} bytes", (chunks - 1) * 4);

    let stream = match volume.read_named_stream(&path.to_lowercase(), wof::STREAM_NAME, 1 << 20) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("  the WofCompressedData stream would not read: {err}");
            std::process::exit(1);
        }
    };
    println!("  stream head, first 64 bytes:");
    print!("   ");
    for byte in stream.iter().take(64) {
        print!(" {byte:02x}");
    }
    println!();
    println!("  first eight table entries, read as little-endian u32:");
    for i in 0..8.min(chunks.saturating_sub(1)) {
        let at = i * 4;
        let Some(slice) = stream.get(at..at + 4) else { break };
        let value = u32::from_le_bytes(slice.try_into().unwrap());
        println!("    chunk {:>3} ends at +{value}", i + 1);
    }
    println!(
        "  those offsets must ascend, and the last must be under the stream length minus the \n\
         table. If they do, the layout in `mm_raw::wof` is the layout on this disk."
    );

    match volume.read_record_capped(record, wof::MAX_OUTPUT) {
        Ok(bytes) => println!(
            "  decompressed to {} bytes, first four: {:02x?}",
            bytes.len(),
            &bytes[..4.min(bytes.len())]
        ),
        Err(err) => println!("  it would not decompress: {err}"),
    }
}
