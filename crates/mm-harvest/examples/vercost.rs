use std::time::Instant;

use mm_harvest::pe;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(list) = args.next() else {
        eprintln!("usage: vercost <paths.txt> [n]");
        std::process::exit(2);
    };
    let limit: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(2000);

    let Ok(text) = std::fs::read_to_string(&list) else {
        eprintln!("could not read {list}");
        std::process::exit(2);
    };

    let mut images: Vec<Vec<u8>> = Vec::new();
    let mut total_bytes = 0usize;
    for path in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if images.len() >= limit {
            break;
        }
        if let Ok(bytes) = std::fs::read(path) {
            total_bytes += bytes.len();
            images.push(bytes);
        }
    }
    println!(
        "{} images held in memory, {:.1} MB, mean {:.0} KB",
        images.len(),
        total_bytes as f64 / 1e6,
        total_bytes as f64 / images.len().max(1) as f64 / 1024.0
    );

    let mut sink = 0usize;
    for image in &images {
        sink += usize::from(pe::has_version_resource(image).is_some());
    }

    let started = Instant::now();
    let rounds = 20;
    for _ in 0..rounds {
        for image in &images {
            sink += usize::from(pe::has_version_resource(image) == Some(false));
            sink += usize::from(pe::entry_point_is_inside_a_section(image) == Some(false));
        }
    }
    let elapsed = started.elapsed();
    let calls = rounds * images.len();
    let per_file = elapsed.as_secs_f64() / calls as f64;

    println!("(checksum {sink})");
    println!(
        "\nversion resource + entry point, both, on bytes already in memory:\n  \
         {:.3} us per file  ({} files x {rounds} rounds in {:.3} s)",
        per_file * 1e6,
        images.len(),
        elapsed.as_secs_f64()
    );

    println!("\nscaled to the shortlists the two datasets actually produce:");
    for (label, n) in [
        ("VM, signature shortlist", 27usize),
        ("reference laptop, signature shortlist", 116),
        ("reference laptop, plus the 861 out-of-band admissions", 977),
        ("ten times the largest shortlist measured", 9770),
    ] {
        println!("  {:<56} {:>9.2} ms", label, per_file * n as f64 * 1e3);
    }

    let started = Instant::now();
    for image in &images {
        sink += pe::code_sections(image).len();
    }
    println!(
        "\nfor contrast, `code_sections` (the entropy histogram) on the same {} files: \
         {:.1} us per file - {:.0}x this feature",
        images.len(),
        started.elapsed().as_secs_f64() / images.len() as f64 * 1e6,
        (started.elapsed().as_secs_f64() / images.len() as f64) / per_file
    );
    println!("(checksum {sink})");
}
