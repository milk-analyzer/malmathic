use std::io::Write;

use mm_harvest::pe;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (image, list, out) = match args.as_slice() {
        [i, l] => (i.clone(), l.clone(), None),
        [i, l, o] => (i.clone(), l.clone(), Some(o.clone())),
        _ => {
            eprintln!("usage: verimage <image> <paths.txt> [out.tsv]");
            std::process::exit(2);
        }
    };

    let partitions = mm_env::find_ntfs_partitions(std::path::Path::new(&image))
        .expect("scanning the image for NTFS");
    let mut chosen = None;
    for partition in &partitions {
        if let Ok(volume) = mm_env::open_partition(std::path::Path::new(&image), *partition) {
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

    let text = std::fs::read_to_string(&list).expect("reading the path list");
    let paths: Vec<&str> = text
        .lines()
        .map(|l| l.trim().trim_start_matches('\u{feff}'))
        .filter(|l| !l.is_empty())
        .collect();
    eprintln!("reading {} files from {image}", paths.len());

    let (mut native, mut none, mut managed, mut unknown, mut unreadable) = (0, 0, 0, 0, 0);
    let mut rows = Vec::new();
    for path in &paths {
        let Ok(bytes) = volume.read_capped(path, 128 * 1024 * 1024) else {
            unreadable += 1;
            rows.push(format!("{path}\tunreadable\t-"));
            continue;
        };
        if pe::is_managed_assembly(&bytes) {
            managed += 1;
            rows.push(format!("{path}\tmanaged\t-"));
            continue;
        }
        match pe::has_version_resource(&bytes) {
            None => {
                unknown += 1;
                rows.push(format!("{path}\tunknown\t-"));
            }
            Some(true) => {
                native += 1;
                rows.push(format!("{path}\tnative\thas"));
            }
            Some(false) => {
                native += 1;
                none += 1;
                rows.push(format!("{path}\tnative\tnone"));
            }
        }
    }

    println!(
        "native {native}, of which no version resource {none} ({:.2}%); \
         managed {managed}; unparsable {unknown}; unreadable {unreadable}",
        100.0 * none as f64 / native.max(1) as f64
    );
    for row in rows.iter().filter(|r| r.ends_with("\tnone")) {
        println!("  NO VERSION RESOURCE  {}", row.split('\t').next().unwrap_or(""));
    }

    if let Some(out) = out {
        let mut file = std::io::BufWriter::new(std::fs::File::create(&out).unwrap());
        for row in &rows {
            let _ = writeln!(file, "{row}");
        }
        let _ = file.flush();
        eprintln!("wrote {} rows to {out}", rows.len());
    }
}
