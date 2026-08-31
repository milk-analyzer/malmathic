use std::io::{BufWriter, Write};

fn ts(t: Option<chrono::DateTime<chrono::Utc>>) -> String {
    t.map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()).unwrap_or_else(|| "-".into())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (image, out) = match args.as_slice() {
        [i, o] => (i.clone(), o.clone()),
        _ => {
            eprintln!("usage: mftdump <image> <out.tsv>");
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

    let file = std::fs::File::create(&out).expect("creating the output");
    let mut w = BufWriter::with_capacity(1 << 20, file);
    let mut n: u64 = 0;
    let stats = mm_harvest::filesystem::enumerate(&volume, &mut |path, f| {
        n += 1;
        let _ = writeln!(
            w,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            path.display_path(),
            f.size,
            if f.is_directory { "D" } else { "F" },
            if f.in_use { "L" } else { "X" },
            ts(f.si_created),
            ts(f.si_modified),
            ts(f.si_mft_modified),
            ts(f.fn_created),
        );
    })
    .expect("walking the $MFT");
    w.flush().unwrap();
    eprintln!(
        "{n} emitted; records_read={} files_seen={} deleted_seen={} unparsable={}",
        stats.records_read, stats.files_seen, stats.deleted_seen, stats.unparsable
    );
}
