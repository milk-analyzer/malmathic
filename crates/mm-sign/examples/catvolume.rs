use std::time::Instant;

use mm_raw::Volume;
use mm_sign::{catroot, TrustStore};

fn main() {
    let device = std::env::args().nth(1).unwrap_or_else(|| r"\\.\C:".to_string());

    let file = match std::fs::File::open(&device) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("could not open {device}: {err}");
            eprintln!("raw volume access needs Administrator");
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

    let trust = TrustStore::embedded();
    let started = Instant::now();
    let index = catroot::index_volume(&volume, &trust);
    let elapsed = started.elapsed();

    let stats = index.stats();
    println!("built in            {:.1}s", elapsed.as_secs_f64());
    println!("catalogs offered    {}", stats.offered);
    println!("catalogs rejected   {}", stats.rejected);
    println!(
        "signature verdicts  valid {} / expired {} / untrusted {} / invalid {} / unknown {}",
        stats.valid, stats.expired, stats.untrusted, stats.invalid, stats.unknown
    );
    println!("members indexed     {}", index.member_count());
    println!("index memory        {:.1} MB", index.memory_bytes() as f64 / 1e6);

    for path in
        [r"\Windows\System32\notepad.exe", r"\Windows\explorer.exe", r"\Windows\System32\ntdll.dll"]
    {
        match volume.read_capped(path, 64 * 1024 * 1024) {
            Ok(bytes) => {
                println!("{path}: {}", mm_sign::verify_file(&bytes, &trust, &index).describe())
            }
            Err(err) => println!("{path}: unreadable: {err}"),
        }
    }
}
