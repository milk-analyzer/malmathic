use std::io::Cursor;

fn main() {
    for mib in [1usize, 4, 16, 64] {
        let bytes = mib * 1024 * 1024;
        let mut data = vec![0u8; bytes];
        for chunk in data.chunks_mut(8) {
            chunk[0] = 1;
        }
        let t = std::time::Instant::now();
        let (carved, stats) = ntfs_core::usn::carve_usn_records(&data);
        println!(
            "{mib} MiB of garbage: carver survived, {} records, {} candidates, {:?}",
            carved.len(),
            stats.candidates_examined,
            t.elapsed()
        );

        if std::env::args().any(|a| a == "--reader") {
            let handle = std::thread::Builder::new()
                .stack_size(8 * 1024 * 1024)
                .spawn(move || {
                    let reader = ntfs_core::usn::UsnJournalReader::new(Cursor::new(data)).unwrap();
                    reader.count()
                })
                .unwrap();
            match handle.join() {
                Ok(n) => println!("  reader yielded {n} records (survived)"),
                Err(_) => println!("  reader THREAD DIED"),
            }
        }
    }
}
