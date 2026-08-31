use mm_sign::catalog::{CatalogIndex, CatalogTrust};
use mm_sign::TrustStore;

fn main() {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: catbad <catroot-directory>");
        std::process::exit(2);
    };
    let trust = TrustStore::embedded();
    let now = mm_sign::now();
    let mut index = CatalogIndex::new();

    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("could not read {dir}");
        std::process::exit(2);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.extension().is_some_and(|e| e.eq_ignore_ascii_case("cat")) {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if let Ok(bytes) = std::fs::read(&path) {
            let _ = index.add(&name, &bytes, &trust, now);
        }
    }

    for record in index.catalogs() {
        if record.trust != CatalogTrust::Valid || !record.root_is_microsoft {
            println!(
                "{:<28} {:<10} microsoft={:<5} root={:?}\n    signer: {}\n    detail: {}",
                record.name,
                record.trust.label(),
                record.root_is_microsoft,
                record.root,
                record.signer,
                record.detail
            );
        }
    }
    let stats = index.stats();
    println!(
        "\n{} catalogs, valid {} expired {} untrusted {} invalid {} unknown {}",
        index.catalogs().len(),
        stats.valid,
        stats.expired,
        stats.untrusted,
        stats.invalid,
        stats.unknown
    );
}
