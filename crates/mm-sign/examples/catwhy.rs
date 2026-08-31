use mm_sign::catalog::{self, CatalogIndex};
use mm_sign::TrustStore;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(catroot), Some(target)) = (args.next(), args.next()) else {
        eprintln!("usage: catwhy <catroot-dir> <file>");
        std::process::exit(2);
    };
    let Ok(bytes) = std::fs::read(&target) else {
        eprintln!("could not read {target}");
        std::process::exit(2);
    };

    let trust = TrustStore::embedded();
    let now = mm_sign::now();

    let keys = catalog::candidate_keys(&bytes);
    println!("{target}");
    for key in &keys {
        println!("  candidate {:?} {}", key.alg(), key.to_hex());
    }
    if keys.is_empty() {
        println!("  no candidate keys — the file is not a PE this build can parse");
    }

    let mut entries: Vec<_> = std::fs::read_dir(&catroot).unwrap().filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.to_ascii_lowercase().ends_with(".cat") {
            continue;
        }
        let Ok(cat_bytes) = std::fs::read(entry.path()) else { continue };
        let Ok(parsed) = catalog::parse(&cat_bytes) else { continue };
        let hits: Vec<_> = parsed
            .members()
            .into_iter()
            .filter(|m| m.key.is_some_and(|k| keys.contains(&k)))
            .collect();
        if hits.is_empty() {
            continue;
        }
        let mut index = CatalogIndex::new();
        let record = index.add(&name, &cat_bytes, &trust, now);
        println!("  listed in {name}");
        for hit in &hits {
            println!(
                "      member {:?} {}  file={:?}  osattr={:?}",
                hit.key.map(|k| k.alg()),
                hit.key.map(|k| k.to_hex()).unwrap_or_default(),
                hit.file_name(),
                hit.name_value("OSAttr"),
            );
        }
        match record {
            Ok(record) => println!(
                "      catalog signature: {} by {} (root {:?}, microsoft={}) {}",
                record.trust.label(),
                record.signer,
                record.root,
                record.root_is_microsoft,
                record.detail
            ),
            Err(err) => println!("      catalog signature: unreadable: {err}"),
        }
    }
}
