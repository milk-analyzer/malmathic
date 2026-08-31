use std::io::Write;
use std::time::Instant;

use mm_sign::catalog::{self, CatalogIndex, CatalogTrust};
use mm_sign::{TrustStore, Verdict};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(catroot), Some(list)) = (args.next(), args.next()) else {
        eprintln!("usage: catscan <catroot-dir> <file-with-one-path-per-line>");
        std::process::exit(2);
    };

    let trust = TrustStore::embedded();
    let now = mm_sign::now();

    let started = Instant::now();
    let mut index = CatalogIndex::new();
    let mut bytes_read = 0u64;
    let mut entries: Vec<_> = match std::fs::read_dir(&catroot) {
        Ok(dir) => dir.filter_map(|e| e.ok()).collect(),
        Err(err) => {
            eprintln!("could not read {catroot}: {err}");
            std::process::exit(2);
        }
    };
    entries.sort_by_key(|e| e.file_name());
    for entry in &entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.to_ascii_lowercase().ends_with(".cat") {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else { continue };
        bytes_read = bytes_read.saturating_add(bytes.len() as u64);
        let _ = index.add(&name, &bytes, &trust, now);
    }
    let build = started.elapsed();

    let stats = index.stats();
    eprintln!("catalog index");
    eprintln!(
        "  built in            {:.1}s from {:.1} MB",
        build.as_secs_f64(),
        bytes_read as f64 / 1e6
    );
    eprintln!("  catalogs offered    {}", stats.offered);
    eprintln!("  catalogs parsed     {}", stats.offered - stats.rejected);
    eprintln!("  catalogs rejected   {}", stats.rejected);
    for (name, why) in stats.rejections.iter().take(8) {
        eprintln!("      {name}: {why}");
    }
    eprintln!(
        "  signature verdicts  valid {} / expired {} / untrusted {} / invalid {} / unknown {}",
        stats.valid, stats.expired, stats.untrusted, stats.invalid, stats.unknown
    );
    eprintln!("  members seen        {}", stats.members_seen);
    eprintln!("  members indexed     {}", index.member_count());
    eprintln!("  duplicate members   {}", stats.duplicate_members);
    eprintln!("  unkeyed members     {} {:?}", stats.unkeyed_members, stats.unkeyed_lengths);
    eprintln!("  index memory        {:.1} MB", index.memory_bytes() as f64 / 1e6);

    let non_microsoft: Vec<_> = index
        .catalogs()
        .iter()
        .filter(|c| c.trust == CatalogTrust::Valid && !c.root_is_microsoft)
        .collect();
    eprintln!("  valid, non-Microsoft root: {}", non_microsoft.len());
    for record in non_microsoft.iter().take(8) {
        eprintln!("      {} — {} — {}", record.name, record.signer, record.root.unwrap_or("?"));
    }

    let Ok(text) = std::fs::read_to_string(&list) else {
        eprintln!("could not read {list}");
        std::process::exit(2);
    };

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let _ = writeln!(out, "path\tcombined\tembedded\tcatalog\tsigner\tmicrosoft\tdetail");

    let scan_started = Instant::now();
    let mut files = 0usize;
    for line in text.lines() {
        let path = line.trim().trim_start_matches('\u{feff}');
        if path.is_empty() {
            continue;
        }
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                let _ = writeln!(out, "{path}\tREADERR\tREADERR\tREADERR\t\t\t{err}");
                continue;
            }
        };
        files += 1;

        let embedded = mm_sign::verify_embedded_at(&bytes, &trust, now);
        let from_catalog = catalog::verify_catalog(&bytes, &index);
        let combined = mm_sign::verify_file_at(&bytes, &trust, &index, now);

        let (kind, signer, microsoft, detail) = describe(&combined);
        let _ = writeln!(
            out,
            "{path}\t{kind}\t{}\t{}\t{signer}\t{microsoft}\t{detail}",
            describe(&embedded).0,
            describe(&from_catalog).0
        );
    }
    let _ = out.flush();
    eprintln!("\nverified {files} files in {:.1}s", scan_started.elapsed().as_secs_f64());
}

fn describe(verdict: &Verdict) -> (&'static str, String, bool, String) {
    match verdict {
        Verdict::Unsigned => ("Unsigned", String::new(), false, String::new()),
        Verdict::Valid { signer, root_is_microsoft } => {
            ("Valid", signer.clone(), *root_is_microsoft, String::new())
        }
        Verdict::CatalogValid { signer, catalog, root_is_microsoft } => {
            ("CatalogValid", signer.clone(), *root_is_microsoft, catalog.clone())
        }
        Verdict::Invalid { reason } => ("Invalid", String::new(), false, reason.clone()),
        Verdict::Expired { signer } => ("Expired", signer.clone(), false, String::new()),
        Verdict::Untrusted { signer, self_signed_leaf } => (
            "Untrusted",
            signer.clone(),
            false,
            if *self_signed_leaf { "self-signed leaf" } else { "unrecognised CA" }.into(),
        ),
        Verdict::Unknown { reason } => ("Unknown", String::new(), false, reason.clone()),
    }
}
