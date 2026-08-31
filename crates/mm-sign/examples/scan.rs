use std::io::Write;

use mm_sign::{embedded_signers, verify_embedded, TrustStore, Verdict};

fn main() {
    let Some(list) = std::env::args().nth(1) else {
        eprintln!("usage: scan <file-with-one-path-per-line>");
        std::process::exit(2);
    };
    let Ok(text) = std::fs::read_to_string(&list) else {
        eprintln!("could not read {list}");
        std::process::exit(2);
    };

    let trust = TrustStore::embedded();
    let now = mm_sign::now();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let _ = writeln!(
        out,
        "path\tverdict\tsigner\tmicrosoft\troot\tsigning_time\ttime_trusted\tunreached\tdetail"
    );

    for line in text.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                let _ = writeln!(out, "{path}\tREADERR\t\t\t\t\t\t\t{err}");
                continue;
            }
        };

        let verdict = verify_embedded(&bytes, &trust);
        let signers = embedded_signers(&bytes, &trust, now).unwrap_or_default();
        let best = signers.iter().max_by_key(|s| s.rank());

        let (kind, signer, microsoft, detail) = match &verdict {
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
        };

        let root = best.and_then(|b| b.root).unwrap_or("");
        let time = best.and_then(|b| b.signing_time).map(|t| t.to_rfc3339()).unwrap_or_default();
        let time_trusted = best.map(|b| b.signing_time_trusted).unwrap_or(false);
        let unreached = best.and_then(|b| b.unreached_issuer.clone()).unwrap_or_default();

        let _ = writeln!(
            out,
            "{path}\t{kind}\t{signer}\t{microsoft}\t{root}\t{time}\t{time_trusted}\t{unreached}\t{detail}"
        );
    }
}
