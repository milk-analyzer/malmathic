use authenticode::AttributeCertificateIterator;
use mm_sign::pe::PeBytes;
use mm_sign::{pkcs7, verify, TrustStore};

fn main() {
    let trust = TrustStore::embedded();
    let now = mm_sign::now();

    for path in std::env::args().skip(1) {
        println!("{path}");
        let Ok(bytes) = std::fs::read(&path) else {
            println!("  could not be read");
            continue;
        };
        println!("  verdict: {}", mm_sign::verify_embedded(&bytes, &trust).describe());

        let Some(pe) = PeBytes::parse(&bytes) else {
            println!("  not a PE image");
            continue;
        };
        let entries = match AttributeCertificateIterator::new(&pe) {
            Ok(Some(entries)) => entries,
            Ok(None) => {
                println!("  no certificate table");
                continue;
            }
            Err(err) => {
                println!("  certificate table: {err}");
                continue;
            }
        };

        for entry in entries {
            let Ok(entry) = entry else {
                println!("  malformed certificate table entry");
                continue;
            };
            println!(
                "  entry revision={:#06x} type={:#06x} bytes={}",
                entry.revision,
                entry.certificate_type,
                entry.data.len()
            );
            let signed_data = match pkcs7::parse(entry.data) {
                Ok(parsed) => parsed,
                Err(err) => {
                    println!("    {err}");
                    continue;
                }
            };
            println!("    content type: {}", signed_data.econtent_type);
            for cert in &signed_data.certs {
                println!(
                    "    cert: {:?} <- {:?}  ca={}  {:?}..{:?}",
                    cert.display_name(),
                    cert.issuer_name(),
                    cert.is_ca(),
                    cert.not_before(),
                    cert.not_after()
                );
            }
            for signer in &signed_data.signers {
                println!(
                    "    signer: digest={} signature={}",
                    signer.info.digest_alg.oid, signer.info.signature_algorithm.oid
                );
                for attr in &signer.signed_attrs {
                    println!("      signed   {}", attr.oid);
                }
                for attr in &signer.unsigned_attrs {
                    println!("      unsigned {}", attr.oid);
                }
                if let Some(counter) = verify::signing_time(&signed_data, signer, &trust, now) {
                    println!(
                        "      signing time: {} (corroborated: {})",
                        counter.at, counter.trusted
                    );
                }
                let outcome = verify::verify_signer(&signed_data, signer, &trust, now);
                println!(
                    "      outcome: {:?}  root={:?}  evaluated at {}",
                    outcome.outcome, outcome.root, outcome.evaluated_at
                );
            }
        }
    }
}
