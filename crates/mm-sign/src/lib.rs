#![forbid(unsafe_code)]

#[cfg(test)]
mod attacks;
pub mod catalog;
pub mod catroot;
pub mod cert;
pub mod crypto;
pub mod der_walk;
pub mod pe;
pub mod pkcs7;
pub mod trust;
pub mod verify;

use authenticode::{
    authenticode_digest, AttributeCertificateIterator, PeTrait, WIN_CERT_REVISION_2_0,
    WIN_CERT_TYPE_PKCS_SIGNED_DATA,
};
use chrono::{DateTime, Utc};
use der::Decode;
use mm_core::SignatureStatus;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::crypto::HashAlg;
use crate::pe::PeBytes;
use crate::verify::{Outcome, SignerOutcome};

pub use crate::trust::{TrustStore, TrustedRoot};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Unsigned,
    Valid { signer: String, root_is_microsoft: bool },
    CatalogValid { signer: String, catalog: String, root_is_microsoft: bool },
    Invalid { reason: String },
    Expired { signer: String },
    Untrusted { signer: String, self_signed_leaf: bool },
    Unknown { reason: String },
}

impl Verdict {
    pub fn to_status(&self) -> SignatureStatus {
        match self {
            Verdict::Unsigned => SignatureStatus::Unsigned,
            Verdict::Valid { signer, .. } => {
                SignatureStatus::EmbeddedValid { signer: signer.clone() }
            }
            Verdict::CatalogValid { signer, catalog, root_is_microsoft } => {
                SignatureStatus::CatalogValid {
                    signer: signer.clone(),
                    catalog: catalog.clone(),
                    root_is_microsoft: *root_is_microsoft,
                }
            }
            Verdict::Invalid { reason } => SignatureStatus::Invalid { reason: reason.clone() },
            Verdict::Expired { signer } => SignatureStatus::Expired { signer: signer.clone() },
            Verdict::Untrusted { signer, self_signed_leaf } => SignatureStatus::Untrusted {
                signer: signer.clone(),
                self_signed_leaf: *self_signed_leaf,
            },
            Verdict::Unknown { reason } => SignatureStatus::Unknown { reason: reason.clone() },
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Verdict::Unsigned => "no embedded signature".into(),
            Verdict::Valid { signer, root_is_microsoft } => {
                if *root_is_microsoft {
                    format!("validly signed by {signer}, chaining to a Microsoft root")
                } else {
                    format!("validly signed by {signer}")
                }
            }
            Verdict::CatalogValid { signer, catalog, root_is_microsoft } => {
                if *root_is_microsoft {
                    format!("catalog-signed by {signer} ({catalog}), chaining to a Microsoft root")
                } else {
                    format!("catalog-signed by {signer} ({catalog})")
                }
            }
            Verdict::Invalid { reason } => format!("signature does not verify: {reason}"),
            Verdict::Expired { signer } => {
                format!("signed by {signer} with a certificate that was not valid at signing time")
            }
            Verdict::Untrusted { signer, self_signed_leaf: true } => format!(
                "self-signed: {signer} issued its own signing certificate, so nothing outside                  the file vouches for it"
            ),
            Verdict::Untrusted { signer, self_signed_leaf: false } => format!(
                "signed by {signer}; the signature verifies, but its chain ends at a certificate                  authority this build does not carry — THIS BUILD DOES NOT HAVE THAT ROOT, which                  is not a finding about the file"
            ),
            Verdict::Unknown { reason } => format!("could not be verified: {reason}"),
        }
    }
}

impl Verdict {
    fn rank(&self) -> u8 {
        match self {
            Verdict::Valid { .. } | Verdict::CatalogValid { .. } => 6,
            Verdict::Expired { .. } => 5,
            Verdict::Untrusted { .. } => 4,
            Verdict::Invalid { .. } => 3,
            Verdict::Unknown { .. } => 2,
            Verdict::Unsigned => 1,
        }
    }
}

pub fn verify_file(pe_bytes: &[u8], trust: &TrustStore, index: &catalog::CatalogIndex) -> Verdict {
    verify_file_at(pe_bytes, trust, index, now())
}

pub fn verify_file_at(
    pe_bytes: &[u8],
    trust: &TrustStore,
    index: &catalog::CatalogIndex,
    now: DateTime<Utc>,
) -> Verdict {
    match verify_embedded_first(pe_bytes, trust, now) {
        FileVerdict::Settled(verdict) => verdict,
        FileVerdict::NeedsCatalog(embedded) => finish_with_catalog(embedded, pe_bytes, index),
    }
}

#[derive(Clone, Debug)]
pub enum FileVerdict {
    Settled(Verdict),
    NeedsCatalog(Verdict),
}

impl FileVerdict {
    pub fn needs_catalog(&self) -> bool {
        matches!(self, FileVerdict::NeedsCatalog(_))
    }
}

pub fn verify_embedded_first(
    pe_bytes: &[u8],
    trust: &TrustStore,
    now: DateTime<Utc>,
) -> FileVerdict {
    let embedded = verify_embedded_at(pe_bytes, trust, now);
    if matches!(embedded, Verdict::Valid { .. }) {
        FileVerdict::Settled(embedded)
    } else {
        FileVerdict::NeedsCatalog(embedded)
    }
}

pub fn finish_with_catalog(
    embedded: Verdict,
    pe_bytes: &[u8],
    index: &catalog::CatalogIndex,
) -> Verdict {
    let from_catalog = catalog::verify_catalog(pe_bytes, index);
    if from_catalog.rank() > embedded.rank() {
        from_catalog
    } else {
        embedded
    }
}

pub fn verify_embedded(pe_bytes: &[u8], trust: &TrustStore) -> Verdict {
    verify_embedded_at(pe_bytes, trust, now())
}

pub fn now() -> DateTime<Utc> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    DateTime::from_timestamp(seconds, 0)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap_or(DateTime::<Utc>::MIN_UTC))
}

pub fn verify_embedded_at(pe_bytes: &[u8], trust: &TrustStore, now: DateTime<Utc>) -> Verdict {
    let outcomes = match embedded_signers(pe_bytes, trust, now) {
        Ok(outcomes) => outcomes,
        Err(verdict) => return verdict,
    };

    let Some(best) = outcomes.into_iter().max_by_key(|o| o.rank()) else {
        return Verdict::Unsigned;
    };

    match best.outcome {
        Outcome::Valid => {
            Verdict::Valid { signer: best.signer, root_is_microsoft: best.root_is_microsoft }
        }
        Outcome::Expired => Verdict::Expired { signer: best.signer },
        Outcome::Untrusted => {
            Verdict::Untrusted { signer: best.signer, self_signed_leaf: best.self_signed_leaf }
        }
        Outcome::Invalid(reason) => Verdict::Invalid { reason },
        Outcome::Unknown(reason) => Verdict::Unknown { reason },
    }
}

pub fn embedded_signers(
    pe_bytes: &[u8],
    trust: &TrustStore,
    now: DateTime<Utc>,
) -> Result<Vec<SignerOutcome>, Verdict> {
    let Some(pe) = PeBytes::parse(pe_bytes) else {
        return Err(Verdict::Unknown { reason: "not a PE image this build can parse".into() });
    };

    let entries = match AttributeCertificateIterator::new(&pe) {
        Ok(Some(iter)) => iter,
        Ok(None) => return Err(Verdict::Unsigned),
        Err(err) => {
            return Err(Verdict::Invalid {
                reason: format!("certificate table is malformed: {err}"),
            })
        }
    };

    let mut outcomes = Vec::new();
    let mut saw_entry = false;
    let mut skipped: Option<String> = None;

    for entry in entries {
        let Ok(entry) = entry else {
            skipped.get_or_insert_with(|| "a certificate table entry is malformed".into());
            continue;
        };
        saw_entry = true;
        if entry.revision != WIN_CERT_REVISION_2_0 {
            skipped.get_or_insert_with(|| {
                format!("certificate entry revision {:#06x}", entry.revision)
            });
            continue;
        }
        if entry.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            skipped.get_or_insert_with(|| {
                format!("certificate entry type {:#06x}", entry.certificate_type)
            });
            continue;
        }
        evaluate_pkcs7(entry.data, &pe, trust, now, &mut outcomes, 0);
    }

    if outcomes.is_empty() {
        if let Some(reason) = skipped {
            return Err(Verdict::Unknown { reason });
        }
        if !saw_entry {
            return Err(Verdict::Unsigned);
        }
        return Err(Verdict::Unknown {
            reason: "the certificate table held no readable signature".into(),
        });
    }

    Ok(outcomes)
}

const MAX_NESTING: usize = 4;

const MAX_SIGNATURES_PER_FILE: usize = 64;

fn evaluate_pkcs7(
    der: &[u8],
    pe: &PeBytes<'_>,
    trust: &TrustStore,
    now: DateTime<Utc>,
    outcomes: &mut Vec<SignerOutcome>,
    depth: usize,
) {
    if depth >= MAX_NESTING || outcomes.len() >= MAX_SIGNATURES_PER_FILE {
        return;
    }

    let signed_data = match pkcs7::parse(der) {
        Ok(parsed) => parsed,
        Err(err) => {
            outcomes.push(unknown_outcome(format!("signature did not parse: {err}"), now));
            return;
        }
    };

    if signed_data.econtent_type != pkcs7::OID_SPC_INDIRECT_DATA {
        outcomes.push(unknown_outcome(
            format!(
                "embedded signature carries {} rather than Authenticode indirect data",
                signed_data.econtent_type
            ),
            now,
        ));
        return;
    }

    let Some(content) = signed_data.econtent else {
        outcomes.push(unknown_outcome("signature encapsulates no content".into(), now));
        return;
    };
    let indirect = match authenticode::SpcIndirectDataContent::from_der(content.full) {
        Ok(indirect) => indirect,
        Err(err) => {
            outcomes.push(unknown_outcome(
                format!("Authenticode indirect data did not parse: {err}"),
                now,
            ));
            return;
        }
    };
    let Some(alg) = HashAlg::from_oid(indirect.message_digest.digest_algorithm.oid) else {
        outcomes.push(unknown_outcome(
            format!(
                "Authenticode digest algorithm {}",
                indirect.message_digest.digest_algorithm.oid
            ),
            now,
        ));
        return;
    };

    let expected = indirect.message_digest.digest.as_bytes();
    match pe_digest(pe, alg) {
        Some(computed) => {
            if computed != expected && pe_digest_contiguous(pe, alg).as_deref() != Some(expected) {
                outcomes.push(SignerOutcome {
                    outcome: Outcome::Invalid(format!(
                        "the file's {} Authenticode hash does not match the one in the signature",
                        alg.name()
                    )),
                    signer: signed_data
                        .certs
                        .first()
                        .map(|c| c.display_name())
                        .unwrap_or_else(|| "unknown signer".into()),
                    root: None,
                    unreached_issuer: None,
                    self_signed_leaf: false,
                    root_is_microsoft: false,
                    signing_time: None,
                    signing_time_trusted: false,
                    evaluated_at: now,
                });
                return;
            }
        }
        None => {
            outcomes.push(unknown_outcome(
                "the file's Authenticode hash could not be computed".into(),
                now,
            ));
            return;
        }
    }

    for signer in &signed_data.signers {
        if outcomes.len() >= MAX_SIGNATURES_PER_FILE {
            return;
        }
        outcomes.push(verify::verify_signer(&signed_data, signer, trust, now));

        if let Some(nested) = signer.unsigned_attr(verify::OID_NESTED_SIGNATURE) {
            evaluate_pkcs7(nested.full, pe, trust, now, outcomes, depth.saturating_add(1));
        }
    }
}

fn unknown_outcome(reason: String, now: DateTime<Utc>) -> SignerOutcome {
    SignerOutcome {
        outcome: Outcome::Unknown(reason),
        signer: "unknown signer".into(),
        root: None,
        unreached_issuer: None,
        self_signed_leaf: false,
        root_is_microsoft: false,
        signing_time: None,
        signing_time_trusted: false,
        evaluated_at: now,
    }
}

pub fn pe_digest(pe: &PeBytes<'_>, alg: HashAlg) -> Option<Vec<u8>> {
    fn run<D: Digest + sha2::digest::Update>(pe: &dyn PeTrait) -> Option<Vec<u8>> {
        let mut hasher = D::new();
        authenticode_digest(pe, &mut hasher).ok()?;
        Some(hasher.finalize().to_vec())
    }
    match alg {
        HashAlg::Sha1 => run::<Sha1>(pe),
        HashAlg::Sha256 => run::<Sha256>(pe),
        HashAlg::Sha384 => run::<Sha384>(pe),
        HashAlg::Sha512 => run::<Sha512>(pe),
    }
}

pub fn pe_digest_contiguous(pe: &PeBytes<'_>, alg: HashAlg) -> Option<Vec<u8>> {
    let offsets = pe.offsets().ok()?;
    let table = pe.certificate_table_range().ok()??;
    if table.end != pe.data().len() {
        return None;
    }

    let spans = [
        0..offsets.check_sum,
        offsets.after_check_sum..offsets.security_data_dir,
        offsets.after_security_data_dir..offsets.after_header,
        offsets.after_header..table.start,
    ];

    fn run<D: Digest>(data: &[u8], spans: &[core::ops::Range<usize>]) -> Option<Vec<u8>> {
        let mut hasher = D::new();
        for span in spans {
            hasher.update(data.get(span.clone())?);
        }
        Some(hasher.finalize().to_vec())
    }

    match alg {
        HashAlg::Sha1 => run::<Sha1>(pe.data(), &spans),
        HashAlg::Sha256 => run::<Sha256>(pe.data(), &spans),
        HashAlg::Sha384 => run::<Sha384>(pe.data(), &spans),
        HashAlg::Sha512 => run::<Sha512>(pe.data(), &spans),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_is_not_a_pe_is_unknown_not_unsigned() {
        let trust = TrustStore::embedded();
        assert!(matches!(verify_embedded(b"this is a text file", &trust), Verdict::Unknown { .. }));
        assert!(matches!(verify_embedded(&[], &trust), Verdict::Unknown { .. }));
    }

    #[test]
    fn unknown_is_not_scoreable_and_unsigned_is() {
        let unknown = Verdict::Unknown { reason: "CatRoot unreadable".into() }.to_status();
        assert_eq!(unknown, SignatureStatus::Unknown { reason: "CatRoot unreadable".into() });
        assert!(!unknown.is_evidence(), "an unfinished check must score nothing");

        assert_eq!(Verdict::Unsigned.to_status(), SignatureStatus::Unsigned);
        assert!(SignatureStatus::Unsigned.is_evidence());

        assert_eq!(
            Verdict::Valid { signer: "MS".into(), root_is_microsoft: true }.to_status(),
            SignatureStatus::EmbeddedValid { signer: "MS".into() }
        );
    }

    #[test]
    fn a_catalogs_root_survives_into_the_scored_status() {
        let oem = Verdict::CatalogValid {
            signer: "OpenVPN Technologies, Inc.".into(),
            catalog: "oem40.cat".into(),
            root_is_microsoft: false,
        };
        assert_eq!(
            oem.to_status(),
            SignatureStatus::CatalogValid {
                signer: "OpenVPN Technologies, Inc.".into(),
                catalog: "oem40.cat".into(),
                root_is_microsoft: false,
            }
        );
        assert_eq!(
            Verdict::Untrusted { signer: "evil".into(), self_signed_leaf: true }.to_status(),
            SignatureStatus::Untrusted { signer: "evil".into(), self_signed_leaf: true }
        );
    }

    #[test]
    fn arbitrary_bytes_that_start_like_a_pe_never_panic() {
        let trust = TrustStore::embedded();
        let mut state = 0x0bad_f00du32;
        for _ in 0..2_000 {
            let len = (state % 1024) as usize;
            let mut buf = vec![b'M', b'Z'];
            for _ in 0..len {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                buf.push((state >> 16) as u8);
            }
            let _ = verify_embedded(&buf, &trust);
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        }
    }
}
