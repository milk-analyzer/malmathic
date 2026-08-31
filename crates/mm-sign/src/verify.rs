use chrono::{DateTime, TimeZone, Utc};
use cms::signed_data::SignerIdentifier;
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};

use crate::cert::ParsedCert;
use crate::crypto::{self, CryptoError, HashAlg};
use crate::der_walk::{self, Tlv};
use crate::pkcs7::{SignedDataRef, SignerRef};
use crate::trust::TrustStore;

const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
const OID_COUNTERSIGNATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");
pub const OID_RFC3161_COUNTERSIGN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
pub const OID_NESTED_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.4.1");

const MAX_CHAIN_DEPTH: usize = 8;

const MAX_CHAIN_WORK: u32 = 512;

const MAX_COUNTERSIGNATURE_DEPTH: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Valid,
    Expired,
    Untrusted,
    Invalid(String),
    Unknown(String),
}

#[derive(Clone, Debug)]
pub struct SignerOutcome {
    pub outcome: Outcome,
    pub signer: String,
    pub root: Option<&'static str>,
    pub unreached_issuer: Option<String>,
    pub self_signed_leaf: bool,
    pub root_is_microsoft: bool,
    pub signing_time: Option<DateTime<Utc>>,
    pub signing_time_trusted: bool,
    pub evaluated_at: DateTime<Utc>,
}

impl SignerOutcome {
    fn failed(outcome: Outcome, signer: String, at: DateTime<Utc>) -> Self {
        SignerOutcome {
            outcome,
            signer,
            root: None,
            unreached_issuer: None,
            self_signed_leaf: false,
            root_is_microsoft: false,
            signing_time: None,
            signing_time_trusted: false,
            evaluated_at: at,
        }
    }

    pub fn rank(&self) -> u8 {
        match self.outcome {
            Outcome::Valid => 5,
            Outcome::Expired => 4,
            Outcome::Untrusted => 3,
            Outcome::Invalid(_) => 2,
            Outcome::Unknown(_) => 1,
        }
    }
}

pub fn verify_signer(
    signed_data: &SignedDataRef<'_>,
    signer: &SignerRef<'_>,
    trust: &TrustStore,
    now: DateTime<Utc>,
) -> SignerOutcome {
    verify_signer_for(signed_data, signer, trust, now, CODE_SIGNING_PURPOSES)
}

pub const CODE_SIGNING_PURPOSES: &[ObjectIdentifier] =
    &[crate::cert::OID_CODE_SIGNING, crate::cert::OID_MS_SYSTEM_COMPONENT];

pub const CATALOG_SIGNING_PURPOSES: &[ObjectIdentifier] = &[
    crate::cert::OID_CODE_SIGNING,
    crate::cert::OID_CTL_SIGNING,
    crate::cert::OID_MS_SYSTEM_COMPONENT,
];

pub const TIMESTAMPING_PURPOSES: &[ObjectIdentifier] = &[crate::cert::OID_TIME_STAMPING];

pub fn verify_signer_for(
    signed_data: &SignedDataRef<'_>,
    signer: &SignerRef<'_>,
    trust: &TrustStore,
    now: DateTime<Utc>,
    purposes: &[ObjectIdentifier],
) -> SignerOutcome {
    verify_signer_nested(signed_data, signer, trust, now, 0, purposes)
}

fn verify_signer_nested(
    signed_data: &SignedDataRef<'_>,
    signer: &SignerRef<'_>,
    trust: &TrustStore,
    now: DateTime<Utc>,
    depth: usize,
    purposes: &[ObjectIdentifier],
) -> SignerOutcome {
    let Some(digest_alg) = HashAlg::from_oid(signer.info.digest_alg.oid) else {
        return SignerOutcome::failed(
            Outcome::Unknown(format!("digest algorithm {}", signer.info.digest_alg.oid)),
            "unknown signer".into(),
            now,
        );
    };

    let Some(leaf) = find_signer_cert(signer, &signed_data.certs) else {
        return SignerOutcome::failed(
            Outcome::Unknown("the signing certificate is not in the signature".into()),
            "unknown signer".into(),
            now,
        );
    };
    let signer_name = leaf.display_name();

    let message: Vec<u8> = match &signer.signed_attrs_der {
        Some(attrs) => {
            if let Err(reason) = check_bound_attributes(signed_data, signer, digest_alg) {
                return SignerOutcome::failed(reason, signer_name, now);
            }
            attrs.clone()
        }
        None => match signed_data.content_to_digest() {
            Some(content) => content.to_vec(),
            None => {
                return SignerOutcome::failed(
                    Outcome::Invalid("no signed attributes and no content to sign".into()),
                    signer_name,
                    now,
                )
            }
        },
    };

    if !leaf.allows_any(purposes) {
        return SignerOutcome::failed(
            Outcome::Invalid(format!(
                "the signing certificate was not issued for this: its extendedKeyUsage is \
                 {}, which does not include the purpose being claimed",
                leaf.purposes()
            )),
            signer_name,
            now,
        );
    }

    let signature = signer.info.signature.as_bytes();
    if let Err(err) = crypto::verify(
        &leaf.cert.tbs_certificate.subject_public_key_info,
        &signer.info.signature_algorithm,
        Some(digest_alg),
        &message,
        signature,
    ) {
        return SignerOutcome::failed(outcome_for(err, "signer signature"), signer_name, now);
    }

    let countersignature = if depth < MAX_COUNTERSIGNATURE_DEPTH {
        signing_time_nested(signed_data, signer, trust, now, depth)
    } else {
        None
    };

    let evaluated_at = countersignature.as_ref().filter(|c| c.trusted).map(|c| c.at).unwrap_or(now);

    let mut result = SignerOutcome {
        outcome: Outcome::Valid,
        signer: signer_name,
        root: None,
        unreached_issuer: None,
        self_signed_leaf: false,
        root_is_microsoft: false,
        signing_time: countersignature.as_ref().map(|c| c.at),
        signing_time_trusted: countersignature.as_ref().is_some_and(|c| c.trusted),
        evaluated_at,
    };

    match build_chain(leaf, &signed_data.certs, trust) {
        ChainResult::Reached { path, root, root_is_microsoft } => {
            result.root = Some(root);
            result.root_is_microsoft = root_is_microsoft;
            if path.iter().any(|c| !c.is_valid_at(evaluated_at)) {
                result.outcome = match &countersignature {
                    Some(counter) if !counter.trusted => Outcome::Unknown(format!(
                        "the signing certificate is outside its validity window now, and the \
                         countersignature that dates the signature to {} could not be \
                         corroborated — its timestamp authority does not chain to a root this \
                         build embeds",
                        counter.at.format("%Y-%m-%d")
                    )),
                    _ => Outcome::Expired,
                };
            }
        }
        ChainResult::SelfSignedTop { top, self_signed_leaf } => {
            result.outcome = Outcome::Untrusted;
            result.unreached_issuer = Some(top);
            result.self_signed_leaf = self_signed_leaf;
        }
        ChainResult::Incomplete { wanted } => {
            result.outcome = Outcome::Unknown(format!(
                "the chain ends below a root: no certificate for {wanted} is in the file or in \
                 the embedded trust store"
            ));
            result.unreached_issuer = Some(wanted);
        }
        ChainResult::Broken(reason) => result.outcome = Outcome::Invalid(reason),
        ChainResult::Uncheckable(reason) => result.outcome = Outcome::Unknown(reason),
    }

    result
}

fn check_bound_attributes(
    signed_data: &SignedDataRef<'_>,
    signer: &SignerRef<'_>,
    digest_alg: HashAlg,
) -> Result<(), Outcome> {
    let Some(declared) = signer.signed_attr(OID_CONTENT_TYPE) else {
        return Err(Outcome::Invalid(
            "signed attributes carry no contentType, so the signature does not say what it \
             signed"
                .into(),
        ));
    };
    match ObjectIdentifier::from_bytes(declared.content) {
        Ok(oid) if oid == signed_data.econtent_type => {}
        Ok(oid) => {
            return Err(Outcome::Invalid(format!(
                "signed contentType is {oid} but the content is {}",
                signed_data.econtent_type
            )))
        }
        Err(_) => {
            return Err(Outcome::Invalid(
                "the signed contentType is not a readable object identifier".into(),
            ))
        }
    }

    let Some(attr) = signer.signed_attr(OID_MESSAGE_DIGEST) else {
        return Err(Outcome::Invalid("signed attributes carry no messageDigest".into()));
    };
    let Some(content) = signed_data.content_to_digest() else {
        return Err(Outcome::Invalid("the signature encapsulates no content".into()));
    };
    if digest_alg.digest(content) != attr.content {
        return Err(Outcome::Invalid(
            "the signed messageDigest does not match the signed content".into(),
        ));
    }
    Ok(())
}

fn outcome_for(err: CryptoError, what: &str) -> Outcome {
    match err {
        CryptoError::Unsupported(detail) => Outcome::Unknown(format!("{what}: {detail}")),
        CryptoError::Malformed(detail) => Outcome::Invalid(format!("{what}: malformed {detail}")),
        CryptoError::BadSignature => Outcome::Invalid(format!("{what} does not verify")),
    }
}

enum ChainResult<'a> {
    Reached { path: Vec<ParsedCert<'a>>, root: &'static str, root_is_microsoft: bool },
    SelfSignedTop { top: String, self_signed_leaf: bool },
    Incomplete { wanted: String },
    Broken(String),
    Uncheckable(String),
}

#[derive(Default)]
struct WalkNotes<'a> {
    broken: Option<String>,
    uncheckable: Option<String>,
    deepest: Vec<ParsedCert<'a>>,
    budget: u32,
}

impl WalkNotes<'_> {
    fn new() -> Self {
        WalkNotes { budget: MAX_CHAIN_WORK, ..Default::default() }
    }

    fn spend(&mut self) -> bool {
        match self.budget.checked_sub(1) {
            Some(left) => {
                self.budget = left;
                true
            }
            None => false,
        }
    }
}

fn build_chain<'a>(
    leaf: &ParsedCert<'a>,
    pool: &[ParsedCert<'a>],
    trust: &TrustStore,
) -> ChainResult<'a> {
    let mut path: Vec<ParsedCert<'a>> = vec![leaf.clone()];
    let mut notes = WalkNotes::new();

    if let Some((root, root_is_microsoft)) = walk(&mut path, pool, trust, 0, &mut notes) {
        return ChainResult::Reached { path, root, root_is_microsoft };
    }

    if notes.budget == 0 {
        return ChainResult::Uncheckable(
            "the certificates in this file are too tangled to search: the chain walk gave up \
             after 512 issuer checks"
                .into(),
        );
    }

    if let Some(reason) = notes.uncheckable {
        return ChainResult::Uncheckable(reason);
    }
    if let Some(reason) = notes.broken {
        return ChainResult::Broken(reason);
    }

    let reached: &[ParsedCert<'a>] =
        if notes.deepest.is_empty() { path.as_slice() } else { notes.deepest.as_slice() };
    match reached.last() {
        Some(top) if top.is_self_issued() => ChainResult::SelfSignedTop {
            top: top.display_name(),
            self_signed_leaf: reached.len() == 1,
        },
        Some(top) => ChainResult::Incomplete { wanted: top.issuer_name() },
        None => ChainResult::Incomplete { wanted: String::new() },
    }
}

fn walk<'a>(
    path: &mut Vec<ParsedCert<'a>>,
    pool: &[ParsedCert<'a>],
    trust: &TrustStore,
    depth: usize,
    notes: &mut WalkNotes<'a>,
) -> Option<(&'static str, bool)> {
    if depth >= MAX_CHAIN_DEPTH {
        return None;
    }
    if path.len() > notes.deepest.len() {
        notes.deepest = path.clone();
    }
    let current = path.last()?.clone();

    for root in trust.candidates_for(current.issuer_der) {
        if !notes.spend() {
            return None;
        }
        match verify_issued_by(&current, root.cert()) {
            Ok(()) => return Some((root.name, root.is_microsoft)),
            Err(CryptoError::BadSignature) => {
                notes.broken.get_or_insert_with(|| {
                    format!("{} was not issued by {}", current.display_name(), root.name)
                });
            }
            Err(other) => {
                notes.uncheckable.get_or_insert_with(|| format!("chain to {}: {other}", root.name));
            }
        }
    }

    for candidate in pool {
        if candidate.subject_der != current.issuer_der {
            continue;
        }
        if path.iter().any(|c| c.der == candidate.der) {
            continue;
        }
        if !candidate.is_ca() {
            continue;
        }
        if !notes.spend() {
            return None;
        }
        match verify_issued_by(&current, candidate) {
            Ok(()) => {
                path.push(candidate.clone());
                if let Some(found) = walk(path, pool, trust, depth.saturating_add(1), notes) {
                    return Some(found);
                }
                path.pop();
            }
            Err(CryptoError::BadSignature) => {
                notes.broken.get_or_insert_with(|| {
                    format!(
                        "{} was not issued by {}",
                        current.display_name(),
                        candidate.display_name()
                    )
                });
            }
            Err(other) => {
                notes.uncheckable.get_or_insert_with(|| {
                    format!("chain above {}: {other}", current.display_name())
                });
            }
        }
    }

    None
}

fn verify_issued_by(child: &ParsedCert<'_>, issuer: &ParsedCert<'_>) -> Result<(), CryptoError> {
    let signature = child
        .cert
        .signature
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("certificate signature bit string".into()))?;
    crypto::verify(
        &issuer.cert.tbs_certificate.subject_public_key_info,
        &child.cert.signature_algorithm,
        HashAlg::from_oid(child.cert.signature_algorithm.oid),
        child.tbs,
        signature,
    )
}

fn find_signer_cert<'a, 'p>(
    signer: &SignerRef<'_>,
    pool: &'p [ParsedCert<'a>],
) -> Option<&'p ParsedCert<'a>> {
    match &signer.info.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            let wanted = ias.issuer.to_der().ok()?;
            let serial = ias.serial_number.as_bytes();
            pool.iter().find(|cert| {
                cert.serial() == serial
                    && cert.cert.tbs_certificate.issuer.to_der().is_ok_and(|der| der == wanted)
            })
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            let wanted = ski.0.as_bytes();
            pool.iter().find(|cert| cert.subject_key_identifier() == Some(wanted))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Countersignature {
    pub at: DateTime<Utc>,
    pub trusted: bool,
}

pub fn signing_time(
    signed_data: &SignedDataRef<'_>,
    signer: &SignerRef<'_>,
    trust: &TrustStore,
    now: DateTime<Utc>,
) -> Option<Countersignature> {
    signing_time_nested(signed_data, signer, trust, now, 0)
}

fn signing_time_nested(
    signed_data: &SignedDataRef<'_>,
    signer: &SignerRef<'_>,
    trust: &TrustStore,
    now: DateTime<Utc>,
    depth: usize,
) -> Option<Countersignature> {
    if let Some(token) = signer.unsigned_attr(OID_RFC3161_COUNTERSIGN) {
        if let Some(found) = rfc3161_time(token, signer, trust, now, depth) {
            return Some(found);
        }
    }
    if let Some(counter) = signer.unsigned_attr(OID_COUNTERSIGNATURE) {
        if let Some(found) = legacy_countersignature_time(counter, signed_data, signer, trust) {
            return Some(found);
        }
    }
    None
}

fn rfc3161_time(
    token: Tlv<'_>,
    primary: &SignerRef<'_>,
    trust: &TrustStore,
    now: DateTime<Utc>,
    depth: usize,
) -> Option<Countersignature> {
    let tst = crate::pkcs7::parse(token.full).ok()?;
    if tst.econtent_type != OID_TST_INFO {
        return None;
    }

    let content = tst.econtent?;
    let info = if content.tag == 0x04 { der_walk::first(content.content)? } else { content };
    let fields = info.children();
    let at = parse_time(*fields.get(4)?)?;

    let imprint_ok = fields
        .get(2)
        .is_some_and(|imprint| imprint_matches(*imprint, primary.info.signature.as_bytes()));

    let signer_ok = tst.signers.first().is_some_and(|tsa_signer| {
        matches!(
            verify_signer_nested(
                &tst,
                tsa_signer,
                trust,
                now,
                depth.saturating_add(1),
                TIMESTAMPING_PURPOSES,
            )
            .outcome,
            Outcome::Valid | Outcome::Expired
        )
    });

    Some(Countersignature { at, trusted: imprint_ok && signer_ok })
}

fn imprint_matches(imprint: Tlv<'_>, signature: &[u8]) -> bool {
    let fields = imprint.children();
    let Some(alg) = fields.first() else { return false };
    let Some(oid_tlv) = alg.children().first().copied() else {
        return false;
    };
    let Ok(oid) = ObjectIdentifier::from_bytes(oid_tlv.content) else {
        return false;
    };
    let Some(hash) = HashAlg::from_oid(oid) else {
        return false;
    };
    fields.get(1).is_some_and(|hashed| hash.digest(signature) == hashed.content)
}

fn legacy_countersignature_time(
    counter: Tlv<'_>,
    signed_data: &SignedDataRef<'_>,
    primary: &SignerRef<'_>,
    trust: &TrustStore,
) -> Option<Countersignature> {
    let signer = parse_countersigner(counter)?;
    let at = parse_time(signer.signed_attr(OID_SIGNING_TIME)?)?;

    let trusted = verify_legacy_countersignature(&signer, signed_data, primary, trust, at);
    Some(Countersignature { at, trusted })
}

fn parse_countersigner(counter: Tlv<'_>) -> Option<SignerRef<'_>> {
    if counter.tag != 0x30 {
        return None;
    }
    let info = cms::signed_data::SignerInfo::from_der(counter.full).ok()?;
    let fields = counter.children();
    let signed_attrs_tlv = fields.iter().find(|f| f.tag == 0xa0);
    Some(SignerRef {
        info,
        signed_attrs_der: signed_attrs_tlv.and_then(der_walk::retag_as_set),
        signed_attrs: signed_attrs_tlv.map(|t| crate::pkcs7::attributes_of(*t)).unwrap_or_default(),
        unsigned_attrs: Vec::new(),
    })
}

fn verify_legacy_countersignature(
    signer: &SignerRef<'_>,
    signed_data: &SignedDataRef<'_>,
    primary: &SignerRef<'_>,
    trust: &TrustStore,
    at: DateTime<Utc>,
) -> bool {
    let Some(digest_alg) = HashAlg::from_oid(signer.info.digest_alg.oid) else {
        return false;
    };
    let Some(attr) = signer.signed_attr(OID_MESSAGE_DIGEST) else {
        return false;
    };
    if digest_alg.digest(primary.info.signature.as_bytes()) != attr.content {
        return false;
    }
    let Some(message) = &signer.signed_attrs_der else {
        return false;
    };
    let Some(cert) = find_signer_cert(signer, &signed_data.certs) else {
        return false;
    };
    if crypto::verify(
        &cert.cert.tbs_certificate.subject_public_key_info,
        &signer.info.signature_algorithm,
        Some(digest_alg),
        message,
        signer.info.signature.as_bytes(),
    )
    .is_err()
    {
        return false;
    }
    match build_chain(cert, &signed_data.certs, trust) {
        ChainResult::Reached { path, .. } => path.iter().all(|c| c.is_valid_at(at)),
        _ => false,
    }
}

fn parse_time(tlv: Tlv<'_>) -> Option<DateTime<Utc>> {
    let bytes = tlv.content;
    let digits = |from: usize, len: usize| -> Option<u32> {
        let to = from.checked_add(len)?;
        let slice = bytes.get(from..to)?;
        if !slice.iter().all(|b| b.is_ascii_digit()) {
            return None;
        }
        core::str::from_utf8(slice).ok()?.parse::<u32>().ok()
    };

    let (year, mut cursor) = match tlv.tag {
        0x17 => {
            let yy = digits(0, 2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2usize)
        }
        0x18 => (digits(0, 4)?, 4usize),
        _ => return None,
    };

    let month = digits(cursor, 2)?;
    cursor = cursor.checked_add(2)?;
    let day = digits(cursor, 2)?;
    cursor = cursor.checked_add(2)?;
    let hour = digits(cursor, 2)?;
    cursor = cursor.checked_add(2)?;
    let minute = digits(cursor, 2)?;
    cursor = cursor.checked_add(2)?;

    let second = match digits(cursor, 2) {
        Some(value) => {
            cursor = cursor.checked_add(2)?;
            value
        }
        None => 0,
    };

    if bytes.get(cursor) == Some(&b'.') || bytes.get(cursor) == Some(&b',') {
        cursor = cursor.checked_add(1)?;
        while bytes.get(cursor).is_some_and(|b| b.is_ascii_digit()) {
            cursor = cursor.checked_add(1)?;
        }
    }

    let naive = Utc
        .with_ymd_and_hms(i32::try_from(year).ok()?, month, day, hour, minute, second)
        .single()?;

    match bytes.get(cursor) {
        None | Some(b'Z') => Some(naive),
        Some(sign @ (b'+' | b'-')) => {
            let offset_hours = digits(cursor.checked_add(1)?, 2)?;
            let offset_minutes = digits(cursor.checked_add(3)?, 2).unwrap_or(0);
            let offset = i64::from(offset_hours)
                .checked_mul(3600)?
                .checked_add(i64::from(offset_minutes).checked_mul(60)?)?;
            let delta = chrono::Duration::try_seconds(offset)?;
            if *sign == b'+' {
                naive.checked_sub_signed(delta)
            } else {
                naive.checked_add_signed(delta)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_we_could_not_run_never_outranks_one_that_failed() {
        let now = crate::now();
        let unknown = SignerOutcome::failed(Outcome::Unknown("x".into()), "s".into(), now);
        let invalid = SignerOutcome::failed(Outcome::Invalid("x".into()), "s".into(), now);
        let untrusted = SignerOutcome::failed(Outcome::Untrusted, "s".into(), now);
        let expired = SignerOutcome::failed(Outcome::Expired, "s".into(), now);
        let valid = SignerOutcome::failed(Outcome::Valid, "s".into(), now);
        assert!(unknown.rank() < invalid.rank());
        assert!(invalid.rank() < untrusted.rank());
        assert!(untrusted.rank() < expired.rank());
        assert!(expired.rank() < valid.rank());
    }

    #[test]
    fn a_self_signed_certificate_terminates_the_walk_as_itself() {
        let der = include_bytes!("../roots/microsoft-root-2010.der");
        let cert = ParsedCert::parse(der).unwrap();

        match build_chain(&cert, std::slice::from_ref(&cert), &TrustStore::embedded()) {
            ChainResult::Reached { root, root_is_microsoft, path } => {
                assert_eq!(root, "Microsoft Root Certificate Authority 2010");
                assert!(root_is_microsoft);
                assert_eq!(path.len(), 1);
            }
            _ => panic!("the embedded store should have anchored its own root"),
        }

        match build_chain(&cert, std::slice::from_ref(&cert), &TrustStore::empty()) {
            ChainResult::SelfSignedTop { top, self_signed_leaf } => {
                assert_eq!(top, "Microsoft Root Certificate Authority 2010");
                assert!(self_signed_leaf);
            }
            _ => panic!("an unanchored self-signed certificate is untrusted, not unknown"),
        }
    }

    #[test]
    fn a_matching_name_is_not_enough_to_extend_a_chain() {
        let real = ParsedCert::parse(include_bytes!("../roots/microsoft-root-2010.der")).unwrap();
        let other = ParsedCert::parse(include_bytes!("../roots/microsoft-root-2011.der")).unwrap();

        let mut impostor = real.clone();
        impostor.issuer_der = other.subject_der;

        match build_chain(&impostor, &[], &TrustStore::embedded()) {
            ChainResult::Broken(reason) => assert!(reason.contains("2011"), "{reason}"),
            other => panic!("expected a broken link, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn times_parse_in_both_encodings() {
        let utc = [
            0x17u8, 0x0d, b'2', b'1', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'0', b'5',
            b'Z',
        ];
        let parsed = parse_time(der_walk::single(&utc).unwrap()).unwrap();
        assert_eq!(parsed.to_rfc3339(), "2021-01-02T03:04:05+00:00");

        let gen = [
            0x18u8, 0x0f, b'2', b'0', b'3', b'1', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4',
            b'0', b'5', b'Z',
        ];
        let parsed = parse_time(der_walk::single(&gen).unwrap()).unwrap();
        assert_eq!(parsed.to_rfc3339(), "2031-01-02T03:04:05+00:00");

        assert!(parse_time(der_walk::single(&[0x02, 0x01, 0x05]).unwrap()).is_none());
    }
}
