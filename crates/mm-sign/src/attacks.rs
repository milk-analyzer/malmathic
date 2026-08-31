use chrono::{DateTime, TimeZone, Utc};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;

use crate::crypto::HashAlg;
use crate::pe::PeBytes;
use crate::trust::TrustStore;
use crate::Verdict;

pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.push(0x81);
        out.push(n as u8);
    } else if n < 0x1_0000 {
        out.push(0x82);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0x84);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

pub fn seq(body: &[u8]) -> Vec<u8> {
    tlv(0x30, body)
}
pub fn set(body: &[u8]) -> Vec<u8> {
    tlv(0x31, body)
}
pub fn octets(body: &[u8]) -> Vec<u8> {
    tlv(0x04, body)
}
pub fn oid(text: &str) -> Vec<u8> {
    tlv(0x06, const_oid::ObjectIdentifier::new(text).expect("test OID").as_bytes())
}
pub fn int(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    if bytes[first] & 0x80 != 0 {
        first = first.saturating_sub(1);
    }
    tlv(0x02, &bytes[first..])
}
pub fn utf8(text: &str) -> Vec<u8> {
    tlv(0x0c, text.as_bytes())
}
pub fn utctime(text: &str) -> Vec<u8> {
    tlv(0x17, text.as_bytes())
}
pub fn bits(body: &[u8]) -> Vec<u8> {
    let mut with_pad = vec![0u8];
    with_pad.extend_from_slice(body);
    tlv(0x03, &with_pad)
}
pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}
pub fn explicit(number: u8, body: &[u8]) -> Vec<u8> {
    tlv(0xa0 | number, body)
}
pub fn name(cn: &str) -> Vec<u8> {
    seq(&set(&seq(&[oid("2.5.4.3"), utf8(cn)].concat())))
}
pub fn alg_id(algorithm: &str, params: bool) -> Vec<u8> {
    let mut body = oid(algorithm);
    if params {
        body.extend_from_slice(&null());
    }
    seq(&body)
}

const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_SPC_INDIRECT: &str = "1.3.6.1.4.1.311.2.1.4";
const OID_SPC_PE_IMAGE: &str = "1.3.6.1.4.1.311.2.1.15";
const OID_CTL: &str = "1.3.6.1.4.1.311.10.1";
const OID_CATALOG_LIST: &str = "1.3.6.1.4.1.311.12.1.1";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const OID_COUNTERSIGNATURE: &str = "1.2.840.113549.1.9.6";
const OID_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";

pub fn key(seed: u8) -> SigningKey {
    let mut scalar = [1u8; 32];
    scalar[31] = seed.max(1);
    SigningKey::from_slice(&scalar).expect("valid scalar")
}

fn spki_of(k: &SigningKey) -> Vec<u8> {
    p256::PublicKey::from(*k.verifying_key()).to_public_key_der().expect("SPKI").as_bytes().to_vec()
}

fn sign(k: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = k.sign(message);
    signature.to_der().as_bytes().to_vec()
}

#[derive(Clone)]
pub struct CertSpec {
    pub subject: String,
    pub issuer: String,
    pub serial: u64,
    pub not_before: String,
    pub not_after: String,
    pub ca: bool,
    pub eku: Option<Vec<String>>,
}

impl CertSpec {
    pub fn leaf(subject: &str, issuer: &str) -> Self {
        CertSpec {
            subject: subject.into(),
            issuer: issuer.into(),
            serial: 0x1234,
            not_before: "200101000000Z".into(),
            not_after: "491231000000Z".into(),
            ca: false,
            eku: Some(vec![OID_CODE_SIGNING.into()]),
        }
    }

    pub fn ca(subject: &str, issuer: &str) -> Self {
        let mut spec = Self::leaf(subject, issuer);
        spec.ca = true;
        spec.serial = 0x4321;
        spec
    }

    pub fn valid_between(mut self, from: &str, to: &str) -> Self {
        self.not_before = from.into();
        self.not_after = to.into();
        self
    }

    pub fn with_serial(mut self, serial: u64) -> Self {
        self.serial = serial;
        self
    }

    pub fn with_eku(mut self, eku: Option<Vec<String>>) -> Self {
        self.eku = eku;
        self
    }
}

pub fn make_cert(spec: &CertSpec, subject_key: &SigningKey, issuer_key: &SigningKey) -> Vec<u8> {
    let mut extensions = Vec::new();
    if spec.ca {
        let basic = seq(&[0x01, 0x01, 0xff]);
        extensions
            .extend(seq(&[oid("2.5.29.19"), vec![0x01, 0x01, 0xff], octets(&basic)].concat()));
    }
    if let Some(usages) = &spec.eku {
        let body: Vec<u8> = usages.iter().flat_map(|u| oid(u)).collect();
        let value = seq(&body);
        extensions.extend(seq(&[oid("2.5.29.37"), octets(&value)].concat()));
    }

    let mut tbs_body = explicit(0, &int(2));
    tbs_body.extend(int(spec.serial));
    tbs_body.extend(alg_id(OID_ECDSA_SHA256, false));
    tbs_body.extend(name(&spec.issuer));
    tbs_body.extend(seq(&[utctime(&spec.not_before), utctime(&spec.not_after)].concat()));
    tbs_body.extend(name(&spec.subject));
    tbs_body.extend(spki_of(subject_key));
    if !extensions.is_empty() {
        tbs_body.extend(explicit(3, &seq(&extensions)));
    }
    let tbs = seq(&tbs_body);

    let signature = sign(issuer_key, &tbs);
    let mut cert = tbs;
    cert.extend(alg_id(OID_ECDSA_SHA256, false));
    cert.extend(bits(&signature));
    seq(&cert)
}

pub struct SignerSpec<'a> {
    pub issuer: &'a str,
    pub serial: u64,
    pub key: &'a SigningKey,
    pub content: &'a [u8],
    pub content_type: &'a str,
    pub unsigned: Vec<Vec<u8>>,
}

fn signed_attrs_body(content_type: &str, content: &[u8]) -> Vec<u8> {
    [
        seq(&[oid(OID_CONTENT_TYPE), set(&oid(content_type))].concat()),
        seq(&[oid(OID_MESSAGE_DIGEST), set(&octets(&HashAlg::Sha256.digest(content)))].concat()),
    ]
    .concat()
}

pub fn signature_value(k: &SigningKey, content_type: &str, content: &[u8]) -> Vec<u8> {
    sign(k, &tlv(0x31, &signed_attrs_body(content_type, content)))
}

pub fn make_signer_without_content_type(spec: &SignerSpec<'_>) -> Vec<u8> {
    let attrs_body =
        seq(&[oid(OID_MESSAGE_DIGEST), set(&octets(&HashAlg::Sha256.digest(spec.content)))]
            .concat());
    let wire = tlv(0xa0, &attrs_body);
    let signature = sign(spec.key, &tlv(0x31, &attrs_body));
    let mut body = int(1);
    body.extend(seq(&[name(spec.issuer), int(spec.serial)].concat()));
    body.extend(alg_id(OID_SHA256, true));
    body.extend(wire);
    body.extend(alg_id(OID_ECDSA_SHA256, false));
    body.extend(octets(&signature));
    seq(&body)
}

pub fn make_signer(spec: &SignerSpec<'_>) -> Vec<u8> {
    let attrs_body = signed_attrs_body(spec.content_type, spec.content);
    let wire = tlv(0xa0, &attrs_body);
    let signature = sign(spec.key, &tlv(0x31, &attrs_body));

    let mut body = int(1);
    body.extend(seq(&[name(spec.issuer), int(spec.serial)].concat()));
    body.extend(alg_id(OID_SHA256, true));
    body.extend(wire);
    body.extend(alg_id(OID_ECDSA_SHA256, false));
    body.extend(octets(&signature));
    if !spec.unsigned.is_empty() {
        body.extend(tlv(0xa1, &spec.unsigned.concat()));
    }
    seq(&body)
}

pub fn make_pkcs7(
    content_type: &str,
    econtent: &[u8],
    certs: &[Vec<u8>],
    signers: &[Vec<u8>],
) -> Vec<u8> {
    let mut body = int(1);
    body.extend(set(&alg_id(OID_SHA256, true)));
    body.extend(seq(&[oid(content_type), explicit(0, econtent)].concat()));
    if !certs.is_empty() {
        body.extend(tlv(0xa0, &certs.concat()));
    }
    body.extend(set(&signers.concat()));
    let signed_data = seq(&body);
    seq(&[oid(OID_SIGNED_DATA), explicit(0, &signed_data)].concat())
}

pub fn spc_indirect(digest: &[u8]) -> Vec<u8> {
    let data = seq(&[oid(OID_SPC_PE_IMAGE), null()].concat());
    let message_digest = seq(&[alg_id(OID_SHA256, true), octets(digest)].concat());
    seq(&[data, message_digest].concat())
}

const HEADERS: usize = 0x200;
const OPTIONAL_HEADER: usize = 0x98;
const SECURITY_DIR: usize = 0x128;
const SECTION_TABLE: usize = 0x188;

pub fn build_pe(section: &[u8], certificate_table: &[u8]) -> Vec<u8> {
    build_pe_with_sections(&[section.to_vec()], certificate_table)
}

pub fn build_pe_with_sections(sections: &[Vec<u8>], certificate_table: &[u8]) -> Vec<u8> {
    let count = sections.len();
    let mut file = vec![0u8; HEADERS];
    file[0] = b'M';
    file[1] = b'Z';
    file[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    file[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    file[0x86..0x88].copy_from_slice(&(count as u16).to_le_bytes());
    file[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    file[OPTIONAL_HEADER..OPTIONAL_HEADER + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    file[OPTIONAL_HEADER + 60..OPTIONAL_HEADER + 64]
        .copy_from_slice(&(HEADERS as u32).to_le_bytes());
    file[OPTIONAL_HEADER + 108..OPTIONAL_HEADER + 112].copy_from_slice(&16u32.to_le_bytes());

    let mut at = HEADERS;
    for (index, data) in sections.iter().enumerate() {
        let header = SECTION_TABLE + index * 40;
        if header + 40 <= HEADERS {
            file[header..header + 8].copy_from_slice(b".text\0\0\0");
            file[header + 16..header + 20].copy_from_slice(&(data.len() as u32).to_le_bytes());
            file[header + 20..header + 24].copy_from_slice(&(at as u32).to_le_bytes());
        }
        at += data.len();
    }
    for data in sections {
        file.extend_from_slice(data);
    }

    if !certificate_table.is_empty() {
        let start = file.len() as u32;
        file[SECURITY_DIR..SECURITY_DIR + 4].copy_from_slice(&start.to_le_bytes());
        file[SECURITY_DIR + 4..SECURITY_DIR + 8]
            .copy_from_slice(&(certificate_table.len() as u32).to_le_bytes());
        file.extend_from_slice(certificate_table);
    }
    file
}

pub fn win_cert(pkcs7: &[u8], revision: u16, certificate_type: u16) -> Vec<u8> {
    let length = 8 + pkcs7.len();
    let mut entry = Vec::with_capacity(length);
    entry.extend_from_slice(&(length as u32).to_le_bytes());
    entry.extend_from_slice(&revision.to_le_bytes());
    entry.extend_from_slice(&certificate_type.to_le_bytes());
    entry.extend_from_slice(pkcs7);
    while entry.len() % 8 != 0 {
        entry.push(0);
    }
    entry
}

pub fn digest_of(file: &[u8]) -> Vec<u8> {
    let pe = PeBytes::parse(file).expect("the harness builds a parseable PE");
    crate::pe_digest(&pe, HashAlg::Sha256).expect("digest")
}

pub struct Anchor {
    pub key: SigningKey,
    pub der: Vec<u8>,
    pub store: TrustStore,
}

pub fn anchor(name: &str) -> Anchor {
    let root_key = key(1);
    let spec = CertSpec::ca(name, name).with_serial(1);
    let der = make_cert(&spec, &root_key, &root_key);
    let leaked: &'static [u8] = Box::leak(der.clone().into_boxed_slice());
    Anchor { key: root_key, der, store: TrustStore::pinning(leaked, "Synthetic Test Root", false) }
}

pub fn at(text: &str) -> DateTime<Utc> {
    let year: i32 = text[0..4].parse().unwrap();
    let month: u32 = text[5..7].parse().unwrap();
    let day: u32 = text[8..10].parse().unwrap();
    Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).single().unwrap()
}

pub struct Forgery {
    pub anchor: Anchor,
    pub leaf_key: SigningKey,
    pub leaf: CertSpec,
    pub leaf_issued_by: Option<SigningKey>,
    pub extra_certs: Vec<Vec<u8>>,
    pub unsigned: Vec<Vec<u8>>,
    pub timestamp: Option<String>,
    pub digest_override: Option<Vec<u8>>,
}

impl Forgery {
    pub fn new(anchor: Anchor) -> Self {
        Forgery {
            leaf_key: key(2),
            leaf: CertSpec::leaf("Evil Software Ltd", &subject_of(&anchor)),
            anchor,
            leaf_issued_by: None,
            extra_certs: Vec::new(),
            unsigned: Vec::new(),
            timestamp: None,
            digest_override: None,
        }
    }

    pub fn build(&self, section: &[u8]) -> Vec<u8> {
        let issuer_key = self.leaf_issued_by.clone().unwrap_or_else(|| self.anchor.key.clone());
        let leaf_der = make_cert(&self.leaf, &self.leaf_key, &issuer_key);
        let mut unsigned = self.unsigned.clone();
        let issuer = self.leaf.issuer.clone();

        let stub = build_pe(section, &win_cert(&[0u8; 8], 0x0200, 0x0002));
        let digest = self.digest_override.clone().unwrap_or_else(|| digest_of(&stub));
        let econtent = spc_indirect(&digest);

        if let Some(gen_time) = &self.timestamp {
            let content = &econtent[header_len(&econtent)..];
            let signature = signature_value(&self.leaf_key, OID_SPC_INDIRECT, content);
            unsigned.push(real_timestamp(&self.anchor, gen_time, &signature));
        }

        let signer = make_signer(&SignerSpec {
            issuer: &issuer,
            serial: self.leaf.serial,
            key: &self.leaf_key,
            content: &econtent[header_len(&econtent)..],
            content_type: OID_SPC_INDIRECT,
            unsigned,
        });
        let mut certs = vec![leaf_der, self.anchor.der.clone()];
        certs.extend(self.extra_certs.clone());
        let pkcs7 = make_pkcs7(OID_SPC_INDIRECT, &econtent, &certs, &[signer]);
        build_pe(section, &win_cert(&pkcs7, 0x0200, 0x0002))
    }
}

fn subject_of(anchor: &Anchor) -> String {
    crate::cert::ParsedCert::parse(&anchor.der).unwrap().display_name()
}

pub fn header_len(tlv: &[u8]) -> usize {
    let first = tlv.get(1).copied().unwrap_or(0);
    if first & 0x80 == 0 {
        2
    } else {
        2 + usize::from(first & 0x7f)
    }
}

pub fn build_catalog(anchor: &Anchor, signer_key: &SigningKey, members: &[Vec<u8>]) -> Vec<u8> {
    let leaf_spec = CertSpec::leaf("Catalog Signer", &subject_of(anchor));
    let leaf_der = make_cert(&leaf_spec, signer_key, &anchor.key);

    let items: Vec<u8> =
        members.iter().map(|id| seq(&[octets(id), set(&[])].concat())).collect::<Vec<_>>().concat();
    let ctl = seq(&[
        seq(&oid(OID_CATALOG_LIST)),
        octets(&[0x01; 16]),
        utctime("240101000000Z"),
        alg_id(OID_SHA256, true),
        seq(&items),
    ]
    .concat());

    let signer = make_signer(&SignerSpec {
        issuer: &leaf_spec.issuer,
        serial: leaf_spec.serial,
        key: signer_key,
        content: &ctl[header_len(&ctl)..],
        content_type: OID_CTL,
        unsigned: Vec::new(),
    });
    make_pkcs7(OID_CTL, &ctl, &[leaf_der, anchor.der.clone()], &[signer])
}

pub fn forged_countersignature(time: &str, issuer: &str, serial: u64) -> Vec<u8> {
    let attrs = seq(&[oid(OID_SIGNING_TIME), set(&utctime(time))].concat());
    let mut body = int(1);
    body.extend(seq(&[name(issuer), int(serial)].concat()));
    body.extend(alg_id(OID_SHA256, true));
    body.extend(tlv(0xa0, &attrs));
    body.extend(alg_id(OID_ECDSA_SHA256, false));
    body.extend(octets(&[0x42; 70]));
    let signer_info = seq(&body);
    seq(&[oid(OID_COUNTERSIGNATURE), set(&signer_info)].concat())
}

pub fn real_timestamp(anchor: &Anchor, gen_time: &str, signature: &[u8]) -> Vec<u8> {
    let tsa_key = key(5);
    let tsa_spec = CertSpec::leaf("Test Timestamp Authority", &subject_of(anchor))
        .with_serial(0x7551)
        .with_eku(Some(vec!["1.3.6.1.5.5.7.3.8".into()]));
    let tsa_der = make_cert(&tsa_spec, &tsa_key, &anchor.key);

    let imprint =
        seq(&[alg_id(OID_SHA256, true), octets(&HashAlg::Sha256.digest(signature))].concat());
    let tst_info = seq(&[
        int(1),
        oid("1.3.6.1.4.1.311.3.2.1"),
        imprint,
        int(42),
        tlv(0x18, gen_time.as_bytes()),
    ]
    .concat());

    let econtent = octets(&tst_info);
    let signer = make_signer(&SignerSpec {
        issuer: &tsa_spec.issuer,
        serial: tsa_spec.serial,
        key: &tsa_key,
        content: &tst_info,
        content_type: OID_TST_INFO,
        unsigned: Vec::new(),
    });
    let token = make_pkcs7(OID_TST_INFO, &econtent, &[tsa_der, anchor.der.clone()], &[signer]);
    seq(&[oid(OID_RFC3161), set(&token)].concat())
}

const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_RFC3161: &str = "1.3.6.1.4.1.311.3.3.1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_harness_can_produce_a_signature_that_really_verifies() {
        let forgery = Forgery::new(anchor("Synthetic Test Root"));
        let file = forgery.build(&[0x90; 64]);
        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        assert!(matches!(verdict, Verdict::Valid { .. }), "the harness cannot sign: {verdict:?}");

        let mut tampered = file;
        tampered[HEADERS] ^= 0xff;
        assert!(matches!(
            crate::verify_embedded_at(&tampered, &forgery.anchor.store, at("2024-01-01")),
            Verdict::Invalid { .. }
        ));
    }

    #[test]
    fn a_forged_countersignature_cannot_resurrect_an_expired_certificate() {
        let mut forgery = Forgery::new(anchor("Synthetic Test Root"));
        forgery.leaf = forgery.leaf.clone().valid_between("150101000000Z", "160101000000Z");

        let honest = forgery.build(&[0x90; 64]);
        assert!(
            matches!(
                crate::verify_embedded_at(&honest, &forgery.anchor.store, at("2024-01-01")),
                Verdict::Expired { .. }
            ),
            "an expired leaf with no timestamp is Expired"
        );

        let issuer = forgery.leaf.issuer.clone();
        forgery.unsigned = vec![forged_countersignature("150601000000Z", &issuer, 0x99)];
        let forged = forgery.build(&[0x90; 64]);

        let verdict = crate::verify_embedded_at(&forged, &forgery.anchor.store, at("2024-01-01"));
        assert!(
            matches!(verdict, Verdict::Unknown { .. }),
            "a countersignature that verifies nothing must not turn a dead certificate \
             into a valid signature: {verdict:?}"
        );
    }

    #[test]
    fn a_corroborated_timestamp_still_rescues_an_expired_certificate() {
        let mut forgery = Forgery::new(anchor("Synthetic Test Root"));
        forgery.leaf = forgery.leaf.clone().valid_between("150101000000Z", "160101000000Z");
        forgery.timestamp = Some("20150601120000Z".into());

        let file = forgery.build(&[0x90; 64]);
        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        assert!(
            matches!(verdict, Verdict::Valid { .. }),
            "a corroborated timestamp must still date the signature: {verdict:?}"
        );

        let signers =
            crate::embedded_signers(&file, &forgery.anchor.store, at("2024-01-01")).unwrap();
        assert!(signers[0].signing_time_trusted);
        assert_eq!(signers[0].evaluated_at.format("%Y-%m-%d").to_string(), "2015-06-01");
    }

    #[test]
    fn a_timestamp_over_someone_elses_signature_does_not_count() {
        let mut forgery = Forgery::new(anchor("Synthetic Test Root"));
        forgery.leaf = forgery.leaf.clone().valid_between("150101000000Z", "160101000000Z");
        let stolen = real_timestamp(&forgery.anchor, "20150601120000Z", b"another signature");
        forgery.unsigned = vec![stolen];

        let file = forgery.build(&[0x90; 64]);
        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        assert!(matches!(verdict, Verdict::Unknown { .. }), "{verdict:?}");
    }

    #[test]
    fn a_certificate_bag_cannot_make_chain_building_explode() {
        let mut forgery = Forgery::new(anchor("Synthetic Test Root"));
        let hydra_key = key(7);
        forgery.leaf = CertSpec::leaf("Evil Software Ltd", "Hydra");
        forgery.leaf_issued_by = Some(hydra_key.clone());
        forgery.extra_certs = (1..=10)
            .map(|serial| {
                make_cert(
                    &CertSpec::ca("Hydra", "Hydra").with_serial(serial),
                    &hydra_key,
                    &hydra_key,
                )
            })
            .collect();

        let file = forgery.build(&[0x90; 64]);
        let started = std::time::Instant::now();
        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        let elapsed = started.elapsed();
        assert!(
            !matches!(verdict, Verdict::Valid { .. }),
            "an unanchored chain must not be valid: {verdict:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "chain building took {elapsed:?} on a 10-certificate bag — the search is \
             exponential in the bag, which is a denial of service reachable from any file"
        );
    }

    #[test]
    fn overlapping_sections_cannot_make_hashing_quadratic() {
        let body = vec![0u8; 1024 * 1024];
        let mut file = build_pe(&body, &[]);
        let count = 60usize;
        let whole = file.len() as u32;
        file[0x86..0x88].copy_from_slice(&(count as u16).to_le_bytes());
        for index in 0..count {
            let header = SECTION_TABLE + index * 40;
            file[header + 16..header + 20].copy_from_slice(&whole.to_le_bytes());
            file[header + 20..header + 24].copy_from_slice(&0u32.to_le_bytes());
        }

        let started = std::time::Instant::now();
        let keys = crate::catalog::candidate_keys(&file);
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "hashing a 1 MB file took {elapsed:?} because its {count} sections each claim the \
             whole image: work is O(sections x size), not O(size), and 65,535 sections are legal ({} keys)",
            keys.len()
        );
    }

    #[test]
    fn nested_signatures_cannot_multiply_the_work_of_judging_one_file() {
        let anchor = anchor("Synthetic Test Root");
        let leaf_key = key(2);
        let leaf_spec = CertSpec::leaf("Evil Software Ltd", &subject_of(&anchor));
        let leaf_der = make_cert(&leaf_spec, &leaf_key, &anchor.key);

        let section = [0x90u8; 64];
        let stub = build_pe(&section, &win_cert(&[0u8; 8], 0x0200, 0x0002));
        let econtent = spc_indirect(&digest_of(&stub));
        let content = &econtent[header_len(&econtent)..];

        let one = |unsigned: Vec<Vec<u8>>| {
            make_signer(&SignerSpec {
                issuer: &leaf_spec.issuer,
                serial: leaf_spec.serial,
                key: &leaf_key,
                content,
                content_type: OID_SPC_INDIRECT,
                unsigned,
            })
        };

        let inner = make_pkcs7(
            OID_SPC_INDIRECT,
            &econtent,
            std::slice::from_ref(&leaf_der),
            &vec![one(Vec::new()); 32],
        );
        let nested_attr = seq(&[oid("1.3.6.1.4.1.311.2.4.1"), set(&inner)].concat());
        let outer = make_pkcs7(
            OID_SPC_INDIRECT,
            &econtent,
            &[leaf_der, anchor.der.clone()],
            &vec![one(vec![nested_attr]); 32],
        );
        let file = build_pe(&section, &win_cert(&outer, 0x0200, 0x0002));

        let started = std::time::Instant::now();
        let outcomes = crate::embedded_signers(&file, &anchor.store, at("2024-01-01")).unwrap();
        assert!(outcomes.len() <= 64, "{} signatures were evaluated for one file", outcomes.len());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn signed_attributes_must_say_what_they_signed() {
        let anchor = anchor("Synthetic Test Root");
        let leaf_key = key(2);
        let leaf_spec = CertSpec::leaf("Evil Software Ltd", &subject_of(&anchor));
        let leaf_der = make_cert(&leaf_spec, &leaf_key, &anchor.key);

        let section = [0x90u8; 64];
        let stub = build_pe(&section, &win_cert(&[0u8; 8], 0x0200, 0x0002));
        let econtent = spc_indirect(&digest_of(&stub));
        let spec = SignerSpec {
            issuer: &leaf_spec.issuer,
            serial: leaf_spec.serial,
            key: &leaf_key,
            content: &econtent[header_len(&econtent)..],
            content_type: OID_SPC_INDIRECT,
            unsigned: Vec::new(),
        };

        let silent = make_signer_without_content_type(&spec);
        let pkcs7 = make_pkcs7(
            OID_SPC_INDIRECT,
            &econtent,
            &[leaf_der.clone(), anchor.der.clone()],
            &[silent],
        );
        let file = build_pe(&section, &win_cert(&pkcs7, 0x0200, 0x0002));
        let verdict = crate::verify_embedded_at(&file, &anchor.store, at("2024-01-01"));
        assert!(matches!(verdict, Verdict::Invalid { .. }), "{verdict:?}");

        let speaking = make_signer(&spec);
        let pkcs7 =
            make_pkcs7(OID_SPC_INDIRECT, &econtent, &[leaf_der, anchor.der.clone()], &[speaking]);
        let file = build_pe(&section, &win_cert(&pkcs7, 0x0200, 0x0002));
        assert!(matches!(
            crate::verify_embedded_at(&file, &anchor.store, at("2024-01-01")),
            Verdict::Valid { .. }
        ));
    }

    #[test]
    fn a_signature_lifted_from_another_file_does_not_verify() {
        let forgery = Forgery::new(anchor("Synthetic Test Root"));
        let signed = forgery.build(&[0x90; 64]);
        let table_start =
            u32::from_le_bytes(signed[SECURITY_DIR..SECURITY_DIR + 4].try_into().unwrap()) as usize;
        let table = signed[table_start..].to_vec();

        let other = build_pe(&[0xcc; 64], &table);
        assert!(matches!(
            crate::verify_embedded_at(&other, &forgery.anchor.store, at("2024-01-01")),
            Verdict::Invalid { .. }
        ));
    }

    #[test]
    fn data_appended_after_the_certificate_table_is_not_signed_for() {
        let forgery = Forgery::new(anchor("Synthetic Test Root"));
        let mut file = forgery.build(&[0x90; 64]);
        file.extend_from_slice(b"payload that nobody signed");
        assert!(
            !matches!(
                crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01")),
                Verdict::Valid { .. }
            ),
            "trailing data outside the certificate table must break the digest"
        );
    }

    #[test]
    fn a_certificate_table_pointing_outside_the_file_is_not_a_signature() {
        let forgery = Forgery::new(anchor("Synthetic Test Root"));
        let mut file = forgery.build(&[0x90; 64]);
        let huge = u32::MAX - 16;
        file[SECURITY_DIR..SECURITY_DIR + 4].copy_from_slice(&huge.to_le_bytes());
        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        assert!(matches!(verdict, Verdict::Unsigned | Verdict::Unknown { .. }), "{verdict:?}");
    }

    #[test]
    fn a_chain_that_skips_an_intermediate_is_not_valid() {
        let mut forgery = Forgery::new(anchor("Synthetic Test Root"));
        let intermediate_key = key(9);
        forgery.leaf = CertSpec::leaf("Evil Software Ltd", "Missing Intermediate CA");
        forgery.leaf_issued_by = Some(intermediate_key.clone());

        let file = forgery.build(&[0x90; 64]);
        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        assert!(matches!(verdict, Verdict::Unknown { .. }), "{verdict:?}");

        let stray = make_cert(
            &CertSpec::ca("Missing Intermediate CA", "Synthetic Test Root"),
            &intermediate_key,
            &key(11),
        );
        forgery.extra_certs = vec![stray];
        let file = forgery.build(&[0x90; 64]);
        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        assert!(
            !matches!(verdict, Verdict::Valid { .. }),
            "an intermediate the root did not issue must not complete a chain: {verdict:?}"
        );
    }

    #[test]
    fn a_certificate_not_issued_for_code_signing_does_not_exonerate() {
        let mut forgery = Forgery::new(anchor("Synthetic Test Root"));
        forgery.leaf = forgery.leaf.clone().with_eku(Some(vec!["1.3.6.1.5.5.7.3.1".into()]));
        let file = forgery.build(&[0x90; 64]);
        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        assert!(
            !matches!(verdict, Verdict::Valid { .. }),
            "a TLS server certificate signed this and it came out {verdict:?}"
        );
    }

    #[test]
    fn a_payload_in_a_second_certificate_table_entry_is_visible_but_unsigned() {
        let forgery = Forgery::new(anchor("Synthetic Test Root"));
        let signed = forgery.build(&[0x90; 64]);
        let table_start =
            u32::from_le_bytes(signed[SECURITY_DIR..SECURITY_DIR + 4].try_into().unwrap()) as usize;

        let mut table = signed[table_start..].to_vec();
        table.extend(win_cert(&[0xde; 4096], 0x0200, 0x0001));

        let mut file = signed[..table_start].to_vec();
        file[SECURITY_DIR + 4..SECURITY_DIR + 8]
            .copy_from_slice(&(table.len() as u32).to_le_bytes());
        file.extend_from_slice(&table);

        let verdict = crate::verify_embedded_at(&file, &forgery.anchor.store, at("2024-01-01"));
        assert!(matches!(verdict, Verdict::Valid { .. }), "{verdict:?}");

        let mut tampered = file.clone();
        tampered[HEADERS] ^= 0x01;
        assert!(matches!(
            crate::verify_embedded_at(&tampered, &forgery.anchor.store, at("2024-01-01")),
            Verdict::Invalid { .. }
        ));
    }

    #[test]
    fn a_self_signed_leaf_and_an_unrecognised_ca_are_told_apart() {
        let internal = anchor("Contoso Internal Root");
        let deep = Forgery::new(internal).build(&[0x90; 64]);
        let verdict = crate::verify_embedded_at(&deep, &TrustStore::empty(), at("2024-01-01"));
        match &verdict {
            Verdict::Untrusted { self_signed_leaf, .. } => assert!(
                !self_signed_leaf,
                "a leaf issued by a CA above it is not self-signed: {verdict:?}"
            ),
            other => panic!("expected Untrusted, got {other:?}"),
        }
        let said = verdict.describe();
        assert!(said.contains("THIS BUILD DOES NOT HAVE THAT ROOT"), "{said}");
        assert!(!said.contains("self-signed"), "{said}");

        let mut own = Forgery::new(anchor("Unused Root"));
        own.leaf = CertSpec::leaf("Evil Software Ltd", "Evil Software Ltd");
        own.leaf_issued_by = Some(own.leaf_key.clone());
        let flat = own.build(&[0x90; 64]);
        let verdict = crate::verify_embedded_at(&flat, &TrustStore::empty(), at("2024-01-01"));
        match &verdict {
            Verdict::Untrusted { self_signed_leaf, .. } => {
                assert!(self_signed_leaf, "the leaf issued itself: {verdict:?}")
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }
        let said = verdict.describe();
        assert!(said.contains("issued its own signing certificate"), "{said}");
        assert!(!said.contains("THIS BUILD DOES NOT HAVE THAT ROOT"), "{said}");

        let real = anchor("Synthetic Test Root");
        let honest = Forgery::new(anchor("Synthetic Test Root")).build(&[0x90; 64]);
        assert!(
            matches!(
                crate::verify_embedded_at(&honest, &real.store, at("2024-01-01")),
                Verdict::Valid { .. }
            ),
            "the anchored control must verify"
        );
    }

    #[test]
    fn an_unanchored_chain_is_never_reported_as_a_modified_file() {
        for file in [Forgery::new(anchor("Contoso Internal Root")).build(&[0x90; 64]), {
            let mut own = Forgery::new(anchor("Unused Root"));
            own.leaf = CertSpec::leaf("Evil Software Ltd", "Evil Software Ltd");
            own.leaf_issued_by = Some(own.leaf_key.clone());
            own.build(&[0x90; 64])
        }] {
            let verdict = crate::verify_embedded_at(&file, &TrustStore::empty(), at("2024-01-01"));
            assert!(
                !matches!(verdict, Verdict::Invalid { .. }),
                "not having a root is not evidence the file was modified: {verdict:?}"
            );
        }

        let mut tampered = Forgery::new(anchor("Contoso Internal Root")).build(&[0x90; 64]);
        tampered[HEADERS] ^= 0x01;
        assert!(matches!(
            crate::verify_embedded_at(&tampered, &TrustStore::empty(), at("2024-01-01")),
            Verdict::Invalid { .. }
        ));
    }

    #[test]
    fn a_catalog_we_do_not_trust_cannot_vouch_for_a_file() {
        let real = anchor("Synthetic Test Root");
        let file = build_pe(&[0x90; 64], &[]);
        let digest = crate::catalog::candidate_keys(&file);
        let members: Vec<Vec<u8>> = digest.iter().map(|k| k.bytes().to_vec()).collect();
        assert!(!members.is_empty());

        let rogue_root = anchor("Rogue Root");
        let rogue = build_catalog(&rogue_root, &key(3), &members);

        let mut index = crate::catalog::CatalogIndex::new();
        index
            .add("rogue.cat", &rogue, &real.store, at("2024-01-01"))
            .expect("a well-formed catalog");
        let verdict = crate::catalog::verify_catalog(&file, &index);
        assert!(
            matches!(verdict, Verdict::Untrusted { .. }),
            "an unanchored catalog must not vouch for a file: {verdict:?}"
        );

        let honest = build_catalog(&real, &key(3), &members);
        let mut index = crate::catalog::CatalogIndex::new();
        index
            .add("honest.cat", &honest, &real.store, at("2024-01-01"))
            .expect("a well-formed catalog");
        assert!(matches!(
            crate::catalog::verify_catalog(&file, &index),
            Verdict::CatalogValid { .. }
        ));
    }
}
