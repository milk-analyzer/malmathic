use chrono::{DateTime, TimeZone, Utc};
use const_oid::ObjectIdentifier;
use der::{Decode, Tagged};
use x509_cert::Certificate;

use crate::der_walk;

const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_ANY_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");
pub const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
pub const OID_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
pub const OID_CTL_SIGNING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.1");
pub const OID_MS_SYSTEM_COMPONENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.6");

#[derive(Clone, Debug)]
pub struct ParsedCert<'a> {
    pub der: &'a [u8],
    pub tbs: &'a [u8],
    pub issuer_der: &'a [u8],
    pub subject_der: &'a [u8],
    pub cert: Certificate,
}

impl<'a> ParsedCert<'a> {
    pub fn parse(der: &'a [u8]) -> Option<Self> {
        let cert = Certificate::from_der(der).ok()?;

        let outer = der_walk::first(der)?;
        if outer.tag != 0x30 {
            return None;
        }
        let tbs_tlv = der_walk::first(outer.content)?;
        if tbs_tlv.tag != 0x30 {
            return None;
        }

        let fields = tbs_tlv.children();
        let mut index = 0usize;
        if fields.first().map(|f| f.tag) == Some(0xa0) {
            index = 1;
        }
        let issuer = fields.get(index.checked_add(2)?)?;
        let subject = fields.get(index.checked_add(4)?)?;

        Some(ParsedCert {
            der,
            tbs: tbs_tlv.full,
            issuer_der: issuer.full,
            subject_der: subject.full,
            cert,
        })
    }

    pub fn is_self_issued(&self) -> bool {
        self.issuer_der == self.subject_der
    }

    pub fn not_before(&self) -> Option<DateTime<Utc>> {
        to_chrono(self.cert.tbs_certificate.validity.not_before)
    }

    pub fn not_after(&self) -> Option<DateTime<Utc>> {
        to_chrono(self.cert.tbs_certificate.validity.not_after)
    }

    pub fn is_valid_at(&self, at: DateTime<Utc>) -> bool {
        match (self.not_before(), self.not_after()) {
            (Some(before), Some(after)) => at >= before && at <= after,
            _ => false,
        }
    }

    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        let extensions = self.cert.tbs_certificate.extensions.as_ref()?;
        let ext = extensions.iter().find(|e| e.extn_id == OID_SUBJECT_KEY_ID)?;
        let inner = der_walk::first(ext.extn_value.as_bytes())?;
        if inner.tag != 0x04 {
            return None;
        }
        Some(inner.content)
    }

    pub fn is_ca(&self) -> bool {
        let Some(extensions) = self.cert.tbs_certificate.extensions.as_ref() else {
            return false;
        };
        let Some(ext) = extensions.iter().find(|e| e.extn_id == OID_BASIC_CONSTRAINTS) else {
            return false;
        };
        let Some(seq) = der_walk::first(ext.extn_value.as_bytes()) else {
            return false;
        };
        seq.children()
            .first()
            .is_some_and(|f| f.tag == 0x01 && f.content.first().is_some_and(|b| *b != 0))
    }

    pub fn extended_key_usages(&self) -> Option<Vec<ObjectIdentifier>> {
        let extensions = self.cert.tbs_certificate.extensions.as_ref()?;
        let ext = extensions.iter().find(|e| e.extn_id == OID_EXT_KEY_USAGE)?;
        let seq = der_walk::first(ext.extn_value.as_bytes())?;
        if seq.tag != 0x30 {
            return Some(Vec::new());
        }
        Some(
            seq.children()
                .iter()
                .filter(|f| f.tag == 0x06)
                .filter_map(|f| ObjectIdentifier::from_bytes(f.content).ok())
                .collect(),
        )
    }

    pub fn allows_any(&self, purposes: &[ObjectIdentifier]) -> bool {
        match self.extended_key_usages() {
            None => true,
            Some(usages) => usages.iter().any(|oid| *oid == OID_ANY_EKU || purposes.contains(oid)),
        }
    }

    pub fn purposes(&self) -> String {
        match self.extended_key_usages() {
            None => "unconstrained".into(),
            Some(usages) if usages.is_empty() => "none".into(),
            Some(usages) => usages.iter().map(|o| o.to_string()).collect::<Vec<_>>().join(", "),
        }
    }

    pub fn display_name(&self) -> String {
        common_name(&self.cert.tbs_certificate.subject)
            .or_else(|| attribute(&self.cert.tbs_certificate.subject, OID_ORGANIZATION))
            .unwrap_or_else(|| "unnamed certificate".to_string())
    }

    pub fn issuer_name(&self) -> String {
        common_name(&self.cert.tbs_certificate.issuer)
            .or_else(|| attribute(&self.cert.tbs_certificate.issuer, OID_ORGANIZATION))
            .unwrap_or_else(|| "unnamed issuer".to_string())
    }

    pub fn serial(&self) -> &[u8] {
        self.cert.tbs_certificate.serial_number.as_bytes()
    }
}

fn common_name(name: &x509_cert::name::Name) -> Option<String> {
    attribute(name, OID_COMMON_NAME)
}

fn attribute(name: &x509_cert::name::Name, oid: ObjectIdentifier) -> Option<String> {
    let mut found = None;
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == oid {
                if let Some(text) = string_value(&atv.value) {
                    found = Some(text);
                }
            }
        }
    }
    found
}

fn string_value(value: &der::Any) -> Option<String> {
    let bytes = value.value();
    match value.tag() {
        der::Tag::Utf8String
        | der::Tag::PrintableString
        | der::Tag::Ia5String
        | der::Tag::TeletexString
        | der::Tag::VisibleString => Some(String::from_utf8_lossy(bytes).into_owned()),
        der::Tag::BmpString => {
            let units: Vec<u16> =
                bytes.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            Some(String::from_utf16_lossy(&units))
        }
        _ => None,
    }
}

fn to_chrono(time: x509_cert::time::Time) -> Option<DateTime<Utc>> {
    let seconds = i64::try_from(time.to_unix_duration().as_secs()).ok()?;
    Utc.timestamp_opt(seconds, 0).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_root_parses_and_reports_itself() {
        let der = include_bytes!("../roots/microsoft-root-2010.der");
        let cert = ParsedCert::parse(der).expect("the embedded root must parse");
        assert!(cert.is_self_issued());
        assert!(cert.is_ca());
        assert_eq!(cert.display_name(), "Microsoft Root Certificate Authority 2010");
        assert_eq!(cert.issuer_name(), "Microsoft Root Certificate Authority 2010");
        assert!(cert.tbs.len() < der.len());
        assert!(der.windows(cert.tbs.len()).any(|w| w == cert.tbs));
    }

    #[test]
    fn truncated_certificates_return_none_rather_than_panicking() {
        let der = include_bytes!("../roots/microsoft-root-2010.der");
        for cut in 0..der.len() {
            let _ = ParsedCert::parse(&der[..cut]);
        }
        for flip in (0..der.len()).step_by(7) {
            let mut copy = der.to_vec();
            copy[flip] ^= 0xff;
            let _ = ParsedCert::parse(&copy);
        }
    }
}
