use cms::signed_data::SignerInfo;
use const_oid::ObjectIdentifier;
use der::Decode;

use crate::cert::ParsedCert;
use crate::der_walk::{self, Tlv};

pub const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
pub const OID_SPC_INDIRECT_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");
pub const OID_CTL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.1");

const MAX_CERTIFICATES: usize = 512;

const MAX_SIGNERS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    Malformed(&'static str),
    NotSignedData(ObjectIdentifier),
    NoSigners,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Malformed(what) => write!(f, "malformed PKCS#7: {what}"),
            ParseError::NotSignedData(oid) => write!(f, "content type is {oid}, not signedData"),
            ParseError::NoSigners => write!(f, "PKCS#7 carries no readable signer information"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttributeRef<'a> {
    pub oid: ObjectIdentifier,
    pub values: Vec<Tlv<'a>>,
}

#[derive(Clone, Debug)]
pub struct SignerRef<'a> {
    pub info: SignerInfo,
    pub signed_attrs_der: Option<Vec<u8>>,
    pub signed_attrs: Vec<AttributeRef<'a>>,
    pub unsigned_attrs: Vec<AttributeRef<'a>>,
}

impl<'a> SignerRef<'a> {
    pub fn signed_attr(&self, oid: ObjectIdentifier) -> Option<Tlv<'a>> {
        self.signed_attrs.iter().find(|a| a.oid == oid).and_then(|a| a.values.first().copied())
    }

    pub fn unsigned_attr(&self, oid: ObjectIdentifier) -> Option<Tlv<'a>> {
        self.unsigned_attrs.iter().find(|a| a.oid == oid).and_then(|a| a.values.first().copied())
    }
}

pub struct SignedDataRef<'a> {
    pub raw: &'a [u8],
    pub econtent_type: ObjectIdentifier,
    pub econtent: Option<Tlv<'a>>,
    pub certs: Vec<ParsedCert<'a>>,
    pub signers: Vec<SignerRef<'a>>,
}

impl<'a> SignedDataRef<'a> {
    pub fn content_to_digest(&self) -> Option<&'a [u8]> {
        Some(self.econtent?.content)
    }
}

pub fn parse(der: &[u8]) -> Result<SignedDataRef<'_>, ParseError> {
    let outer = der_walk::first(der).ok_or(ParseError::Malformed("not a DER structure"))?;
    if outer.tag != 0x30 {
        return Err(ParseError::Malformed("ContentInfo is not a SEQUENCE"));
    }

    let fields = outer.children();
    let type_tlv = fields.first().ok_or(ParseError::Malformed("ContentInfo has no contentType"))?;
    if type_tlv.tag != 0x06 {
        return Err(ParseError::Malformed("contentType is not an OID"));
    }
    let content_type = ObjectIdentifier::from_bytes(type_tlv.content)
        .map_err(|_| ParseError::Malformed("contentType is not a readable OID"))?;
    if content_type != OID_SIGNED_DATA {
        return Err(ParseError::NotSignedData(content_type));
    }

    let explicit = fields
        .get(1)
        .filter(|f| f.context_tag() == Some(0))
        .ok_or(ParseError::Malformed("ContentInfo has no content"))?;
    let signed_data_tlv = der_walk::first(explicit.content)
        .ok_or(ParseError::Malformed("content is not a DER structure"))?;

    from_signed_data_tlv(signed_data_tlv)
}

pub fn from_signed_data_tlv(tlv: Tlv<'_>) -> Result<SignedDataRef<'_>, ParseError> {
    if tlv.tag != 0x30 {
        return Err(ParseError::Malformed("SignedData is not a SEQUENCE"));
    }

    let fields = tlv.children();

    let encap = fields.get(2).ok_or(ParseError::Malformed("SignedData has no encapContentInfo"))?;
    let encap_fields = encap.children();
    let econtent_type = encap_fields
        .first()
        .filter(|f| f.tag == 0x06)
        .and_then(|f| ObjectIdentifier::from_bytes(f.content).ok())
        .ok_or(ParseError::Malformed("encapContentInfo has no eContentType"))?;
    let econtent = encap_fields
        .get(1)
        .filter(|f| f.context_tag() == Some(0))
        .and_then(|f| der_walk::first(f.content));

    let mut certs = Vec::new();
    let mut signers = Vec::new();

    for field in fields.iter().skip(3) {
        match (field.context_tag(), field.tag) {
            (Some(0), _) => {
                der_walk::for_each_child(field.content, |entry| {
                    if certs.len() >= MAX_CERTIFICATES {
                        return;
                    }
                    if entry.tag == 0x30 {
                        if let Some(parsed) = ParsedCert::parse(entry.full) {
                            certs.push(parsed);
                        }
                    }
                });
            }
            (Some(1), _) => {}
            (None, 0x31) => {
                der_walk::for_each_child(field.content, |entry| {
                    if signers.len() >= MAX_SIGNERS || entry.tag != 0x30 {
                        return;
                    }
                    if let Some(signer) = parse_signer(entry) {
                        signers.push(signer);
                    }
                });
            }
            _ => {}
        }
    }

    if signers.is_empty() {
        return Err(ParseError::NoSigners);
    }

    Ok(SignedDataRef { raw: tlv.full, econtent_type, econtent, certs, signers })
}

fn parse_signer(tlv: Tlv<'_>) -> Option<SignerRef<'_>> {
    let info = SignerInfo::from_der(tlv.full).ok()?;
    let fields = tlv.children();

    let signed_attrs_tlv = fields.iter().find(|f| f.tag == 0xa0);
    let unsigned_attrs_tlv = fields.iter().find(|f| f.tag == 0xa1);

    Some(SignerRef {
        info,
        signed_attrs_der: signed_attrs_tlv.and_then(der_walk::retag_as_set),
        signed_attrs: signed_attrs_tlv.map(|t| attributes_of(*t)).unwrap_or_default(),
        unsigned_attrs: unsigned_attrs_tlv.map(|t| attributes_of(*t)).unwrap_or_default(),
    })
}

pub fn attributes_of(set: Tlv<'_>) -> Vec<AttributeRef<'_>> {
    let mut out = Vec::new();
    for attr in set.children() {
        if attr.tag != 0x30 {
            continue;
        }
        let fields = attr.children();
        let Some(oid_tlv) = fields.first().filter(|f| f.tag == 0x06) else {
            continue;
        };
        let Ok(oid) = ObjectIdentifier::from_bytes(oid_tlv.content) else {
            continue;
        };
        let values =
            fields.get(1).filter(|f| f.tag == 0x31).map(|f| f.children()).unwrap_or_default();
        out.push(AttributeRef { oid, values });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_in_here_panics_on_garbage() {
        let mut state = 0x2468_1357u32;
        for _ in 0..20_000 {
            let len = (state % 96) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                buf.push((state >> 16) as u8);
            }
            let _ = parse(&buf);
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        }
    }

    #[test]
    fn a_non_signed_data_content_info_is_named_not_guessed() {
        let der = [
            0x30u8, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0,
            0x00,
        ];
        assert!(matches!(parse(&der), Err(ParseError::NotSignedData(_))));
    }
}
