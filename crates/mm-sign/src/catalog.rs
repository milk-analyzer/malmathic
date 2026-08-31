use std::collections::HashMap;

use chrono::{DateTime, Utc};
use const_oid::ObjectIdentifier;

use crate::crypto::HashAlg;
use crate::der_walk::{self, Tlv};
use crate::pe::PeBytes;
use crate::pkcs7::{self, AttributeRef, SignedDataRef};
use crate::trust::TrustStore;
use crate::verify::{self, Outcome};
use crate::{pe_digest, pe_digest_contiguous, Verdict};

pub const OID_CATALOG_LIST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.12.1.1");
pub const OID_CATALOG_LIST_MEMBER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.12.1.2");
pub const OID_CAT_NAMEVALUE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.12.2.1");
pub const OID_CAT_MEMBERINFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.12.2.2");
pub const OID_CAT_MEMBERINFO2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.12.2.3");

pub const CATROOT_DIRECTORIES: &[&str] = &[
    "\\Windows\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
    "\\Windows\\System32\\CatRoot\\{127D0A1D-4EF2-11D1-8608-00C04FC295EE}",
];

pub const MAX_CATALOG_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemberKey {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl MemberKey {
    pub fn from_subject_identifier(octets: &[u8]) -> Option<Self> {
        match octets.len() {
            20 | 32 => Self::from_digest(octets),
            40 | 64 => Self::from_digest(&decode_ascii_hex(octets)?),
            80 | 82 | 128 | 130 => Self::from_digest(&decode_ascii_hex(&narrow_utf16(octets)?)?),
            _ => None,
        }
    }

    pub fn from_digest(digest: &[u8]) -> Option<Self> {
        match digest.len() {
            20 => Some(MemberKey::Sha1(<[u8; 20]>::try_from(digest).ok()?)),
            32 => Some(MemberKey::Sha256(<[u8; 32]>::try_from(digest).ok()?)),
            _ => None,
        }
    }

    pub fn alg(&self) -> HashAlg {
        match self {
            MemberKey::Sha1(_) => HashAlg::Sha1,
            MemberKey::Sha256(_) => HashAlg::Sha256,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            MemberKey::Sha1(d) => d,
            MemberKey::Sha256(d) => d,
        }
    }

    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.bytes().len().saturating_mul(2));
        for byte in self.bytes() {
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
        out
    }
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble.saturating_sub(10)) as char,
    }
}

fn narrow_utf16(octets: &[u8]) -> Option<Vec<u8>> {
    if !octets.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(octets.len() / 2);
    for &[lo, hi] in octets.as_chunks::<2>().0 {
        if lo == 0 && hi == 0 {
            break;
        }
        if hi != 0 || !lo.is_ascii() {
            return None;
        }
        out.push(lo);
    }
    Some(out)
}

fn decode_ascii_hex(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for &[hi, lo] in text.as_chunks::<2>().0 {
        let hi = (hi as char).to_digit(16)?;
        let lo = (lo as char).to_digit(16)?;
        out.push(u8::try_from(hi.checked_mul(16)?.checked_add(lo)?).ok()?);
    }
    Some(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogError {
    Pkcs7(pkcs7::ParseError),
    NotACtl(ObjectIdentifier),
    NotACatalog,
    Malformed(&'static str),
}

impl core::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CatalogError::Pkcs7(err) => write!(f, "{err}"),
            CatalogError::NotACtl(oid) => {
                write!(f, "encapsulates {oid}, not a certificate trust list")
            }
            CatalogError::NotACatalog => write!(f, "a trust list, but not a file catalog"),
            CatalogError::Malformed(what) => write!(f, "malformed certificate trust list: {what}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Member<'a> {
    pub key: Option<MemberKey>,
    pub raw_identifier: &'a [u8],
    pub attributes: Vec<AttributeRef<'a>>,
}

impl Member<'_> {
    pub fn file_name(&self) -> Option<String> {
        self.name_value("File")
    }

    pub fn name_value(&self, wanted: &str) -> Option<String> {
        for attr in self.attributes.iter().filter(|a| a.oid == OID_CAT_NAMEVALUE) {
            for value in &attr.values {
                let fields = value.children();
                let Some(name) = fields.first().filter(|f| f.tag == 0x1e) else { continue };
                if utf16_be_string(name.content).as_deref() != Some(wanted) {
                    continue;
                }
                let Some(data) = fields.get(2).filter(|f| f.tag == 0x04) else { continue };
                if let Some(text) = narrow_utf16(data.content)
                    .and_then(|b| String::from_utf8(b).ok())
                    .or_else(|| utf16_le_string(data.content))
                {
                    return Some(text);
                }
            }
        }
        None
    }

    pub fn indirect_digest(&self) -> Option<MemberKey> {
        let attr = self.attributes.iter().find(|a| a.oid == pkcs7::OID_SPC_INDIRECT_DATA)?;
        let value = attr.values.first()?;
        let digest_info = value.children().get(1).copied()?;
        let octets = digest_info.children().get(1).copied()?;
        if octets.tag != 0x04 {
            return None;
        }
        MemberKey::from_digest(octets.content)
    }
}

pub struct CatalogRef<'a> {
    pub signed_data: SignedDataRef<'a>,
    pub ctl: Tlv<'a>,
}

pub fn parse(bytes: &[u8]) -> Result<CatalogRef<'_>, CatalogError> {
    let signed_data = pkcs7::parse(bytes).map_err(CatalogError::Pkcs7)?;
    if signed_data.econtent_type != pkcs7::OID_CTL {
        return Err(CatalogError::NotACtl(signed_data.econtent_type));
    }
    let ctl = signed_data.econtent.ok_or(CatalogError::Malformed("the trust list is empty"))?;
    if ctl.tag != 0x30 {
        return Err(CatalogError::Malformed("the trust list is not a SEQUENCE"));
    }
    let catalog = CatalogRef { signed_data, ctl };
    if !catalog.subject_usage().contains(&OID_CATALOG_LIST) {
        return Err(CatalogError::NotACatalog);
    }
    Ok(catalog)
}

impl<'a> CatalogRef<'a> {
    pub fn subject_usage(&self) -> Vec<ObjectIdentifier> {
        let fields = self.ctl.children();
        let mut at = 0usize;
        if fields.first().map(|f| f.tag) == Some(0x02) {
            at = 1;
        }
        let Some(usage) = fields.get(at).filter(|f| f.tag == 0x30) else {
            return Vec::new();
        };
        usage
            .children()
            .iter()
            .filter(|f| f.tag == 0x06)
            .filter_map(|f| ObjectIdentifier::from_bytes(f.content).ok())
            .collect()
    }

    pub fn members(&self) -> Vec<Member<'a>> {
        let mut out = Vec::new();
        self.for_each_member(|member| out.push(member));
        out
    }

    pub fn for_each_member(&self, mut visit: impl FnMut(Member<'a>)) {
        let Some(items) = self.subject_items() else {
            return;
        };
        der_walk::for_each_child(items.content, |item| {
            if item.tag != 0x30 {
                return;
            }
            let fields = item.children();
            let Some(id) = fields.first().filter(|f| f.tag == 0x04) else {
                return;
            };
            let attributes = fields
                .get(1)
                .filter(|f| f.tag == 0x31)
                .map(|f| pkcs7::attributes_of(*f))
                .unwrap_or_default();
            visit(Member {
                key: MemberKey::from_subject_identifier(id.content),
                raw_identifier: id.content,
                attributes,
            });
        });
    }

    fn subject_items(&self) -> Option<Tlv<'a>> {
        let fields = self.ctl.children();
        let mut at = 0usize;
        let tag_at = |fields: &[Tlv<'a>], at: usize| fields.get(at).map(|f| f.tag);

        if tag_at(&fields, at) == Some(0x02) {
            at = at.checked_add(1)?;
        }
        if tag_at(&fields, at) != Some(0x30) {
            return self.subject_items_by_shape();
        }
        at = at.checked_add(1)?;
        if tag_at(&fields, at) == Some(0x04) {
            at = at.checked_add(1)?;
        }
        if tag_at(&fields, at) == Some(0x02) {
            at = at.checked_add(1)?;
        }
        if !matches!(tag_at(&fields, at), Some(0x17) | Some(0x18)) {
            return self.subject_items_by_shape();
        }
        at = at.checked_add(1)?;
        if matches!(tag_at(&fields, at), Some(0x17) | Some(0x18)) {
            at = at.checked_add(1)?;
        }
        if tag_at(&fields, at) != Some(0x30) {
            return self.subject_items_by_shape();
        }
        at = at.checked_add(1)?;
        match fields.get(at) {
            Some(items) if items.tag == 0x30 => Some(*items),
            _ => None,
        }
    }

    fn subject_items_by_shape(&self) -> Option<Tlv<'a>> {
        self.ctl.children().into_iter().find(|field| {
            if field.tag != 0x30 {
                return false;
            }
            let items = field.children();
            !items.is_empty()
                && items.iter().all(|item| {
                    item.tag == 0x30 && item.children().first().map(|f| f.tag) == Some(0x04)
                })
        })
    }

    pub fn verify(&self, trust: &TrustStore, now: DateTime<Utc>) -> CatalogSignature {
        const MAX_EVALUATED_SIGNERS: usize = 8;

        let best = self
            .signed_data
            .signers
            .iter()
            .take(MAX_EVALUATED_SIGNERS)
            .map(|signer| {
                verify::verify_signer_for(
                    &self.signed_data,
                    signer,
                    trust,
                    now,
                    verify::CATALOG_SIGNING_PURPOSES,
                )
            })
            .max_by_key(|outcome| outcome.rank());

        let Some(best) = best else {
            return CatalogSignature {
                trust: CatalogTrust::Unknown,
                signer: "unknown signer".into(),
                detail: "the catalog carries no signer information".into(),
                root: None,
                root_is_microsoft: false,
                signing_time: None,
                self_signed_leaf: false,
            };
        };

        let (level, detail) = match &best.outcome {
            Outcome::Valid => (CatalogTrust::Valid, String::new()),
            Outcome::Expired => (
                CatalogTrust::Expired,
                "the signing certificate was outside its validity window at signing time".into(),
            ),
            Outcome::Untrusted => (
                CatalogTrust::Untrusted,
                match (&best.unreached_issuer, best.self_signed_leaf) {
                    (_, true) => "the catalog signer issued its own certificate".into(),
                    (Some(top), false) => format!(
                        "chains to {top}, a certificate authority this build does not carry"
                    ),
                    (None, false) => {
                        "chains to a certificate authority this build does not carry".into()
                    }
                },
            ),
            Outcome::Invalid(reason) => (CatalogTrust::Invalid, reason.clone()),
            Outcome::Unknown(reason) => (CatalogTrust::Unknown, reason.clone()),
        };

        CatalogSignature {
            trust: level,
            signer: best.signer,
            detail,
            root: best.root,
            root_is_microsoft: best.root_is_microsoft,
            signing_time: best.signing_time,
            self_signed_leaf: best.self_signed_leaf,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CatalogSignature {
    pub trust: CatalogTrust,
    pub signer: String,
    pub detail: String,
    pub root: Option<&'static str>,
    pub root_is_microsoft: bool,
    pub signing_time: Option<DateTime<Utc>>,
    pub self_signed_leaf: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CatalogTrust {
    Unknown,
    Invalid,
    Untrusted,
    Expired,
    Valid,
}

impl CatalogTrust {
    pub fn label(&self) -> &'static str {
        match self {
            CatalogTrust::Valid => "valid",
            CatalogTrust::Expired => "expired",
            CatalogTrust::Untrusted => "untrusted",
            CatalogTrust::Invalid => "invalid",
            CatalogTrust::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CatalogRecord {
    pub name: String,
    pub signer: String,
    pub trust: CatalogTrust,
    pub detail: String,
    pub root: Option<&'static str>,
    pub root_is_microsoft: bool,
    pub self_signed_leaf: bool,
    pub members: u32,
    pub unkeyed_members: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct CatalogHit<'i> {
    pub key: MemberKey,
    pub catalog: &'i CatalogRecord,
}

#[derive(Clone, Debug, Default)]
pub struct IndexStats {
    pub offered: usize,
    pub parsed: usize,
    pub rejected: usize,
    pub unreadable: usize,
    pub rejections: Vec<(String, String)>,
    pub members_seen: usize,
    pub duplicate_members: usize,
    pub unkeyed_members: usize,
    pub unkeyed_lengths: std::collections::BTreeMap<usize, usize>,
    pub valid: usize,
    pub expired: usize,
    pub untrusted: usize,
    pub invalid: usize,
    pub unknown: usize,
}

const MAX_RECORDED_REJECTIONS: usize = 32;

pub struct CatalogIndex {
    catalogs: Vec<CatalogRecord>,
    sha1: HashMap<[u8; 20], u32>,
    sha256: HashMap<[u8; 32], u32>,
    stats: IndexStats,
}

impl Default for CatalogIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CatalogIndex {
    pub fn new() -> Self {
        CatalogIndex {
            catalogs: Vec::new(),
            sha1: HashMap::new(),
            sha256: HashMap::new(),
            stats: IndexStats::default(),
        }
    }

    pub fn add(
        &mut self,
        name: &str,
        bytes: &[u8],
        trust: &TrustStore,
        now: DateTime<Utc>,
    ) -> Result<&CatalogRecord, CatalogError> {
        self.stats.offered = self.stats.offered.saturating_add(1);

        let catalog = match parse(bytes) {
            Ok(catalog) => catalog,
            Err(err) => {
                self.stats.rejected = self.stats.rejected.saturating_add(1);
                if self.stats.rejections.len() < MAX_RECORDED_REJECTIONS {
                    self.stats.rejections.push((name.to_string(), err.to_string()));
                }
                return Err(err);
            }
        };

        let signature = catalog.verify(trust, now);
        match signature.trust {
            CatalogTrust::Valid => self.stats.valid = self.stats.valid.saturating_add(1),
            CatalogTrust::Expired => self.stats.expired = self.stats.expired.saturating_add(1),
            CatalogTrust::Untrusted => {
                self.stats.untrusted = self.stats.untrusted.saturating_add(1)
            }
            CatalogTrust::Invalid => self.stats.invalid = self.stats.invalid.saturating_add(1),
            CatalogTrust::Unknown => self.stats.unknown = self.stats.unknown.saturating_add(1),
        }

        let slot = u32::try_from(self.catalogs.len()).unwrap_or(u32::MAX);
        self.catalogs.push(CatalogRecord {
            name: name.to_string(),
            signer: signature.signer,
            trust: signature.trust,
            detail: signature.detail,
            root: signature.root,
            root_is_microsoft: signature.root_is_microsoft,
            self_signed_leaf: signature.self_signed_leaf,
            members: 0,
            unkeyed_members: 0,
        });

        let mut indexed = 0u32;
        let mut unkeyed = 0u32;
        let level = signature.trust;
        let CatalogIndex { catalogs, sha1, sha256, stats } = self;
        catalog.for_each_member(|member| {
            stats.members_seen = stats.members_seen.saturating_add(1);
            let Some(key) = member.key else {
                unkeyed = unkeyed.saturating_add(1);
                stats.unkeyed_members = stats.unkeyed_members.saturating_add(1);
                let seen = stats.unkeyed_lengths.entry(member.raw_identifier.len()).or_default();
                *seen = seen.saturating_add(1);
                return;
            };
            if insert_member(sha1, sha256, catalogs, key, slot, level) {
                indexed = indexed.saturating_add(1);
            } else {
                stats.duplicate_members = stats.duplicate_members.saturating_add(1);
            }
        });

        let record = self
            .catalogs
            .get_mut(usize::try_from(slot).unwrap_or(usize::MAX))
            .ok_or(CatalogError::Malformed("index is empty"))?;
        record.members = indexed;
        record.unkeyed_members = unkeyed;
        Ok(record)
    }

    pub fn lookup(&self, key: MemberKey) -> Option<CatalogHit<'_>> {
        let slot = match key {
            MemberKey::Sha1(digest) => *self.sha1.get(&digest)?,
            MemberKey::Sha256(digest) => *self.sha256.get(&digest)?,
        };
        let catalog = self.catalogs.get(usize::try_from(slot).ok()?)?;
        Some(CatalogHit { key, catalog })
    }

    pub fn is_usable(&self) -> bool {
        !self.catalogs.is_empty() && self.member_count() > 0
    }

    pub fn catalogs(&self) -> &[CatalogRecord] {
        &self.catalogs
    }

    pub fn member_count(&self) -> usize {
        self.sha1.len().saturating_add(self.sha256.len())
    }

    pub fn stats(&self) -> &IndexStats {
        &self.stats
    }

    pub fn note_unreadable(&mut self) {
        self.stats.unreadable = self.stats.unreadable.saturating_add(1);
    }

    pub fn memory_bytes(&self) -> usize {
        let sha1 = self
            .sha1
            .capacity()
            .saturating_mul(core::mem::size_of::<([u8; 20], u32)>().saturating_add(1));
        let sha256 = self
            .sha256
            .capacity()
            .saturating_mul(core::mem::size_of::<([u8; 32], u32)>().saturating_add(1));
        let records =
            self.catalogs.capacity().saturating_mul(core::mem::size_of::<CatalogRecord>());
        let strings = self.catalogs.iter().fold(0usize, |sum, record| {
            sum.saturating_add(record.name.capacity())
                .saturating_add(record.signer.capacity())
                .saturating_add(record.detail.capacity())
        });
        sha1.saturating_add(sha256).saturating_add(records).saturating_add(strings)
    }
}

fn insert_member(
    sha1: &mut HashMap<[u8; 20], u32>,
    sha256: &mut HashMap<[u8; 32], u32>,
    catalogs: &[CatalogRecord],
    key: MemberKey,
    slot: u32,
    level: CatalogTrust,
) -> bool {
    use std::collections::hash_map::Entry;

    fn wins(catalogs: &[CatalogRecord], held: u32, level: CatalogTrust) -> bool {
        catalogs
            .get(usize::try_from(held).unwrap_or(usize::MAX))
            .is_none_or(|record| level > record.trust)
    }

    match key {
        MemberKey::Sha1(digest) => match sha1.entry(digest) {
            Entry::Vacant(vacant) => {
                vacant.insert(slot);
                true
            }
            Entry::Occupied(mut occupied) => {
                if wins(catalogs, *occupied.get(), level) {
                    occupied.insert(slot);
                }
                false
            }
        },
        MemberKey::Sha256(digest) => match sha256.entry(digest) {
            Entry::Vacant(vacant) => {
                vacant.insert(slot);
                true
            }
            Entry::Occupied(mut occupied) => {
                if wins(catalogs, *occupied.get(), level) {
                    occupied.insert(slot);
                }
                false
            }
        },
    }
}

pub fn candidate_keys(bytes: &[u8]) -> Vec<MemberKey> {
    let mut keys: Vec<MemberKey> = Vec::with_capacity(4);
    let mut offer = |digest: Option<Vec<u8>>| {
        if let Some(key) = digest.as_deref().and_then(MemberKey::from_digest) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    };

    match PeBytes::parse(bytes) {
        Some(pe) => {
            for alg in [HashAlg::Sha256, HashAlg::Sha1] {
                offer(pe_digest(&pe, alg));
                offer(pe_digest_contiguous(&pe, alg));
            }
        }
        None => {
            for alg in [HashAlg::Sha256, HashAlg::Sha1] {
                offer(Some(alg.digest(bytes)));
            }
        }
    }
    keys
}

pub fn verify_catalog(pe_bytes: &[u8], index: &CatalogIndex) -> Verdict {
    if !index.is_usable() {
        return Verdict::Unknown {
            reason: "no catalog index was built, so catalog signing could not be checked".into(),
        };
    }

    let keys = candidate_keys(pe_bytes);
    if keys.is_empty() {
        return Verdict::Unknown { reason: "the file's hash could not be computed".into() };
    }

    let best = keys
        .into_iter()
        .filter_map(|key| index.lookup(key))
        .max_by_key(|hit| (hit.catalog.trust, matches!(hit.key, MemberKey::Sha256(_))));

    let Some(hit) = best else {
        return Verdict::Unsigned;
    };

    let record = hit.catalog;
    match record.trust {
        CatalogTrust::Valid => Verdict::CatalogValid {
            signer: record.signer.clone(),
            catalog: record.name.clone(),
            root_is_microsoft: record.root_is_microsoft,
        },
        CatalogTrust::Expired => {
            Verdict::Expired { signer: format!("{} (catalog {})", record.signer, record.name) }
        }
        CatalogTrust::Untrusted => Verdict::Untrusted {
            signer: format!("{} (catalog {})", record.signer, record.name),
            self_signed_leaf: record.self_signed_leaf,
        },
        CatalogTrust::Invalid => Verdict::Unknown {
            reason: format!(
                "listed in {}, whose own signature does not verify: {}",
                record.name, record.detail
            ),
        },
        CatalogTrust::Unknown => Verdict::Unknown {
            reason: format!(
                "listed in {}, which could not be verified: {}",
                record.name, record.detail
            ),
        },
    }
}

fn utf16_be_string(octets: &[u8]) -> Option<String> {
    decode_utf16(octets, true)
}

fn utf16_le_string(octets: &[u8]) -> Option<String> {
    decode_utf16(octets, false)
}

fn decode_utf16(octets: &[u8], big_endian: bool) -> Option<String> {
    if !octets.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = octets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| if big_endian { u16::from_be_bytes(pair) } else { u16::from_le_bytes(pair) })
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_identifiers_are_read_in_every_encoding_real_catalogs_use() {
        let sha1 = [0x11u8; 20];
        assert_eq!(MemberKey::from_subject_identifier(&sha1), Some(MemberKey::Sha1(sha1)));

        let sha256 = [0x22u8; 32];
        assert_eq!(MemberKey::from_subject_identifier(&sha256), Some(MemberKey::Sha256(sha256)));

        let mut utf16 = Vec::new();
        for ch in "1111111111111111111111111111111111111111".bytes() {
            utf16.push(ch);
            utf16.push(0);
        }
        utf16.extend_from_slice(&[0, 0]);
        assert_eq!(utf16.len(), 82);
        assert_eq!(MemberKey::from_subject_identifier(&utf16), Some(MemberKey::Sha1(sha1)));

        assert_eq!(
            MemberKey::from_subject_identifier(b"1111111111111111111111111111111111111111"),
            Some(MemberKey::Sha1(sha1))
        );
    }

    #[test]
    fn unrecognised_identifiers_are_dropped_rather_than_guessed() {
        assert_eq!(MemberKey::from_subject_identifier(&[]), None);
        assert_eq!(MemberKey::from_subject_identifier(&[0u8; 16]), None);
        assert_eq!(MemberKey::from_subject_identifier(&[0u8; 33]), None);
        assert_eq!(MemberKey::from_subject_identifier(&[b'z'; 40]), None);
        let mut bad = vec![0u8; 82];
        bad[1] = 0x30;
        assert_eq!(MemberKey::from_subject_identifier(&bad), None);
    }

    #[test]
    fn hex_rendering_round_trips() {
        let key = MemberKey::Sha1([0xab; 20]);
        assert_eq!(key.to_hex(), "ab".repeat(20));
        assert_eq!(key.alg(), HashAlg::Sha1);
        assert_eq!(MemberKey::Sha256([0u8; 32]).alg(), HashAlg::Sha256);
    }

    #[test]
    fn candidate_keys_fall_back_to_the_flat_hash_for_a_non_image() {
        let keys = candidate_keys(b"this is not an executable at all");
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|k| matches!(k, MemberKey::Sha1(_))));
        assert!(keys.iter().any(|k| matches!(k, MemberKey::Sha256(_))));
        let flat = HashAlg::Sha256.digest(b"this is not an executable at all");
        assert!(keys.contains(&MemberKey::from_digest(&flat).unwrap()));
    }

    #[test]
    fn an_empty_index_is_unknown_not_unsigned() {
        let index = CatalogIndex::new();
        assert!(!index.is_usable());
        assert!(matches!(verify_catalog(b"MZ not really a pe", &index), Verdict::Unknown { .. }));
    }

    #[test]
    fn a_non_catalog_pkcs7_is_named_rather_than_indexed() {
        let der = [
            0x30u8, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0,
            0x00,
        ];
        assert!(matches!(parse(&der), Err(CatalogError::Pkcs7(_))));
    }

    #[test]
    fn nothing_in_here_panics_on_garbage() {
        let trust = TrustStore::empty();
        let now = crate::now();
        let mut state = 0x0c47_10adu32;
        for _ in 0..20_000 {
            let len = (state % 128) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                buf.push((state >> 16) as u8);
            }
            let _ = parse(&buf);
            let _ = MemberKey::from_subject_identifier(&buf);
            let mut index = CatalogIndex::new();
            let _ = index.add("fuzz.cat", &buf, &trust, now);
            let _ = verify_catalog(&buf, &index);
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        }
    }

    #[test]
    fn the_member_walk_finds_both_algorithms() {
        let ctl = synthetic_ctl();
        let tlv = der_walk::single(&ctl).unwrap();
        let catalog = CatalogRef {
            signed_data: SignedDataRef {
                raw: &[],
                econtent_type: pkcs7::OID_CTL,
                econtent: None,
                certs: Vec::new(),
                signers: Vec::new(),
            },
            ctl: tlv,
        };
        let members = catalog.members();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].key, Some(MemberKey::Sha256([0xaa; 32])));
        assert_eq!(members[1].key, Some(MemberKey::Sha1([0xbb; 20])));
        assert!(catalog.subject_usage().contains(&OID_CATALOG_LIST));
    }

    #[test]
    fn the_member_walk_does_not_confuse_usage_or_algorithm_with_members() {
        let ctl = synthetic_ctl();
        let tlv = der_walk::single(&ctl).unwrap();
        let catalog = CatalogRef {
            signed_data: SignedDataRef {
                raw: &[],
                econtent_type: pkcs7::OID_CTL,
                econtent: None,
                certs: Vec::new(),
                signers: Vec::new(),
            },
            ctl: tlv,
        };
        let by_shape = catalog.subject_items_by_shape().unwrap();
        let positional = catalog.subject_items().unwrap();
        assert_eq!(by_shape.full, positional.full);
    }

    fn seq(tag: u8, body: Vec<u8>) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else if body.len() < 0x100 {
            out.push(0x81);
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.push((body.len() >> 8) as u8);
            out.push(body.len() as u8);
        }
        out.extend(body);
        out
    }

    fn synthetic_ctl() -> Vec<u8> {
        let usage_oid = seq(0x06, OID_CATALOG_LIST.as_bytes().to_vec());
        let usage = seq(0x30, usage_oid);
        let list_id = seq(0x04, vec![0x01; 16]);
        let this_update = seq(0x17, b"241229065900Z".to_vec());
        let mut alg_body = seq(0x06, vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        alg_body.extend(seq(0x05, Vec::new()));
        let algorithm = seq(0x30, alg_body);
        let mut member_a = seq(0x04, vec![0xaa; 32]);
        member_a.extend(seq(0x31, Vec::new()));
        let mut member_b = seq(0x04, vec![0xbb; 20]);
        member_b.extend(seq(0x31, Vec::new()));
        let mut items_body = seq(0x30, member_a);
        items_body.extend(seq(0x30, member_b));
        let items = seq(0x30, items_body);

        let mut body = usage;
        body.extend(list_id);
        body.extend(this_update);
        body.extend(algorithm);
        body.extend(items);
        seq(0x30, body)
    }
}
