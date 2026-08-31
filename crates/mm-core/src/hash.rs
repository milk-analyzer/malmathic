use std::fmt;

use md5::Md5;
use sha1::{Digest, Sha1};
use sha2::Sha256;

#[derive(Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileHash {
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
    pub sha256: Option<[u8; 32]>,
}

impl FileHash {
    pub fn compute(bytes: &[u8]) -> Self {
        FileHash {
            md5: Some(Md5::digest(bytes).into()),
            sha1: Some(Sha1::digest(bytes).into()),
            sha256: Some(Sha256::digest(bytes).into()),
        }
    }

    pub fn from_amcache_file_id(s: &str) -> Option<Self> {
        let s = s.trim();
        let hex = match s.len() {
            44 => s.strip_prefix("0000")?,
            40 => s,
            _ => return None,
        };
        Some(FileHash { sha1: Some(parse_hex::<20>(hex)?), ..Default::default() })
    }

    pub fn from_sha256_hex(s: &str) -> Option<Self> {
        Some(FileHash { sha256: Some(parse_hex::<32>(s.trim())?), ..Default::default() })
    }

    pub fn from_sha1_hex(s: &str) -> Option<Self> {
        Some(FileHash { sha1: Some(parse_hex::<20>(s.trim())?), ..Default::default() })
    }

    pub fn from_md5_hex(s: &str) -> Option<Self> {
        Some(FileHash { md5: Some(parse_hex::<16>(s.trim())?), ..Default::default() })
    }

    pub fn is_empty(&self) -> bool {
        self.md5.is_none() && self.sha1.is_none() && self.sha256.is_none()
    }

    pub fn agrees_with(&self, other: &FileHash) -> bool {
        let pairs = [
            (self.sha256.map(|h| h.to_vec()), other.sha256.map(|h| h.to_vec())),
            (self.sha1.map(|h| h.to_vec()), other.sha1.map(|h| h.to_vec())),
            (self.md5.map(|h| h.to_vec()), other.md5.map(|h| h.to_vec())),
        ];
        pairs.iter().any(|(a, b)| matches!((a, b), (Some(a), Some(b)) if a == b))
    }

    pub fn same_file_as(&self, other: &FileHash) -> Option<bool> {
        let pairs = [
            (self.sha256.map(|h| h.to_vec()), other.sha256.map(|h| h.to_vec())),
            (self.sha1.map(|h| h.to_vec()), other.sha1.map(|h| h.to_vec())),
            (self.md5.map(|h| h.to_vec()), other.md5.map(|h| h.to_vec())),
        ];
        let mut shared = false;
        for (a, b) in &pairs {
            if let (Some(a), Some(b)) = (a, b) {
                if a != b {
                    return Some(false);
                }
                shared = true;
            }
        }
        shared.then_some(true)
    }

    #[must_use]
    pub fn agreeing_algorithm(&self, other: &FileHash) -> Option<&'static str> {
        if self.same_file_as(other) != Some(true) {
            return None;
        }
        if self.sha256.is_some() && self.sha256 == other.sha256 {
            Some("SHA-256")
        } else if self.sha1.is_some() && self.sha1 == other.sha1 {
            Some("SHA-1")
        } else if self.md5.is_some() && self.md5 == other.md5 {
            Some("MD5")
        } else {
            None
        }
    }

    pub fn merge(&mut self, other: &FileHash) {
        self.md5 = self.md5.or(other.md5);
        self.sha1 = self.sha1.or(other.sha1);
        self.sha256 = self.sha256.or(other.sha256);
    }

    pub fn supersede_with(&mut self, computed: &FileHash) {
        self.md5 = computed.md5.or(self.md5);
        self.sha1 = computed.sha1.or(self.sha1);
        self.sha256 = computed.sha256.or(self.sha256);
    }

    pub fn checked_against(&self, computed: &FileHash, recorded_by: &str) -> Vec<HashCheck> {
        let mut checks = Vec::new();
        let mut check = |algorithm: &str, recorded: Option<Vec<u8>>, got: Option<Vec<u8>>| {
            if let (Some(recorded), Some(got)) = (recorded, got) {
                checks.push(HashCheck {
                    algorithm: algorithm.to_string(),
                    recorded_by: recorded_by.to_string(),
                    agrees: recorded == got,
                    recorded: hex(&recorded),
                    computed: hex(&got),
                });
            }
        };
        check("sha256", self.sha256.map(|h| h.to_vec()), computed.sha256.map(|h| h.to_vec()));
        check("sha1", self.sha1.map(|h| h.to_vec()), computed.sha1.map(|h| h.to_vec()));
        check("md5", self.md5.map(|h| h.to_vec()), computed.md5.map(|h| h.to_vec()));
        checks
    }

    pub fn best(&self) -> Option<String> {
        if let Some(h) = &self.sha256 {
            return Some(hex(h));
        }
        if let Some(h) = &self.sha1 {
            return Some(hex(h));
        }
        self.md5.as_ref().map(|h| hex(h))
    }

    pub fn sha256_hex(&self) -> Option<String> {
        self.sha256.as_ref().map(|h| hex(h))
    }

    pub fn sha1_hex(&self) -> Option<String> {
        self.sha1.as_ref().map(|h| hex(h))
    }

    pub fn md5_hex(&self) -> Option<String> {
        self.md5.as_ref().map(|h| hex(h))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HashCheck {
    pub algorithm: String,
    pub recorded_by: String,
    pub recorded: String,
    pub computed: String,
    pub agrees: bool,
}

impl fmt::Debug for FileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.best() {
            Some(h) => write!(f, "FileHash({h})"),
            None => f.write_str("FileHash(none)"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_char_boundary(0) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    #[test]
    fn compute_matches_known_digests() {
        let h = FileHash::compute(b"");
        assert_eq!(h.sha1_hex().unwrap(), EMPTY_SHA1);
        assert_eq!(h.md5_hex().unwrap(), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            h.sha256_hex().unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn amcache_file_id_strips_the_zero_prefix() {
        let with_prefix = format!("0000{EMPTY_SHA1}");
        let h = FileHash::from_amcache_file_id(&with_prefix).unwrap();
        assert_eq!(h.sha1_hex().unwrap(), EMPTY_SHA1);

        let bare = FileHash::from_amcache_file_id(EMPTY_SHA1).unwrap();
        assert_eq!(bare, h);
    }

    #[test]
    fn amcache_file_id_rejects_junk() {
        assert!(FileHash::from_amcache_file_id("").is_none());
        assert!(FileHash::from_amcache_file_id("0000deadbeef").is_none());
        assert!(FileHash::from_amcache_file_id(&"z".repeat(44)).is_none());
    }

    #[test]
    fn disjoint_algorithms_never_agree() {
        let a = FileHash::from_sha1_hex(EMPTY_SHA1).unwrap();
        let b = FileHash::from_md5_hex("d41d8cd98f00b204e9800998ecf8427e").unwrap();
        assert!(!a.agrees_with(&b));
        assert!(!FileHash::default().agrees_with(&FileHash::default()));
    }

    #[test]
    fn shared_algorithm_decides_agreement() {
        let full = FileHash::compute(b"");
        let just_sha1 = FileHash::from_sha1_hex(EMPTY_SHA1).unwrap();
        assert!(full.agrees_with(&just_sha1));

        let other = FileHash::from_sha1_hex(&"a".repeat(40)).unwrap();
        assert!(!full.agrees_with(&other));
    }

    #[test]
    fn same_file_as_separates_disagreement_from_ignorance() {
        let full = FileHash::compute(b"the bytes");
        let other = FileHash::compute(b"different bytes");

        assert_eq!(full.same_file_as(&full.clone()), Some(true));
        assert_eq!(
            full.same_file_as(&FileHash::from_sha1_hex(&full.sha1_hex().unwrap()).unwrap()),
            Some(true)
        );

        assert_eq!(full.same_file_as(&other), Some(false));
        assert_eq!(
            full.same_file_as(&FileHash::from_sha256_hex(&other.sha256_hex().unwrap()).unwrap()),
            Some(false)
        );

        let sha1_only = FileHash::from_sha1_hex(&full.sha1_hex().unwrap()).unwrap();
        let sha256_only = FileHash::from_sha256_hex(&other.sha256_hex().unwrap()).unwrap();
        assert_eq!(sha1_only.same_file_as(&sha256_only), None);
        assert_eq!(FileHash::default().same_file_as(&full), None);

        let mixed = FileHash { md5: full.md5, sha1: other.sha1, sha256: None };
        assert_eq!(full.same_file_as(&mixed), Some(false));
    }

    #[test]
    fn merge_fills_gaps_without_overwriting() {
        let mut a = FileHash::from_sha1_hex(EMPTY_SHA1).unwrap();
        let b = FileHash::compute(b"");
        a.merge(&b);
        assert_eq!(a.sha1_hex().unwrap(), EMPTY_SHA1);
        assert!(a.sha256.is_some() && a.md5.is_some());
    }

    #[test]
    fn a_computed_digest_supersedes_an_artifacts_claim() {
        let stale = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut identity = FileHash::from_sha1_hex(stale).unwrap();
        let computed = FileHash::compute(b"the bytes actually on the volume");

        identity.supersede_with(&computed);

        assert_eq!(identity.sha1, computed.sha1, "the artifact's SHA-1 must not survive");
        assert_eq!(identity.sha256, computed.sha256);
        assert_eq!(identity.md5, computed.md5);
        assert_ne!(identity.sha1_hex().unwrap(), stale);
    }

    #[test]
    fn superseding_never_drops_a_digest_it_cannot_replace() {
        let mut identity = FileHash::from_sha1_hex(EMPTY_SHA1).unwrap();
        identity
            .supersede_with(&FileHash::from_md5_hex("d41d8cd98f00b204e9800998ecf8427e").unwrap());
        assert_eq!(identity.sha1_hex().unwrap(), EMPTY_SHA1);
        assert!(identity.md5.is_some());
    }

    #[test]
    fn merge_and_supersede_are_mirror_images() {
        let artifact = FileHash::from_sha1_hex("bb".repeat(20).as_str()).unwrap();
        let computed = FileHash::compute(b"bytes");

        let mut kept_the_claim = artifact.clone();
        kept_the_claim.merge(&computed);
        assert_eq!(kept_the_claim.sha1, artifact.sha1);

        let mut kept_the_bytes = artifact;
        kept_the_bytes.supersede_with(&computed);
        assert_eq!(kept_the_bytes.sha1, computed.sha1);
    }

    #[test]
    fn a_disagreement_is_reported_with_both_hexes() {
        let recorded = FileHash::from_sha1_hex(&"cd".repeat(20)).unwrap();
        let computed = FileHash::compute(b"different bytes");
        let checks = recorded.checked_against(&computed, "Amcache");

        assert_eq!(checks.len(), 1, "only SHA-1 is named by both sides: {checks:?}");
        let check = &checks[0];
        assert_eq!(check.algorithm, "sha1");
        assert_eq!(check.recorded_by, "Amcache");
        assert!(!check.agrees);
        assert_eq!(check.recorded, "cd".repeat(20));
        assert_eq!(check.computed, computed.sha1_hex().unwrap());
    }

    #[test]
    fn agreement_is_recorded_too_because_it_is_corroboration() {
        let computed = FileHash::compute(b"bytes");
        let recorded = FileHash::from_sha1_hex(&computed.sha1_hex().unwrap()).unwrap();
        let checks = recorded.checked_against(&computed, "Amcache");
        assert_eq!(checks.len(), 1);
        assert!(checks[0].agrees);
    }

    #[test]
    fn algorithms_only_one_side_names_produce_no_check() {
        let recorded = FileHash::from_md5_hex("d41d8cd98f00b204e9800998ecf8427e").unwrap();
        let computed = FileHash { sha1: Some([7u8; 20]), ..Default::default() };
        assert!(recorded.checked_against(&computed, "Amcache").is_empty());
        assert!(FileHash::default().checked_against(&FileHash::default(), "Amcache").is_empty());
    }

    #[test]
    fn best_prefers_the_strongest_digest() {
        let h = FileHash::compute(b"");
        assert_eq!(h.best().unwrap().len(), 64);
        let h = FileHash::from_sha1_hex(EMPTY_SHA1).unwrap();
        assert_eq!(h.best().unwrap().len(), 40);
        assert!(FileHash::default().best().is_none());
    }
}
