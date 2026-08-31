use const_oid::ObjectIdentifier;
use ecdsa::signature::hazmat::PrehashVerifier;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::der_walk;

const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_SHA1_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_SHA1_WITH_RSA_OIW: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.29");

const OID_ECDSA_WITH_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_WITH_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            OID_SHA1 | OID_SHA1_WITH_RSA_OIW => Some(HashAlg::Sha1),
            OID_SHA256 => Some(HashAlg::Sha256),
            OID_SHA384 => Some(HashAlg::Sha384),
            OID_SHA512 => Some(HashAlg::Sha512),
            _ => None,
        }
    }

    pub fn digest(&self, message: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha1 => Sha1::digest(message).to_vec(),
            HashAlg::Sha256 => Sha256::digest(message).to_vec(),
            HashAlg::Sha384 => Sha384::digest(message).to_vec(),
            HashAlg::Sha512 => Sha512::digest(message).to_vec(),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            HashAlg::Sha1 => "SHA-1",
            HashAlg::Sha256 => "SHA-256",
            HashAlg::Sha384 => "SHA-384",
            HashAlg::Sha512 => "SHA-512",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    Unsupported(String),
    Malformed(String),
    BadSignature,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::Unsupported(what) => write!(f, "unsupported {what}"),
            CryptoError::Malformed(what) => write!(f, "malformed {what}"),
            CryptoError::BadSignature => write!(f, "signature does not verify"),
        }
    }
}

enum Scheme {
    RsaPkcs1(HashAlg),
    RsaPss { hash: HashAlg, salt_len: usize },
    Ecdsa(HashAlg),
}

fn scheme_for(
    alg: &AlgorithmIdentifierOwned,
    digest_hint: Option<HashAlg>,
) -> Result<Scheme, CryptoError> {
    match alg.oid {
        OID_SHA1_WITH_RSA | OID_SHA1_WITH_RSA_OIW => Ok(Scheme::RsaPkcs1(HashAlg::Sha1)),
        OID_SHA256_WITH_RSA => Ok(Scheme::RsaPkcs1(HashAlg::Sha256)),
        OID_SHA384_WITH_RSA => Ok(Scheme::RsaPkcs1(HashAlg::Sha384)),
        OID_SHA512_WITH_RSA => Ok(Scheme::RsaPkcs1(HashAlg::Sha512)),
        OID_RSA_ENCRYPTION => digest_hint.map(Scheme::RsaPkcs1).ok_or_else(|| {
            CryptoError::Unsupported("rsaEncryption without a digest algorithm".into())
        }),
        OID_RSASSA_PSS => pss_params(alg),
        OID_EC_PUBLIC_KEY => digest_hint.map(Scheme::Ecdsa).ok_or_else(|| {
            CryptoError::Unsupported("ecPublicKey without a digest algorithm".into())
        }),
        OID_ECDSA_WITH_SHA1 => Ok(Scheme::Ecdsa(HashAlg::Sha1)),
        OID_ECDSA_WITH_SHA256 => Ok(Scheme::Ecdsa(HashAlg::Sha256)),
        OID_ECDSA_WITH_SHA384 => Ok(Scheme::Ecdsa(HashAlg::Sha384)),
        OID_ECDSA_WITH_SHA512 => Ok(Scheme::Ecdsa(HashAlg::Sha512)),
        other => Err(CryptoError::Unsupported(format!("signature algorithm {other}"))),
    }
}

fn pss_params(alg: &AlgorithmIdentifierOwned) -> Result<Scheme, CryptoError> {
    let mut hash = HashAlg::Sha1;
    let mut salt_len = 20usize;

    if let Some(params) = &alg.parameters {
        let encoded = der::Encode::to_der(params)
            .map_err(|_| CryptoError::Malformed("RSASSA-PSS parameters".into()))?;
        let Some(seq) = der_walk::first(&encoded) else {
            return Err(CryptoError::Malformed("RSASSA-PSS parameters".into()));
        };
        for field in seq.children() {
            match field.context_tag() {
                Some(0) => {
                    let Some(inner) = der_walk::first(field.content) else { continue };
                    let Some(oid_tlv) = inner.children().first().copied() else { continue };
                    let Ok(oid) = ObjectIdentifier::from_bytes(oid_tlv.content) else { continue };
                    match HashAlg::from_oid(oid) {
                        Some(found) => hash = found,
                        None => {
                            return Err(CryptoError::Unsupported(format!("PSS hash {oid}")));
                        }
                    }
                }
                Some(2) => {
                    let Some(int) = der_walk::first(field.content) else { continue };
                    let mut value = 0usize;
                    for byte in int.content.iter().take(4) {
                        value = value.saturating_mul(256).saturating_add(usize::from(*byte));
                    }
                    salt_len = value;
                }
                _ => {}
            }
        }
    }

    Ok(Scheme::RsaPss { hash, salt_len })
}

pub fn verify(
    spki: &SubjectPublicKeyInfoOwned,
    signature_algorithm: &AlgorithmIdentifierOwned,
    digest_hint: Option<HashAlg>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let scheme = scheme_for(signature_algorithm, digest_hint)?;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CryptoError::Malformed("public key bit string".into()))?;

    match scheme {
        Scheme::RsaPkcs1(hash) => {
            let key = rsa_key(spki, key_bytes)?;
            verify_rsa_pkcs1(key, hash, message, signature)
        }
        Scheme::RsaPss { hash, salt_len } => {
            let key = rsa_key(spki, key_bytes)?;
            verify_rsa_pss(key, hash, salt_len, message, signature)
        }
        Scheme::Ecdsa(hash) => verify_ecdsa(spki, key_bytes, hash, message, signature),
    }
}

fn rsa_key(
    spki: &SubjectPublicKeyInfoOwned,
    key_bytes: &[u8],
) -> Result<RsaPublicKey, CryptoError> {
    if spki.algorithm.oid != OID_RSA_ENCRYPTION {
        return Err(CryptoError::Unsupported(format!(
            "RSA signature over a {} key",
            spki.algorithm.oid
        )));
    }
    <RsaPublicKey as rsa::pkcs1::DecodeRsaPublicKey>::from_pkcs1_der(key_bytes)
        .map_err(|e| CryptoError::Malformed(format!("RSA public key ({e})")))
}

fn verify_rsa_pkcs1(
    key: RsaPublicKey,
    hash: HashAlg,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let sig = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| CryptoError::Malformed("RSA signature value".into()))?;
    let ok = match hash {
        HashAlg::Sha1 => rsa::pkcs1v15::VerifyingKey::<Sha1>::new(key).verify(message, &sig),
        HashAlg::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key).verify(message, &sig),
        HashAlg::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key).verify(message, &sig),
        HashAlg::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key).verify(message, &sig),
    };
    ok.map_err(|_| CryptoError::BadSignature)
}

fn verify_rsa_pss(
    key: RsaPublicKey,
    hash: HashAlg,
    salt_len: usize,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let sig = rsa::pss::Signature::try_from(signature)
        .map_err(|_| CryptoError::Malformed("RSA-PSS signature value".into()))?;
    let ok =
        match hash {
            HashAlg::Sha1 => rsa::pss::VerifyingKey::<Sha1>::new_with_salt_len(key, salt_len)
                .verify(message, &sig),
            HashAlg::Sha256 => rsa::pss::VerifyingKey::<Sha256>::new_with_salt_len(key, salt_len)
                .verify(message, &sig),
            HashAlg::Sha384 => rsa::pss::VerifyingKey::<Sha384>::new_with_salt_len(key, salt_len)
                .verify(message, &sig),
            HashAlg::Sha512 => rsa::pss::VerifyingKey::<Sha512>::new_with_salt_len(key, salt_len)
                .verify(message, &sig),
        };
    ok.map_err(|_| CryptoError::BadSignature)
}

fn verify_ecdsa(
    spki: &SubjectPublicKeyInfoOwned,
    key_bytes: &[u8],
    hash: HashAlg,
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(CryptoError::Unsupported(format!(
            "ECDSA signature over a {} key",
            spki.algorithm.oid
        )));
    }

    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| CryptoError::Unsupported("EC key without curve parameters".into()))?;
    let encoded = der::Encode::to_der(params)
        .map_err(|_| CryptoError::Malformed("EC curve parameters".into()))?;
    let curve_tlv = der_walk::first(&encoded)
        .ok_or_else(|| CryptoError::Malformed("EC curve parameters".into()))?;
    let curve = ObjectIdentifier::from_bytes(curve_tlv.content)
        .map_err(|_| CryptoError::Malformed("EC curve OID".into()))?;

    let prehash = hash.digest(message);

    match curve {
        OID_SECP256R1 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                .map_err(|_| CryptoError::Malformed("P-256 public key".into()))?;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| CryptoError::Malformed("P-256 signature".into()))?;
            key.verify_prehash(&prehash, &sig).map_err(|_| CryptoError::BadSignature)
        }
        OID_SECP384R1 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                .map_err(|_| CryptoError::Malformed("P-384 public key".into()))?;
            let sig = p384::ecdsa::Signature::from_der(signature)
                .map_err(|_| CryptoError::Malformed("P-384 signature".into()))?;
            key.verify_prehash(&prehash, &sig).map_err(|_| CryptoError::BadSignature)
        }
        other => Err(CryptoError::Unsupported(format!("EC curve {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::ParsedCert;

    #[test]
    fn every_embedded_root_verifies_its_own_self_signature() {
        let mut verified = 0usize;
        let mut skipped = Vec::new();
        for (name, der) in
            crate::trust::TrustStore::embedded().roots().iter().map(|r| (r.name, r.der()))
        {
            let cert = ParsedCert::parse(der).expect(name);
            let hint = HashAlg::from_oid(cert.cert.signature_algorithm.oid);
            let signature = cert.cert.signature.as_bytes().expect("signature bit string is whole");
            match verify(
                &cert.cert.tbs_certificate.subject_public_key_info,
                &cert.cert.signature_algorithm,
                hint,
                cert.tbs,
                signature,
            ) {
                Ok(()) => verified = verified.saturating_add(1),
                Err(CryptoError::Unsupported(_)) => skipped.push(name),
                Err(other) => panic!("{name} failed to verify itself: {other}"),
            }
        }
        assert_eq!(skipped, vec!["Microsoft Root Authority"]);
        assert_eq!(verified, 17);
    }

    #[test]
    fn a_tampered_certificate_body_fails() {
        let der = include_bytes!("../roots/microsoft-root-2010.der");
        let cert = ParsedCert::parse(der).unwrap();
        let mut tampered = cert.tbs.to_vec();
        let last = tampered.len().saturating_sub(1);
        tampered[last] ^= 0x01;
        let result = verify(
            &cert.cert.tbs_certificate.subject_public_key_info,
            &cert.cert.signature_algorithm,
            HashAlg::from_oid(cert.cert.signature_algorithm.oid),
            &tampered,
            cert.cert.signature.as_bytes().unwrap(),
        );
        assert_eq!(result, Err(CryptoError::BadSignature));
    }

    #[test]
    fn the_ecc_root_really_is_ecdsa() {
        let der = include_bytes!("../roots/sslcom-root-ecc.der");
        let cert = ParsedCert::parse(der).unwrap();
        assert_eq!(
            cert.cert.tbs_certificate.subject_public_key_info.algorithm.oid,
            OID_EC_PUBLIC_KEY
        );
        assert_eq!(cert.cert.signature_algorithm.oid, OID_ECDSA_WITH_SHA256);
        let params = cert
            .cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters
            .as_ref()
            .unwrap();
        let encoded = der::Encode::to_der(params).unwrap();
        let curve =
            ObjectIdentifier::from_bytes(der_walk::first(&encoded).unwrap().content).unwrap();
        assert_eq!(curve, OID_SECP384R1);
    }

    #[test]
    fn an_unknown_algorithm_is_unsupported_not_invalid() {
        let der = include_bytes!("../roots/microsoft-root-2010.der");
        let cert = ParsedCert::parse(der).unwrap();
        let bogus = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.3.4.5"),
            parameters: None,
        };
        let result = verify(
            &cert.cert.tbs_certificate.subject_public_key_info,
            &bogus,
            None,
            cert.tbs,
            &[0u8; 8],
        );
        assert!(matches!(result, Err(CryptoError::Unsupported(_))));
    }

    #[test]
    fn hash_lengths_are_what_they_claim() {
        assert_eq!(HashAlg::Sha1.digest(b"x").len(), 20);
        assert_eq!(HashAlg::Sha256.digest(b"x").len(), 32);
        assert_eq!(HashAlg::Sha384.digest(b"x").len(), 48);
        assert_eq!(HashAlg::Sha512.digest(b"x").len(), 64);
    }
}
