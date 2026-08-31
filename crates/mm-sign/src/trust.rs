use sha1::{Digest, Sha1};

use crate::cert::ParsedCert;

pub struct TrustedRoot {
    pub name: &'static str,
    pub thumbprint: [u8; 20],
    pub is_microsoft: bool,
    pub source: &'static str,
    der: &'static [u8],
    parsed: ParsedCert<'static>,
}

impl TrustedRoot {
    pub fn der(&self) -> &'static [u8] {
        self.der
    }

    pub fn cert(&self) -> &ParsedCert<'static> {
        &self.parsed
    }
}

struct RootSpec {
    name: &'static str,
    thumbprint: &'static str,
    is_microsoft: bool,
    der: &'static [u8],
}

const ROOTS: &[RootSpec] = &[
    RootSpec {
        name: "Microsoft Root Certificate Authority 2011",
        thumbprint: "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
        is_microsoft: true,
        der: include_bytes!("../roots/microsoft-root-2011.der"),
    },
    RootSpec {
        name: "Microsoft Root Certificate Authority 2010",
        thumbprint: "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
        is_microsoft: true,
        der: include_bytes!("../roots/microsoft-root-2010.der"),
    },
    RootSpec {
        name: "DigiCert Trusted Root G4",
        thumbprint: "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4",
        is_microsoft: false,
        der: include_bytes!("../roots/digicert-trusted-root-g4.der"),
    },
    RootSpec {
        name: "VeriSign Class 3 Public Primary Certification Authority - G5",
        thumbprint: "4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5",
        is_microsoft: false,
        der: include_bytes!("../roots/verisign-class3-pca-g5.der"),
    },
    RootSpec {
        name: "DigiCert Global Root G3",
        thumbprint: "7E04DE896A3E666D00E687D33FFAD93BE83D349E",
        is_microsoft: false,
        der: include_bytes!("../roots/digicert-global-root-g3.der"),
    },
    RootSpec {
        name: "AAA Certificate Services",
        thumbprint: "D1EB23A46D17D68FD92564C2F1F1601764D8E349",
        is_microsoft: false,
        der: include_bytes!("../roots/comodo-aaa-certificate-services.der"),
    },
    RootSpec {
        name: "DigiCert Assured ID Root CA",
        thumbprint: "0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43",
        is_microsoft: false,
        der: include_bytes!("../roots/digicert-assured-id-root-ca.der"),
    },
    RootSpec {
        name: "DigiCert High Assurance EV Root CA",
        thumbprint: "5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25",
        is_microsoft: false,
        der: include_bytes!("../roots/digicert-high-assurance-ev-root-ca.der"),
    },
    RootSpec {
        name: "GlobalSign Code Signing Root R45",
        thumbprint: "4EFC31460C619ECAE59C1BCE2C008036D94C84B8",
        is_microsoft: false,
        der: include_bytes!("../roots/globalsign-code-signing-root-r45.der"),
    },
    RootSpec {
        name: "SSL.com Root Certification Authority ECC",
        thumbprint: "C3197C3924E654AF1BC4AB20957AE2C30E13026A",
        is_microsoft: false,
        der: include_bytes!("../roots/sslcom-root-ecc.der"),
    },
    RootSpec {
        name: "Microsoft Root Authority",
        thumbprint: "A43489159A520F0D93D032CCAF37E7FE20A8B419",
        is_microsoft: true,
        der: include_bytes!("../roots/microsoft-root-authority-1997.der"),
    },
    RootSpec {
        name: "Microsoft Root Certificate Authority",
        thumbprint: "CDD4EEAE6000AC7F40C3802C171E30148030C072",
        is_microsoft: true,
        der: include_bytes!("../roots/microsoft-root-2001.der"),
    },
    RootSpec {
        name: "Microsoft Identity Verification Root Certificate Authority 2020",
        thumbprint: "F40042E2E5F7E8EF8189FED15519AECE42C3BFA2",
        is_microsoft: false,
        der: include_bytes!("../roots/microsoft-identity-verification-root-2020.der"),
    },
    RootSpec {
        name: "Entrust Root Certification Authority - G2",
        thumbprint: "8CF427FD790C3AD166068DE81E57EFBB932272D4",
        is_microsoft: false,
        der: include_bytes!("../roots/entrust-root-g2.der"),
    },
    RootSpec {
        name: "thawte Primary Root CA",
        thumbprint: "91C6D6EE3E8AC86384E548C299295C756C817B81",
        is_microsoft: false,
        der: include_bytes!("../roots/thawte-primary-root-ca.der"),
    },
    RootSpec {
        name: "DigiCert CS RSA4096 Root G5",
        thumbprint: "5EEED86FA37C675230642F55C84DDBF67CD33C80",
        is_microsoft: false,
        der: include_bytes!("../roots/digicert-cs-rsa4096-root-g5.der"),
    },
    RootSpec {
        name: "GLOBALTRUST 2015",
        thumbprint: "465B26BEBE7106DD8544C1139D9FA25700C1D7BD",
        is_microsoft: false,
        der: include_bytes!("../roots/globaltrust-2015.der"),
    },
    RootSpec {
        name: "Certum Trusted Network CA 2",
        thumbprint: "D3DD483E2BBF4C05E8AF10F5FA7626CFD3DC3092",
        is_microsoft: false,
        der: include_bytes!("../roots/certum-trusted-network-ca-2.der"),
    },
];

pub const PROVENANCE: &str = "Exported from Cert:\\LocalMachine\\Root on a Windows 11 build 26100 \
     machine (Get-ChildItem Cert:\\LocalMachine\\Root, RawData written verbatim), pinned by the \
     SHA-1 thumbprints recorded beside each root in `ROOTS`.";

pub struct TrustStore {
    roots: Vec<TrustedRoot>,
}

impl TrustStore {
    pub fn embedded() -> Self {
        let roots = ROOTS
            .iter()
            .filter_map(|spec| {
                Some(TrustedRoot {
                    name: spec.name,
                    thumbprint: parse_thumbprint(spec.thumbprint),
                    is_microsoft: spec.is_microsoft,
                    source: PROVENANCE,
                    der: spec.der,
                    parsed: ParsedCert::parse(spec.der)?,
                })
            })
            .collect();
        TrustStore { roots }
    }

    pub fn empty() -> Self {
        TrustStore { roots: Vec::new() }
    }

    #[cfg(test)]
    pub(crate) fn pinning(der: &'static [u8], name: &'static str, is_microsoft: bool) -> Self {
        let Some(parsed) = ParsedCert::parse(der) else {
            return TrustStore { roots: Vec::new() };
        };
        TrustStore {
            roots: vec![TrustedRoot {
                name,
                thumbprint: thumbprint(der),
                is_microsoft,
                source: "synthetic, test only",
                der,
                parsed,
            }],
        }
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn roots(&self) -> &[TrustedRoot] {
        &self.roots
    }

    pub fn candidates_for<'s>(
        &'s self,
        issuer_der: &[u8],
    ) -> impl Iterator<Item = &'s TrustedRoot> {
        let wanted = issuer_der.to_vec();
        self.roots.iter().filter(move |root| root.parsed.subject_der == wanted)
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::embedded()
    }
}

pub fn thumbprint(der: &[u8]) -> [u8; 20] {
    let digest = Sha1::digest(der);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

pub fn thumbprint_hex(thumbprint: &[u8; 20]) -> String {
    thumbprint.iter().map(|b| format!("{b:02X}")).collect()
}

fn parse_thumbprint(hex: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    let bytes = hex.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let Some(pair) = index.checked_mul(2).and_then(|i| bytes.get(i..i.saturating_add(2)))
        else {
            break;
        };
        let Ok(text) = core::str::from_utf8(pair) else { break };
        let Ok(value) = u8::from_str_radix(text, 16) else { break };
        *slot = value;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_root_parses() {
        let store = TrustStore::embedded();
        assert_eq!(store.len(), ROOTS.len(), "a root failed to parse");
        assert_eq!(store.len(), 18);
    }

    #[test]
    fn every_root_matches_the_thumbprint_the_design_document_records() {
        for spec in ROOTS {
            let computed = thumbprint_hex(&thumbprint(spec.der));
            assert_eq!(computed, spec.thumbprint, "thumbprint mismatch for {}", spec.name);
        }
    }

    #[test]
    fn every_root_is_self_issued_and_named_what_the_table_says() {
        for spec in ROOTS {
            let cert = ParsedCert::parse(spec.der).expect(spec.name);
            assert!(cert.is_self_issued(), "{} is not self-issued", spec.name);
            assert_eq!(cert.display_name(), spec.name);
        }
    }

    #[test]
    fn only_the_v1_microsoft_root_lacks_basic_constraints() {
        let without: Vec<&str> = ROOTS
            .iter()
            .filter(|spec| !ParsedCert::parse(spec.der).is_some_and(|c| c.is_ca()))
            .map(|spec| spec.name)
            .collect();
        assert_eq!(without, vec!["Microsoft Root Authority"]);
    }

    #[test]
    fn both_microsoft_roots_are_present() {
        let store = TrustStore::embedded();
        let microsoft: Vec<_> = store.roots().iter().filter(|r| r.is_microsoft).collect();
        assert_eq!(microsoft.len(), 4);
        assert!(microsoft.iter().any(|r| r.name.contains("2010")));
        assert!(microsoft.iter().any(|r| r.name.contains("2011")));
    }

    #[test]
    fn an_issuer_name_finds_its_root() {
        let store = TrustStore::embedded();
        let root = ParsedCert::parse(include_bytes!("../roots/microsoft-root-2010.der")).unwrap();
        let found: Vec<_> = store.candidates_for(root.subject_der).collect();
        assert_eq!(found.len(), 1);
        assert!(found[0].is_microsoft);

        assert_eq!(store.candidates_for(b"not a name").count(), 0);
    }

    #[test]
    fn an_ecc_root_is_in_the_store() {
        let store = TrustStore::embedded();
        assert!(store.roots().iter().any(|r| r.name.contains("ECC")));
    }
}
