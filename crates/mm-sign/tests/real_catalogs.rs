#![cfg(windows)]

use mm_sign::catalog::{self, CatalogIndex, CatalogTrust, MemberKey};
use mm_sign::{TrustStore, Verdict};

const CATROOT: &str = r"C:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}";

const CATALOG_ONLY: &[&str] = &[
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\calc.exe",
];

fn shipped_volume() -> Option<mm_raw::Volume<mm_env::BlockReader<mm_env::win::VolumeDevice>>> {
    let device = mm_env::win::VolumeDevice::open(r"\\.\C:").ok()?;
    let volume = mm_raw::Volume::open(mm_env::BlockReader::new(device), r"\\.\C:").ok()?;
    volume.is_windows_install().then_some(volume)
}

fn catalog_paths() -> Vec<std::path::PathBuf> {
    let Ok(dir) = std::fs::read_dir(CATROOT) else {
        return Vec::new();
    };
    let mut paths: Vec<_> = dir
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("cat")))
        .collect();
    paths.sort();
    paths
}

fn catalogs_listing(keys: &[MemberKey]) -> Vec<(String, Vec<u8>)> {
    let mut found = Vec::new();
    for path in catalog_paths() {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let Ok(catalog) = catalog::parse(&bytes) else { continue };
        let listed = catalog
            .members()
            .iter()
            .any(|member| member.key.is_some_and(|key| keys.contains(&key)));
        if listed {
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            found.push((name, bytes));
        }
    }
    found
}

fn index_covering(pe_bytes: &[u8], trust: &TrustStore) -> CatalogIndex {
    let mut index = CatalogIndex::new();
    let now = mm_sign::now();
    for (name, bytes) in catalogs_listing(&catalog::candidate_keys(pe_bytes)) {
        let _ = index.add(&name, &bytes, trust, now);
    }
    index
}

#[test]
fn the_catalog_corpus_is_actually_present() {
    let paths = catalog_paths();
    if paths.is_empty() {
        return;
    }
    assert!(
        paths.len() > 100,
        "CatRoot held only {} catalogs, which is not a real corpus",
        paths.len()
    );
}

#[test]
fn catalog_only_binaries_come_back_catalog_valid() {
    let trust = TrustStore::embedded();
    let mut checked = 0;
    let mut had_no_embedded_signature = 0;
    for path in CATALOG_ONLY {
        let Ok(bytes) = std::fs::read(path) else { continue };
        if mm_sign::verify_embedded(&bytes, &trust) == Verdict::Unsigned {
            had_no_embedded_signature += 1;
        }

        let index = index_covering(&bytes, &trust);
        if !index.is_usable() {
            continue;
        }
        checked += 1;

        match catalog::verify_catalog(&bytes, &index) {
            Verdict::CatalogValid { signer, catalog, root_is_microsoft } => {
                assert!(
                    root_is_microsoft,
                    "{path} was vouched for by a non-Microsoft catalog {catalog}"
                );
                assert!(!signer.is_empty());
                assert!(catalog.to_ascii_lowercase().ends_with(".cat"));
            }
            other => panic!("{path} came back {other:?}"),
        }

        assert!(matches!(
            mm_sign::verify_file(&bytes, &trust, &index),
            Verdict::CatalogValid { .. } | Verdict::Valid { .. }
        ));
    }
    if !catalog_paths().is_empty() {
        assert!(checked > 0, "no catalog-only fixture was covered by any catalog");
        assert!(
            had_no_embedded_signature > 0,
            "every fixture turned out to be embedded-signed, so this proved nothing about catalogs"
        );
    }
}

#[test]
fn members_outnumber_spc_indirect_data_so_the_key_must_be_the_identifier() {
    let mut members = 0usize;
    let mut indirect = 0usize;
    for path in catalog_paths().into_iter().take(300) {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let Ok(catalog) = catalog::parse(&bytes) else { continue };
        for member in catalog.members() {
            members += 1;
            if member.indirect_digest().is_some() {
                indirect += 1;
            }
        }
    }
    if members == 0 {
        return;
    }
    assert!(
        members > indirect + indirect / 2,
        "indexing on the indirect digest would have kept {indirect} of {members} members"
    );
    let mut unkeyed = 0usize;
    for path in catalog_paths().into_iter().take(300) {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let Ok(catalog) = catalog::parse(&bytes) else { continue };
        unkeyed += catalog.members().iter().filter(|m| m.key.is_none()).count();
    }
    assert_eq!(unkeyed, 0, "{unkeyed} member identifiers were in an encoding we do not read");
}

#[test]
fn both_digest_algorithms_are_present_in_real_catalogs() {
    let mut sha1 = 0usize;
    let mut sha256 = 0usize;
    for path in catalog_paths().into_iter().take(50) {
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let Ok(catalog) = catalog::parse(&bytes) else { continue };
        for member in catalog.members() {
            match member.key {
                Some(MemberKey::Sha1(_)) => sha1 += 1,
                Some(MemberKey::Sha256(_)) => sha256 += 1,
                None => {}
            }
        }
    }
    if sha1 + sha256 == 0 {
        return;
    }
    assert!(sha1 > 0 && sha256 > 0, "saw {sha1} SHA-1 and {sha256} SHA-256 members");
}

#[test]
fn a_member_that_is_not_a_pe_image_is_found_by_its_flat_hash() {
    let trust = TrustStore::embedded();
    let mut checked = 0;
    for path in [
        r"C:\Windows\SysWOW64\compobj.dll",
        r"C:\Windows\SysWOW64\ole2.dll",
        r"C:\Windows\SysWOW64\storage.dll",
    ] {
        let Ok(bytes) = std::fs::read(path) else { continue };
        assert!(
            matches!(mm_sign::verify_embedded(&bytes, &trust), Verdict::Unknown { .. }),
            "{path} parsed as a PE, so it no longer tests the fallback"
        );
        let keys = catalog::candidate_keys(&bytes);
        assert_eq!(keys.len(), 2, "a non-image should offer one flat hash per algorithm");

        let index = index_covering(&bytes, &trust);
        if !index.is_usable() {
            continue;
        }
        checked += 1;
        assert!(
            matches!(catalog::verify_catalog(&bytes, &index), Verdict::CatalogValid { .. }),
            "{path} is listed in a catalog but did not come back catalog-valid"
        );
    }
    let _ = checked;
}

#[test]
fn a_member_listed_only_under_sha1_is_still_found() {
    let trust = TrustStore::embedded();
    let Ok(bytes) = std::fs::read(r"C:\Windows\System32\drivers\tap0901.sys") else { return };
    let index = index_covering(&bytes, &trust);
    if !index.is_usable() {
        return;
    }
    match catalog::verify_catalog(&bytes, &index) {
        Verdict::CatalogValid { root_is_microsoft, .. } => {
            assert!(!root_is_microsoft, "an OEM driver catalog claimed a Microsoft root");
        }
        other => panic!("a SHA-1-only catalog member came back {other:?}"),
    }
}

#[test]
fn one_flipped_byte_leaves_the_catalog_behind_without_manufacturing_invalid() {
    let trust = TrustStore::embedded();
    let Ok(clean) = std::fs::read(r"C:\Windows\System32\notepad.exe") else { return };
    let index = index_covering(&clean, &trust);
    if !index.is_usable() {
        return;
    }
    assert!(matches!(catalog::verify_catalog(&clean, &index), Verdict::CatalogValid { .. }));

    let mut tampered = clean;
    let at = tampered.len() / 2;
    tampered[at] ^= 0x01;

    let verdict = catalog::verify_catalog(&tampered, &index);
    assert_eq!(verdict, Verdict::Unsigned, "a modified file must not be catalog-valid");
    assert!(!matches!(verdict, Verdict::Invalid { .. }));
}

#[test]
fn a_tampered_catalog_stops_vouching_for_anything() {
    let trust = TrustStore::embedded();
    let Ok(clean) = std::fs::read(r"C:\Windows\System32\notepad.exe") else { return };
    let covering = catalogs_listing(&catalog::candidate_keys(&clean));
    let Some((name, bytes)) = covering.into_iter().next() else { return };

    let now = mm_sign::now();
    let mut good = CatalogIndex::new();
    let record = good.add(&name, &bytes, &trust, now).expect("a real catalog parses");
    assert_eq!(record.trust, CatalogTrust::Valid);

    let mut broken = bytes.clone();
    let at = broken.len() / 3;
    broken[at] ^= 0xff;

    let mut bad = CatalogIndex::new();
    match bad.add(&name, &broken, &trust, now) {
        Ok(record) => assert_ne!(
            record.trust,
            CatalogTrust::Valid,
            "a catalog with a flipped byte still claimed to be valid"
        ),
        Err(_) => return,
    }
    assert!(!matches!(catalog::verify_catalog(&clean, &bad), Verdict::CatalogValid { .. }));
}

#[test]
fn an_empty_trust_store_never_produces_catalog_valid_or_invalid() {
    let Ok(clean) = std::fs::read(r"C:\Windows\System32\notepad.exe") else { return };
    let covering = catalogs_listing(&catalog::candidate_keys(&clean));
    if covering.is_empty() {
        return;
    }

    let empty = TrustStore::empty();
    let now = mm_sign::now();
    let mut index = CatalogIndex::new();
    for (name, bytes) in &covering {
        let _ = index.add(name, bytes, &empty, now);
    }

    for record in index.catalogs() {
        assert_ne!(record.trust, CatalogTrust::Valid);
        assert_ne!(
            record.trust,
            CatalogTrust::Invalid,
            "an unreachable root is not a broken signature"
        );
    }
    match catalog::verify_catalog(&clean, &index) {
        Verdict::Unknown { .. } | Verdict::Untrusted { .. } => {}
        other => panic!("an empty trust store produced {other:?}"),
    }
}

#[test]
fn a_catroot_we_could_not_read_is_unknown_for_every_file() {
    let trust = TrustStore::embedded();
    let Ok(bytes) = std::fs::read(r"C:\Windows\System32\notepad.exe") else { return };
    let empty = CatalogIndex::new();

    assert!(matches!(catalog::verify_catalog(&bytes, &empty), Verdict::Unknown { .. }));
    assert!(matches!(mm_sign::verify_file(&bytes, &trust, &empty), Verdict::Unknown { .. }));
}

#[test]
fn catroot_index_from_a_live_volume() {
    let Some(volume) = shipped_volume() else { return };

    let trust = TrustStore::embedded();
    let mut index = CatalogIndex::new();
    let directory = catalog::CATROOT_DIRECTORIES[0];
    let entries: Vec<_> = volume
        .list_directory_entries(directory)
        .into_iter()
        .filter(|e| e.name.to_ascii_lowercase().ends_with(".cat"))
        .take(25)
        .collect();
    assert!(!entries.is_empty(), "no catalogs were visible through the volume reader");

    let now = mm_sign::now();
    for entry in &entries {
        let Ok(bytes) = volume.read_record_capped(entry.record, catalog::MAX_CATALOG_BYTES) else {
            continue;
        };
        let _ = index.add(&entry.name, &bytes, &trust, now);
    }

    assert!(index.is_usable(), "no catalog read off the volume produced any members");
    assert_eq!(
        index.catalogs().iter().filter(|c| c.trust != CatalogTrust::Valid).count(),
        0,
        "a catalog read through the volume failed to verify, which the std::fs path does not"
    );
}

#[test]
fn reading_a_catalog_by_record_gives_the_same_bytes_as_reading_it_by_path() {
    let Some(volume) = shipped_volume() else { return };

    let directory = catalog::CATROOT_DIRECTORIES[0];
    let entries: Vec<_> = volume
        .list_directory_entries(directory)
        .into_iter()
        .filter(|e| e.name.to_ascii_lowercase().ends_with(".cat"))
        .collect();
    assert!(!entries.is_empty(), "no catalogs were visible through the volume reader");

    let mut compared = 0usize;
    for entry in entries.iter().take(40) {
        let path = format!("{directory}\\{}", entry.name);
        let by_path = volume.read_capped(&path, catalog::MAX_CATALOG_BYTES);
        let by_record = volume.read_record_capped(entry.record, catalog::MAX_CATALOG_BYTES);
        match (by_path, by_record) {
            (Ok(a), Ok(b)) => {
                assert_eq!(
                    a, b,
                    "{} read by record differs from the same file read by path",
                    entry.name
                );
                assert!(!a.is_empty(), "{} read as zero bytes both ways", entry.name);
                compared += 1;
            }
            (a, b) => panic!(
                "{} disagreed on readability: by path {:?}, by record {:?}",
                entry.name,
                a.map(|v| v.len()),
                b.map(|v| v.len())
            ),
        }
    }
    assert!(compared >= 25, "only {compared} catalogs were actually compared");

    let by_name: std::collections::BTreeSet<String> =
        volume.list_directory(directory).into_iter().collect();
    let by_entry: std::collections::BTreeSet<String> =
        volume.list_directory_entries(directory).into_iter().map(|e| e.name).collect();
    assert_eq!(by_name, by_entry);
}
