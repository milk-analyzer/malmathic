#![cfg(windows)]

use mm_sign::{verify_embedded, TrustStore, Verdict};

const EMBEDDED_SIGNED: &[&str] = &[
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\svchost.exe",
];

const GAPPED_SECTIONS: &[&str] =
    &[r"C:\Program Files\Git\cmd\git.exe", r"C:\Program Files\Git\bin\bash.exe"];

const CATALOG_ONLY: &[&str] = &[r"C:\Windows\System32\notepad.exe"];

fn read(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

#[test]
fn the_corpus_is_actually_present() {
    let found =
        EMBEDDED_SIGNED.iter().chain(CATALOG_ONLY.iter()).filter(|p| read(p).is_some()).count();
    assert!(found > 0, "no fixture binaries were readable; the tests below would pass vacuously");
}

#[test]
fn real_microsoft_binaries_verify_against_the_embedded_roots() {
    let trust = TrustStore::embedded();
    for path in EMBEDDED_SIGNED {
        let Some(bytes) = read(path) else { continue };
        match verify_embedded(&bytes, &trust) {
            Verdict::Valid { signer, root_is_microsoft } => {
                assert!(
                    signer.contains("Microsoft"),
                    "{path} is signed by {signer}, which is not Microsoft"
                );
                assert!(root_is_microsoft, "{path} did not reach a Microsoft root");
            }
            other => panic!("{path} came out {other:?}"),
        }
    }
}

#[test]
fn validity_is_evaluated_at_the_countersigned_signing_time() {
    let trust = TrustStore::embedded();
    let now = mm_sign::now();
    let mut checked = 0usize;

    for path in EMBEDDED_SIGNED {
        let Some(bytes) = read(path) else { continue };
        let Ok(signers) = mm_sign::embedded_signers(&bytes, &trust, now) else {
            continue;
        };
        for signer in &signers {
            if let Some(at) = signer.signing_time {
                assert!(at < now, "{path} claims to have been signed in the future: {at}");
                assert_eq!(signer.evaluated_at, at, "{path} was judged at the wrong instant");
                checked = checked.saturating_add(1);
            }
        }
    }

    assert!(
        checked > 0,
        "no countersignature was found on any fixture; the timestamp path is untested"
    );
}

#[test]
fn catalog_only_binaries_are_unsigned_not_invalid() {
    let trust = TrustStore::embedded();
    for path in CATALOG_ONLY {
        let Some(bytes) = read(path) else { continue };
        assert_eq!(verify_embedded(&bytes, &trust), Verdict::Unsigned, "{path}");
    }
}

#[test]
fn flipping_one_byte_of_a_signed_image_breaks_it() {
    let trust = TrustStore::embedded();
    let mut tested = 0usize;

    for path in EMBEDDED_SIGNED {
        let Some(bytes) = read(path) else { continue };
        if !matches!(verify_embedded(&bytes, &trust), Verdict::Valid { .. }) {
            continue;
        }

        let mut tampered = bytes.clone();
        let at = tampered.len() / 2;
        tampered[at] ^= 0xff;

        match verify_embedded(&tampered, &trust) {
            Verdict::Invalid { reason } => {
                assert!(reason.contains("hash"), "{path} broke for the wrong reason: {reason}");
            }
            other => panic!("{path} still came out {other:?} after a byte was flipped"),
        }
        tested = tested.saturating_add(1);
    }

    assert!(tested > 0, "no signed fixture was available to tamper with");
}

#[test]
fn a_mangled_certificate_table_is_never_reported_as_unsigned() {
    let trust = TrustStore::embedded();
    let mut tested = 0usize;

    for path in EMBEDDED_SIGNED {
        let Some(bytes) = read(path) else { continue };
        if !matches!(verify_embedded(&bytes, &trust), Verdict::Valid { .. }) {
            continue;
        }
        let mut tampered = bytes.clone();
        let len = tampered.len();
        for byte in tampered.get_mut(len.saturating_sub(64)..).into_iter().flatten() {
            *byte ^= 0x5a;
        }
        assert_ne!(
            verify_embedded(&tampered, &trust),
            Verdict::Unsigned,
            "{path} lost its signature entirely when the blob was corrupted"
        );
        tested = tested.saturating_add(1);
    }

    assert!(tested > 0);
}

#[test]
fn images_with_gaps_between_sections_verify_and_still_detect_tampering() {
    let trust = TrustStore::embedded();
    for path in GAPPED_SECTIONS {
        let Some(bytes) = read(path) else { continue };
        match verify_embedded(&bytes, &trust) {
            Verdict::Valid { .. } => {}
            Verdict::Unknown { ref reason } if reason.contains("countersignature") => {}
            other => panic!("{path} came out {other:?}"),
        }

        let mut tampered = bytes.clone();
        let at = tampered.len() / 2;
        tampered[at] ^= 0xff;
        assert!(
            matches!(verify_embedded(&tampered, &trust), Verdict::Invalid { .. }),
            "{path} survived a flipped byte"
        );
    }
}

#[test]
fn an_empty_trust_store_never_manufactures_invalid() {
    let empty = TrustStore::empty();
    for path in EMBEDDED_SIGNED {
        let Some(bytes) = read(path) else { continue };
        match verify_embedded(&bytes, &empty) {
            Verdict::Unknown { .. } | Verdict::Untrusted { .. } => {}
            other => panic!("{path} came out {other:?} with no roots embedded"),
        }
    }
}
