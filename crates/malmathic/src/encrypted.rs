use std::sync::atomic::{AtomicU32, Ordering};

use mm_core::{
    Acquisition, ArtifactSource, Candidate, CandidateId, NormalizedPath, Observation,
    ObservationKind,
};

use crate::acquire::{
    acquire, ClusterMap, OrphanIndex, QuarantineStore, RecycleBinStore, SampleDir, ShadowStore,
};
use crate::testimage::{Builder, Presence, ROOT_RECORD};

const CIPHERTEXT: &[u8] = b"\x8fB\xd1\x00\x17\xaa\x93\x2c not the plaintext";

const RECORDED_SHA256: &str = "3e08292340a925412039c40af6eefec9a30fca1e60246baca93caf9f4bd3e53c";

#[test]
fn an_encrypted_record_is_recognised() {
    let mut builder = Builder::new();
    let dir = builder.directories(ROOT_RECORD, "Users\\bob");
    let record = builder.file(dir, "secret.exe", CIPHERTEXT, Presence::Live);
    builder.encrypt(record);
    let volume = builder.open();

    assert!(volume.is_efs_encrypted(record));
    assert!(volume.path_is_efs_encrypted("\\Users\\bob\\secret.exe"));
}

#[test]
fn an_ordinary_record_is_not() {
    let mut builder = Builder::new();
    let dir = builder.directories(ROOT_RECORD, "Users\\bob");
    let record = builder.file(dir, "ordinary.exe", b"MZ ordinary", Presence::Live);
    let volume = builder.open();

    assert!(!volume.is_efs_encrypted(record));
    assert!(!volume.path_is_efs_encrypted("\\Users\\bob\\ordinary.exe"));
}

#[test]
fn a_path_that_resolves_to_nothing_is_not_called_encrypted() {
    let mut builder = Builder::new();
    builder.directories(ROOT_RECORD, "Users\\bob");
    let volume = builder.open();

    assert!(!volume.path_is_efs_encrypted("\\Users\\bob\\nothing-here.exe"));
}

fn case_sample_dir() -> SampleDir {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "malmathic-efs-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    SampleDir { path: dir, relative: "sample", write_out: true }
}

fn acquire_through_the_real_chain<R: std::io::Read + std::io::Seek>(
    volume: &mm_raw::Volume<R>,
    candidate: &mut Candidate,
    sample_dir: &SampleDir,
) -> Acquisition {
    acquire(
        volume,
        &QuarantineStore::new(),
        &RecycleBinStore::new(),
        &ShadowStore::none(),
        &OrphanIndex::default(),
        &crate::index_slack::RecoveredNames::default(),
        &crate::acquire::GhostIndex::default(),
        &mut ClusterMap::new(),
        candidate,
        sample_dir,
    )
}

fn candidate_at(path: &str) -> Candidate {
    let mut candidate = Candidate::new(CandidateId(0), -9.0);
    let path = NormalizedPath::parse(path).expect("a normal path");
    candidate.path = Some(path.clone());
    candidate.observe(Observation::about_path(
        ArtifactSource::Mft,
        path,
        ObservationKind::FileExists {
            size: CIPHERTEXT.len() as u64,
            created: None,
            modified: None,
            mft_modified: None,
            record: None,
        },
    ));
    candidate
}

#[test]
fn the_ciphertext_of_a_present_file_is_never_saved_or_hashed() {
    let mut builder = Builder::new();
    let dir = builder.directories(ROOT_RECORD, "Users\\bob");
    let record = builder.file(dir, "secret.exe", CIPHERTEXT, Presence::Live);
    builder.encrypt(record);
    let volume = builder.open();

    let mut candidate = candidate_at("C:\\Users\\bob\\secret.exe");
    let out = case_sample_dir();
    let acquisition = acquire_through_the_real_chain(&volume, &mut candidate, &out);

    match acquisition {
        Acquisition::Failed { reason } => {
            assert!(reason.contains("EFS-encrypted"), "the report has to say why, got: {reason}");
            assert!(
                reason.contains("ciphertext"),
                "and has to name what the bytes are, got: {reason}"
            );
        }
        other => panic!("ciphertext must not be offered as the sample, got {other:?}"),
    }

    assert!(
        candidate.acquired_hash.is_none(),
        "no digest of the ciphertext may be recorded as this file's"
    );
    assert!(candidate.hash.is_empty(), "and none of it may reach the candidate's identity either");
}

#[test]
fn an_artifacts_plaintext_digest_still_reaches_the_report() {
    let mut builder = Builder::new();
    let dir = builder.directories(ROOT_RECORD, "Users\\bob");
    let record = builder.file(dir, "secret.exe", CIPHERTEXT, Presence::Live);
    builder.encrypt(record);
    let volume = builder.open();

    let mut candidate = candidate_at("C:\\Users\\bob\\secret.exe");
    let mut recorded = mm_core::FileHash::default();
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(RECORDED_SHA256.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    recorded.sha256 = Some(digest);
    candidate.observe(
        Observation::about_path(
            ArtifactSource::Amcache,
            NormalizedPath::parse("C:\\Users\\bob\\secret.exe").unwrap(),
            ObservationKind::Executed { when: None, run_count: Some(1) },
        )
        .with_hash(recorded),
    );

    let out = case_sample_dir();
    match acquire_through_the_real_chain(&volume, &mut candidate, &out) {
        Acquisition::HashOnly { via } => assert_eq!(via, ArtifactSource::Amcache),
        other => panic!("the recorded plaintext digest is the fallback, got {other:?}"),
    }
    assert_eq!(candidate.hash.sha256_hex().as_deref(), Some(RECORDED_SHA256));
}
