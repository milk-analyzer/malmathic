#![cfg(test)]

use std::io::{Read, Seek};

use mm_core::{
    Acquisition, ArtifactSource, Candidate, CandidateId, NormalizedPath, Observation,
    ObservationKind, Recovery,
};
use mm_harvest::filesystem;

use mm_raw::Volume;

use crate::acquire::{
    ClusterMap, OrphanIndex, QuarantineStore, RecycleBinStore, SampleDir, ShadowStore,
};
use crate::testimage::{Builder, Presence, ROOT_RECORD};

const NOW: u16 = 5;
const THEN: u16 = 4;

fn walk<R: Read + Seek>(volume: &Volume<R>) -> (Vec<String>, filesystem::WalkReport) {
    let mut keys = Vec::new();
    let report = filesystem::enumerate_with_progress(
        volume,
        &mut |path, _facts| keys.push(path.key().to_string()),
        &mut |_, _| {},
    )
    .expect("the synthetic volume walks");
    keys.sort();
    (keys, report)
}

fn windows(builder: &mut Builder) {
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
}

fn sample_bytes() -> Vec<u8> {
    let mut bytes = b"MZ\x90\x00".to_vec();
    bytes.extend(std::iter::repeat_n(0xA7u8, 24_060));
    bytes
}

fn a_deleted_tree(payload: &[u8]) -> (Builder, u64) {
    let mut builder = Builder::new();
    windows(&mut builder);

    let tool = builder.directories(ROOT_RECORD, "Program Files\\Vendor\\Tool");
    builder.set_sequence(tool, NOW);

    let gone = builder.directory(tool, "v1");
    builder.set_parent_sequence(gone, THEN);
    let payload_record = builder.file(gone, "dropper.exe", payload, Presence::Deleted);
    (builder, payload_record)
}

fn case_sample_dir() -> SampleDir {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "malmathic-orphan-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a case directory");
    SampleDir { path: dir, relative: "sample/unranked", write_out: true }
}

fn executed_only(path_str: &str) -> Candidate {
    let mut c = Candidate::new(CandidateId(1), -7.8);
    c.path = NormalizedPath::parse(path_str);
    c.observe(Observation::about_path(
        ArtifactSource::ShimCache,
        NormalizedPath::parse(path_str).unwrap(),
        ObservationKind::Executed { when: None, run_count: None },
    ));
    c
}

#[test]
fn a_deleted_executable_whose_directory_is_gone_is_placed_at_no_path() {
    let (builder, record) = a_deleted_tree(&sample_bytes());
    let volume = builder.open();
    let (keys, report) = walk(&volume);

    assert!(
        !keys.iter().any(|k| k.ends_with("dropper.exe")),
        "the walk placed it after all, so this volume is not the case under test: {keys:?}"
    );
    assert_eq!(
        report.stats.unresolved_files_deleted, 1,
        "one deleted record could be placed at no name"
    );
    let identity = volume.record_identity(record).expect("the record still reads");
    assert!(!identity.in_use);
    assert_eq!(identity.name, "dropper.exe");
}

#[test]
fn the_walk_carries_the_orphaned_record_out() {
    let (builder, record) = a_deleted_tree(&sample_bytes());
    let volume = builder.open();
    let (_keys, report) = walk(&volume);

    assert_eq!(report.stats.orphaned_executables, 1);
    assert_eq!(report.stats.orphans_kept, 1);
    assert_eq!(report.orphans.len(), 1);
    assert_eq!(report.orphans[0].record, record);
    assert_eq!(&*report.orphans[0].name, "dropper.exe");
    assert_eq!(report.orphans[0].size, sample_bytes().len() as u64);
}

#[test]
fn a_deleted_document_with_no_directory_is_counted_but_not_carried() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let tool = builder.directories(ROOT_RECORD, "Program Files\\Vendor\\Tool");
    builder.set_sequence(tool, NOW);
    let gone = builder.directory(tool, "v1");
    builder.set_parent_sequence(gone, THEN);
    builder.file(gone, "readme.txt", b"notes", Presence::Deleted);
    let volume = builder.open();

    let (_keys, report) = walk(&volume);
    assert_eq!(report.stats.unresolved_files_deleted, 1, "it is in the population");
    assert_eq!(report.stats.orphaned_executables, 0, "and not in the carveable one");
    assert!(report.orphans.is_empty());
    assert!(OrphanIndex::build(&report.orphans).is_empty());
}

#[test]
fn the_bytes_come_back_from_a_record_the_walk_could_not_place() {
    let payload = sample_bytes();
    let (builder, record) = a_deleted_tree(&payload);
    let volume = builder.open();
    let (_keys, report) = walk(&volume);
    let orphans = OrphanIndex::build(&report.orphans);
    assert_eq!(orphans.len(), 1);

    let out = case_sample_dir();
    let mut candidate = executed_only("C:\\Program Files\\Vendor\\Tool\\v1\\dropper.exe");
    let acquisition = crate::acquire::acquire(
        &volume,
        &QuarantineStore::new(),
        &RecycleBinStore::new(),
        &ShadowStore::none(),
        &orphans,
        &crate::index_slack::RecoveredNames::default(),
        &crate::acquire::GhostIndex::default(),
        &mut ClusterMap::new(),
        &mut candidate,
        &out,
    );

    match &acquisition {
        Acquisition::Bytes { via, size, saved_as, recovery } => {
            assert_eq!(*via, ArtifactSource::Mft);
            assert_eq!(*size, payload.len() as u64);
            assert!(
                saved_as.starts_with("sample/unranked/"),
                "a recovery the score did not reach belongs in its own directory: {saved_as}"
            );
            match recovery {
                Recovery::Unverified { basis } => {
                    assert!(
                        basis.contains("DIRECTORY THIS RECORD WAS IN IS UNKNOWN"),
                        "the caveat has to name what is unknown: {basis}"
                    );
                    assert!(basis.contains(&record.to_string()), "and the record: {basis}");
                }
                other => panic!("a name-matched carve is never more than unverified: {other:?}"),
            }
            let bytes = std::fs::read(out.path.join(format!("{}.bin", candidate.id)))
                .expect("the sample was written");
            assert_eq!(bytes, payload, "the carved bytes are not the file");
        }
        other => panic!("nothing was recovered: {other:?}"),
    }

    assert!(
        candidate.hash.is_empty(),
        "an unconfirmed name match must not become the file's identity"
    );
}

#[test]
fn without_the_orphan_index_the_same_candidate_recovers_nothing() {
    let (builder, _record) = a_deleted_tree(&sample_bytes());
    let volume = builder.open();

    let out = case_sample_dir();
    let mut candidate = executed_only("C:\\Program Files\\Vendor\\Tool\\v1\\dropper.exe");
    let acquisition = crate::acquire::acquire(
        &volume,
        &QuarantineStore::new(),
        &RecycleBinStore::new(),
        &ShadowStore::none(),
        &OrphanIndex::default(),
        &crate::index_slack::RecoveredNames::default(),
        &crate::acquire::GhostIndex::default(),
        &mut ClusterMap::new(),
        &mut candidate,
        &out,
    );
    assert!(
        matches!(acquisition, Acquisition::Failed { .. }),
        "with the index empty this is exactly the old behaviour: {acquisition:?}"
    );
    assert!(!out.path.join(format!("{}.bin", candidate.id)).exists());
}

#[test]
fn an_ambiguous_name_recovers_nothing_and_says_why() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let tool = builder.directories(ROOT_RECORD, "Program Files\\Vendor\\Tool");
    builder.set_sequence(tool, NOW);
    for version in ["v1", "v2"] {
        let gone = builder.directory(tool, version);
        builder.set_parent_sequence(gone, THEN);
        builder.file(gone, "dropper.exe", format!("MZ {version}").as_bytes(), Presence::Deleted);
    }
    let volume = builder.open();
    let (_keys, report) = walk(&volume);
    let orphans = OrphanIndex::build(&report.orphans);
    assert_eq!(report.stats.orphaned_executables, 2);
    assert_eq!(orphans.len(), 0, "neither is carveable on its own");

    let out = case_sample_dir();
    let mut candidate = executed_only("C:\\Program Files\\Vendor\\Tool\\v1\\dropper.exe");
    let acquisition = crate::acquire::acquire(
        &volume,
        &QuarantineStore::new(),
        &RecycleBinStore::new(),
        &ShadowStore::none(),
        &orphans,
        &crate::index_slack::RecoveredNames::default(),
        &crate::acquire::GhostIndex::default(),
        &mut ClusterMap::new(),
        &mut candidate,
        &out,
    );
    match &acquisition {
        Acquisition::Failed { reason } => {
            assert!(reason.contains('2'), "it says how many: {reason}");
            assert!(reason.contains("dropper.exe"), "and which name: {reason}");
        }
        other => panic!("a guess was made: {other:?}"),
    }
    assert!(!out.path.join(format!("{}.bin", candidate.id)).exists());
}

#[test]
fn a_reallocated_record_is_refused_by_name() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let taken = builder.resident_file(temp, "notepad.exe", b"MZ someone else", Presence::Live);
    let volume = builder.open();

    let orphans = OrphanIndex::build(&[filesystem::OrphanedDeleted {
        record: taken,
        name: "dropper.exe".into(),
        size: 10,
        deleted_at: None,
    }]);
    let out = case_sample_dir();
    let mut candidate = executed_only("C:\\Program Files\\Vendor\\Tool\\v1\\dropper.exe");
    let acquisition = crate::acquire::acquire(
        &volume,
        &QuarantineStore::new(),
        &RecycleBinStore::new(),
        &ShadowStore::none(),
        &orphans,
        &crate::index_slack::RecoveredNames::default(),
        &crate::acquire::GhostIndex::default(),
        &mut ClusterMap::new(),
        &mut candidate,
        &out,
    );
    match &acquisition {
        Acquisition::Failed { reason } => assert!(
            reason.contains("notepad.exe") || reason.contains("reallocated"),
            "the refusal has to say what holds the record now: {reason}"
        ),
        other => panic!("another file's bytes were carved: {other:?}"),
    }
    assert!(!out.path.join(format!("{}.bin", candidate.id)).exists());

    let orphans = OrphanIndex::build(&[filesystem::OrphanedDeleted {
        record: 1_000_000,
        name: "dropper.exe".into(),
        size: 10,
        deleted_at: None,
    }]);
    let mut candidate = executed_only("C:\\Program Files\\Vendor\\Tool\\v1\\dropper.exe");
    let acquisition = crate::acquire::acquire(
        &volume,
        &QuarantineStore::new(),
        &RecycleBinStore::new(),
        &ShadowStore::none(),
        &orphans,
        &crate::index_slack::RecoveredNames::default(),
        &crate::acquire::GhostIndex::default(),
        &mut ClusterMap::new(),
        &mut candidate,
        &out,
    );
    assert!(matches!(acquisition, Acquisition::Failed { .. }), "{acquisition:?}");
}

#[test]
fn a_file_the_walk_placed_is_still_recovered_by_path() {
    let payload = sample_bytes();
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let placed = builder.file(temp, "dropper.exe", &payload, Presence::Deleted);
    let tool = builder.directories(ROOT_RECORD, "Program Files\\Vendor\\Tool");
    builder.set_sequence(tool, NOW);
    let gone = builder.directory(tool, "v1");
    builder.set_parent_sequence(gone, THEN);
    builder.file(gone, "dropper.exe", b"MZ the wrong one", Presence::Deleted);
    let volume = builder.open();
    let (_keys, report) = walk(&volume);
    let orphans = OrphanIndex::build(&report.orphans);

    let out = case_sample_dir();
    let mut candidate = executed_only("C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe");
    candidate.observe(Observation::about_path(
        ArtifactSource::Mft,
        NormalizedPath::parse("C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe").unwrap(),
        ObservationKind::FileDeleted { when: None, record: Some(placed), sequence: None },
    ));
    let acquisition = crate::acquire::acquire(
        &volume,
        &QuarantineStore::new(),
        &RecycleBinStore::new(),
        &ShadowStore::none(),
        &orphans,
        &crate::index_slack::RecoveredNames::default(),
        &crate::acquire::GhostIndex::default(),
        &mut ClusterMap::new(),
        &mut candidate,
        &out,
    );
    match &acquisition {
        Acquisition::Bytes { recovery, size, .. } => {
            assert_eq!(*size, payload.len() as u64, "the placed file's bytes, not the orphan's");
            if let Recovery::Unverified { basis } = recovery {
                assert!(
                    !basis.contains("DIRECTORY THIS RECORD WAS IN IS UNKNOWN"),
                    "a path-matched carve must not carry the name-match caveat: {basis}"
                );
            }
        }
        other => panic!("the ordinary carve stopped working: {other:?}"),
    }
    let bytes = std::fs::read(out.path.join(format!("{}.bin", candidate.id))).expect("a sample");
    assert_eq!(bytes, payload);
}
