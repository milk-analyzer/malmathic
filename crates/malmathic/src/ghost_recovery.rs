#![cfg(test)]

use std::io::Cursor;

use mm_core::{
    Acquisition, ArtifactSource, Candidate, CandidateId, FileHash, NormalizedPath, Observation,
    ObservationKind, Recovery,
};
use mm_raw::Volume;

use crate::acquire::{
    acquire, ClusterMap, GhostIndex, OrphanIndex, QuarantineStore, RecycleBinStore, SampleDir,
    ShadowStore,
};
use crate::index_slack::RecoveredNames;
use crate::testimage::{log_file, record_image, Builder, Presence, ROOT_RECORD};

const DIR: &str = "Users\\bob\\AppData\\Local\\Temp";
const WHEN_IT_RAN: u16 = 1;
const TAKEN: u16 = 2;
const DISPLAY: &str = "C:\\Users\\bob\\AppData\\Local\\Temp\\vanished.exe";

fn payload() -> Vec<u8> {
    let mut bytes = b"MZ\x90\x00this is the dropper and nothing else".to_vec();
    bytes.extend(std::iter::repeat_n(0x5Au8, 12_000));
    bytes
}

fn case_sample_dir() -> SampleDir {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "malmathic-ghost-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a case directory");
    SampleDir { path: dir, relative: "sample", write_out: true }
}

fn ran_and_vanished() -> Candidate {
    let mut c = Candidate::new(CandidateId(1), -7.8);
    c.path = NormalizedPath::parse(DISPLAY);
    c.observe(Observation::about_path(
        ArtifactSource::ShimCache,
        NormalizedPath::parse(DISPLAY).unwrap(),
        ObservationKind::Executed { when: None, run_count: None },
    ));
    c
}

fn deleted_by_the_journal(record: u64) -> Candidate {
    let mut c = ran_and_vanished();
    c.observe(Observation::about_path(
        ArtifactSource::UsnJournal,
        NormalizedPath::parse(DISPLAY).unwrap(),
        ObservationKind::FileDeleted {
            when: None,
            record: Some(record),
            sequence: Some(WHEN_IT_RAN),
        },
    ));
    c
}

fn windows(builder: &mut Builder) {
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
}

fn take(
    volume: &Volume<Cursor<Vec<u8>>>,
    ghosts: &GhostIndex,
    candidate: &mut Candidate,
    dir: &SampleDir,
) -> Acquisition {
    acquire(
        volume,
        &QuarantineStore::new(),
        &RecycleBinStore::new(),
        &ShadowStore::none(),
        &OrphanIndex::default(),
        &RecoveredNames::default(),
        ghosts,
        &mut ClusterMap::new(),
        candidate,
        dir,
    )
}

fn saved_bytes(acquisition: &Acquisition, dir: &SampleDir) -> Vec<u8> {
    match acquisition {
        Acquisition::Bytes { saved_as, .. } => {
            let name = saved_as.rsplit('/').next().expect("a file name");
            std::fs::read(dir.path.join(name)).expect("the sample was written")
        }
        other => panic!("no bytes were written: {other:?}"),
    }
}

fn a_volume_whose_record_was_handed_on() -> (Builder, u64, u64, u64) {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, DIR);
    let record = builder.file(
        temp,
        "vanished.exe",
        &payload(),
        Presence::RecordReallocatedClustersFree("harmless.log"),
    );
    let (lcn, clusters) = builder.data_location(record).expect("the payload is on the disk");
    builder.set_sequence(record, TAKEN);
    builder.leave_in_record_slack(
        record,
        temp,
        "vanished.exe",
        lcn,
        clusters,
        payload().len() as u64,
    );
    (builder, record, lcn, clusters)
}

#[test]
fn a_file_whose_record_was_handed_to_another_is_recovered_from_that_records_tail() {
    let (builder, record, _, _) = a_volume_whose_record_was_handed_on();
    let volume = builder.open();

    assert!(
        volume.resolve(&format!("\\{DIR}\\vanished.exe")).is_none(),
        "the name must be gone from its directory, or this is not the case under test"
    );
    let identity = volume.record_identity(record).expect("the record reads");
    assert!(identity.in_use && identity.name == "harmless.log", "{identity:?}");

    let dir = case_sample_dir();
    let mut candidate = deleted_by_the_journal(record);
    let acquisition = take(&volume, &GhostIndex::default(), &mut candidate, &dir);

    assert_eq!(saved_bytes(&acquisition, &dir), payload(), "the bytes must be the file's own");
    let Acquisition::Bytes { via, size, recovery, .. } = &acquisition else {
        panic!("{acquisition:?}");
    };
    assert_eq!(*via, ArtifactSource::Mft);
    assert_eq!(*size, payload().len() as u64);
    let Recovery::Unverified { basis } = recovery else {
        panic!("nothing independent confirms a ghost: {recovery:?}")
    };
    assert!(basis.contains("outlived their own $MFT record"), "{basis}");
    assert!(basis.contains(&format!("the unused tail of $MFT record {record}")), "{basis}");
    assert!(basis.contains("still marked free in $Bitmap"), "{basis}");
    assert!(basis.contains("No artifact recorded a hash"), "{basis}");
}

#[test]
fn a_recorded_hash_turns_a_ghost_from_unverified_into_confirmed() {
    let (builder, record, _, _) = a_volume_whose_record_was_handed_on();
    let volume = builder.open();

    let dir = case_sample_dir();
    let mut candidate = deleted_by_the_journal(record);
    let recorded = FileHash::compute(&payload());
    candidate.observe(
        Observation::about_path(
            ArtifactSource::Amcache,
            NormalizedPath::parse(DISPLAY).unwrap(),
            ObservationKind::HashRecovered,
        )
        .with_hash(FileHash::from_sha1_hex(&recorded.sha1_hex().unwrap()).unwrap()),
    );

    let acquisition = take(&volume, &GhostIndex::default(), &mut candidate, &dir);
    assert_eq!(saved_bytes(&acquisition, &dir), payload());
    let Acquisition::Bytes { recovery: Recovery::Confirmed { against }, .. } = &acquisition else {
        panic!("the recorded digest must confirm it: {acquisition:?}")
    };
    assert!(against.contains("Amcache"), "{against}");
}

#[test]
fn a_ghost_whose_clusters_were_given_away_is_refused_rather_than_offered() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, DIR);
    let record = builder.file(
        temp,
        "vanished.exe",
        &payload(),
        Presence::RecordReallocatedClustersOverwritten("harmless.log"),
    );
    let (lcn, clusters) = builder.data_location(record).expect("a location");
    builder.set_sequence(record, TAKEN);
    builder.leave_in_record_slack(
        record,
        temp,
        "vanished.exe",
        lcn,
        clusters,
        payload().len() as u64,
    );
    let volume = builder.open();

    let dir = case_sample_dir();
    let mut candidate = deleted_by_the_journal(record);
    let acquisition = take(&volume, &GhostIndex::default(), &mut candidate, &dir);

    let Acquisition::Failed { reason } = &acquisition else {
        panic!("overwritten clusters must not be offered as the sample: {acquisition:?}")
    };
    assert!(reason.contains("REALLOCATED to `harmless.log`"), "{reason}");
    assert!(reason.contains("would offer another file's clusters"), "{reason}");
    assert_eq!(std::fs::read_dir(&dir.path).unwrap().count(), 0, "and nothing was written");
}

#[test]
fn a_log_file_ghost_whose_clusters_were_given_away_says_so_and_carves_nothing() {
    let bytes = payload();
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, DIR);
    let record = builder.file(temp, "vanished.exe", &bytes, Presence::DeletedClustersReused);
    let (lcn, clusters) = builder.data_location(record).expect("a location");
    builder.file(
        ROOT_RECORD,
        "$LogFile",
        &log_file(&[record_image(temp, "vanished.exe", lcn, clusters, bytes.len() as u64)]),
        Presence::Live,
    );
    let volume = builder.open();

    let dir = case_sample_dir();
    let mut candidate = ran_and_vanished();
    let acquisition = take(&volume, &GhostIndex::build(&volume), &mut candidate, &dir);

    let Acquisition::Failed { reason } = &acquisition else {
        panic!("clusters $Bitmap has given away are not this file's: {acquisition:?}")
    };
    assert!(reason.contains("$LogFile at offset"), "{reason}");
    assert!(reason.contains("given"), "{reason}");
    assert!(reason.contains("another file"), "{reason}");
    assert!(reason.contains("cannot be told"), "{reason}");
    assert_eq!(std::fs::read_dir(&dir.path).unwrap().count(), 0, "and nothing was written");
}

#[test]
fn a_record_image_in_the_log_file_recovers_a_file_with_no_record_left_at_all() {
    let bytes = payload();
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, DIR);
    let record = builder.file(temp, "vanished.exe", &bytes, Presence::Deleted);
    let (lcn, clusters) = builder.data_location(record).expect("a location");
    builder.file(
        ROOT_RECORD,
        "$LogFile",
        &log_file(&[record_image(temp, "vanished.exe", lcn, clusters, bytes.len() as u64)]),
        Presence::Live,
    );
    let volume = builder.open();

    let ghosts = GhostIndex::build(&volume);
    assert_eq!(ghosts.len(), 1, "the log holds exactly one placeable name");
    assert!(ghosts.coverage_line().contains("record image"), "{}", ghosts.coverage_line());

    let dir = case_sample_dir();
    let mut candidate = ran_and_vanished();
    let acquisition = take(&volume, &ghosts, &mut candidate, &dir);

    assert_eq!(saved_bytes(&acquisition, &dir), bytes);
    let Acquisition::Bytes { recovery: Recovery::Unverified { basis }, .. } = &acquisition else {
        panic!("{acquisition:?}")
    };
    assert!(basis.contains("$LogFile at offset"), "{basis}");
    assert!(basis.contains("the same parent that image records"), "{basis}");
}

#[test]
fn a_log_file_image_from_another_directory_is_refused_by_its_parent() {
    let bytes = payload();
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, DIR);
    let elsewhere = builder.directories(ROOT_RECORD, "Users\\bob\\Downloads");
    let record = builder.file(temp, "vanished.exe", &bytes, Presence::Deleted);
    let (lcn, clusters) = builder.data_location(record).expect("a location");
    builder.file(
        ROOT_RECORD,
        "$LogFile",
        &log_file(&[record_image(elsewhere, "vanished.exe", lcn, clusters, bytes.len() as u64)]),
        Presence::Live,
    );
    let volume = builder.open();

    let dir = case_sample_dir();
    let mut candidate = ran_and_vanished();
    let acquisition = take(&volume, &GhostIndex::build(&volume), &mut candidate, &dir);

    let Acquisition::Failed { reason } = &acquisition else {
        panic!("a different directory's file of the same name is not this one: {acquisition:?}")
    };
    assert!(reason.contains("a different file of the same name"), "{reason}");
    assert_eq!(std::fs::read_dir(&dir.path).unwrap().count(), 0);
}

#[test]
fn two_images_of_different_files_under_one_name_are_refused_as_ambiguous() {
    let bytes = payload();
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, DIR);
    let record = builder.file(temp, "vanished.exe", &bytes, Presence::Deleted);
    let (lcn, clusters) = builder.data_location(record).expect("a location");
    builder.file(
        ROOT_RECORD,
        "$LogFile",
        &log_file(&[
            record_image(temp, "vanished.exe", lcn, clusters, bytes.len() as u64),
            record_image(temp, "vanished.exe", lcn + 64, clusters, bytes.len() as u64),
        ]),
        Presence::Live,
    );
    let volume = builder.open();

    let ghosts = GhostIndex::build(&volume);
    assert!(ghosts.is_empty(), "neither image may be offered as the file");

    let dir = case_sample_dir();
    let mut candidate = ran_and_vanished();
    let acquisition = take(&volume, &ghosts, &mut candidate, &dir);
    let Acquisition::Failed { reason } = &acquisition else { panic!("{acquisition:?}") };
    assert!(reason.contains("different files"), "{reason}");
    assert_eq!(std::fs::read_dir(&dir.path).unwrap().count(), 0);
}

#[test]
fn a_volume_with_no_log_file_says_so_and_recovers_nothing_from_it() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, DIR);
    builder.file(temp, "vanished.exe", &payload(), Presence::DeletedClustersReused);
    let volume = builder.open();

    let ghosts = GhostIndex::build(&volume);
    assert!(ghosts.is_empty());
    assert!(ghosts.coverage_line().starts_with("$LogFile (not read"), "{}", ghosts.coverage_line());

    let dir = case_sample_dir();
    let mut candidate = ran_and_vanished();
    assert!(matches!(take(&volume, &ghosts, &mut candidate, &dir), Acquisition::Failed { .. },));
}

#[test]
fn a_file_still_in_its_directory_is_never_taken_from_a_ghost() {
    let bytes = payload();
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, DIR);
    let record = builder.file(temp, "vanished.exe", &bytes, Presence::Live);
    let (lcn, clusters) = builder.data_location(record).expect("a location");
    let lie = b"MZ these bytes are not the file and never were".to_vec();
    builder.file(
        ROOT_RECORD,
        "$LogFile",
        &log_file(&[record_image(temp, "vanished.exe", lcn + clusters + 8, 1, lie.len() as u64)]),
        Presence::Live,
    );
    let volume = builder.open();

    let dir = case_sample_dir();
    let mut candidate = ran_and_vanished();
    candidate.observe(Observation::about_path(
        ArtifactSource::Mft,
        NormalizedPath::parse(DISPLAY).unwrap(),
        ObservationKind::FileExists {
            size: bytes.len() as u64,
            created: None,
            modified: None,
            mft_modified: None,
            record: Some(record),
        },
    ));

    let acquisition = take(&volume, &GhostIndex::build(&volume), &mut candidate, &dir);
    assert_eq!(saved_bytes(&acquisition, &dir), bytes, "the live file wins every ghost");
    assert!(matches!(
        &acquisition,
        Acquisition::Bytes { recovery: Recovery::Intact, via: ArtifactSource::Mft, .. }
    ));
}
