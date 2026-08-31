#![cfg(test)]

use std::collections::HashSet;

use mm_core::{ArtifactSource, ObservationKind};
use mm_harvest::usn_journal::{self, KnownPaths};
use mm_raw::usn::Verdict;

use crate::testimage::{
    journal_filetime, usn_journal_stream, usn_record, Builder, Presence, ROOT_RECORD,
};

const FILE_DELETE: u32 = 0x0000_0200;
const FILE_CREATE: u32 = 0x0000_0100;
const RENAME_NEW_NAME: u32 = 0x0000_2000;

fn max_stream() -> Vec<u8> {
    let mut m = vec![0u8; 32];
    m[0x00..0x08].copy_from_slice(&(32u64 * 1024 * 1024).to_le_bytes());
    m[0x08..0x10].copy_from_slice(&(8u64 * 1024 * 1024).to_le_bytes());
    m[0x10..0x18].copy_from_slice(&journal_filetime(0).to_le_bytes());
    m
}

fn windows(builder: &mut Builder) {
    let system32 = builder.directories(ROOT_RECORD, "Windows\\System32");
    builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
}

fn keys(paths: &[&str]) -> HashSet<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

#[test]
fn a_deletion_the_run_already_knew_about_gets_its_driver_written_time() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let dropper = builder.file(temp, "dropper.exe", b"MZ payload", Presence::Deleted);

    let deleted_at = journal_filetime(4_000);
    let journal = usn_journal_stream(&[usn_record(
        dropper,
        1,
        temp,
        1,
        0,
        deleted_at,
        FILE_DELETE,
        "dropper.exe",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let known = keys(&["\\users\\bob\\appdata\\local\\temp\\dropper.exe"]);
    let present = HashSet::new();
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &known, present: &present });

    assert!(
        matches!(harvest.state.verdict, Verdict::Active { records: 1 }),
        "{:?}",
        harvest.state.verdict
    );
    assert_eq!(harvest.observations.len(), 1, "{:?}", harvest.observations);
    let observation = &harvest.observations[0];
    assert_eq!(observation.source, ArtifactSource::UsnJournal);
    assert_eq!(
        observation.path.as_ref().map(|p| p.key()),
        Some("\\users\\bob\\appdata\\local\\temp\\dropper.exe")
    );
    match &observation.kind {
        ObservationKind::FileDeleted { when, record, sequence } => {
            assert!(when.is_some(), "the whole point of the source is the moment");
            assert_eq!(
                when.map(|w| w.timestamp()),
                Some(1_767_229_600),
                "the journal's own FILETIME, not the record's"
            );
            assert_eq!(
                (*record, *sequence),
                (Some(dropper), Some(1)),
                "a journal row names the record AND the incarnation it saw deleted, so a carve \
                 can be aimed at that one and refused for any other"
            );
        }
        other => panic!("a journal row is a deletion, not {other:?}"),
    }
}

#[test]
fn a_deletion_nothing_else_knows_about_creates_nothing() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let churn = builder.file(temp, "installer.tmp", b"junk", Presence::Deleted);

    let journal = usn_journal_stream(&[usn_record(
        churn,
        1,
        temp,
        1,
        0,
        journal_filetime(4_000),
        FILE_DELETE,
        "installer.tmp",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let known = keys(&["\\windows\\system32\\ntoskrnl.exe"]);
    let present = keys(&["\\windows\\system32\\ntoskrnl.exe"]);
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &known, present: &present });

    assert!(harvest.observations.is_empty(), "{:?}", harvest.observations);
    assert_eq!(harvest.unresolved, 0);
    assert_eq!(harvest.path_refilled, 0);
    assert!(matches!(harvest.state.verdict, Verdict::Active { records: 1 }));
    assert_eq!(harvest.state.deletions, 1);
}

#[test]
fn a_path_that_holds_a_live_file_today_is_not_dated_as_deleted() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let live = builder.file(temp, "setup.exe", b"MZ the second one", Presence::Live);

    let journal = usn_journal_stream(&[usn_record(
        live,
        1,
        temp,
        1,
        0,
        journal_filetime(4_000),
        FILE_DELETE,
        "setup.exe",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let known = keys(&["\\users\\bob\\appdata\\local\\temp\\setup.exe"]);
    let present = known.clone();
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &known, present: &present });

    assert!(harvest.observations.is_empty(), "{:?}", harvest.observations);
    assert_eq!(harvest.path_refilled, 1);
    let summary = harvest.corroboration_summary();
    assert!(summary.contains("holds a live file today"), "{summary}");
}

#[test]
fn a_creation_row_never_becomes_a_claim_that_the_file_is_there() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let dropper = builder.file(temp, "dropper.exe", b"MZ payload", Presence::Deleted);

    let journal = usn_journal_stream(&[usn_record(
        dropper,
        1,
        temp,
        1,
        0,
        journal_filetime(3_000),
        FILE_CREATE,
        "dropper.exe",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let known = keys(&["\\users\\bob\\appdata\\local\\temp\\dropper.exe"]);
    let present = HashSet::new();
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &known, present: &present });

    assert_eq!(harvest.state.creations, 1, "the row was read");
    assert!(harvest.observations.is_empty(), "a creation row claims nothing");
    assert!(
        !harvest.observations.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. })),
        "no journal row may ever assert present existence"
    );
    assert_eq!(
        harvest.clock().created("\\users\\bob\\appdata\\local\\temp\\dropper.exe"),
        Some(mm_core::from_filetime(journal_filetime(3_000) as u64).expect("a valid moment")),
        "the driver-written creation instant must survive the harvest"
    );
}

#[test]
fn a_rename_into_the_window_is_not_a_creation() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let victim = builder.file(desktop, "notes.txt.fuckazov", b"encrypted", Presence::Live);

    let journal = usn_journal_stream(&[usn_record(
        victim,
        1,
        desktop,
        1,
        0,
        journal_filetime(9_000),
        RENAME_NEW_NAME,
        "notes.txt.fuckazov",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let known = keys(&["\\users\\bob\\desktop\\notes.txt.fuckazov"]);
    let present = known.clone();
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &known, present: &present });

    assert!(harvest.creations.is_empty(), "{:?}", harvest.creations);
    assert_eq!(
        harvest.clock().created("\\users\\bob\\desktop\\notes.txt.fuckazov"),
        None,
        "a renamed file must never be dated as created"
    );
    assert!(harvest.observations.is_empty(), "and it claims nothing else either");
}

#[test]
fn a_matching_name_in_another_directory_is_not_moved_to_the_one_we_know() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let known_dir = builder.directories(ROOT_RECORD, "Program Files\\Vendor\\en");
    let other_dir = builder.directories(ROOT_RECORD, "Program Files\\Vendor\\de");
    let gone = builder.file(other_dir, "resources.dll", b"MZ elsewhere", Presence::Deleted);
    builder.resident_file(known_dir, "resources.dll", b"MZ here", Presence::Live);

    let journal = usn_journal_stream(&[usn_record(
        gone,
        1,
        other_dir,
        1,
        0,
        journal_filetime(4_000),
        FILE_DELETE,
        "resources.dll",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let known = keys(&["\\program files\\vendor\\en\\resources.dll"]);
    let present = known.clone();
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &known, present: &present });

    assert!(harvest.observations.is_empty(), "{:?}", harvest.observations);
    assert_eq!(harvest.unresolved, 1, "the row was seen, placed, and refused");
}

#[test]
fn a_reused_parent_record_does_not_lend_its_path_to_the_old_file() {
    const THEN: u16 = 4;
    const NOW: u16 = 5;

    let mut builder = Builder::new();
    windows(&mut builder);
    let vendor = builder.directories(ROOT_RECORD, "Program Files\\Vendor");
    builder.set_sequence(vendor, NOW);
    let gone = builder.file(vendor, "payload.exe", b"MZ payload", Presence::Deleted);

    let journal = usn_journal_stream(&[usn_record(
        gone,
        1,
        vendor,
        THEN,
        0,
        journal_filetime(4_000),
        FILE_DELETE,
        "payload.exe",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let known = keys(&["\\program files\\vendor\\payload.exe"]);
    let present = HashSet::new();
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &known, present: &present });

    assert!(
        harvest.observations.is_empty(),
        "a stale parent reference must not be resolved against today's directory: {:?}",
        harvest.observations
    );
    assert_eq!(harvest.unresolved, 1);
}

#[test]
fn an_absent_journal_and_a_cleared_one_are_told_apart_on_a_real_volume() {
    let mut bare = Builder::new();
    windows(&mut bare);
    let volume = bare.open();
    let empty = HashSet::new();
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &empty, present: &empty });
    assert_eq!(harvest.state.verdict, Verdict::NoJournal);
    assert!(harvest.state.limits().is_empty(), "{:?}", harvest.state.limits());

    let mut cleared = Builder::new();
    windows(&mut cleared);
    cleared.usn_journal(Some(&max_stream()), &vec![0u8; 4096]);
    let volume = cleared.open();
    let harvest = usn_journal::harvest(&volume, &KnownPaths { known: &empty, present: &empty });
    assert!(
        matches!(harvest.state.verdict, Verdict::EmptyOrCleared { .. }),
        "{:?}",
        harvest.state.verdict
    );
    let limits = harvest.state.limits();
    assert_eq!(limits.len(), 1, "{limits:?}");
    assert!(limits[0].contains("deletejournal"), "{}", limits[0]);
    assert!(limits[0].contains("cannot tell those apart"), "{}", limits[0]);
}

#[test]
fn the_journal_stream_is_read_through_its_runlist() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let temp = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let dropper = builder.file(temp, "dropper.exe", b"MZ payload", Presence::Deleted);
    let journal = usn_journal_stream(&[usn_record(
        dropper,
        1,
        temp,
        1,
        0,
        journal_filetime(4_000),
        FILE_DELETE,
        "dropper.exe",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let read = mm_raw::usn::read_journal(&volume);
    assert!(read.allocated_bytes > 0, "a resident $J would report no allocated clusters");
    assert!(read.bytes_read > 0, "nothing was read off the volume");
    assert_eq!(read.records.len(), 1);
    let max = read.max.as_ref().expect("$Max is a resident named stream and parses");
    assert_eq!(max.maximum_size, 32 * 1024 * 1024);
}
