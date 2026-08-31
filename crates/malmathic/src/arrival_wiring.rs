#![cfg(test)]

use std::collections::HashMap;

use mm_core::arrival::{Admission, Role};
use mm_core::CandidateId;
use mm_harvest::arrival::{self, Anchor, Context};

use crate::testimage::{
    journal_filetime, usn_journal_stream, usn_record, Builder, Presence, ROOT_RECORD,
};

const FILE_CREATE: u32 = 0x0000_0100;
const CLOSE: u32 = 0x8000_0000;
const DATA_EXTEND: u32 = 0x0000_0002;
const BASIC_INFO_CHANGE: u32 = 0x0000_8000;
const SECURITY_CHANGE: u32 = 0x0000_0800;
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

fn anchor(record: u64, path: &str, probability: f64, finding: bool) -> Anchor {
    Anchor {
        candidate: CandidateId(1),
        display_path: path.to_string(),
        key: path.to_ascii_lowercase(),
        record,
        probability,
        is_finding: finding,
    }
}

fn context() -> Context<'static> {
    static NONE: std::sync::OnceLock<HashMap<String, (CandidateId, f64)>> =
        std::sync::OnceLock::new();
    Context { candidates: NONE.get_or_init(HashMap::new), threshold: 0.5, window: None }
}

#[test]
fn the_anchor_and_what_arrived_beside_it_are_both_listed() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let zip = builder.file(desktop, "payload.zip", b"PK stuff", Presence::Live);
    let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);

    let journal = usn_journal_stream(&[
        usn_record(zip, 1, desktop, 1, 0, journal_filetime(1_000), FILE_CREATE, "payload.zip"),
        usn_record(
            exe,
            1,
            desktop,
            1,
            0,
            journal_filetime(1_030),
            FILE_CREATE | DATA_EXTEND,
            "payload.exe",
        ),
        usn_record(exe, 1, desktop, 1, 0, journal_filetime(1_030), CLOSE, "payload.exe"),
    ]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
    let timeline = arrival::read(&volume, &anchors, &context()).expect("a block");

    assert_eq!(timeline.anchors.len(), 1);
    let block = &timeline.anchors[0];
    assert_eq!(block.admission, Admission::Finding);
    assert_eq!(block.directory.as_deref(), Some("\\Users\\bob\\Desktop"));
    let names: Vec<&str> = block.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["payload.zip", "payload.exe"], "earliest arrival first");

    assert_eq!(block.files[0].role, Role::NotACandidate);
    assert!(
        (block.files[1].gap_seconds.expect("a gap") - 30.0).abs() < 0.001,
        "{:?}",
        block.files[1].gap_seconds
    );
    assert!((block.files[0].offset_seconds + 30.0).abs() < 0.001);
    assert_eq!(timeline.files_named, 2);
}

#[test]
fn a_records_previous_tenant_does_not_lend_its_history_to_the_anchor() {
    const THEN: u16 = 4;
    const NOW: u16 = 5;

    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let cache = builder.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Chrome");
    let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);
    builder.set_sequence(exe, NOW);

    let journal = usn_journal_stream(&[
        usn_record(exe, THEN, cache, 1, 0, journal_filetime(1_029), FILE_CREATE, "chrome.LOG"),
        usn_record(exe, THEN, cache, 1, 0, journal_filetime(1_029), CLOSE, "chrome.LOG"),
        usn_record(exe, NOW, desktop, 1, 0, journal_filetime(1_030), FILE_CREATE, "payload.exe"),
    ]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
    let timeline = arrival::read(&volume, &anchors, &context()).expect("a block");
    let block = &timeline.anchors[0];

    let names: Vec<&str> = block.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["payload.exe"], "the previous tenant is not this file's history");
    assert_eq!(block.sequence, Some(NOW));
    assert_eq!(block.files[0].rows, 1, "one row survived the sequence check, not three");
    assert_eq!(timeline.rows_admitted, 1);
    assert_eq!(block.directory.as_deref(), Some("\\Users\\bob\\Desktop"));
}

#[test]
fn a_previous_tenant_that_did_arrive_beside_the_anchor_is_a_neighbour_and_not_its_history() {
    const THEN: u16 = 4;
    const NOW: u16 = 5;

    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);
    builder.set_sequence(exe, NOW);

    let journal = usn_journal_stream(&[
        usn_record(exe, THEN, desktop, 1, 0, journal_filetime(1_029), FILE_CREATE, "scratch.tmp"),
        usn_record(exe, NOW, desktop, 1, 0, journal_filetime(1_030), FILE_CREATE, "payload.exe"),
    ]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
    let timeline = arrival::read(&volume, &anchors, &context()).expect("a block");
    let block = &timeline.anchors[0];

    assert_eq!(block.files.len(), 2, "{:?}", block.files);
    assert_eq!(block.files[0].name, "scratch.tmp");
    assert_eq!(block.files[0].sequence, THEN, "listed as the tenancy it was");
    assert_eq!(block.files[0].role, Role::NotACandidate, "and accused of nothing");
    assert_eq!(block.files[1].name, "payload.exe");
    assert_eq!(block.files[1].sequence, NOW);
    assert_eq!(block.files[1].rows, 1, "the anchor's life holds only the anchor's rows");
}

#[test]
fn a_file_that_arrived_in_another_directory_is_not_beside_the_anchor() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let downloads = builder.directories(ROOT_RECORD, "Users\\bob\\Downloads");
    let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);
    let other = builder.file(downloads, "installer.tmp", b"junk", Presence::Live);

    let journal = usn_journal_stream(&[
        usn_record(exe, 1, desktop, 1, 0, journal_filetime(1_030), FILE_CREATE, "payload.exe"),
        usn_record(
            other,
            1,
            downloads,
            1,
            0,
            journal_filetime(1_031),
            FILE_CREATE,
            "installer.tmp",
        ),
    ]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
    let timeline = arrival::read(&volume, &anchors, &context()).expect("a block");
    let names: Vec<&str> = timeline.anchors[0].files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["payload.exe"]);
}

#[test]
fn the_radius_admits_fifty_nine_seconds_and_refuses_sixty_one() {
    for (offset, expected) in [(59i64, 2usize), (61, 1)] {
        let mut builder = Builder::new();
        windows(&mut builder);
        let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
        let neighbour = builder.file(desktop, "earlier.dat", b"data", Presence::Live);
        let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);

        let journal = usn_journal_stream(&[
            usn_record(
                neighbour,
                1,
                desktop,
                1,
                0,
                journal_filetime(1_030 - offset),
                FILE_CREATE,
                "earlier.dat",
            ),
            usn_record(exe, 1, desktop, 1, 0, journal_filetime(1_030), FILE_CREATE, "payload.exe"),
        ]);
        builder.usn_journal(Some(&max_stream()), &journal);

        let volume = builder.open();
        let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
        let timeline = arrival::read(&volume, &anchors, &context()).expect("a block");
        assert_eq!(
            timeline.anchors[0].files.len(),
            expected,
            "at {offset} s the neighbour should {}be listed",
            if expected == 2 { "" } else { "NOT " }
        );
    }
}

#[test]
fn a_file_renamed_in_the_directory_did_not_arrive_in_it() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let victim = builder.file(desktop, "notes.txt.locked", b"encrypted", Presence::Live);
    let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);

    let journal = usn_journal_stream(&[
        usn_record(exe, 1, desktop, 1, 0, journal_filetime(1_030), FILE_CREATE, "payload.exe"),
        usn_record(
            victim,
            1,
            desktop,
            1,
            0,
            journal_filetime(1_040),
            RENAME_NEW_NAME,
            "notes.txt.locked",
        ),
    ]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
    let timeline = arrival::read(&volume, &anchors, &context()).expect("a block");
    let names: Vec<&str> = timeline.anchors[0].files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["payload.exe"], "a renamed file did not arrive");
}

#[test]
fn a_below_threshold_candidate_anchors_only_inside_the_incident_window() {
    let build = || {
        let mut builder = Builder::new();
        windows(&mut builder);
        let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
        let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);
        let journal = usn_journal_stream(&[usn_record(
            exe,
            1,
            desktop,
            1,
            0,
            journal_filetime(1_030),
            FILE_CREATE,
            "payload.exe",
        )]);
        builder.usn_journal(Some(&max_stream()), &journal);
        (builder.open(), exe)
    };

    let moment = |seconds: i64| {
        mm_core::from_filetime(journal_filetime(seconds) as u64).expect("a valid moment")
    };
    let candidates = HashMap::new();

    let (volume, exe) = build();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.34, false)];
    assert!(
        arrival::read(
            &volume,
            &anchors,
            &Context { candidates: &candidates, threshold: 0.5, window: None }
        )
        .is_none(),
        "a low score with no window may not anchor"
    );

    let (volume, exe) = build();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.34, false)];
    assert!(
        arrival::read(
            &volume,
            &anchors,
            &Context {
                candidates: &candidates,
                threshold: 0.5,
                window: Some((moment(2_000), moment(3_000))),
            }
        )
        .is_none(),
        "a window that does not contain the arrival may not admit it"
    );

    let (volume, exe) = build();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.34, false)];
    let timeline = arrival::read(
        &volume,
        &anchors,
        &Context {
            candidates: &candidates,
            threshold: 0.5,
            window: Some((moment(1_000), moment(1_100))),
        },
    )
    .expect("a block");
    assert_eq!(timeline.anchors[0].admission, Admission::InIncidentWindow);
    assert!(timeline.anchors[0].probability < 0.5, "and it is still below the threshold");
}

#[test]
fn the_two_flags_that_are_not_distinctions_produce_no_event() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);

    let journal = usn_journal_stream(&[
        usn_record(exe, 1, desktop, 1, 0, journal_filetime(1_030), FILE_CREATE, "payload.exe"),
        usn_record(
            exe,
            1,
            desktop,
            1,
            0,
            journal_filetime(1_031),
            BASIC_INFO_CHANGE | SECURITY_CHANGE,
            "payload.exe",
        ),
    ]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
    let timeline = arrival::read(&volume, &anchors, &context()).expect("a block");
    let file = &timeline.anchors[0].files[0];

    assert_eq!(file.rows, 2, "both rows were folded in");
    assert_eq!(file.events.len(), 1, "{:?}", file.events);
    assert!(matches!(file.events[0], mm_core::Event::Appeared { .. }), "{:?}", file.events);

    let text = format!("{:?}", timeline);
    assert!(!text.contains("BASIC_INFO"), "{text}");
    assert!(!text.contains("SECURITY_CHANGE"), "{text}");
}

#[test]
fn a_finding_the_journal_does_not_reach_is_unknown_rather_than_silent() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);
    let other = builder.file(desktop, "unrelated.dat", b"data", Presence::Live);

    let journal = usn_journal_stream(&[usn_record(
        other,
        1,
        desktop,
        1,
        0,
        journal_filetime(1_030),
        FILE_CREATE,
        "unrelated.dat",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
    let timeline = arrival::read(&volume, &anchors, &context()).expect("a block, saying nothing");

    assert_eq!(timeline.anchors.len(), 1, "a finding always gets its block");
    assert!(timeline.anchors[0].files.is_empty(), "{:?}", timeline.anchors[0].files);
    assert_eq!(timeline.anchors[0].sequence, None, "no row, so no sequence to report");
    assert_eq!(timeline.files_named, 0);
}

#[test]
fn nothing_to_anchor_produces_nothing_at_all() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let exe = builder.file(desktop, "ordinary.exe", b"MZ ordinary", Presence::Live);
    let journal = usn_journal_stream(&[usn_record(
        exe,
        1,
        desktop,
        1,
        0,
        journal_filetime(1_030),
        FILE_CREATE,
        "ordinary.exe",
    )]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    assert!(arrival::read(&volume, &[], &context()).is_none());
}

#[test]
fn a_neighbour_the_run_scored_carries_its_own_score_and_its_own_side_of_the_bar() {
    let mut builder = Builder::new();
    windows(&mut builder);
    let desktop = builder.directories(ROOT_RECORD, "Users\\bob\\Desktop");
    let neighbour = builder.file(desktop, "helper.exe", b"MZ helper", Presence::Live);
    let exe = builder.file(desktop, "payload.exe", b"MZ payload", Presence::Live);

    let journal = usn_journal_stream(&[
        usn_record(neighbour, 1, desktop, 1, 0, journal_filetime(1_020), FILE_CREATE, "helper.exe"),
        usn_record(exe, 1, desktop, 1, 0, journal_filetime(1_030), FILE_CREATE, "payload.exe"),
    ]);
    builder.usn_journal(Some(&max_stream()), &journal);

    let volume = builder.open();
    let mut candidates = HashMap::new();
    candidates.insert("\\users\\bob\\desktop\\helper.exe".to_string(), (CandidateId(42), 0.19_f64));
    let anchors = [anchor(exe, "\\Users\\bob\\Desktop\\payload.exe", 0.9, true)];
    let timeline = arrival::read(
        &volume,
        &anchors,
        &Context { candidates: &candidates, threshold: 0.5, window: None },
    )
    .expect("a block");

    match &timeline.anchors[0].files[0].role {
        Role::Candidate { id, probability, below_threshold } => {
            assert_eq!(*id, CandidateId(42));
            assert!((*probability - 0.19).abs() < 1e-9);
            assert!(*below_threshold, "0.19 is below 0.50 and the report must say so");
        }
        other => panic!("the neighbour should be named as the candidate it is, got {other:?}"),
    }
}
