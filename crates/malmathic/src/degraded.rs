#![cfg(test)]

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use mm_env::Environment;
use mm_raw::Volume;
use mm_report::{CoverageStatus, Report, Target};

use crate::hostile_index::record_offset;
use crate::pipeline::{self, Options};
use crate::testimage::{Builder, Presence, ROOT_RECORD};

const RECORDS: u64 = 3_000;

const DELETED: usize = 240;

const FIRST_BAD: u64 = 1_400;

struct FailingDisk {
    inner: Cursor<Vec<u8>>,
    bad: std::ops::Range<u64>,
}

impl Read for FailingDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let at = self.inner.position();
        let end = at.saturating_add(buf.len() as u64);
        if at < self.bad.end && end > self.bad.start {
            return Err(io::Error::other("the device reported an unrecoverable read error"));
        }
        self.inner.read(buf)
    }
}

impl Seek for FailingDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

fn machine() -> Vec<u8> {
    let mut image = Builder::with_records(RECORDS);

    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    image.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);

    let temp = image.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Temp");
    let docs = image.directories(ROOT_RECORD, "Users\\bob\\Documents");

    let mut deleted = 0usize;
    for i in 0..(RECORDS as usize - 60) {
        if i % 9 == 0 && deleted < DELETED {
            image.file(temp, &format!("stub{deleted}.exe"), b"MZ a stub", Presence::Deleted);
            deleted += 1;
        } else {
            image.census_file(docs, &format!("doc{i}.txt"));
        }
    }
    assert_eq!(deleted, DELETED, "the fixture must carry every candidate it claims to");
    image.bytes()
}

fn triage(image: Vec<u8>, bad: Option<std::ops::Range<u64>>) -> Report {
    let target = Target {
        display_name: "synthetic".into(),
        device_path: "synthetic".into(),
        volume_serial: "0000000000000000".into(),
    };

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-degraded-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).expect("a case directory");

    let options = Options {
        output_dir: out.clone(),
        acquire_top: 0,
        write_samples: true,
        deep: false,
        verify_top: 0,
        progress: crate::progress::Style::Silent,
    };

    let report = match bad {
        None => {
            let volume = Volume::open(Cursor::new(image), "healthy").expect("the volume opens");
            pipeline::run(&volume, Environment::Recovery, target, &options)
        }
        Some(bad) => {
            let reader = FailingDisk { inner: Cursor::new(image), bad };
            let volume = Volume::open(reader, "failing").expect("the volume opens");
            pipeline::run(&volume, Environment::Recovery, target, &options)
        }
    };
    let _ = std::fs::remove_dir_all(&out);
    report
}

fn observations(report: &Report, artifact: &str) -> Option<usize> {
    report.coverage.artifacts.iter().find(|a| a.artifact == artifact).and_then(|a| match a.status {
        CoverageStatus::Read { observations } => Some(observations),
        _ => None,
    })
}

fn both() -> (Report, Report) {
    let image = machine();
    let bad = record_offset(&image, FIRST_BAD) as u64..record_offset(&image, RECORDS) as u64;
    (triage(image.clone(), None), triage(image, Some(bad)))
}

#[test]
fn the_fixture_still_produces_the_numbers_the_module_doc_quotes() {
    let (healthy, failing) = both();

    let h = healthy.enumeration.expect("a real run records what it enumerated");
    let f = failing.enumeration.expect("a real run records what it enumerated");

    assert_eq!((h.files_placed, h.files_lost), (2_941, 0), "the healthy walk");
    assert_eq!((f.files_placed, f.files_lost), (1_376, 1_600), "the failing walk");
    assert_eq!((healthy.candidates.len(), failing.candidates.len()), (240, 153));

    let hp = healthy.prior_log_odds().expect("candidates were formed");
    let fp = failing.prior_log_odds().expect("candidates were formed");
    let uncorrected = mm_core::log_odds_of_one_in(failing.candidates.len() as f64);
    assert!((hp - -5.4806).abs() < 5e-4, "healthy prior {hp:.4}");
    assert!((fp - -7.4691).abs() < 5e-4, "failing prior {fp:.4}");
    assert!((uncorrected - -5.0304).abs() < 5e-4, "old rule would say {uncorrected:.4}");
    assert!(uncorrected > hp, "the defect this fixture reproduces is gone");
}

#[test]
fn the_healthy_run_is_complete() {
    let (healthy, _) = both();

    let enumeration = healthy.enumeration.expect("a real run records what it enumerated");
    assert!(enumeration.attempted);
    assert_eq!(enumeration.files_lost, 0, "nothing on a healthy volume is lost");
    assert!(enumeration.is_complete());
    assert!(healthy.prior_established());
    assert_eq!(
        observations(&healthy, "$MFT records the device would not return"),
        None,
        "an undamaged volume reports the line as Absent, not as a count"
    );

    let prior = healthy.prior_log_odds().expect("candidates were formed");
    let n = healthy.candidates.len();
    assert!((prior - mm_core::log_odds_of_one_in(n as f64)).abs() < 1e-12);
}

#[test]
fn a_bad_sector_is_counted_as_unread_and_not_as_absent() {
    let (healthy, failing) = both();

    let unreadable = observations(&failing, "$MFT records the device would not return")
        .expect("the failing run must report the records the device refused");
    assert!(unreadable > 0, "the failing reader refused nothing");

    let enumeration = failing.enumeration.expect("a real run records what it enumerated");
    assert!(enumeration.attempted, "the walk still ran");
    assert!(enumeration.files_lost > 0, "the walk lost records and must say so");
    assert!(
        enumeration.files_placed < healthy.enumeration.unwrap().files_placed,
        "the failing run should have placed fewer files"
    );

    assert!(
        failing.coverage.warnings.iter().any(|w| w.contains("could not be read from the device")),
        "the run said nothing about the records it could not read: {:?}",
        failing.coverage.warnings
    );
}

#[test]
fn a_failing_disk_does_not_sharpen_the_base_rate() {
    let (healthy, failing) = both();

    let whole = healthy.candidates.len();
    let short = failing.candidates.len();
    assert!(short < whole, "the fixture must actually lose candidates: {whole} then {short}");

    let complete_prior = healthy.prior_log_odds().expect("candidates were formed");
    let degraded_prior = failing.prior_log_odds().expect("candidates were formed");

    let uncorrected = mm_core::log_odds_of_one_in(short as f64);
    assert!(
        uncorrected > complete_prior,
        "the fixture does not reproduce the defect: {uncorrected} vs {complete_prior}"
    );

    assert!(
        degraded_prior <= complete_prior,
        "a run that read less of the volume came out with a higher base rate: \
         {degraded_prior} against {complete_prior}"
    );
}

#[test]
fn no_candidate_scores_higher_on_the_failing_run() {
    let (healthy, failing) = both();

    let strongest =
        |report: &Report| report.candidates.iter().map(|c| c.probability()).fold(0.0f64, f64::max);
    assert!(
        strongest(&failing) <= strongest(&healthy) + 1e-9,
        "the failing run's strongest candidate scored {} against {}",
        strongest(&failing),
        strongest(&healthy)
    );

    assert_eq!(healthy.reportable_count(), 0);
    assert_eq!(failing.reportable_count(), 0);
}
