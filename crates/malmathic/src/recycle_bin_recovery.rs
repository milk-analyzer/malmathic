#![cfg(test)]

use std::io::Cursor;

use mm_core::{Acquisition, ArtifactSource, Candidate, Recovery};
use mm_env::Environment;
use mm_harvest::testhive::{utf16, Builder as Hive, REG_SZ_T, ROOT_FLAG};
use mm_raw::Volume;
use mm_report::{Report, Target};

use crate::pipeline::{self, Options};
use crate::testimage::{Builder as Image, Presence, ROOT_RECORD};

const ORIGINAL: &str = "C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svchost.exe";
const ORIGINAL_KEY: &str = "\\users\\bob\\appdata\\roaming\\vendor\\svchost.exe";
const SUFFIX: &str = "K9C8D3.exe";
const BIN: &str = "$Recycle.Bin\\S-1-5-21-1";

const DOCUMENT: &str = "C:\\Users\\bob\\Documents\\quarterly.docx";
const DOCUMENT_SUFFIX: &str = "AB12CD.docx";

const PURGED: &str = "C:\\Users\\bob\\Downloads\\dropper.exe";
const PURGED_SUFFIX: &str = "ZZ99YY.exe";

const FOREIGN: &str = "W:\\TRASH\\Downloads\\svch0st.exe";
const FOREIGN_SUFFIX: &str = "WW11XX.exe";

const DELETED_AT: u64 = 0x01dc_dfe5_3458_c550;

fn payload() -> Vec<u8> {
    let mut bytes = b"MZ\x90\x00".to_vec();
    bytes.extend(std::iter::repeat_n(0x4Eu8, 8_188));
    bytes
}

fn info_stub(size: u64, path: &str) -> Vec<u8> {
    let mut units: Vec<u16> = path.encode_utf16().collect();
    units.push(0);
    let mut out = Vec::new();
    out.extend_from_slice(&2u64.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&DELETED_AT.to_le_bytes());
    out.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bin {
    Paired,
    SizeDisagrees,
    StubOnly,
    Empty,
    ForeignVolume,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Elsewhere {
    Nothing,
    RunKey,
    AlsoOnTheVolume,
}

fn software_hive(elsewhere: Elsewhere) -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);

    let cv = b.path(root, &["Microsoft", "Windows NT", "CurrentVersion"]);
    let sr = b.value("SystemRoot", REG_SZ_T, &utf16("C:\\Windows"), true);
    let list = b.value_list(&[sr], true);
    b.set_values(cv, list, 1);

    let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
    if elsewhere == Elsewhere::RunKey {
        let v = b.value("Vendor", REG_SZ_T, &utf16(ORIGINAL), true);
        let list = b.value_list(&[v], true);
        b.set_values(run, list, 1);
    }
    b.finish(root)
}

fn triage(bin: Bin, elsewhere: Elsewhere) -> (Report, std::path::PathBuf) {
    let mut image = Image::new();

    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");
    image.file(config, "SOFTWARE", &software_hive(elsewhere), Presence::Live);

    if bin != Bin::Empty {
        let dir = image.directories(ROOT_RECORD, BIN);
        image.file(dir, "desktop.ini", b"[.ShellClassInfo]\r\n", Presence::Live);

        let bytes = payload();
        let claimed = match bin {
            Bin::SizeDisagrees => 4_096,
            _ => bytes.len() as u64,
        };
        image.file(dir, &format!("$I{SUFFIX}"), &info_stub(claimed, ORIGINAL), Presence::Live);
        if bin != Bin::StubOnly {
            image.file(dir, &format!("$R{SUFFIX}"), &bytes, Presence::Live);
        }

        image.file(
            dir,
            &format!("$I{DOCUMENT_SUFFIX}"),
            &info_stub(1_024, DOCUMENT),
            Presence::Live,
        );
        image.file(dir, &format!("$R{DOCUMENT_SUFFIX}"), b"PK ordinary document", Presence::Live);

        image.file(dir, &format!("$I{PURGED_SUFFIX}"), &info_stub(2_048, PURGED), Presence::Live);

        if bin == Bin::ForeignVolume {
            let dir = image.directories(ROOT_RECORD, r"$Recycle.Bin\S-1-5-21-2");
            image.file(
                dir,
                &format!("$I{FOREIGN_SUFFIX}"),
                &info_stub(64, FOREIGN),
                Presence::Live,
            );
            image.file(
                dir,
                &format!("$R{FOREIGN_SUFFIX}"),
                b"MZ bytes claimed to be from another disk",
                Presence::Live,
            );
        }
    }

    if elsewhere == Elsewhere::AlsoOnTheVolume {
        let vendor = image.directories(ROOT_RECORD, "Users\\bob\\AppData\\Roaming\\Vendor");
        image.file(vendor, "svchost.exe", b"MZ the copy that is still here", Presence::Live);
    }

    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    for name in ["notepad.exe", "kernel32.dll", "explorer.exe", "cmd.exe", "taskhostw.exe"] {
        image.file(system32, name, b"MZ ordinary system file", Presence::Live);
    }
    let vendor = image.directories(ROOT_RECORD, "Program Files\\Vendor");
    for name in ["update.exe", "helper.exe"] {
        image.file(vendor, name, b"MZ ordinary vendor file", Presence::Live);
    }

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-recyclebin-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).expect("a case directory");

    let target = Target {
        display_name: "synthetic".into(),
        device_path: "synthetic".into(),
        volume_serial: format!("{:016x}", volume.serial()),
    };
    let options = Options {
        output_dir: out.clone(),
        acquire_top: 25,
        write_samples: true,
        deep: false,
        verify_top: 25,
        progress: crate::progress::Style::Silent,
    };
    let report = pipeline::run(&volume, Environment::Recovery, target, &options);
    (report, out)
}

fn find<'a>(report: &'a Report, key: &str) -> Option<&'a Candidate> {
    report.candidates.iter().find(|c| c.path.as_ref().is_some_and(|p| p.key() == key))
}

fn sample(report: &Report) -> &Candidate {
    find(report, ORIGINAL_KEY).expect("the recycled executable is a candidate")
}

#[test]
fn the_bytes_come_back_out_of_the_recycle_bin() {
    let (report, out) = triage(Bin::Paired, Elsewhere::RunKey);
    let c = sample(&report);
    match &c.acquisition {
        Acquisition::Bytes { via, size, saved_as, .. } => {
            assert_eq!(*via, ArtifactSource::RecycleBin, "the report must name the bin");
            assert_eq!(*size, payload().len() as u64);
            let written = out.join(saved_as.replace('/', std::path::MAIN_SEPARATOR_STR));
            let bytes = std::fs::read(&written).expect("the sample was written out");
            assert_eq!(bytes, payload(), "the sample in the case directory is the file");
        }
        other => panic!("expected bytes out of the recycle bin, got {other:?}"),
    }
    let text = mm_report::text::render(&report);
    assert!(text.contains("$Recycle.Bin"), "the report must name where the bytes came from");
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn the_recovery_states_that_the_bytes_are_whole_and_the_name_is_not() {
    let (report, out) = triage(Bin::Paired, Elsewhere::RunKey);
    let c = sample(&report);
    let Acquisition::Bytes { recovery, .. } = &c.acquisition else {
        panic!("expected bytes: {:?}", c.acquisition)
    };
    assert_ne!(*recovery, Recovery::Intact, "only a file at its own path is Intact");
    let Recovery::Unverified { basis } = recovery else {
        panic!("expected Unverified, got {recovery:?}")
    };
    assert!(basis.contains("allocated file on this volume"), "{basis}");
    assert!(basis.contains("nothing was reconstructed"), "{basis}");
    assert!(basis.contains("$I"), "the basis must name the evidence: {basis}");
    assert!(basis.contains(ORIGINAL), "the basis must state the path claimed: {basis}");
    assert!(basis.contains("2026-05-09"), "the basis must state when: {basis}");
    assert!(
        basis.contains("the deleting user could write"),
        "the basis must price the stub: {basis}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn the_original_path_joins_the_graph_on_the_stub_alone() {
    let (report, out) = triage(Bin::Paired, Elsewhere::Nothing);
    let c = sample(&report);
    let features: Vec<&str> = c.evidence.iter().map(|e| e.feature.as_str()).collect();
    assert!(
        features.contains(&"executable_in_user_appdata"),
        "the stub's path must be what the candidate is scored on: {features:?}"
    );
    assert!(matches!(c.acquisition, Acquisition::Bytes { .. }), "{:?}", c.acquisition);
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_recycled_document_does_not_become_a_candidate() {
    let (report, out) = triage(Bin::Paired, Elsewhere::Nothing);
    assert!(
        find(&report, "\\users\\bob\\documents\\quarterly.docx").is_none(),
        "a .docx in the bin became a candidate: {:?}",
        report.candidates.iter().filter_map(|c| c.path.as_ref()).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_stub_whose_bytes_are_gone_yields_the_path_and_no_sample() {
    let (report, out) = triage(Bin::StubOnly, Elsewhere::Nothing);
    let purged = find(&report, "\\users\\bob\\downloads\\dropper.exe")
        .expect("the purged file's original path is still known");
    assert!(
        !matches!(purged.acquisition, Acquisition::Bytes { .. }),
        "there are no bytes to hand over: {:?}",
        purged.acquisition
    );
    let c = sample(&report);
    assert!(!matches!(c.acquisition, Acquisition::Bytes { .. }), "{:?}", c.acquisition);
    assert!(
        report.coverage.warnings.iter().any(|w| w.contains("`$R` copy is no longer in the bin")),
        "the coverage must say the bytes were purged: {:?}",
        report.coverage.warnings
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_size_disagreement_is_reported_with_both_numbers() {
    let (report, out) = triage(Bin::SizeDisagrees, Elsewhere::RunKey);
    let c = sample(&report);
    let Acquisition::Bytes { recovery, .. } = &c.acquisition else {
        panic!("the bytes are still handed over: {:?}", c.acquisition)
    };
    let Recovery::Partial { detail } = recovery else {
        panic!("a disagreement must not be Unverified: {recovery:?}")
    };
    assert!(detail.contains("8192"), "the measurement must be stated: {detail}");
    assert!(detail.contains("4096"), "the stub's claim must be stated: {detail}");
    assert!(!recovery.is_trustworthy(), "a disagreement must not read as the sample");
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn an_empty_bin_is_absent_rather_than_silent() {
    let (report, out) = triage(Bin::Empty, Elsewhere::Nothing);
    let line = report
        .coverage
        .artifacts
        .iter()
        .find(|a| a.artifact == "recycle bin")
        .expect("the bin gets a coverage line whether or not it holds anything");
    assert!(matches!(line.status, mm_report::CoverageStatus::Absent), "{:?}", line.status);
    assert!(find(&report, ORIGINAL_KEY).is_none());
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_file_still_at_its_own_path_outranks_the_bin() {
    let (report, out) = triage(Bin::Paired, Elsewhere::AlsoOnTheVolume);
    let c = sample(&report);
    let Acquisition::Bytes { via, recovery, saved_as, .. } = &c.acquisition else {
        panic!("expected bytes: {:?}", c.acquisition)
    };
    assert_eq!(*via, ArtifactSource::Mft, "the file at its own path answers first");
    assert_eq!(*recovery, Recovery::Intact);
    let written = out.join(saved_as.replace('/', std::path::MAIN_SEPARATOR_STR));
    assert_eq!(
        std::fs::read(&written).expect("a sample"),
        b"MZ the copy that is still here",
        "the copy on the volume is what was saved, not the bin's"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_deletion_into_the_bin_never_pays_the_self_deleting_dropper_weight() {
    let (report, out) = triage(Bin::Paired, Elsewhere::RunKey);
    let c = sample(&report);
    let features: Vec<&str> = c.evidence.iter().map(|e| e.feature.as_str()).collect();
    assert!(
        !features.contains(&"deleted_soon_after_execution"),
        "a file sitting intact in the recycle bin was called a self-deleting dropper: {features:?}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn the_deletion_time_survives_on_the_observation() {
    let (report, out) = triage(Bin::Paired, Elsewhere::Nothing);
    let c = sample(&report);
    let when = c
        .observations
        .iter()
        .filter(|o| o.source == ArtifactSource::RecycleBin)
        .find_map(|o| match o.kind {
            mm_core::ObservationKind::FileDeleted { when, .. } => when,
            _ => None,
        })
        .expect("the stub's deletion time reaches the candidate");
    assert_eq!(mm_core::filetime::format(when), "2026-05-09 18:54:03Z");
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn the_observation_carries_no_mft_record() {
    let (report, out) = triage(Bin::Paired, Elsewhere::Nothing);
    let c = sample(&report);
    for o in c.observations.iter().filter(|o| o.source == ArtifactSource::RecycleBin) {
        match o.kind {
            mm_core::ObservationKind::FileDeleted { record, .. } => assert_eq!(
                record, None,
                "the $R entry's live record must not be offered to the carver"
            ),
            ref other => panic!("unexpected kind from the bin: {other:?}"),
        }
    }
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn an_ordinary_bin_produces_no_finding() {
    let (report, out) = triage(Bin::Paired, Elsewhere::Nothing);
    let findings: Vec<String> = report
        .candidates
        .iter()
        .filter(|c| c.probability() >= mm_report::DEFAULT_THRESHOLD)
        .filter_map(|c| c.path.as_ref().map(|p| p.key().to_string()))
        .collect();
    assert!(
        !findings.iter().any(|f| f.contains("quarterly")),
        "a recycled document reached the threshold: {findings:?}"
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_stub_naming_another_volume_is_neither_scored_nor_indexed() {
    let (report, out) = triage(Bin::ForeignVolume, Elsewhere::Nothing);
    assert!(
        find(&report, "\\trash\\downloads\\svch0st.exe").is_none(),
        "a path on W: became a candidate on this volume: {:?}",
        report
            .candidates
            .iter()
            .filter_map(|c| c.path.as_ref().map(|p| p.key()))
            .collect::<Vec<_>>()
    );
    assert!(
        matches!(sample(&report).acquisition, Acquisition::Bytes { .. }),
        "{:?}",
        sample(&report).acquisition
    );
    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn the_other_volume_the_stub_named_is_reported_as_a_lead() {
    let (report, out) = triage(Bin::ForeignVolume, Elsewhere::Nothing);
    let others = &report.coverage.other_volumes;
    assert_eq!(others.len(), 1, "one other volume, named once: {others:?}");
    assert_eq!(others[0].volume, "W:");
    assert_eq!(others[0].paths[0].path, FOREIGN);
    let _ = std::fs::remove_dir_all(&out);
}
