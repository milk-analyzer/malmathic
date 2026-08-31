#![cfg(test)]

use std::io::Cursor;

use mm_env::Environment;
use mm_harvest::testhive::{utf16, Builder as Hive, REG_SZ_T, ROOT_FLAG};
use mm_raw::Volume;
use mm_report::{Report, Target};

use crate::pipeline::{self, Options, MAX_UNRANKED_ACQUISITIONS};
use crate::testimage::{Builder as Image, Presence, ROOT_RECORD};

const SAMPLE_PATH: &str = "C:\\Windows\\Temp\\server.exe";
const SAMPLE_NAME: &str = "server.exe";

const RUN_VALUE: &str = "652fab3ea15bd655a912b0600fe39a37";

const RAN: u64 = (1_785_197_385 + 11_644_473_600) * 10_000_000;

const NIL_LIST: u32 = u32::MAX;

const INSTALLERS: [(&str, &str, &str); 3] = [
    (
        "Windows\\Temp\\{54106D84-F4CC-40B5-9660-909117B8066E}\\.be",
        "VC_redist.x64.exe",
        "C:\\Windows\\Temp\\{54106D84-F4CC-40B5-9660-909117B8066E}\\.be\\VC_redist.x64.exe",
    ),
    (
        "Windows\\Temp\\69B4930B-E838-49BC-8624-11A2CA3DF8D5",
        "MpRecovery.exe",
        "C:\\Windows\\Temp\\69B4930B-E838-49BC-8624-11A2CA3DF8D5\\MpRecovery.exe",
    ),
    (
        "Windows\\SystemTemp\\GoogleUpdater_chrome_Unpacker_1",
        "UpdaterSetup.exe",
        "C:\\Windows\\SystemTemp\\GoogleUpdater_chrome_Unpacker_1\\UpdaterSetup.exe",
    ),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Infected,
    Cleaned,
}

fn system_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);
    let cache = b.path(root, &["ControlSet001", "Control", "Session Manager", "AppCompatCache"]);
    let mut entries = vec![(SAMPLE_PATH, RAN)];
    for (_, _, recorded) in INSTALLERS {
        entries.push((recorded, RAN - 10_000_000));
    }
    let blob = win10_cache(&entries);
    let v = b.value("AppCompatCache", 3, &blob, true);
    let list = b.value_list(&[v], true);
    b.set_values(cache, list, 1);
    b.finish(root)
}

fn win10_cache(entries: &[(&str, u64)]) -> Vec<u8> {
    const HEADER: usize = 0x34;
    let mut blob = vec![0u8; HEADER];
    blob[..4].copy_from_slice(&(HEADER as u32).to_le_bytes());
    blob[0x28..0x2c].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (path, ts) in entries {
        let path_bytes: Vec<u8> = path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut body = Vec::new();
        body.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        body.extend_from_slice(&path_bytes);
        body.extend_from_slice(&ts.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(b"10ts");
        blob.extend_from_slice(&0xdead_beefu32.to_le_bytes());
        blob.extend_from_slice(&(body.len() as u32).to_le_bytes());
        blob.extend_from_slice(&body);
    }
    blob
}

fn software_hive(state: State) -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);
    let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
    let command = format!("\"{SAMPLE_PATH}\" ..");
    match state {
        State::Infected => {
            let v = b.value(RUN_VALUE, REG_SZ_T, &utf16(&command), true);
            let list = b.value_list(&[v], true);
            b.set_values(run, list, 1);
        }
        State::Cleaned => {
            let v = b.value(RUN_VALUE, REG_SZ_T, &utf16(&command), false);
            let _ = b.value_list(&[v], false);
            b.set_values(run, NIL_LIST, 0);
        }
    }
    b.finish(root)
}

fn sample_bytes() -> Vec<u8> {
    let mut bytes = b"MZ\x90\x00".to_vec();
    bytes.extend(std::iter::repeat_n(0x4Eu8, 24_060));
    bytes
}

fn triage(state: State) -> (Report, std::path::PathBuf) {
    let mut image = Image::new();

    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");
    image.file(config, "SOFTWARE", &software_hive(state), Presence::Live);
    image.file(config, "SYSTEM", &system_hive(), Presence::Live);

    let temp = image.directories(ROOT_RECORD, "Windows\\Temp");
    match state {
        State::Infected => {
            image.file(temp, SAMPLE_NAME, &sample_bytes(), Presence::Live);
        }
        State::Cleaned => {
            image.file(
                temp,
                SAMPLE_NAME,
                &sample_bytes(),
                Presence::RecordReallocatedTo("MpSigStub.tmp"),
            );
        }
    }

    for (dir, name, _) in INSTALLERS {
        let d = image.directories(ROOT_RECORD, dir);
        image.file(d, name, b"MZ an ordinary installer", Presence::Deleted);
    }

    let vendor = image.directories(ROOT_RECORD, "Program Files\\Vendor");
    image.file(vendor, "update.exe", b"MZ ordinary updater", Presence::Live);
    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    for name in ["notepad.exe", "kernel32.dll", "svchost.exe"] {
        image.file(system32, name, b"MZ ordinary system file", Presence::Live);
    }

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-cleanup-{}-{}",
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
        acquire_top: 10,
        write_samples: true,
        deep: false,
        verify_top: 10,
        progress: crate::progress::Style::Silent,
    };
    let report = pipeline::run(&volume, Environment::Recovery, target, &options);
    (report, out)
}

fn sample_of(report: &Report) -> &mm_core::Candidate {
    report
        .candidates
        .iter()
        .find(|c| c.path.as_ref().is_some_and(|p| p.key() == "\\windows\\temp\\server.exe"))
        .expect("the sample is a candidate in both states")
}

fn rows(c: &mm_core::Candidate) -> Vec<String> {
    c.evidence.iter().map(|e| e.feature.to_string()).collect()
}

fn evidence(c: &mm_core::Candidate) -> f64 {
    c.evidence.iter().map(|e| e.log_lr).sum()
}

#[test]
fn before_the_cleanup_the_sample_is_a_finding() {
    let (report, _out) = triage(State::Infected);
    let sample = sample_of(&report);
    assert!(
        sample.probability() >= 0.5,
        "the intact case regressed: {:.4} on {:?}",
        sample.probability(),
        rows(sample)
    );
    assert!(rows(sample).iter().any(|r| r == "persistence_run_key"));
}

#[test]
fn after_the_cleanup_the_sample_is_a_lead_and_not_an_installer() {
    let (report, _out) = triage(State::Cleaned);
    let sample = sample_of(&report);
    let r = rows(sample);

    assert!(
        r.iter().any(|x| x == "executed_but_now_absent"),
        "the temp ROOT does not get the installer discount: {r:?}"
    );
    assert!(!r.iter().any(|x| x == "executed_but_now_absent_from_scratch_space"), "{r:?}");
    assert!(r.iter().any(|x| x == "executable_in_windows_temp"), "{r:?}");

    let installer = report
        .candidates
        .iter()
        .find(|c| c.path.as_ref().is_some_and(|p| p.key().contains("vc_redist")))
        .expect("the benign scratch population is on this volume");
    assert!(
        rows(installer).iter().any(|x| x == "executed_but_now_absent_from_scratch_space"),
        "the installer lost the discount it was measured to keep: {:?}",
        rows(installer)
    );
    let gap = evidence(sample) - evidence(installer);
    assert!(
        (gap - 2.0).abs() < 1e-9,
        "the sample should stand exactly the general row's premium clear of an \
         installer: sample {:.3} {:?}, installer {:.3} {:?}",
        evidence(sample),
        r,
        evidence(installer),
        rows(installer)
    );
}

#[test]
fn the_installers_in_their_own_scratch_directories_are_untouched() {
    let mut seen = 0usize;
    for state in [State::Infected, State::Cleaned] {
        let (report, _out) = triage(state);
        for c in &report.candidates {
            let Some(path) = c.path.as_ref() else { continue };
            let key = path.key();
            if key == "\\windows\\temp\\server.exe" {
                continue;
            }
            if !key.contains("\\temp\\") && !key.contains("systemtemp") {
                continue;
            }
            seen += 1;
            let r = rows(c);
            if r.iter().any(|x| x.starts_with("executed_but_now_absent")) {
                assert!(
                    r.iter().any(|x| x == "executed_but_now_absent_from_scratch_space"),
                    "{key} lost the discount it was measured to keep: {r:?}"
                );
            }
            assert!(
                !r.iter().any(|x| x == "executed_but_now_absent"),
                "{key} took the undiscounted row: {r:?}"
            );
        }
    }
    assert!(seen >= 6, "the fixture stopped producing the benign population: {seen}");
}

#[test]
fn the_report_states_the_failed_recovery_rather_than_going_quiet() {
    let (report, out) = triage(State::Cleaned);
    let sample = sample_of(&report);

    match &sample.acquisition {
        mm_core::Acquisition::NotAttempted => panic!(
            "the file is unrecoverable and the report does not say so — \
             this is the silence the unranked pass exists to break"
        ),
        mm_core::Acquisition::Failed { reason } => {
            assert!(!reason.is_empty(), "a failure with no reason is a silence");
        }
        other => panic!("nothing here can produce bytes: {other:?}"),
    }

    assert!(!out.join("sample").join(format!("{}.bin", sample.id)).exists());

    let text = mm_report::text::render(&report);
    assert!(text.contains("server.exe"), "the sample is not in the report at all");
}

#[test]
fn a_finding_names_the_mft_record_it_was_read_from() {
    let (report, _out) = triage(State::Infected);
    let text = mm_report::text::render(&report);
    assert!(
        text.contains("record   $MFT") && text.contains(", in use"),
        "no record line in:\n{text}"
    );
}

#[test]
fn the_run_value_defender_removed_is_recovered_and_priced_at_nothing() {
    let (report, _out) = triage(State::Cleaned);
    let sample = sample_of(&report);

    let recovered: Vec<&str> = sample
        .observations
        .iter()
        .filter_map(|o| match &o.kind {
            mm_core::ObservationKind::DeletedRegistryValue { value_name, .. } => {
                Some(value_name.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(recovered, vec![RUN_VALUE], "the removed Run value is the whole point of this test");

    assert!(
        !sample
            .observations
            .iter()
            .any(|o| matches!(o.kind, mm_core::ObservationKind::Persistence { .. })),
        "the key is gone and this claims to know it"
    );
    let r = rows(sample);
    assert!(
        !r.iter().any(|x| x.starts_with("persistence")),
        "a recovered value must pay no persistence row: {r:?}"
    );

    let text = mm_report::text::render(&report);
    assert!(text.contains("a registry value naming this file has been REMOVED"), "{text}");
    assert!(text.contains("this scores nothing"), "{text}");
    assert!(text.contains(RUN_VALUE), "the value name is what an analyst pivots on:\n{text}");
}

#[test]
fn a_live_run_value_is_still_persistence_and_not_a_recovered_fragment() {
    let (report, _out) = triage(State::Infected);
    let sample = sample_of(&report);
    assert!(
        sample
            .observations
            .iter()
            .any(|o| matches!(o.kind, mm_core::ObservationKind::Persistence { .. })),
        "the live Run key stopped being read"
    );
    assert!(
        !sample
            .observations
            .iter()
            .any(|o| matches!(o.kind, mm_core::ObservationKind::DeletedRegistryValue { .. })),
        "a live value must not also arrive as wreckage"
    );
}

const FANOUT: usize = 6;

fn bulk_volume() -> (Report, std::path::PathBuf) {
    let mut image = Image::with_records(1024);
    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");
    image.file(config, "SOFTWARE", &software_hive(State::Cleaned), Presence::Live);

    let programs = image.directories(ROOT_RECORD, "opt");
    for d in 0..FANOUT {
        let outer = image.directory(programs, &format!("d{d}"));
        for e in 0..FANOUT {
            let inner = image.directory(outer, &format!("e{e}"));
            for f in 0..FANOUT {
                image.file(
                    inner,
                    &format!("f{f}.exe"),
                    format!("MZ {d}{e}{f}").as_bytes(),
                    Presence::Deleted,
                );
            }
        }
    }

    let volume: Volume<Cursor<Vec<u8>>> = image.open();
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-bulk-{}-{}",
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
        acquire_top: 10,
        write_samples: true,
        deep: false,
        verify_top: 10,
        progress: crate::progress::Style::Silent,
    };
    let report = pipeline::run(&volume, Environment::Recovery, target, &options);
    (report, out)
}

#[test]
fn bytes_are_taken_from_candidates_the_score_declined() {
    let (report, out) = bulk_volume();

    assert!(
        report.candidates.iter().all(|c| c.probability() < 0.5),
        "the fixture stopped being a volume the score says no to"
    );
    assert!(
        report.candidates.len() >= FANOUT * FANOUT * FANOUT,
        "only {} candidates: the prior is not small enough to test anything",
        report.candidates.len()
    );

    let ranked = out.join("sample");
    let unranked = ranked.join("unranked");
    assert!(unranked.is_dir(), "no unranked directory was created");

    let count = |d: &std::path::Path| {
        std::fs::read_dir(d)
            .map(|it| it.filter_map(Result::ok).filter(|e| e.path().is_file()).count())
            .unwrap_or(0)
    };
    assert_eq!(
        count(&unranked),
        MAX_UNRANKED_ACQUISITIONS,
        "the cap is what bounds an attacker who knows the rule"
    );
    assert_eq!(count(&ranked), 0, "bytes landed where they imply a verdict");

    let acquired: Vec<&mm_core::Candidate> = report
        .candidates
        .iter()
        .filter(|c| match &c.acquisition {
            mm_core::Acquisition::Bytes { saved_as, .. } => saved_as.contains("unranked"),
            _ => false,
        })
        .collect();
    assert_eq!(acquired.len(), MAX_UNRANKED_ACQUISITIONS);
    assert!(
        report.coverage.warnings.iter().any(|w| w.contains("matched a recovery rule and were NOT")),
        "a run that hit the cap has to say the rest are recoverable and it does \
         not hold them: {:?}",
        report.coverage.warnings
    );
}

#[test]
fn a_volume_with_nothing_to_recover_grows_no_unranked_directory() {
    let (_report, out) = triage(State::Infected);
    assert!(
        !out.join("sample").join("unranked").exists(),
        "an empty directory is a claim nobody made"
    );
}

#[test]
fn a_near_miss_carries_its_record_number() {
    let (report, _out) = bulk_volume();
    assert!(
        report.candidates.iter().all(|c| c.probability() < 0.5),
        "this fixture has to be all near-misses"
    );
    let text = mm_report::text::render(&report);
    assert!(
        text.contains("$MFT record ") && text.contains("FREE"),
        "the near-miss list dropped the record number:\n{text}"
    );
    assert!(text.contains("diag mft --record"), "and it has to say what to do with it:\n{text}");
}

#[test]
fn a_recovered_value_naming_an_unknown_path_creates_no_candidate() {
    let mut image = Image::new();
    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");

    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);
    let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
    let v =
        b.value("Ghost", REG_SZ_T, &utf16("C:\\Users\\nobody\\AppData\\Roaming\\ghost.exe"), false);
    let _ = b.value_list(&[v], false);
    b.set_values(run, NIL_LIST, 0);
    image.file(config, "SOFTWARE", &b.finish(root), Presence::Live);

    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    image.file(system32, "notepad.exe", b"MZ ordinary system file", Presence::Live);

    let volume: Volume<Cursor<Vec<u8>>> = image.open();
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-ghost-{}-{}",
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
        output_dir: out,
        acquire_top: 10,
        write_samples: true,
        deep: false,
        verify_top: 10,
        progress: crate::progress::Style::Silent,
    };
    let report = pipeline::run(&volume, Environment::Recovery, target, &options);

    assert!(
        !report
            .candidates
            .iter()
            .any(|c| c.path.as_ref().is_some_and(|p| p.key().contains("ghost.exe"))),
        "a deleted registry value introduced a candidate: {:?}",
        report
            .candidates
            .iter()
            .filter_map(|c| c.path.as_ref().map(|p| p.key().to_string()))
            .collect::<Vec<_>>()
    );
    assert!(
        report.coverage.warnings.iter().any(|w| w.contains("name a path nothing else on this")),
        "the unmatched recovery is not reported: {:?}",
        report.coverage.warnings
    );
}
