#![cfg(test)]

use std::io::Cursor;

use mm_env::Environment;
use mm_harvest::testhive::{utf16, Builder as Hive, REG_BINARY_T, REG_SZ_T, ROOT_FLAG};
use mm_raw::Volume;
use mm_report::Report;

use crate::pipeline::{self, Options};
use crate::testimage::{Builder as Image, Presence, ROOT_RECORD};
use mm_report::Target;

const FOREIGN: &str = "W:\\TRASH\\Downloads\\svch0st.exe";
const LOCAL: &str = "C:\\Users\\bob\\AppData\\Roaming\\updater.exe";

const TOKEN_FOREIGN: &str = "\\VOLUME{0000000000000000-6d5c4b3a}\\SETUP.EXE";
const TOKEN_SAME: &str =
    "\\VOLUME{01dc0f1122334455-e5f60718}\\Users\\bob\\AppData\\Roaming\\updater.exe";
const TOKEN_GUID: &str = "\\\\?\\Volume{0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fa}\\guidprobe.exe";

fn software_hive(state_letter: bool, tokens: bool) -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);

    if state_letter {
        let cv = b.path(root, &["Microsoft", "Windows NT", "CurrentVersion"]);
        let vk = b.value("SystemRoot", REG_SZ_T, &utf16("C:\\Windows"), true);
        let list = b.value_list(&[vk], true);
        b.set_values(cv, list, 1);
    }

    let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
    let mut values = vec![
        b.value("Helper", REG_SZ_T, &utf16(FOREIGN), true),
        b.value("Updater", REG_SZ_T, &utf16(LOCAL), true),
    ];
    if tokens {
        values.push(b.value("Setup", REG_SZ_T, &utf16(TOKEN_FOREIGN), true));
        values.push(b.value("UpdaterByToken", REG_SZ_T, &utf16(TOKEN_SAME), true));
        values.push(b.value("GuidProbe", REG_SZ_T, &utf16(TOKEN_GUID), true));
    }
    let count = values.len() as u32;
    let list = b.value_list(&values, true);
    b.set_values(run, list, count);

    b.finish(root)
}

fn system_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);
    let mounted = b.child(root, "MountedDevices");

    let mut blob = b"DMIO:ID:".to_vec();
    blob.extend_from_slice(&[
        0x0f, 0x9e, 0x8d, 0x7c, 0x2b, 0x1a, 0x3d, 0x4c, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8, 0xe9,
        0xfa,
    ]);
    let w = b.value("\\DosDevices\\W:", REG_BINARY_T, &blob, true);
    let list = b.value_list(&[w], true);
    b.set_values(mounted, list, 1);

    b.finish(root)
}

fn triage(state_letter: bool) -> Report {
    triage_from(state_letter, false)
}

fn triage_with_tokens() -> Report {
    triage_from(true, true)
}

fn triage_from(state_letter: bool, tokens: bool) -> Report {
    let mut image = Image::new();

    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");
    image.file(config, "SOFTWARE", &software_hive(state_letter, tokens), Presence::Live);
    image.file(config, "SYSTEM", &system_hive(), Presence::Live);

    let roaming = image.directories(ROOT_RECORD, "Users\\bob\\AppData\\Roaming");
    image.file(roaming, "updater.exe", b"MZ an ordinary updater", Presence::Live);

    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    for name in ["notepad.exe", "kernel32.dll", "svchost.exe"] {
        image.file(system32, name, b"MZ ordinary system file", Presence::Live);
    }

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-othervolume-{}-{}",
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
    let _ = std::fs::remove_dir_all(&out);
    report
}

fn keys(report: &Report) -> Vec<String> {
    report.candidates.iter().filter_map(|c| c.path.as_ref().map(|p| p.key().to_string())).collect()
}

#[test]
fn a_path_on_another_volume_does_not_become_a_candidate_here() {
    let report = triage(true);
    assert!(
        !keys(&report).iter().any(|k| k.contains("svch0st")),
        "the file on W: was made a candidate on this volume: {:?}",
        keys(&report)
    );
}

#[test]
fn the_other_volume_is_named_as_a_lead() {
    let report = triage(true);
    let others = &report.coverage.other_volumes;
    assert_eq!(others.len(), 1, "one other volume, named once: {others:?}");
    assert_eq!(others[0].volume, "W:");
    assert_eq!(others[0].observations, 1);
    assert_eq!(others[0].paths[0].path, FOREIGN);
    assert!(
        others[0].paths[0].claim.contains("wired to run again"),
        "the report should say what the artifact claimed: {:?}",
        others[0].paths[0]
    );
}

#[test]
fn the_report_says_what_that_volume_was() {
    let report = triage(true);
    let identity =
        report.coverage.other_volumes[0].identified_as.clone().expect("MountedDevices recorded W:");
    assert_eq!(identity, "volume ID {7c8d9e0f-1a2b-4c3d-8394-a5b6c7d8e9fa}");
}

#[test]
fn a_volume_that_was_not_examined_is_not_a_clean_bill_of_health() {
    let report = triage(true);
    assert!(!report.coverage.looked_everywhere());

    let text = mm_report::text::render(&report);
    assert!(text.contains("RECORDED ON A VOLUME THIS RUN DID NOT EXAMINE"), "{text}");
    assert!(!text.contains("This is a real result rather than a failure"), "{text}");
}

#[test]
fn a_path_on_this_volume_still_joins() {
    let report = triage(true);
    let updater = report
        .candidates
        .iter()
        .find(|c| c.path.as_ref().is_some_and(|p| p.key().ends_with("updater.exe")))
        .expect("the local Run target is still a candidate");

    assert!(
        updater
            .observations
            .iter()
            .any(|o| matches!(o.kind, mm_core::ObservationKind::FileExists { .. })),
        "and it still joined to the file on disk: {:?}",
        updater.observations
    );
}

#[test]
fn without_an_established_letter_nothing_is_withheld() {
    let report = triage(false);
    assert!(
        report.coverage.other_volumes.is_empty(),
        "nothing may be called foreign when nothing was established: {:?}",
        report.coverage.other_volumes
    );
    assert!(
        keys(&report).iter().any(|k| k.contains("svch0st")),
        "and the path is handled exactly as it was before: {:?}",
        keys(&report)
    );
}

#[test]
fn the_letter_the_recovery_environment_assigned_is_irrelevant() {
    let report = triage(true);
    assert!(
        keys(&report).iter().any(|k| k.ends_with("updater.exe")),
        "the C: paths are this volume's own: {:?}",
        keys(&report)
    );
}

#[test]
fn a_volume_token_with_a_foreign_serial_does_not_become_a_candidate_here() {
    let report = triage_with_tokens();
    assert!(
        !keys(&report).iter().any(|k| k.contains("setup.exe")),
        "the file on the other volume was made a candidate here: {:?}",
        keys(&report)
    );

    let other = report
        .coverage
        .other_volumes
        .iter()
        .find(|o| o.volume.contains("6d5c4b3a"))
        .expect("the volume it was really on is named");
    assert_eq!(other.volume, "volume serial 6d5c4b3a");
    assert_eq!(other.observations, 1);
    assert_eq!(other.paths[0].path, TOKEN_FOREIGN);
}

#[test]
fn a_volume_token_with_this_volumes_serial_still_joins() {
    let report = triage_with_tokens();
    let updater = report
        .candidates
        .iter()
        .find(|c| c.path.as_ref().is_some_and(|p| p.key().ends_with("updater.exe")))
        .expect("the token path joined to the local file");
    assert!(
        updater
            .observations
            .iter()
            .any(|o| matches!(o.kind, mm_core::ObservationKind::FileExists { .. })),
        "and it reached the $MFT record: {:?}",
        updater.observations
    );
    assert!(
        !report.coverage.other_volumes.iter().any(|o| o.volume.contains("e5f60718")),
        "this volume's own serial must never be listed as another volume: {:?}",
        report.coverage.other_volumes
    );
}

#[test]
fn a_guid_token_carries_no_serial_and_is_not_withheld() {
    let report = triage_with_tokens();
    assert!(
        keys(&report).iter().any(|k| k.contains("guidprobe")),
        "a GUID token names no serial, so nothing about it was established: {:?}",
        keys(&report)
    );
    assert!(
        !report.coverage.other_volumes.iter().any(|o| o.volume.contains("0b1c2d3e")),
        "and it is not claimed to be somewhere else either: {:?}",
        report.coverage.other_volumes
    );
}

#[test]
fn both_spellings_of_a_foreign_volume_are_listed() {
    let report = triage_with_tokens();
    let named: Vec<&str> =
        report.coverage.other_volumes.iter().map(|o| o.volume.as_str()).collect();
    assert_eq!(named, ["W:", "volume serial 6d5c4b3a"], "{named:?}");

    let text = mm_report::text::render(&report);
    assert!(text.contains("RECORDED ON A VOLUME THIS RUN DID NOT EXAMINE"), "{text}");
    assert!(text.contains("volume serial 6d5c4b3a"), "{text}");
}

#[test]
#[ignore = "prints the report; run with --ignored to read it"]
fn print_the_report() {
    println!("{}", mm_report::text::render(&triage(true)));
}

#[test]
fn the_json_report_carries_the_other_volume() {
    let json = triage(true).to_json();
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let others = &value["coverage"]["other_volumes"];
    assert_eq!(others[0]["volume"], "W:");
    assert_eq!(others[0]["observations"], 1);
    assert_eq!(others[0]["paths"][0]["path"], FOREIGN);
    assert!(others[0]["identified_as"].is_string());

    let clean: serde_json::Value =
        serde_json::from_str(&triage(false).to_json()).expect("valid JSON");
    assert!(clean["coverage"]["other_volumes"].is_null());
}
