#![cfg(test)]

use std::io::Cursor;

use mm_core::{Acquisition, FileHash};
use mm_env::Environment;
use mm_harvest::testhive::{utf16, Builder as Hive, REG_EXPAND_SZ_T, REG_SZ_T, ROOT_FLAG};
use mm_raw::Volume;
use mm_report::{Report, Target};

use crate::pipeline::{self, Options};
use crate::testimage::{Builder as Image, Presence, Times, ROOT_RECORD};

const SAMPLE_PATH: &str = "c:\\users\\bob\\appdata\\roaming\\fenix\\fenix-agent.exe";
const SAMPLE_DIR: &str = "Users\\bob\\AppData\\Roaming\\Fenix";
const SAMPLE_NAME: &str = "fenix-agent.exe";

const SAMPLE_DROPPED: i64 = 1_773_522_298;
const SAMPLE_RAN: i64 = 1_773_522_300;
const SAMPLE_DELETED: i64 = SAMPLE_RAN + 40;

const UPDATER_RAN: i64 = 1_773_518_700;
const UPDATER_DELETED: i64 = UPDATER_RAN + 3018;

const TICK_DROPPED: u32 = 1_234_567;
const TICK_RAN: u32 = 2_500_000;
const TICK_DELETED: u32 = 7_654_321;

const UPDATER_PATH: &str = "c:\\programdata\\vendor\\cache\\vendor-setup.exe";
const UPDATER_DIR: &str = "ProgramData\\Vendor\\Cache";
const UPDATER_NAME: &str = "vendor-setup.exe";

fn sample_bytes() -> Vec<u8> {
    let mut bytes = b"MZ\x90\x00 inert test pattern, not a program ".to_vec();
    bytes.extend((0..=251u8).cycle().take(crate::testimage::CLUSTER * 3 + 617));
    bytes
}

fn amcache_hive(sha1_hex: &str) -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("Root", ROOT_FLAG, true);
    let entry = b.path(root, &["InventoryApplicationFile", "fenix-agent.exe|9a1c0f22e4"]);

    let path_value = b.value("LowerCaseLongPath", REG_SZ_T, &utf16(SAMPLE_PATH), true);
    let id_value = b.value("FileId", REG_SZ_T, &utf16(&format!("0000{sha1_hex}")), true);
    let name_value = b.value("Name", REG_SZ_T, &utf16(SAMPLE_NAME), true);
    let list = b.value_list(&[path_value, id_value, name_value], true);
    b.set_values(entry, list, 3);
    b.set_last_written(entry, Times::at(SAMPLE_RAN, TICK_RAN));

    let other = b.path(root, &["InventoryApplicationFile", "notepad.exe|0f0e0d0c0b"]);
    let other_path =
        b.value("LowerCaseLongPath", REG_SZ_T, &utf16("c:\\windows\\system32\\notepad.exe"), true);
    let other_list = b.value_list(&[other_path], true);
    b.set_values(other, other_list, 1);
    b.set_last_written(other, Times::at(UPDATER_RAN, TICK_DROPPED));

    let updater = b.path(root, &["InventoryApplicationFile", "vendor-setup.exe|5c4b3a2910"]);
    let updater_path = b.value("LowerCaseLongPath", REG_SZ_T, &utf16(UPDATER_PATH), true);
    let updater_name = b.value("Name", REG_SZ_T, &utf16(UPDATER_NAME), true);
    let updater_list = b.value_list(&[updater_path, updater_name], true);
    b.set_values(updater, updater_list, 2);
    b.set_last_written(updater, Times::at(UPDATER_RAN, TICK_RAN));

    b.finish(root)
}

fn software_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);
    let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);

    let evil = b.value(
        "FenixAgent",
        REG_SZ_T,
        &utf16("C:\\Users\\bob\\AppData\\Roaming\\Fenix\\fenix-agent.exe"),
        true,
    );
    let benign = b.value(
        "VendorUpdate",
        REG_SZ_T,
        &utf16("\"C:\\Program Files\\Vendor\\update.exe\" /background"),
        true,
    );
    let list = b.value_list(&[evil, benign], true);
    b.set_values(run, list, 2);

    b.finish(root)
}

fn triage() -> (Report, String, std::path::PathBuf) {
    let sha1 = FileHash::compute(&sample_bytes()).sha1_hex().expect("a sha-1");
    let (report, out) = triage_with(Presence::Deleted, &sha1);
    (report, sha1, out)
}

fn triage_with(sample_presence: Presence, amcache_sha1: &str) -> (Report, std::path::PathBuf) {
    let bytes = sample_bytes();

    let mut image = Image::new();

    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");
    image.file(config, "SOFTWARE", &software_hive(), Presence::Live);

    let programs = image.directories(ROOT_RECORD, "Windows\\appcompat\\Programs");
    image.file(programs, "Amcache.hve", &amcache_hive(amcache_sha1), Presence::Live);

    let roaming = image.directories(ROOT_RECORD, SAMPLE_DIR);
    let sample = image.file(roaming, SAMPLE_NAME, &bytes, sample_presence);
    image.set_times(
        sample,
        Times::all_at(Times::at(SAMPLE_DROPPED, TICK_DROPPED))
            .record_changed_at(Times::at(SAMPLE_DELETED, TICK_DELETED)),
    );

    let cache = image.directories(ROOT_RECORD, UPDATER_DIR);
    let updater =
        image.file(cache, UPDATER_NAME, b"MZ ordinary vendor installer", Presence::Deleted);
    image.set_times(
        updater,
        Times::all_at(Times::at(UPDATER_RAN - 60, TICK_DROPPED))
            .record_changed_at(Times::at(UPDATER_DELETED, TICK_DELETED)),
    );

    let vendor = image.directories(ROOT_RECORD, "Program Files\\Vendor");
    image.file(vendor, "update.exe", b"MZ ordinary updater", Presence::Live);
    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    for name in ["notepad.exe", "kernel32.dll", "svchost.exe"] {
        image.file(system32, name, b"MZ ordinary system file", Presence::Live);
    }
    let docs = image.directories(ROOT_RECORD, "Users\\bob\\Documents");
    for i in 0..3 {
        image.file(docs, &format!("report{i}.docx"), b"a document", Presence::Live);
    }

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-scenario-{}-{}",
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
fn the_planted_sample_is_found_and_identified() {
    let (report, planted_sha1, _out) = triage();

    let top = report.strongest().expect("at least one candidate");
    let label = top.label();

    assert!(
        label.contains("fenix-agent.exe"),
        "the sample should rank first; got {label} at {:.3}\nevidence: {:#?}",
        top.probability(),
        top.evidence
    );

    assert_eq!(
        top.hash.sha1_hex().as_deref(),
        Some(planted_sha1.as_str()),
        "the SHA-1 recorded by Amcache should identify the deleted sample"
    );

    assert!(
        report.found_anything(),
        "the sample scored {:.3}, below the reporting threshold\nevidence: {:#?}",
        top.probability(),
        top.evidence
    );
}

#[test]
fn the_reasoning_names_the_persistence_and_the_disappearance() {
    let (report, _, _out) = triage();
    let top = report.strongest().expect("a candidate");

    let features: Vec<&str> = top.evidence.iter().map(|e| e.feature.as_str()).collect();
    assert!(
        features.iter().any(|f| f.starts_with("persistence_")),
        "the Run key should be part of the reasoning; got {features:?}"
    );

    let text = mm_report::text::render(&report);
    assert!(text.contains("fenix-agent.exe"), "the report should name the sample");
    assert!(text.contains("T1547."), "the report should name the persistence technique");
}

#[test]
fn the_deleted_bytes_are_recovered_and_verified_against_amcache() {
    let (report, planted_sha1, out) = triage();
    let top = report.strongest().expect("a candidate");

    match &top.acquisition {
        Acquisition::Bytes { saved_as, size, .. } => {
            let path = out.join(saved_as);
            let recovered = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("reading back {}: {e}", path.display()));
            assert_eq!(recovered.len(), *size as usize);
            assert_eq!(
                FileHash::compute(&recovered).sha1_hex().as_deref(),
                Some(planted_sha1.as_str()),
                "recovered bytes do not match the hash Amcache recorded"
            );
        }
        Acquisition::HashOnly { .. } => {
            assert_eq!(top.hash.sha1_hex().as_deref(), Some(planted_sha1.as_str()));
        }
        other => panic!("nothing was recovered for the sample: {other:?}"),
    }
}

#[test]
fn a_replaced_file_is_identified_by_its_bytes_and_the_change_is_reported() {
    const STALE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let (report, out) = triage_with(Presence::Live, STALE);
    let real = FileHash::compute(&sample_bytes());

    let top = report
        .candidates
        .iter()
        .find(|c| c.label().to_ascii_lowercase().ends_with(SAMPLE_NAME))
        .expect("the sample should be a candidate");

    assert_eq!(
        top.hash.sha1_hex(),
        real.sha1_hex(),
        "the report is identifying the file Amcache remembered, not the one on the volume"
    );
    assert_ne!(top.hash.sha1_hex().as_deref(), Some(STALE));
    assert_eq!(top.hash.sha256_hex(), real.sha256_hex());

    match &top.acquisition {
        Acquisition::Bytes { saved_as, size, .. } => {
            let saved = std::fs::read(out.join(saved_as)).expect("the saved sample");
            assert_eq!(saved.len(), *size as usize);
            assert_eq!(
                FileHash::compute(&saved).sha256_hex(),
                top.hash.sha256_hex(),
                "the printed hash does not describe the bytes in the case directory"
            );
        }
        other => panic!("the sample is on the volume and should have been copied: {other:?}"),
    }

    let disagreements: Vec<_> = top.hash_disagreements().collect();
    assert_eq!(disagreements.len(), 1, "{:?}", top.hash_checks);
    assert_eq!(disagreements[0].recorded_by, "Amcache");
    assert_eq!(disagreements[0].recorded, STALE);
    assert_eq!(disagreements[0].computed, real.sha1_hex().unwrap());

    let text = mm_report::text::render(&report);
    assert!(text.contains("CHANGED"), "the report does not state the change:\n{text}");
    assert!(text.contains(STALE), "the report drops Amcache's hash entirely:\n{text}");
    assert!(text.contains(&real.sha256_hex().unwrap()), "{text}");
    assert!(text.contains("computed from the bytes saved above"), "{text}");
    assert!(
        !top.evidence.iter().any(|e| e.feature.contains("hash_disagree")),
        "the disagreement was given a weight without a measured likelihood ratio"
    );
}

#[test]
fn a_file_that_still_matches_its_amcache_entry_reports_no_change() {
    let real = FileHash::compute(&sample_bytes());
    let (report, _out) = triage_with(Presence::Live, &real.sha1_hex().unwrap());

    let top = report
        .candidates
        .iter()
        .find(|c| c.label().to_ascii_lowercase().ends_with(SAMPLE_NAME))
        .expect("the sample should be a candidate");

    assert_eq!(top.hash_disagreements().count(), 0, "{:?}", top.hash_checks);
    assert!(top.hash_checks.iter().any(|c| c.agrees), "{:?}", top.hash_checks);
    assert!(!mm_report::text::render(&report).contains("CHANGED"));
}

#[test]
fn the_sample_outranks_everything_ordinary() {
    let (report, _, _out) = triage();

    let mut ranked = report.candidates.iter();
    let top = ranked.next().expect("a candidate");
    assert!(
        top.label().contains("fenix-agent.exe"),
        "an ordinary file outranked the sample: {} at {:.3}",
        top.label(),
        top.probability()
    );

    let next = ranked.next().expect("more than one candidate");
    let gap = top.logit() - next.logit();
    assert!(
        gap >= 4.5,
        "the sample leads by only {gap:.2} log-odds over {} at {:.4} — the ordinary file is \
         closing on the sample, and this is now less than the features that separate them",
        next.label(),
        next.probability()
    );
}

#[test]
fn the_self_deletion_is_recognised_as_such() {
    let (report, _, _out) = triage();
    let top = report.strongest().expect("a candidate");
    assert!(top.label().contains("fenix-agent.exe"), "{}", top.label());

    let fired =
        top.evidence.iter().find(|e| e.feature == "deleted_soon_after_execution").unwrap_or_else(
            || {
                panic!(
                "the sample ran at a known time and was deleted forty seconds later, and nothing \
                 noticed\nevidence: {:#?}\nobservations: {:#?}",
                top.evidence, top.observations
            )
            },
        );

    assert!(fired.detail.contains("40 seconds"), "{}", fired.detail);
    assert!(fired.log_lr >= 5.0, "{}", fired.log_lr);

    assert!(
        !top.evidence.iter().any(|e| e.feature == "executed_but_now_absent"),
        "both lifecycle claims scored; they are one fact about when the file went"
    );

    assert!(
        !top.evidence.iter().any(|e| e.feature == "timestomped"),
        "writing honest timestamps made the sample look timestomped: {:#?}",
        top.evidence
    );
}

#[test]
fn an_ordinary_upgrade_fifty_minutes_later_is_not_a_self_deletion() {
    let (report, _, _out) = triage();

    let updater = report
        .candidates
        .iter()
        .find(|c| c.label().contains(UPDATER_NAME))
        .expect("the deleted updater should be a candidate — it ran and it is gone");

    let ran = updater
        .observations
        .iter()
        .any(|o| matches!(&o.kind, mm_core::ObservationKind::Executed { when: Some(_), .. }));
    let deleted = updater
        .observations
        .iter()
        .any(|o| matches!(&o.kind, mm_core::ObservationKind::FileDeleted { when: Some(_), .. }));
    assert!(
        ran && deleted,
        "the fixture did not give the updater both times: {:#?}",
        updater.observations
    );

    assert!(
        !updater.evidence.iter().any(|e| e.feature == "deleted_soon_after_execution"),
        "a fifty-minute gap was read as self-deletion: {:#?}",
        updater.evidence
    );
    assert!(
        updater.evidence.iter().any(|e| e.feature == "executed_but_now_absent"),
        "{:#?}",
        updater.evidence
    );
}

const HIJACKED_CLSID: &str = "{0002df01-0000-0000-c000-000000000046}";
const HIJACK_DLL: &str = "Users\\bob\\AppData\\Roaming\\Fenix";
const HIJACK_NAME: &str = "netshim.dll";

const SHELL_EXTENSIONS: [(&str, &str, &str); 8] = [
    ("{11111111-0000-0000-0000-000000000001}", "Windows\\System32", "photowiz.dll"),
    ("{11111111-0000-0000-0000-000000000002}", "Windows\\System32", "thumbcache.dll"),
    ("{11111111-0000-0000-0000-000000000003}", "Windows\\System32", "zipfldr.dll"),
    ("{11111111-0000-0000-0000-000000000004}", "Windows\\System32", "actxprxy.dll"),
    ("{11111111-0000-0000-0000-000000000005}", "Program Files\\Vendor", "preview.dll"),
    ("{11111111-0000-0000-0000-000000000006}", "Program Files\\Vendor", "menu.dll"),
    ("{11111111-0000-0000-0000-000000000007}", "ProgramData\\Vendor", "sync.dll"),
    ("{11111111-0000-0000-0000-000000000008}", "Program Files\\Common Files", "inkobj.dll"),
];

fn com_software_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);

    let register = |b: &mut Hive, clsid: &str, target: &str| {
        let key = b.path(root, &["Classes", "CLSID", clsid, "InprocServer32"]);
        let v = b.value("", REG_EXPAND_SZ_T, &utf16(target), true);
        let list = b.value_list(&[v], true);
        b.set_values(key, list, 1);
    };

    for (clsid, dir, name) in SHELL_EXTENSIONS {
        let target = match dir {
            "Windows\\System32" => format!("%SystemRoot%\\System32\\{name}"),
            "Program Files\\Common Files" => format!("%CommonProgramFiles%\\{name}"),
            other => format!("C:\\{other}\\{name}"),
        };
        register(&mut b, clsid, &target);
    }
    register(&mut b, HIJACKED_CLSID, "%SystemRoot%\\System32\\ieproxy.dll");

    b.finish(root)
}

fn com_usrclass_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);

    let own = b.path(root, &["CLSID", "{22222222-0000-0000-0000-000000000001}", "InprocServer32"]);
    let ov = b.value(
        "",
        REG_EXPAND_SZ_T,
        &utf16("C:\\Users\\bob\\AppData\\Local\\Toolkit\\ext.dll"),
        true,
    );
    let ol = b.value_list(&[ov], true);
    b.set_values(own, ol, 1);

    let hijack = b.path(root, &["CLSID", HIJACKED_CLSID, "InprocServer32"]);
    let hv =
        b.value("", REG_EXPAND_SZ_T, &utf16(&format!("C:\\{HIJACK_DLL}\\{HIJACK_NAME}")), true);
    let hl = b.value_list(&[hv], true);
    b.set_values(hijack, hl, 1);

    b.finish(root)
}

fn triage_com() -> Report {
    let mut image = Image::new();

    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");
    image.file(config, "SOFTWARE", &com_software_hive(), Presence::Live);

    let usrclass_dir =
        image.directories(ROOT_RECORD, "Users\\bob\\AppData\\Local\\Microsoft\\Windows");
    image.file(usrclass_dir, "UsrClass.dat", &com_usrclass_hive(), Presence::Live);

    for (_, dir, name) in SHELL_EXTENSIONS {
        let d = image.directories(ROOT_RECORD, dir);
        image.file(d, name, b"MZ ordinary shell extension", Presence::Live);
    }
    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    image.file(system32, "ieproxy.dll", b"MZ the class's real server", Presence::Live);

    let staging = image.directories(ROOT_RECORD, HIJACK_DLL);
    image.file(staging, HIJACK_NAME, b"MZ inert test pattern", Presence::Live);

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-com-{}-{}",
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
        acquire_top: 4,
        write_samples: true,
        deep: false,
        verify_top: 4,
        progress: crate::progress::Style::Silent,
    };
    pipeline::run(&volume, Environment::Recovery, target, &options)
}

#[test]
fn a_per_user_com_hijack_is_still_found() {
    let report = triage_com();

    let hijacked =
        report.candidates.iter().find(|c| c.label().contains(HIJACK_NAME)).unwrap_or_else(|| {
            panic!(
                "the hijack was suppressed along with the noise — this is the failure the \
                 demotion rule risks\ncandidates: {:#?}",
                report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
            )
        });

    let fired =
        hijacked.evidence.iter().find(|e| e.feature == "persistence_com_hijack").unwrap_or_else(
            || {
                panic!(
                    "the hijack is a candidate but nothing called it a hijack\nevidence: {:#?}",
                    hijacked.evidence
                )
            },
        );
    assert!(fired.log_lr >= 4.0, "a redirection scored only {}", fired.log_lr);
    assert!(fired.detail.contains("T1546.015"), "{}", fired.detail);

    let top = report.strongest().expect("a candidate");
    assert!(
        top.label().contains(HIJACK_NAME),
        "an ordinary shell extension outranked the hijack: {} at {:.3}",
        top.label(),
        top.probability()
    );
}

#[test]
fn ordinary_shell_extensions_create_no_candidates() {
    let report = triage_com();

    let read = report
        .coverage
        .artifacts
        .iter()
        .find(|a| a.artifact == "COM class registrations")
        .map(|a| match a.status {
            mm_report::CoverageStatus::Read { observations } => observations,
            _ => 0,
        })
        .unwrap_or(0);
    assert!(
        read >= 9,
        "only {read} COM registrations were read — the fixture's hives did not parse, so this \
         test proves nothing"
    );

    for (_, dir, name) in SHELL_EXTENSIONS {
        assert!(
            !report.candidates.iter().any(|c| c.label().contains(name)),
            "`{dir}\\{name}` is registered exactly the way Microsoft documents and became a \
             candidate anyway\ncandidates: {:#?}",
            report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
        );
    }
    assert!(!report.candidates.iter().any(|c| c.label().contains("ieproxy.dll")));

    assert!(
        report.candidates.len() <= 2,
        "twelve registrations produced {} candidates: {:#?}",
        report.candidates.len(),
        report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
    );
}

#[test]
fn the_innocent_run_key_is_attributed_to_its_own_file() {
    let (report, _, _out) = triage();

    let updater = report
        .candidates
        .iter()
        .find(|c| c.label().contains("update.exe"))
        .expect("the updater should be a candidate — it has a Run key");

    assert!(!updater.label().contains("fenix"), "two different files collapsed into one candidate");
    assert!(
        updater.hash.sha1_hex() != report.strongest().unwrap().hash.sha1_hex()
            || updater.hash.is_empty(),
        "the updater inherited the sample's identity"
    );
}

const APP_INSTALLED: i64 = 1_762_071_300;
const SIDELOAD_DROPPED: i64 = APP_INSTALLED + 90 * 24 * 60 * 60;

const APP_DIR: &str = "Program Files\\Vendor\\Reader";
const SIDELOAD_NAME: &str = "version.dll";
const SYSTEM_DROP_NAME: &str = "sspisrv.dll";

pub(crate) fn unsigned_pe() -> Vec<u8> {
    const HEADERS: usize = 0x200;
    const OPTIONAL_HEADER: usize = 0x98;
    const SECTION_TABLE: usize = 0x188;
    const OPCODES: &[u8] = &[0x48, 0x89, 0xe5, 0x00, 0x8b, 0x45, 0xc3, 0x00, 0x00, 0x55];

    let body: Vec<u8> = (0..4096).map(|i| OPCODES[i % OPCODES.len()]).collect();
    let mut file = vec![0u8; HEADERS];
    file[0..2].copy_from_slice(b"MZ");
    file[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    file[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    file[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    file[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    file[OPTIONAL_HEADER..OPTIONAL_HEADER + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    file[OPTIONAL_HEADER + 60..OPTIONAL_HEADER + 64]
        .copy_from_slice(&(HEADERS as u32).to_le_bytes());
    file[OPTIONAL_HEADER + 108..OPTIONAL_HEADER + 112].copy_from_slice(&16u32.to_le_bytes());
    file[SECTION_TABLE..SECTION_TABLE + 8].copy_from_slice(b".text\0\0\0");
    file[SECTION_TABLE + 8..SECTION_TABLE + 12].copy_from_slice(&(body.len() as u32).to_le_bytes());
    file[SECTION_TABLE + 16..SECTION_TABLE + 20]
        .copy_from_slice(&(body.len() as u32).to_le_bytes());
    file[SECTION_TABLE + 20..SECTION_TABLE + 24].copy_from_slice(&(HEADERS as u32).to_le_bytes());
    file[SECTION_TABLE + 36..SECTION_TABLE + 40].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    file.extend_from_slice(&body);
    file
}

pub(crate) fn unsigned_pe_with_version_resource() -> Vec<u8> {
    const HEADERS: usize = 0x200;
    const OPTIONAL_HEADER: usize = 0x98;
    const SECTION_TABLE: usize = 0x188;
    const RSRC_RVA: u32 = 0x3000;
    const RT_VERSION: u32 = 16;

    let mut file = unsigned_pe();
    let text_len = file.len() - HEADERS;

    file[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());

    let resources = OPTIONAL_HEADER + 112 + 2 * 8;
    file[resources..resources + 4].copy_from_slice(&RSRC_RVA.to_le_bytes());
    file[resources + 4..resources + 8].copy_from_slice(&32u32.to_le_bytes());

    let mut rsrc = vec![0u8; 32];
    rsrc[14..16].copy_from_slice(&1u16.to_le_bytes());
    rsrc[16..20].copy_from_slice(&RT_VERSION.to_le_bytes());
    rsrc[20..24].copy_from_slice(&0x8000_0020u32.to_le_bytes());

    let second = SECTION_TABLE + 40;
    file[second..second + 8].copy_from_slice(b".rsrc\0\0\0");
    file[second + 8..second + 12].copy_from_slice(&(rsrc.len() as u32).to_le_bytes());
    file[second + 12..second + 16].copy_from_slice(&RSRC_RVA.to_le_bytes());
    file[second + 16..second + 20].copy_from_slice(&(rsrc.len() as u32).to_le_bytes());
    file[second + 20..second + 24].copy_from_slice(&((HEADERS + text_len) as u32).to_le_bytes());
    file[second + 36..second + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

    file.extend_from_slice(&rsrc);
    file
}

pub(crate) fn one_catalog_naming_something_else() -> Vec<u8> {
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = body.len();
        if n < 0x80 {
            out.push(n as u8);
        } else if n <= 0xff {
            out.extend_from_slice(&[0x81, n as u8]);
        } else {
            out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        out.extend_from_slice(body);
        out
    }

    const OID_SIGNED_DATA: &[u8] =
        &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    const OID_CTL: &[u8] = &[0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x01];
    const OID_CATALOG_LIST: &[u8] =
        &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0c, 0x01, 0x01];
    const OID_SHA256: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    const OID_COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    const OID_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

    let null = [0x05, 0x00];
    let usage = tlv(0x30, OID_CATALOG_LIST);
    let list_id = tlv(0x04, &[0x01; 16]);
    let this_update = tlv(0x17, b"240101000000Z");
    let algorithm = tlv(0x30, &[OID_SHA256, &null[..]].concat());
    let member = tlv(0x30, &tlv(0x04, &[0xaa; 20]));
    let ctl = tlv(0x30, &[usage, list_id, this_update, algorithm, tlv(0x30, &member)].concat());

    let issuer =
        tlv(0x30, &tlv(0x31, &tlv(0x30, &[OID_COMMON_NAME, &tlv(0x0c, b"x")[..]].concat())));
    let signer = tlv(
        0x30,
        &[
            tlv(0x02, &[0x01]),
            tlv(0x30, &[issuer, tlv(0x02, &[0x01])].concat()),
            tlv(0x30, &[OID_SHA256, &null[..]].concat()),
            tlv(0x30, OID_ECDSA_SHA256),
            tlv(0x04, &[0x42; 8]),
        ]
        .concat(),
    );

    let signed_data = tlv(
        0x30,
        &[
            tlv(0x02, &[0x01]),
            tlv(0x31, &tlv(0x30, &[OID_SHA256, &null[..]].concat())),
            tlv(0x30, &[OID_CTL, &tlv(0xa0, &ctl)[..]].concat()),
            tlv(0x31, &signer),
        ]
        .concat(),
    );
    tlv(0x30, &[OID_SIGNED_DATA, &tlv(0xa0, &signed_data)[..]].concat())
}

fn triage_sideload() -> Report {
    let mut image = Image::new();

    let app = image.directories(ROOT_RECORD, APP_DIR);
    image.set_times(app, Times::all_at(Times::at(APP_INSTALLED, TICK_DROPPED)));
    for name in ["reader.exe", "vendorcore.dll"] {
        let record = image.file(app, name, b"MZ shipped with the application", Presence::Live);
        image.set_times(record, Times::all_at(Times::at(APP_INSTALLED + 2, TICK_RAN)));
    }

    let sideload = image.file(app, SIDELOAD_NAME, &unsigned_pe(), Presence::Live);
    image.set_times(sideload, Times::all_at(Times::at(SIDELOAD_DROPPED, TICK_DELETED)));

    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    image.set_times(system32, Times::all_at(Times::at(APP_INSTALLED - 400, TICK_DROPPED)));

    let serviced =
        image.file(system32, "wlanapi.dll", b"MZ a real system component", Presence::Live);
    image.set_hard_links(serviced, 2);
    image.set_times(serviced, Times::all_at(Times::at(APP_INSTALLED - 300, TICK_RAN)));

    let dropped = image.file(system32, SYSTEM_DROP_NAME, &unsigned_pe(), Presence::Live);
    image.set_hard_links(dropped, 1);
    image.set_times(dropped, Times::all_at(Times::at(SIDELOAD_DROPPED + 60, TICK_DELETED)));

    let store = image.directories(
        ROOT_RECORD,
        "Windows\\System32\\DriverStore\\FileRepository\\oem9.inf_amd64_a1",
    );
    let staged = image.file(store, "oemdrv.sys", b"MZ a staged driver package", Presence::Live);
    image.set_hard_links(staged, 1);
    image.set_times(staged, Times::all_at(Times::at(SIDELOAD_DROPPED + 90, TICK_RAN)));

    let winsxs = image.directories(ROOT_RECORD, "Windows\\WinSxS\\amd64_comctl32_deadbeef");
    let master = image.file(winsxs, "comctl32.dll", b"MZ a component store master", Presence::Live);
    image.set_hard_links(master, 1);
    image.set_times(master, Times::all_at(Times::at(SIDELOAD_DROPPED + 120, TICK_RAN)));

    let catroot = image.directories(
        ROOT_RECORD,
        "Windows\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
    );
    image.file(catroot, "vendor.cat", &one_catalog_naming_something_else(), Presence::Live);

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-sideload-{}-{}",
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
        acquire_top: 4,
        write_samples: true,
        deep: false,
        verify_top: 0,
        progress: crate::progress::Style::Silent,
    };
    pipeline::run(&volume, Environment::Recovery, target, &options)
}

#[test]
fn a_side_loaded_dll_becomes_a_candidate() {
    let report = triage_sideload();

    let candidate =
        report.candidates.iter().find(|c| c.label().contains(SIDELOAD_NAME)).unwrap_or_else(|| {
            panic!(
                "the side-loaded DLL is not in the report at all — nothing referenced it, it \
                 was not deleted and its timestamps were not stomped, which is exactly the \
                 hole this rule exists to close\ncandidates: {:#?}",
                report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
            )
        });

    let signature = candidate
        .evidence
        .iter()
        .find(|e| e.feature == "unsigned_in_program_files")
        .unwrap_or_else(|| {
            panic!(
                "the DLL became a candidate but its signature was never checked, so the weight \
                 the admission rule exists to collect was never collected\nevidence: {:#?}",
                candidate.evidence
            )
        });
    assert!(signature.log_lr >= 1.0, "unsigned in Program Files scored {}", signature.log_lr);
    assert!(signature.log_lr < 1.66, "unsigned in Program Files scored {}", signature.log_lr);
}

#[test]
fn an_unlinked_executable_in_the_system_directory_becomes_a_candidate() {
    let report = triage_sideload();

    let candidate =
        report.candidates.iter().find(|c| c.label().contains(SYSTEM_DROP_NAME)).unwrap_or_else(
            || {
                panic!(
                "a System32 file with one hard link never became a candidate\ncandidates: {:#?}",
                report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
            )
            },
        );
    assert!(
        candidate.evidence.iter().any(|e| e.feature == "unsigned_in_system_zone"),
        "evidence: {:#?}",
        candidate.evidence
    );
}

#[test]
fn files_that_arrived_with_their_software_create_no_candidates() {
    let report = triage_sideload();

    for (name, why) in [
        ("reader.exe", "it was installed with its own directory"),
        ("vendorcore.dll", "it was installed with its own directory"),
        ("wlanapi.dll", "it is a hard link into the component store"),
        ("oemdrv.sys", "one link is the normal condition in the driver store"),
        ("comctl32.dll", "the component store holds masters, not links"),
    ] {
        assert!(
            !report.candidates.iter().any(|c| c.label().contains(name)),
            "`{name}` became a candidate, but {why}\ncandidates: {:#?}",
            report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
        );
    }

    assert_eq!(
        report.candidates.len(),
        2,
        "candidates: {:#?}",
        report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
    );
}

#[test]
fn the_out_of_band_admission_is_reported_in_coverage() {
    let report = triage_sideload();

    let line = report
        .coverage
        .artifacts
        .iter()
        .find(|a| a.artifact == "executables installed out of band")
        .expect("the walk must say what the rule admitted");
    assert!(
        matches!(line.status, mm_report::CoverageStatus::Read { observations: 2 }),
        "{:?}",
        line.status
    );
}

const REAL_STARTUP_LINK: &[u8] =
    include_bytes!("../../mm-harvest/testdata/startup/startup-deepl.lnk");

const LINKED_PAYLOAD: &str = "Users\\analyst\\AppData\\Roaming\\0install.net\\\
                              desktop-integration\\stubs\\\
                              1eae01f3cdb5ff0ecf683b15a60a1489573c1188cb34abc205fcf7a924b4e54d";

const USER_STARTUP: &str =
    "Users\\analyst\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
const COMMON_STARTUP: &str = "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp";

fn triage_startup() -> Report {
    let mut image = Image::new();

    let stub = image.directories(ROOT_RECORD, LINKED_PAYLOAD);
    image.file(stub, "auto-start.exe", &unsigned_pe(), Presence::Live);

    let startup = image.directories(ROOT_RECORD, USER_STARTUP);
    image.file(startup, "DeepL auto-start.lnk", REAL_STARTUP_LINK, Presence::Live);
    image.file(startup, "svcupdate.exe", &unsigned_pe(), Presence::Live);
    image.file(startup, "desktop.ini", b"[.ShellClassInfo]\r\n", Presence::Live);

    let common = image.directories(ROOT_RECORD, COMMON_STARTUP);
    image.file(common, "desktop.ini", b"[.ShellClassInfo]\r\n", Presence::Live);

    image.directories(ROOT_RECORD, "Windows\\System32");

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-startup-{}-{}",
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
        acquire_top: 4,
        write_samples: true,
        deep: false,
        verify_top: 0,
        progress: crate::progress::Style::Silent,
    };
    pipeline::run(&volume, Environment::Recovery, target, &options)
}

fn startup_evidence(report: &Report, ends_with: &str) -> Vec<String> {
    report
        .candidates
        .iter()
        .find(|c| c.path.as_ref().is_some_and(|p| p.key().ends_with(ends_with)))
        .unwrap_or_else(|| {
            panic!(
                "{ends_with} should be a candidate; got {:?}",
                report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
            )
        })
        .evidence
        .iter()
        .map(|e| format!("{} {}", e.feature, e.detail))
        .collect()
}

#[test]
fn a_real_shortcut_in_the_startup_folder_incriminates_its_target() {
    let report = triage_startup();
    let evidence = startup_evidence(&report, "\\auto-start.exe");

    assert!(
        evidence.iter().any(|e| e.starts_with("persistence_run_key")
            && e.contains("Startup folder")
            && e.contains("T1547.001")),
        "the target should carry the Startup-folder persistence: {evidence:#?}"
    );
    assert!(
        evidence.iter().any(|e| e.starts_with("persistence_targets_user_profile")),
        "AppData is a directory the user can write to: {evidence:#?}"
    );
    assert!(
        evidence.iter().any(|e| e.contains("DeepL auto-start.lnk ->")),
        "the evidence must name the shortcut: {evidence:#?}"
    );

    assert!(
        !report
            .candidates
            .iter()
            .any(|c| c.path.as_ref().is_some_and(|p| p.key().ends_with(".lnk"))),
        "the shortcut is the pointer, not the payload"
    );
}

#[test]
fn an_executable_dropped_in_the_startup_folder_is_its_own_payload() {
    let report = triage_startup();
    let evidence = startup_evidence(&report, "\\startup\\svcupdate.exe");
    assert!(
        evidence.iter().any(|e| e.starts_with("persistence_run_key") && e.contains("Startup")),
        "{evidence:#?}"
    );
}

#[test]
fn desktop_ini_is_never_a_startup_entry() {
    let report = triage_startup();
    assert!(
        !report
            .candidates
            .iter()
            .any(|c| c.path.as_ref().is_some_and(|p| p.key().ends_with("desktop.ini"))),
        "candidates: {:?}",
        report.candidates.iter().map(|c| c.label()).collect::<Vec<_>>()
    );
}

#[test]
fn the_startup_folders_are_reported_in_coverage() {
    let report = triage_startup();
    let line = report
        .coverage
        .artifacts
        .iter()
        .find(|a| a.artifact.starts_with("Startup folders"))
        .unwrap_or_else(|| {
            panic!(
                "the run must say what it read: {:?}",
                report.coverage.artifacts.iter().map(|a| &a.artifact).collect::<Vec<_>>()
            )
        });
    assert!(line.artifact.contains("2 scopes"), "{}", line.artifact);
    assert!(
        matches!(line.status, mm_report::CoverageStatus::Read { observations: 2 }),
        "{:?}",
        line.status
    );
}
