#![cfg(test)]

use std::io::Cursor;
use std::sync::OnceLock;

use mm_core::Candidate;
use mm_env::Environment;
use mm_harvest::testhive::{utf16, Builder as Hive, REG_SZ_T, ROOT_FLAG};
use mm_raw::Volume;
use mm_report::{Report, Target};

use crate::pipeline::{self, Options};
use crate::scenario::{
    one_catalog_naming_something_else, unsigned_pe, unsigned_pe_with_version_resource,
};
use crate::testimage::{Builder as Image, Presence, Times, ROOT_RECORD};

const VM_PRIOR: f64 = -7.7213;

const VM_WINRE_PRIOR: f64 = -7.7711;

const VM_DEGRADED_PRIOR: f64 = -9.2021;

const VM_DEGRADED_FLOOR_PRIOR: f64 = -8.7065;

const VM_WRECKAGE_PRIOR: f64 = -7.7454;

const VM_EVIDENCED_PRIOR: f64 = -8.7302;

const VM_FRESH_PRIOR: f64 = -7.8047;

const THRESHOLD: f64 = 0.5;

const APP_INSTALLED: i64 = 1_762_071_300;

const DROP_TEMP: i64 = 1_772_366_400;
const DROP_PROGRAMDATA: i64 = DROP_TEMP + 2 * 3600;
const DROP_PF_TASK: i64 = DROP_TEMP + 4 * 3600;
const DROP_PF_RUN: i64 = DROP_TEMP + 6 * 3600;
const DROP_PF_FRESH: i64 = DROP_TEMP + 8 * 3600;

const DOWNLOADS_RAN: i64 = DROP_TEMP + 21 * 3600;
const DOWNLOADS_DELETED: i64 = DOWNLOADS_RAN + 60;

const TICK_A: u32 = 1_234_567;
const TICK_B: u32 = 7_654_321;

const TEMP_DIR: &str = "Users\\bob\\AppData\\Local\\Temp";
const TEMP_NAME: &str = "svcupdate.exe";

const PROGRAMDATA_DIR: &str = "ProgramData\\Vendor";
const PROGRAMDATA_NAME: &str = "netsvchost.exe";

const READER_DIR: &str = "Program Files\\Vendor\\Reader";
const READER_NAME: &str = "rptupdate.exe";

const VIEWER_DIR: &str = "Program Files\\Vendor\\Viewer";
const VIEWER_NAME: &str = "vwrhelper.exe";

const PLAYER_DIR: &str = "Program Files\\Vendor\\Player";
const PLAYER_NAME: &str = "plyagent.exe";

const SYSTEM32_NAME: &str = "svcupd.exe";

const SYSTEM32_STAMPED_NAME: &str = "dsksvc.exe";

const DOWNLOADS_DIR: &str = "Users\\bob\\Downloads";
const DOWNLOADS_NAME: &str = "invoice-scan.exe";
const DOWNLOADS_FULL: &str = "c:\\users\\bob\\downloads\\invoice-scan.exe";

fn ntuser_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("CMI-CreateHive{BOB}", ROOT_FLAG, true);
    let run = b.path(root, &["Software", "Microsoft", "Windows", "CurrentVersion", "Run"]);
    let value = b.value(
        "SvcUpdate",
        REG_SZ_T,
        &utf16("C:\\Users\\bob\\AppData\\Local\\Temp\\svcupdate.exe"),
        true,
    );
    let list = b.value_list(&[value], true);
    b.set_values(run, list, 1);
    b.finish(root)
}

fn software_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);
    let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
    let value = b.value(
        "VendorViewer",
        REG_SZ_T,
        &utf16("\"C:\\Program Files\\Vendor\\Viewer\\vwrhelper.exe\" /background"),
        true,
    );
    let list = b.value_list(&[value], true);
    b.set_values(run, list, 1);
    b.finish(root)
}

fn system_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);
    let service = b.path(root, &["CurrentControlSet", "Services", "NetSvcHost"]);
    let value =
        b.value("ImagePath", REG_SZ_T, &utf16("C:\\ProgramData\\Vendor\\netsvchost.exe"), true);
    let list = b.value_list(&[value], true);
    b.set_values(service, list, 1);

    let one = b.path(root, &["CurrentControlSet", "Services", "SvcUpd"]);
    let v = b.value("ImagePath", REG_SZ_T, &utf16("C:\\Windows\\System32\\svcupd.exe"), true);
    let l = b.value_list(&[v], true);
    b.set_values(one, l, 1);

    let two = b.path(root, &["CurrentControlSet", "Services", "DskSvc"]);
    let v = b.value("ImagePath", REG_SZ_T, &utf16("C:\\Windows\\System32\\dsksvc.exe"), true);
    let l = b.value_list(&[v], true);
    b.set_values(two, l, 1);

    b.finish(root)
}

fn amcache_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("Root", ROOT_FLAG, true);
    let entry = b.path(root, &["InventoryApplicationFile", "invoice-scan.exe|7c1d90a4e2"]);
    let path = b.value("LowerCaseLongPath", REG_SZ_T, &utf16(DOWNLOADS_FULL), true);
    let name = b.value("Name", REG_SZ_T, &utf16(DOWNLOADS_NAME), true);
    let list = b.value_list(&[path, name], true);
    b.set_values(entry, list, 2);
    b.set_last_written(entry, Times::at(DOWNLOADS_RAN, TICK_A));
    b.finish(root)
}

fn task_running(uri: &str, command: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <Task version=\"1.2\" \
         xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
         <RegistrationInfo><Author>WIN11\\bob</Author>\
         <URI>{uri}</URI></RegistrationInfo>\n\
         <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\n\
         <Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId>\
         <RunLevel>HighestAvailable</RunLevel></Principal></Principals>\n\
         <Settings><Hidden>false</Hidden><Enabled>true</Enabled></Settings>\n\
         <Actions Context=\"Author\"><Exec>\n\
         <Command>{command}</Command>\n\
         <Arguments>/silent</Arguments>\n\
         </Exec></Actions>\n\
         </Task>\n"
    )
    .into_bytes()
}

const CENSUS_FILES: usize = 10_000;

const MFT_RECORDS: u64 = 10_400;

fn build_and_run() -> Report {
    let mut image = Image::with_records(MFT_RECORDS);

    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");
    image.file(config, "SOFTWARE", &software_hive(), Presence::Live);
    image.file(config, "SYSTEM", &system_hive(), Presence::Live);

    let programs = image.directories(ROOT_RECORD, "Windows\\appcompat\\Programs");
    image.file(programs, "Amcache.hve", &amcache_hive(), Presence::Live);

    let bob = image.directories(ROOT_RECORD, "Users\\bob");
    image.file(bob, "NTUSER.DAT", &ntuser_hive(), Presence::Live);

    let tasks = image.directories(ROOT_RECORD, "Windows\\System32\\Tasks\\Vendor");
    image.file(
        tasks,
        "ReaderUpdate",
        &task_running("\\Vendor\\ReaderUpdate", "C:\\Program Files\\Vendor\\Reader\\rptupdate.exe"),
        Presence::Live,
    );
    image.file(
        tasks,
        "PlayerUpdate",
        &task_running("\\Vendor\\PlayerUpdate", "C:\\Program Files\\Vendor\\Player\\plyagent.exe"),
        Presence::Live,
    );

    let catroot = image.directories(
        ROOT_RECORD,
        "Windows\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
    );
    image.file(catroot, "vendor.cat", &one_catalog_naming_something_else(), Presence::Live);

    let temp = image.directories(ROOT_RECORD, TEMP_DIR);
    image.set_times(temp, Times::all_at(Times::at(APP_INSTALLED, TICK_A)));
    let sample = image.file(temp, TEMP_NAME, &distinct_unsigned_pe(0x11), Presence::Live);
    image.set_times(sample, Times::all_at(Times::at(DROP_TEMP, TICK_B)));

    let programdata = image.directories(ROOT_RECORD, PROGRAMDATA_DIR);
    image.set_times(programdata, Times::all_at(Times::at(APP_INSTALLED, TICK_A)));
    let sample =
        image.file(programdata, PROGRAMDATA_NAME, &distinct_unsigned_pe(0x12), Presence::Live);
    image.set_times(sample, Times::all_at(Times::at(DROP_PROGRAMDATA, TICK_B)));

    let reader = image.directories(ROOT_RECORD, READER_DIR);
    image.set_times(reader, Times::all_at(Times::at(APP_INSTALLED, TICK_A)));
    for name in ["reader.exe", "vendorcore.dll"] {
        let shipped = image.file(reader, name, b"MZ shipped with the application", Presence::Live);
        image.set_times(shipped, Times::all_at(Times::at(APP_INSTALLED + 2, TICK_B)));
    }
    let sample = image.file(reader, READER_NAME, &distinct_unsigned_pe(0x13), Presence::Live);
    image.set_times(sample, Times::all_at(Times::at(DROP_PF_TASK, TICK_B)));

    let viewer = image.directories(ROOT_RECORD, VIEWER_DIR);
    image.set_times(viewer, Times::all_at(Times::at(APP_INSTALLED, TICK_A)));
    let shipped =
        image.file(viewer, "viewer.exe", b"MZ shipped with the application", Presence::Live);
    image.set_times(shipped, Times::all_at(Times::at(APP_INSTALLED + 2, TICK_B)));
    let sample = image.file(viewer, VIEWER_NAME, &distinct_unsigned_pe(0x14), Presence::Live);
    image.set_times(sample, Times::all_at(Times::at(DROP_PF_RUN, TICK_B)));

    let player = image.directories(ROOT_RECORD, PLAYER_DIR);
    image.set_times(player, Times::all_at(Times::at(DROP_PF_FRESH, TICK_A)));
    let shipped =
        image.file(player, "player.exe", b"MZ shipped with the application", Presence::Live);
    image.set_times(shipped, Times::all_at(Times::at(DROP_PF_FRESH, TICK_B)));
    let sample = image.file(player, PLAYER_NAME, &distinct_unsigned_pe(0x15), Presence::Live);
    image.set_times(sample, Times::all_at(Times::at(DROP_PF_FRESH, TICK_B)));

    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    image.set_times(system32, Times::all_at(Times::at(APP_INSTALLED, TICK_A)));
    let bare = image.file(system32, SYSTEM32_NAME, &distinct_unsigned_pe(0x16), Presence::Live);
    image.set_times(bare, Times::all_at(Times::at(DROP_PROGRAMDATA, TICK_B)));
    let stamped = image.file(
        system32,
        SYSTEM32_STAMPED_NAME,
        &unsigned_pe_with_version_resource(),
        Presence::Live,
    );
    image.set_times(stamped, Times::all_at(Times::at(DROP_PROGRAMDATA, TICK_B)));

    let downloads = image.directories(ROOT_RECORD, DOWNLOADS_DIR);
    image.set_times(downloads, Times::all_at(Times::at(APP_INSTALLED, TICK_A)));
    let sample =
        image.file(downloads, DOWNLOADS_NAME, &distinct_unsigned_pe(0x17), Presence::Deleted);
    image.set_times(
        sample,
        Times::all_at(Times::at(DOWNLOADS_RAN - 300, TICK_B))
            .record_changed_at(Times::at(DOWNLOADS_DELETED, TICK_A)),
    );

    for (dir, stem) in [
        (temp, "tmpnbr"),
        (downloads, "dlnbr"),
        (programdata, "pdnbr"),
        (reader, "rdnbr"),
        (system32, "sysnbr"),
    ] {
        for i in 0..6 {
            image.census_file(dir, &format!("{stem}{i}.exe"));
        }
    }

    let store = image.directories(ROOT_RECORD, "Windows\\System32\\DriverStore");
    for i in 0..CENSUS_FILES {
        image.census_file(store, &format!("census{i:05}.dat"));
    }

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    let out = std::env::temp_dir().join(format!("malmathic-matrix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).expect("a case directory");

    let target = Target {
        display_name: "synthetic".into(),
        device_path: "synthetic".into(),
        volume_serial: format!("{:016x}", volume.serial()),
    };
    let options = Options {
        output_dir: out,
        acquire_top: 3,
        write_samples: true,
        deep: false,
        verify_top: 12,
        progress: crate::progress::Style::Silent,
    };
    pipeline::run(&volume, Environment::Recovery, target, &options)
}

fn machine() -> &'static Report {
    static ONCE: OnceLock<Report> = OnceLock::new();
    ONCE.get_or_init(build_and_run)
}

fn planted(name: &str) -> &'static Candidate {
    machine()
        .candidates
        .iter()
        .find(|c| c.label().to_ascii_lowercase().ends_with(&name.to_ascii_lowercase()))
        .unwrap_or_else(|| {
            panic!(
                "`{name}` never became a candidate; the volume produced {}:\n{}",
                machine().candidates.len(),
                roster()
            )
        })
}

fn roster() -> String {
    machine()
        .candidates
        .iter()
        .map(|c| format!("  {:<60} {}", c.label(), evidence_line(c)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn evidence_line(c: &Candidate) -> String {
    c.evidence
        .iter()
        .map(|e| format!("{}{:+.1}", e.feature, e.log_lr))
        .collect::<Vec<_>>()
        .join(" ")
}

fn distinct_unsigned_pe(tag: u8) -> Vec<u8> {
    let mut bytes = unsigned_pe();
    bytes.extend_from_slice(&[tag; 16]);
    bytes
}

fn evidence_total(c: &Candidate) -> f64 {
    c.evidence.iter().map(|e| e.log_lr).sum()
}

fn at_the_vm_prior(c: &Candidate) -> f64 {
    let logit = VM_PRIOR + evidence_total(c);
    1.0 / (1.0 + (-logit).exp())
}

fn assert_matrix_cell(
    label: &str,
    name: &str,
    expected: &[(&str, f64)],
    cell: f64,
    reported: bool,
) {
    let candidate = planted(name);

    let mut actual: Vec<(String, f64)> = candidate
        .evidence
        .iter()
        .filter(|e| e.log_lr != 0.0)
        .map(|e| (e.feature.clone(), e.log_lr))
        .collect();
    actual.sort_by(|a, b| a.0.cmp(&b.0));

    let mut want: Vec<(String, f64)> =
        expected.iter().map(|(f, w)| ((*f).to_string(), *w)).collect();
    want.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(
        actual,
        want,
        "\n{label}: the pipeline's evidence is not the matrix's.\n  on the volume: {}\n  \
         the matrix:    {}\n",
        evidence_line(candidate),
        expected.iter().map(|(f, w)| format!("{f}{w:+.1}")).collect::<Vec<_>>().join(" "),
    );

    let total: f64 = expected.iter().map(|(_, w)| w).sum();
    assert!(
        (evidence_total(candidate) - total).abs() < 1e-9,
        "{label}: evidence totals {:.4}, the matrix says {total:.4}",
        evidence_total(candidate)
    );

    let scored = at_the_vm_prior(candidate);
    assert!(
        (scored - cell).abs() < 0.001,
        "{label}: at the VM's prior this shape scores {scored:.3}; the matrix cell is {cell:.3}"
    );
    assert_eq!(
        scored >= THRESHOLD,
        reported,
        "{label}: scores {scored:.3} against a {THRESHOLD} bar, which is the wrong side of it"
    );
}

#[test]
fn a_temp_drop_with_a_run_key_scores_what_the_matrix_says() {
    assert_matrix_cell(
        r"AppData\Local\Temp + HKCU Run",
        TEMP_NAME,
        &[
            ("persistence_targets_scratch_space", 4.3),
            ("persistence_run_key", 3.2),
            ("autostart_target_without_version_resource", 1.9),
            ("unsigned_in_user_zone", 1.1),
            ("name_unique_on_machine", 1.0),
        ],
        0.9777,
        true,
    );
}

#[test]
fn a_programdata_drop_with_a_service_scores_what_the_matrix_says() {
    assert_matrix_cell(
        r"ProgramData\Vendor + HKLM service",
        PROGRAMDATA_NAME,
        &[
            ("persistence_service", 3.4),
            ("executable_in_programdata", 2.6),
            ("autostart_target_without_version_resource", 1.9),
            ("unsigned_in_user_zone", 1.1),
            ("name_unique_on_machine", 1.0),
        ],
        0.9071,
        true,
    );
}

#[test]
fn a_program_files_drop_with_a_task_clears_the_bar() {
    assert_matrix_cell(
        r"Program Files (119 days old) + scheduled task",
        READER_NAME,
        &[
            ("persistence_scheduled_task", 3.6),
            ("autostart_target_without_version_resource", 1.9),
            ("arrived_after_its_directory", 1.8),
            ("unsigned_in_program_files", 1.3),
            ("name_unique_on_machine", 1.0),
        ],
        0.8675,
        true,
    );
}

#[test]
fn a_program_files_drop_with_only_a_run_key_also_clears_the_bar() {
    assert_matrix_cell(
        r"Program Files (119 days old) + Run key",
        VIEWER_NAME,
        &[
            ("persistence_run_key", 3.2),
            ("autostart_target_without_version_resource", 1.9),
            ("arrived_after_its_directory", 1.8),
            ("unsigned_in_program_files", 1.3),
            ("name_unique_on_machine", 1.0),
        ],
        0.8144,
        true,
    );
}

const LAPTOP_PRIOR: f64 = -9.7896;

fn at_the_laptop_prior(c: &Candidate) -> f64 {
    1.0 / (1.0 + (-(LAPTOP_PRIOR + evidence_total(c))).exp())
}

#[test]
fn a_system32_service_with_no_version_resource_scores_what_the_matrix_says() {
    assert_matrix_cell(
        r"System32 + HKLM service, no version resource",
        SYSTEM32_NAME,
        &[
            ("unsigned_in_system_zone", 4.2),
            ("persistence_service", 3.4),
            ("no_version_resource", 2.5),
            ("name_unique_on_machine", 1.0),
        ],
        0.967,
        true,
    );
}

#[test]
fn a_system32_service_that_carries_a_version_resource_collects_nothing_for_it() {
    assert_matrix_cell(
        r"System32 + HKLM service, version resource present",
        SYSTEM32_STAMPED_NAME,
        &[
            ("unsigned_in_system_zone", 4.2),
            ("persistence_service", 3.4),
            ("name_unique_on_machine", 1.0),
        ],
        0.707,
        true,
    );
}

#[test]
fn the_version_resource_is_what_separates_two_identical_system32_services() {
    let bare = planted(SYSTEM32_NAME);
    let stamped = planted(SYSTEM32_STAMPED_NAME);

    let rows = |c: &Candidate| -> Vec<String> {
        let mut v: Vec<String> = c
            .evidence
            .iter()
            .filter(|e| e.log_lr != 0.0 && e.feature != "no_version_resource")
            .map(|e| format!("{}{:+.1}", e.feature, e.log_lr))
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        rows(bare),
        rows(stamped),
        "the pair differs in something other than the version resource, so it is not \
         an experiment:\n  bare:    {}\n  stamped: {}\n",
        evidence_line(bare),
        evidence_line(stamped)
    );

    assert!(
        bare.evidence.iter().any(|e| e.feature == "no_version_resource"),
        "the bare sample did not collect the row: {}",
        evidence_line(bare)
    );
    assert!(
        !stamped.evidence.iter().any(|e| e.feature == "no_version_resource"),
        "a binary that HAS a version resource was reported as missing one: {}",
        evidence_line(stamped)
    );

    let bare_p = at_the_laptop_prior(bare);
    let stamped_p = at_the_laptop_prior(stamped);
    assert!(
        bare_p >= THRESHOLD,
        "at the laptop's prior the planted System32 service scores {bare_p:.4}, \
         which is still not reported"
    );
    assert!(
        stamped_p < THRESHOLD,
        "the ImDisk analogue scores {stamped_p:.4} and would be a false accusation"
    );
    assert!((bare_p - 0.7876).abs() < 0.001, "bare scored {bare_p:.4}");
    assert!((stamped_p - 0.2333).abs() < 0.001, "stamped scored {stamped_p:.4}");
}

#[test]
fn a_downloads_sample_that_deleted_itself_scores_what_the_matrix_says() {
    assert_matrix_cell(
        "Downloads, ran and self-deleted, no persistence",
        DOWNLOADS_NAME,
        &[
            ("deleted_soon_after_execution", 5.3),
            ("executable_in_user_downloads", 1.6),
            ("name_unique_on_machine", 1.0),
        ],
        0.545,
        true,
    );
}

#[test]
fn the_self_deletion_names_the_gap_it_measured() {
    let candidate = planted(DOWNLOADS_NAME);
    let fired = candidate
        .evidence
        .iter()
        .find(|e| e.feature == "deleted_soon_after_execution")
        .unwrap_or_else(|| {
            panic!(
                "the file ran and was unlinked sixty seconds later and nothing noticed\n\
                 evidence: {:#?}\nobservations: {:#?}",
                candidate.evidence, candidate.observations
            )
        });
    assert!(fired.detail.contains("60 seconds"), "{}", fired.detail);
}

#[test]
fn a_drop_into_a_directory_of_the_same_age_is_the_weakest_cell_in_the_table() {
    assert_matrix_cell(
        r"Program Files (created in the same act) + scheduled task",
        PLAYER_NAME,
        &[
            ("persistence_scheduled_task", 3.6),
            ("autostart_target_without_version_resource", 1.9),
            ("unsigned_in_program_files", 1.3),
            ("name_unique_on_machine", 1.0),
        ],
        0.5197,
        true,
    );
}

#[test]
fn the_baseline_is_usable_and_the_baseline_weights_stay_silent() {
    let report = machine();
    assert!(
        report.coverage.baseline_usable,
        "the volume did not reach the ten thousand files `Baseline::is_usable` wants; \
         every score in this module would be 1.0 log-odds low"
    );
    for name in [TEMP_NAME, PROGRAMDATA_NAME, DOWNLOADS_NAME] {
        let c = planted(name);
        assert!(
            !c.evidence.iter().any(|e| e.feature == "executable_rare_for_zone_on_this_machine"),
            "{name} collected the rare-zone weight the matrix's baseline suppresses: {}",
            evidence_line(c)
        );
        assert!(
            !c.evidence.iter().any(|e| e.feature == "lone_executable_among_documents"),
            "{name} collected the lone-executable weight the matrix's baseline suppresses: {}",
            evidence_line(c)
        );
    }
}

#[test]
fn the_incident_window_does_not_reach_the_planted_shapes() {
    for name in [TEMP_NAME, PROGRAMDATA_NAME, READER_NAME, VIEWER_NAME] {
        let c = planted(name);
        assert!(
            !c.evidence.iter().any(|e| e.feature == "created_in_incident_window"),
            "{name} was swept into an incident window: {}",
            evidence_line(c)
        );
    }
}

const CORPORATE_PRIOR: f64 = -10.8198;

fn at_prior(c: &Candidate, prior: f64) -> f64 {
    1.0 / (1.0 + (-(prior + evidence_total(c))).exp())
}

fn break_even(c: &Candidate) -> f64 {
    evidence_total(c).exp()
}

#[test]
fn the_matrix_at_every_measured_prior() {
    let shapes: &[(&str, &str)] = &[
        (SYSTEM32_NAME, "System32 + service, NO version resource"),
        (TEMP_NAME, r"AppData\Local\Temp + HKCU Run"),
        (SYSTEM32_STAMPED_NAME, "System32 + service, version resource"),
        (PROGRAMDATA_NAME, r"ProgramData\Vendor + HKLM service"),
        (DOWNLOADS_NAME, "Downloads, ran and self-deleted"),
        (READER_NAME, r"Program Files (119 d) + scheduled task"),
        (VIEWER_NAME, r"Program Files (119 d) + Run key"),
        (PLAYER_NAME, r"Program Files (same-age dir) + task  [control]"),
    ];

    println!(
        "\n{:<46} {:>5}  {:>8}   {:>6} {:>6} {:>9} {:>9} {:>7} {:>7}",
        "shape", "W", "N*", "live", "WinRE", "live+lost", "less wreck", "laptop", "corp"
    );
    println!(
        "{:<46} {:>5}  {:>8}   {:>6} {:>6} {:>9} {:>9} {:>7} {:>7}",
        "", "", "", "2 256", "2 371", "9 918", "2 311", "17 847", "50 000"
    );
    let mut vm = 0;
    let mut winre = 0;
    let mut degraded = 0;
    let mut wreckage = 0;
    let mut laptop = 0;
    let mut corp = 0;
    for (name, label) in shapes {
        let c = planted(name);
        let p_vm = at_prior(c, VM_PRIOR);
        let p_winre = at_prior(c, VM_WINRE_PRIOR);
        let p_deg = at_prior(c, VM_DEGRADED_PRIOR);
        let p_wreck = at_prior(c, VM_WRECKAGE_PRIOR);
        let p_lap = at_prior(c, LAPTOP_PRIOR);
        let p_corp = at_prior(c, CORPORATE_PRIOR);
        vm += usize::from(p_vm >= THRESHOLD);
        winre += usize::from(p_winre >= THRESHOLD);
        degraded += usize::from(p_deg >= THRESHOLD);
        wreckage += usize::from(p_wreck >= THRESHOLD);
        laptop += usize::from(p_lap >= THRESHOLD);
        corp += usize::from(p_corp >= THRESHOLD);
        println!(
            "{label:<46} {:>5.1}  {:>8.0}   {:>6} {:>6} {:>9} {:>9} {:>7} {:>7}",
            evidence_total(c),
            break_even(c),
            cell(p_vm),
            cell(p_winre),
            cell(p_deg),
            cell(p_wreck),
            cell(p_lap),
            cell(p_corp),
        );
    }
    println!(
        "{:<46} {:>5}  {:>8}   {vm:>6} {winre:>6} {degraded:>9} {wreckage:>9} {laptop:>7} {corp:>7}\n",
        "reported", "", ""
    );

    assert_eq!(vm, winre, "live reports {vm} shapes and WinRE {winre}");
    assert_eq!(vm, 8, "the live column reports {vm} shapes, not 8");
    assert_eq!(degraded, 4, "the degraded column reports {degraded} shapes, not 4");
    let wreck_reported = shapes
        .iter()
        .filter(|(name, _)| at_prior(planted(name), VM_WRECKAGE_PRIOR) >= THRESHOLD)
        .count();
    assert_eq!(wreckage, wreck_reported);
    assert_eq!(wreckage, 8, "with the wreckage out {wreckage} shapes report, not 8");
    let evidenced = shapes
        .iter()
        .filter(|(name, _)| at_prior(planted(name), VM_EVIDENCED_PRIOR) >= THRESHOLD)
        .count();
    assert_eq!(evidenced, 5, "on the reports own evidence {evidenced} shapes report, not 5");
    let fresh = shapes
        .iter()
        .filter(|(name, _)| at_prior(planted(name), VM_FRESH_PRIOR) >= THRESHOLD)
        .count();
    assert_eq!(fresh, 7, "the fresh run's prior reports {fresh} shapes, not 7");
    let bracket = [VM_DEGRADED_PRIOR, VM_EVIDENCED_PRIOR, VM_WRECKAGE_PRIOR, VM_PRIOR];
    assert!(
        bracket.windows(2).all(|w| w[0] < w[1]),
        "the bracket runs from most to least degraded and a correction can only ever \
         lower the prior: {bracket:?}"
    );
    for (live_unresolved, want) in
        [(0u64, 8), (129, 8), (130, 7), (386, 7), (387, 6), (3_120, 6), (3_121, 5), (7_587, 4)]
    {
        let prior = mm_core::log_odds_of_one_in((2_256 + 55 + live_unresolved) as f64);
        let got =
            shapes.iter().filter(|(name, _)| at_prior(planted(name), prior) >= THRESHOLD).count();
        assert_eq!(
            got, want,
            "{live_unresolved} live unresolved report(s) leave {got} shapes, not {want}"
        );
    }

    let floor_reported = shapes
        .iter()
        .filter(|(name, _)| at_prior(planted(name), VM_DEGRADED_FLOOR_PRIOR) >= THRESHOLD)
        .count();
    assert_eq!(
        floor_reported, 5,
        "at the most favourable reading of the loss {floor_reported} shapes report, not 5"
    );
    assert!(at_prior(planted(SYSTEM32_NAME), VM_DEGRADED_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(TEMP_NAME), VM_DEGRADED_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(PROGRAMDATA_NAME), VM_DEGRADED_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(READER_NAME), VM_DEGRADED_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(DOWNLOADS_NAME), VM_DEGRADED_PRIOR) < THRESHOLD);
    assert!(at_prior(planted(SYSTEM32_STAMPED_NAME), VM_DEGRADED_PRIOR) < THRESHOLD);
    assert!(at_prior(planted(VIEWER_NAME), VM_DEGRADED_PRIOR) < THRESHOLD);
    assert!(at_prior(planted(PLAYER_NAME), VM_DEGRADED_PRIOR) < THRESHOLD);

    assert_eq!(laptop, 3, "the laptop column reports {laptop} shapes, not 3");
    assert_eq!(corp, 2, "the corporate column reports {corp} shapes, not 2");
    assert!(at_prior(planted(SYSTEM32_NAME), CORPORATE_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(SYSTEM32_STAMPED_NAME), LAPTOP_PRIOR) < THRESHOLD);
    assert!(at_prior(planted(SYSTEM32_STAMPED_NAME), CORPORATE_PRIOR) < THRESHOLD);
    assert!(at_prior(planted(TEMP_NAME), LAPTOP_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(PROGRAMDATA_NAME), LAPTOP_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(PROGRAMDATA_NAME), CORPORATE_PRIOR) < THRESHOLD);
    assert!(at_prior(planted(DOWNLOADS_NAME), VM_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(DOWNLOADS_NAME), LAPTOP_PRIOR) < THRESHOLD);
    assert_eq!(vm, 8, "the VM column reports {vm} shapes, not 8");

    assert!(at_prior(planted(READER_NAME), VM_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(READER_NAME), LAPTOP_PRIOR) < THRESHOLD);
    assert!(at_prior(planted(VIEWER_NAME), VM_PRIOR) >= THRESHOLD);
    assert!(at_prior(planted(VIEWER_NAME), LAPTOP_PRIOR) < THRESHOLD);

    let pf_task = break_even(planted(READER_NAME));
    assert!(
        (14_000.0..16_000.0).contains(&pf_task),
        "Program Files + task breaks even at {pf_task:.0}, not near fifteen thousand"
    );
}

fn cell(p: f64) -> String {
    if p >= THRESHOLD {
        format!("{p:.3}*")
    } else {
        format!("{p:.3} ")
    }
}
