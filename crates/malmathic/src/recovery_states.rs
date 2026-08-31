#![cfg(test)]

use std::io::Cursor;

use mm_core::{Acquisition, ArtifactSource, Candidate, FileHash, Recovery};
use mm_env::Environment;
use mm_harvest::testhive::{utf16, Builder as Hive, REG_SZ_T, ROOT_FLAG};
use mm_raw::Volume;
use mm_report::{Report, Target};

use crate::pipeline::{self, Options};
use crate::testimage::{Builder as Image, Presence, Times, ROOT_RECORD};

const DIR: &str = "Users\\bob\\AppData\\Roaming\\Fenix";
const DIR_DISPLAY: &str = "C:\\Users\\bob\\AppData\\Roaming\\Fenix";

const RAN: i64 = 1_773_522_300;
const DELETED: i64 = RAN + 40;
const TICK_A: u32 = 1_234_567;
const TICK_B: u32 = 7_654_321;

const STAGES: [&str; 7] = [
    "stage1.exe",
    "stage2.exe",
    "stage3.exe",
    "stage4.exe",
    "stage5.exe",
    "stage6.exe",
    "stage7.exe",
];

fn bytes_for(stage: &str) -> Vec<u8> {
    let mut bytes = b"MZ\x90\x00 inert test pattern, not a program: ".to_vec();
    bytes.extend_from_slice(stage.as_bytes());
    bytes.push(b'\n');
    let seed = stage.as_bytes()[5];
    bytes.extend((0..=251u8).map(|b| b ^ seed).cycle().take(crate::testimage::CLUSTER * 3 + 617));
    bytes
}

fn sha1_of(stage: &str) -> String {
    FileHash::compute(&bytes_for(stage)).sha1_hex().expect("a sha-1")
}

fn amcache_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("Root", ROOT_FLAG, true);

    let entry = |name: &str, sha1: &str, b: &mut Hive| {
        let key = b.path(root, &["InventoryApplicationFile", &format!("{name}|9a1c0f22e4")]);
        let path = b.value(
            "LowerCaseLongPath",
            REG_SZ_T,
            &utf16(&format!("{}\\{name}", DIR_DISPLAY.to_lowercase())),
            true,
        );
        let id = b.value("FileId", REG_SZ_T, &utf16(&format!("0000{sha1}")), true);
        let n = b.value("Name", REG_SZ_T, &utf16(name), true);
        let list = b.value_list(&[path, id, n], true);
        b.set_values(key, list, 3);
        b.set_last_written(key, Times::at(RAN, TICK_A));
    };

    entry("stage2.exe", &sha1_of("stage2.exe"), &mut b);
    entry("stage5.exe", &sha1_of("stage1.exe"), &mut b);
    entry("stage7.exe", &sha1_of("stage7.exe"), &mut b);

    b.finish(root)
}

fn software_hive() -> Vec<u8> {
    let mut b = Hive::new();
    let root = b.key("ROOT", ROOT_FLAG, true);

    let cv = b.path(root, &["Microsoft", "Windows NT", "CurrentVersion"]);
    let sr = b.value("SystemRoot", REG_SZ_T, &utf16("C:\\Windows"), true);
    let list = b.value_list(&[sr], true);
    b.set_values(cv, list, 1);

    let run = b.path(root, &["Microsoft", "Windows", "CurrentVersion", "Run"]);
    let values: Vec<u32> = STAGES
        .iter()
        .map(|stage| {
            b.value(
                &format!("Fenix{}", &stage[5..6]),
                REG_SZ_T,
                &utf16(&format!("{DIR_DISPLAY}\\{stage}")),
                true,
            )
        })
        .collect();
    let list = b.value_list(&values, true);
    b.set_values(run, list, values.len() as u32);

    b.finish(root)
}

fn info_stub(size: u64, path: &str) -> Vec<u8> {
    let mut units: Vec<u16> = path.encode_utf16().collect();
    units.push(0);
    let mut out = Vec::new();
    out.extend_from_slice(&2u64.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&0x01dc_dfe5_3458_c550u64.to_le_bytes());
    out.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn triage() -> (Report, std::path::PathBuf) {
    triage_with(true)
}

fn triage_with(write_samples: bool) -> (Report, std::path::PathBuf) {
    let mut image = Image::new();

    let config = image.directories(ROOT_RECORD, "Windows\\System32\\config");
    image.file(config, "SOFTWARE", &software_hive(), Presence::Live);
    let programs = image.directories(ROOT_RECORD, "Windows\\appcompat\\Programs");
    image.file(programs, "Amcache.hve", &amcache_hive(), Presence::Live);

    let fenix = image.directories(ROOT_RECORD, DIR);

    image.file(fenix, "stage1.exe", &bytes_for("stage1.exe"), Presence::Live);

    for stage in ["stage2.exe", "stage3.exe", "stage5.exe", "stage7.exe"] {
        let r = image.file(fenix, stage, &bytes_for(stage), Presence::Deleted);
        image.set_times(
            r,
            Times::all_at(Times::at(RAN - 2, TICK_A)).record_changed_at(Times::at(DELETED, TICK_B)),
        );
    }

    let r =
        image.file(fenix, "stage4.exe", &bytes_for("stage4.exe"), Presence::DeletedClustersReused);
    image.set_times(
        r,
        Times::all_at(Times::at(RAN - 2, TICK_A)).record_changed_at(Times::at(DELETED, TICK_B)),
    );

    let bin = image.directories(ROOT_RECORD, "$Recycle.Bin\\S-1-5-21-1");
    image.file(bin, "desktop.ini", b"[.ShellClassInfo]\r\n", Presence::Live);
    let decoy = b"MZ these are not stage7's bytes and never were".to_vec();
    image.file(
        bin,
        "$IK9C8D3.exe",
        &info_stub(decoy.len() as u64, &format!("{DIR_DISPLAY}\\stage7.exe")),
        Presence::Live,
    );
    image.file(bin, "$RK9C8D3.exe", &decoy, Presence::Live);

    let system32 = image.directories(ROOT_RECORD, "Windows\\System32");
    for name in ["notepad.exe", "kernel32.dll", "svchost.exe", "explorer.exe", "cmd.exe"] {
        image.file(system32, name, b"MZ ordinary system file", Presence::Live);
    }
    let vendor = image.directories(ROOT_RECORD, "Program Files\\Vendor");
    for name in ["update.exe", "helper.exe"] {
        image.file(vendor, name, b"MZ ordinary vendor file", Presence::Live);
    }
    let docs = image.directories(ROOT_RECORD, "Users\\bob\\Documents");
    for i in 0..3 {
        image.file(docs, &format!("report{i}.docx"), b"a document", Presence::Live);
    }

    let volume: Volume<Cursor<Vec<u8>>> = image.open();

    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let out = std::env::temp_dir().join(format!(
        "malmathic-recovery-states-{}-{}",
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
        write_samples,
        deep: false,
        verify_top: 25,
        progress: crate::progress::Style::Silent,
    };
    let report = pipeline::run(&volume, Environment::Recovery, target, &options);
    (report, out)
}

fn stage<'a>(report: &'a Report, name: &str) -> &'a Candidate {
    let key = format!("{}\\{name}", DIR_DISPLAY[2..].to_lowercase());
    report
        .candidates
        .iter()
        .find(|c| c.path.as_ref().is_some_and(|p| p.key() == key))
        .unwrap_or_else(|| panic!("{name} should be a candidate"))
}

fn recovery(report: &Report, name: &str) -> Recovery {
    match &stage(report, name).acquisition {
        Acquisition::Bytes { recovery, .. } => recovery.clone(),
        other => panic!("{name}: expected bytes, got {other:?}"),
    }
}

fn saved(report: &Report, out: &std::path::Path, name: &str) -> Vec<u8> {
    match &stage(report, name).acquisition {
        Acquisition::Bytes { saved_as, .. } => {
            let mut p = out.to_path_buf();
            for part in saved_as.split('/') {
                p.push(part);
            }
            std::fs::read(&p).unwrap_or_else(|e| panic!("{name}: reading {p:?}: {e}"))
        }
        other => panic!("{name}: expected bytes, got {other:?}"),
    }
}

#[test]
fn a_file_still_on_the_volume_is_intact_and_carries_no_caveat() {
    let (report, out) = triage();
    let c = stage(&report, "stage1.exe");

    assert_eq!(recovery(&report, "stage1.exe"), Recovery::Intact);
    assert!(Recovery::Intact.is_trustworthy());
    assert_eq!(saved(&report, &out, "stage1.exe"), bytes_for("stage1.exe"));
    match &c.acquisition {
        Acquisition::Bytes { via, .. } => assert_eq!(*via, ArtifactSource::Mft),
        other => panic!("{other:?}"),
    }

    let text = mm_report::text::render(&report);
    let block = block_for(&text, "stage1.exe");
    assert!(block.contains("sample   recovered from"), "{block}");
    assert!(!block.contains("UNVERIFIED"), "{block}");
    assert!(!block.contains("PARTIAL"), "{block}");
    assert!(!block.contains("VERIFIED"), "{block}");
}

#[test]
fn a_carve_an_independent_digest_matches_is_confirmed() {
    let (report, out) = triage();

    match recovery(&report, "stage2.exe") {
        Recovery::Confirmed { against } => assert_eq!(against, "Amcache"),
        other => panic!("expected Confirmed, got {other:?}"),
    }
    assert!(recovery(&report, "stage2.exe").is_trustworthy());
    assert_eq!(saved(&report, &out, "stage2.exe"), bytes_for("stage2.exe"));

    let c = stage(&report, "stage2.exe");
    assert_eq!(c.hash.sha1_hex().as_deref(), Some(sha1_of("stage2.exe").as_str()));
    assert_eq!(
        c.acquired_hash.as_ref().and_then(|h| h.sha1_hex()).as_deref(),
        Some(sha1_of("stage2.exe").as_str())
    );

    let block = block_for(&mm_report::text::render(&report), "stage2.exe");
    assert!(block.contains("sample   recovered from"), "{block}");
    assert!(block.contains("VERIFIED — hash matches the one Amcache recorded"), "{block}");
}

#[test]
fn a_carve_with_nothing_to_check_it_against_is_unverified() {
    let (report, out) = triage();

    let basis = match recovery(&report, "stage3.exe") {
        Recovery::Unverified { basis } => basis,
        other => panic!("expected Unverified, got {other:?}"),
    };
    assert!(!recovery(&report, "stage3.exe").is_trustworthy());
    assert_eq!(saved(&report, &out, "stage3.exe"), bytes_for("stage3.exe"));
    assert!(basis.contains("still marked free"), "{basis}");
    assert!(basis.contains("No artifact recorded a hash"), "{basis}");

    let block = block_for(&mm_report::text::render(&report), "stage3.exe");
    assert!(block.contains("sample   reconstructed from"), "{block}");
    assert!(block.contains("UNVERIFIED"), "{block}");
}

#[test]
fn a_carve_whose_clusters_were_reused_is_partial() {
    let (report, out) = triage();

    let detail = match recovery(&report, "stage4.exe") {
        Recovery::Partial { detail } => detail,
        other => panic!("expected Partial, got {other:?}"),
    };
    assert!(!recovery(&report, "stage4.exe").is_trustworthy());
    assert!(detail.contains("reallocated since the file was deleted"), "{detail}");
    assert!(detail.contains("fragments, not as the sample"), "{detail}");
    assert_eq!(
        saved(&report, &out, "stage4.exe").len(),
        bytes_for("stage4.exe").len(),
        "the fragments are still written out at full length"
    );

    let block = block_for(&mm_report::text::render(&report), "stage4.exe");
    assert!(block.contains("sample   reconstructed from"), "{block}");
    assert!(block.contains("PARTIAL — NOT the sample"), "{block}");
}

#[test]
fn bytes_an_independent_digest_contradicts_are_partial_and_do_not_become_the_identity() {
    let (report, _out) = triage();
    let c = stage(&report, "stage5.exe");

    let detail = match recovery(&report, "stage5.exe") {
        Recovery::Partial { detail } => detail,
        other => panic!("expected Partial, got {other:?}"),
    };
    assert!(!recovery(&report, "stage5.exe").is_trustworthy());
    assert!(detail.contains("not the file, or not all of it"), "{detail}");

    assert_eq!(c.hash.sha1_hex().as_deref(), Some(sha1_of("stage1.exe").as_str()));
    assert_eq!(
        c.acquired_hash.as_ref().and_then(|h| h.sha1_hex()).as_deref(),
        Some(sha1_of("stage5.exe").as_str())
    );
    assert_eq!(c.hash_disagreements().count(), 1, "{:#?}", c.hash_checks);

    let block = block_for(&mm_report::text::render(&report), "stage5.exe");
    assert!(block.contains("PARTIAL — NOT the sample"), "{block}");
}

#[test]
fn a_candidate_with_no_bytes_and_no_digest_fails_and_says_so() {
    let (report, _out) = triage();
    let c = stage(&report, "stage6.exe");

    let reason = match &c.acquisition {
        Acquisition::Failed { reason } => reason.clone(),
        other => panic!("expected Failed, got {other:?}"),
    };
    assert!(reason.contains("no $MFT record was read for this path"), "{reason}");
    assert!(reason.contains("not on this volume under this name"), "{reason}");
    assert!(reason.contains("no artifact recorded a hash of it"), "{reason}");
    assert!(c.hash.is_empty(), "a failed acquisition may not invent a digest");

    let block = block_for(&mm_report::text::render(&report), "stage6.exe");
    assert!(block.contains("NO BYTES"), "{block}");
    let flat = block.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(flat.contains("no $MFT record was read for this path"), "{block}");
    assert!(flat.contains("no artifact recorded a hash of it"), "{block}");
}

#[test]
fn a_caveated_step_does_not_pre_empt_a_provable_one_below_it() {
    let (report, out) = triage();
    let c = stage(&report, "stage7.exe");

    match &c.acquisition {
        Acquisition::Bytes { via, recovery: Recovery::Confirmed { against }, .. } => {
            assert_eq!(*via, ArtifactSource::Mft, "the carve, not the bin, must be named");
            assert_eq!(against, "Amcache");
        }
        other => panic!("expected a confirmed carve, got {other:?}"),
    }
    assert_eq!(
        saved(&report, &out, "stage7.exe"),
        bytes_for("stage7.exe"),
        "the file in sample/ must be the winning step's bytes, not the losing step's"
    );

    assert_eq!(c.hash_disagreements().count(), 0, "{:#?}", c.hash_checks);
    assert_eq!(
        c.acquired_hash.as_ref().and_then(|h| h.sha1_hex()).as_deref(),
        Some(sha1_of("stage7.exe").as_str())
    );

    let block = block_for(&mm_report::text::render(&report), "stage7.exe");
    assert!(block.contains("VERIFIED — hash matches the one Amcache recorded"), "{block}");
    assert!(!block.contains("PARTIAL"), "{block}");
}

#[test]
fn a_held_result_is_returned_whole_when_nothing_below_it_can_do_better() {
    let (report, out) = triage();

    for name in ["stage5.exe", "stage4.exe"] {
        let c = stage(&report, name);
        match &c.acquisition {
            Acquisition::Bytes { via, size, recovery: Recovery::Partial { .. }, .. } => {
                assert_eq!(*via, ArtifactSource::Mft, "{name}");
                assert_eq!(*size as usize, bytes_for(name).len(), "{name}");
            }
            other => panic!("{name}: expected fragments, got {other:?}"),
        }
        let fragments = saved(&report, &out, name);
        assert_eq!(fragments.len(), bytes_for(name).len(), "{name}");
        assert_eq!(
            c.acquired_hash.as_ref().and_then(|h| h.sha1_hex()),
            FileHash::compute(&fragments).sha1_hex(),
            "{name}: the digest on the candidate must be of the bytes really in sample/"
        );
    }
}

#[test]
fn withholding_the_samples_changes_nothing_but_the_samples() {
    let (kept, kept_out) = triage_with(true);
    let (held, held_out) = triage_with(false);

    assert_eq!(
        kept.candidates.len(),
        held.candidates.len(),
        "the same volume must produce the same candidates whether or not bytes are written"
    );

    for (a, b) in kept.candidates.iter().zip(&held.candidates) {
        let who = a.path.as_ref().map(|p| p.key().to_string()).unwrap_or_else(|| a.id.to_string());
        assert_eq!(a.id, b.id, "{who}: candidate ids must line up");
        assert_eq!(a.path, b.path, "{who}: same path");
        assert_eq!(
            a.probability().to_bits(),
            b.probability().to_bits(),
            "{who}: the score must not move — it is computed from evidence, and no evidence \
             here depends on a file having been written"
        );
        assert_eq!(
            a.evidence
                .iter()
                .map(|e| (&e.feature, e.log_lr.to_bits(), &e.detail))
                .collect::<Vec<_>>(),
            b.evidence
                .iter()
                .map(|e| (&e.feature, e.log_lr.to_bits(), &e.detail))
                .collect::<Vec<_>>(),
            "{who}: same evidence rows, same weights, same wording"
        );

        assert_eq!(a.hash.sha256_hex(), b.hash.sha256_hex(), "{who}: same SHA-256");
        assert_eq!(a.hash.sha1_hex(), b.hash.sha1_hex(), "{who}: same SHA-1");
        assert_eq!(a.hash.md5_hex(), b.hash.md5_hex(), "{who}: same MD5");
        assert_eq!(
            a.acquired_hash.as_ref().and_then(|h| h.sha256_hex()),
            b.acquired_hash.as_ref().and_then(|h| h.sha256_hex()),
            "{who}: the digest of the bytes that were read, which both runs read"
        );
        assert_eq!(
            a.hash_checks.iter().map(|c| (&c.algorithm, c.agrees)).collect::<Vec<_>>(),
            b.hash_checks.iter().map(|c| (&c.algorithm, c.agrees)).collect::<Vec<_>>(),
            "{who}: the hash-provenance check runs on bytes, not on files"
        );

        match (&a.acquisition, &b.acquisition) {
            (
                Acquisition::Bytes { via: v1, size: s1, recovery: r1, .. },
                Acquisition::Withheld { via: v2, size: s2, recovery: r2 },
            ) => {
                assert_eq!(v1, v2, "{who}: same artifact supplied the bytes");
                assert_eq!(s1, s2, "{who}: same number of bytes read");
                assert_eq!(r1, r2, "{who}: same recovery, so the same caveat or none");
            }
            (x, y) => assert_eq!(
                std::mem::discriminant(x),
                std::mem::discriminant(y),
                "{who}: {x:?} became {y:?}; only Bytes may become Withheld"
            ),
        }
    }

    let withheld = held
        .candidates
        .iter()
        .filter(|c| matches!(c.acquisition, Acquisition::Withheld { .. }))
        .count();
    assert!(withheld >= 5, "only {withheld} candidates were withheld; the volume plants seven");

    let held_sample = held_out.join("sample");
    let left: Vec<String> = std::fs::read_dir(&held_sample)
        .map(|d| {
            d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()
        })
        .unwrap_or_default();
    assert!(left.is_empty(), "--no-samples wrote {left:?} into {held_sample:?}");

    let kept_sample = kept_out.join("sample");
    let written = std::fs::read_dir(&kept_sample).map(|d| d.count()).unwrap_or(0);
    assert!(written > 0, "the ordinary run wrote nothing into {kept_sample:?}");
}

#[test]
fn one_report_holds_every_state_and_keeps_them_apart() {
    let (report, _out) = triage();
    let text = mm_report::text::render(&report);

    for (name, wanted) in [
        ("stage1.exe", "recovered"),
        ("stage2.exe", "recovered"),
        ("stage3.exe", "reconstructed"),
        ("stage4.exe", "reconstructed"),
        ("stage5.exe", "reconstructed"),
        ("stage7.exe", "recovered"),
    ] {
        let block = block_for(&text, name);
        assert!(
            block.contains(&format!("sample   {wanted} from")),
            "{name} should read `sample   {wanted} from`:\n{block}"
        );
        let trustworthy = wanted == "recovered";
        assert_eq!(
            trustworthy,
            match &stage(&report, name).acquisition {
                Acquisition::Bytes { recovery, .. } => recovery.is_trustworthy(),
                other => panic!("{name}: {other:?}"),
            },
            "the verb and `is_trustworthy` must never disagree for {name}"
        );
    }
    assert!(block_for(&text, "stage6.exe").contains("NO BYTES"));
}

fn block_for(text: &str, name: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.contains(name))
        .unwrap_or_else(|| panic!("{name} should appear in the report:\n{text}"));
    let end = lines[start + 1..]
        .iter()
        .position(|l| STAGES.iter().any(|s| *s != name && l.contains(s)))
        .map(|i| start + 1 + i)
        .unwrap_or(lines.len());
    lines[start..end].join("\n")
}

#[test]
#[ignore]
fn render_every_state_to_a_file() {
    let (report, out) = triage();
    let text = mm_report::text::render(&report);
    let path = out.join("report.txt");
    std::fs::write(&path, &text).expect("writing the report");
    println!("{}", path.display());
    println!("{text}");
}
