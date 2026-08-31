use std::path::{Path, PathBuf};

use mm_core::{Acquisition, ArtifactSource, Candidate, Recovery};
use mm_report::Report;

const DATASET: &str = "VM_TESTS/test_7_ransomware/report.json";

fn ransomware_run() -> Option<Report> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("mm-report lives two directories below the repository root")
        .to_path_buf();
    let path: PathBuf = root.join(DATASET);
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("SKIPPED: {DATASET} is not present at {}", path.display());
        return None;
    };
    Some(
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("{} did not deserialise as a Report: {e}", path.display())),
    )
}

const FINDINGS: [(&str, f64, u64); 3] = [
    (
        r"\Users\Alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\svchost.url",
        0.7572,
        144,
    ),
    (r"C:\Users\Alice\AppData\Roaming\svchost.exe", 0.6541, 22_528),
    (
        r"\Users\Alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\stop_propaganda.txt",
        0.5343,
        131,
    ),
];

const EVIDENCE: [&[(&str, f64)]; 3] = [
    &[
        ("persistence_run_key", 3.2),
        ("persistence_targets_user_profile", 3.1),
        ("created_in_incident_window", 1.8),
        ("name_unique_on_machine", 1.0),
    ],
    &[
        ("system_binary_name_outside_system_dir", 6.0),
        ("executable_in_user_appdata", 1.5),
        ("unsigned_in_user_zone", 1.1),
    ],
    &[
        ("persistence_run_key", 3.2),
        ("persistence_targets_user_profile", 3.1),
        ("created_in_incident_window", 1.8),
    ],
];

fn findings(report: &Report) -> Vec<&Candidate> {
    report.reportable().collect()
}

#[test]
fn the_ransomware_run_still_finds_three_things_and_ranks_them_the_same_way() {
    let Some(report) = ransomware_run() else { return };

    assert_eq!(report.candidates.len(), 2_868, "the candidate population moved");
    assert_eq!(report.threshold, 0.5);

    let found = findings(&report);
    assert_eq!(
        found.len(),
        3,
        "this run found three things: the .url that starts the dropper at logon, the dropper \
         itself, and the ransom note wired into the Startup folder. It now finds {}",
        found.len()
    );

    for (candidate, (path, probability, _)) in found.iter().zip(FINDINGS) {
        assert_eq!(
            candidate.path.as_ref().map(|p| p.raw()),
            Some(path),
            "a finding changed identity or the ranking reordered"
        );
        assert!(
            (candidate.probability() - probability).abs() < 0.0001,
            "{path} scored {:.4}, was {probability:.4}",
            candidate.probability()
        );
    }
}

#[test]
fn each_finding_still_carries_the_evidence_that_convicted_it() {
    let Some(report) = ransomware_run() else { return };

    for ((candidate, expected), (path, _, _)) in
        findings(&report).iter().zip(EVIDENCE).zip(FINDINGS)
    {
        let actual: Vec<(&str, f64)> =
            candidate.evidence.iter().map(|e| (e.feature.as_str(), e.log_lr)).collect();
        assert_eq!(
            actual.len(),
            expected.len(),
            "{path} carries {} evidence rows, was {}: {actual:?}",
            actual.len(),
            expected.len()
        );
        for ((feature, log_lr), (want_feature, want_log_lr)) in actual.iter().zip(expected.iter()) {
            assert_eq!(feature, want_feature, "{path}: the evidence rows changed or reordered");
            assert!(
                (log_lr - want_log_lr).abs() < 1e-9,
                "{path}: {feature} is {log_lr:+.2}, was {want_log_lr:+.2}"
            );
        }
    }

    let prior = report.prior_log_odds().expect("2,868 candidates have a prior");
    assert!((prior - -7.962_763_930_168_115).abs() < 1e-9, "the prior moved: {prior}");
}

#[test]
fn all_three_still_have_their_bytes_and_still_say_where_they_came_from() {
    let Some(report) = ransomware_run() else { return };

    for (candidate, (path, _, size)) in findings(&report).iter().zip(FINDINGS) {
        match &candidate.acquisition {
            Acquisition::Withheld { via, size: got, recovery } => {
                assert_eq!(*got, size, "{path} came back {got} bytes, was {size}");
                assert_eq!(*via, ArtifactSource::Mft, "{path} no longer comes off the $MFT");
                assert_eq!(
                    *recovery,
                    Recovery::Intact,
                    "{path} is no longer read where the filesystem says it lives; a weaker \
                     recovery state here is a different claim about the same bytes"
                );
            }
            other => panic!(
                "{path} was recovered as {other:?}. All three of this run's findings had their \
                 bytes read whole from a live $MFT record and withheld by --no-samples."
            ),
        }
    }
}

#[test]
fn the_mass_encryption_section_still_holds_every_number_it_was_built_to_hold() {
    let Some(report) = ransomware_run() else { return };
    let found = report.mass_encryption.as_ref().expect(
        "this run's whole point is that it detected the encryption; a report with no \
         mass_encryption section is the regression",
    );

    assert_eq!(found.extension, "fuckazov");
    assert_eq!(found.files, 2_666);
    assert_eq!(found.directories, 476);

    assert_eq!(
        found.files_scanned, 444_482,
        "the count of live files the scan considered is the denominator the honesty of the \
         section rests on"
    );
    assert!(found.files < found.files_scanned, "a cohort cannot be larger than the scan");

    assert_eq!(found.note_name, "stop_propaganda.txt");
    assert_eq!(found.note_size, 131);
    assert_eq!(found.note_directories, 477);
    assert!(
        (found.note_coverage - 1.0).abs() < 1e-9,
        "the note was in every directory of the cohort: {}",
        found.note_coverage
    );
    assert_eq!(found.note_example, r"\Users\Alice\Desktop\stop_propaganda.txt");

    assert_eq!(found.original_extensions.first(), Some(&("js".to_string(), 1_862)));
    assert_eq!(found.original_extensions.len(), 16);
    assert_eq!(
        found.original_extensions.iter().map(|(_, n)| n).sum::<u64>(),
        found.files,
        "every renamed file is accounted for under some original extension"
    );

    assert_eq!(found.roots.first(), Some(&(r"\Users\Alice".to_string(), 2_656)));
    assert_eq!(found.roots.get(1), Some(&(r"\Users\Public".to_string(), 10)));

    let (first, last) = found.window().expect("both ends of the burst are known");
    assert_eq!(first.to_rfc3339(), "2026-05-09T18:42:00.693693700+00:00");
    assert_eq!(last.to_rfc3339(), "2026-05-09T18:42:58.634435700+00:00");
    assert_eq!((last - first).num_seconds(), 57);
}

#[test]
fn the_report_the_analyst_reads_still_says_all_of_it() {
    let Some(report) = ransomware_run() else { return };
    let text = mm_report::text::render(&report);

    assert!(text.contains("FINDINGS — 3 candidates above 0.50"), "{}", head(&text));
    for (path, probability, size) in FINDINGS {
        assert!(text.contains(path), "the report no longer names {path}");
        assert!(
            text.contains(&format!("p = {probability:.2}")),
            "the report no longer prints p = {probability:.2}"
        );
        assert!(
            text.contains(&format!("{} bytes", thousands(size))),
            "the report no longer says how many bytes came back for {path}"
        );
    }

    assert!(text.contains("THIS MACHINE'S OWN FILES WERE ENCRYPTED"), "{}", head(&text));
    assert!(
        text.contains("2 666 of the 444 482 live files this scan considered"),
        "the encryption count lost its denominator"
    );
    assert!(text.contains("`.fuckazov`"), "the appended extension is gone");
    assert!(text.contains("476 directories"), "the directory count is gone");
    assert!(text.contains("stop_propaganda.txt"), "the note is gone");
    assert!(text.contains("does NOT establish"), "the limits of the claim are gone");

    for feature in EVIDENCE.iter().flat_map(|rows| rows.iter().map(|(f, _)| f)) {
        assert!(text.contains(feature), "the evidence rows no longer name the feature `{feature}`");
    }
    assert!(
        text.contains("persistence_targets_user_profile · from startup"),
        "the Startup entry behind the +3.1 is not printed beside it"
    );
    assert!(
        text.contains("              persistence_run_key")
            && !text.contains("persistence_run_key ·"),
        "a source the row had already named was repeated under it"
    );
    assert!(
        text.contains("unsigned_in_user_zone · from file content"),
        "the bytes-derived source of the signature row is not printed"
    );

    assert!(text.contains("malmathic explain <feature>"), "the weight table is unreachable again");
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

fn head(text: &str) -> String {
    text.lines().take(40).collect::<Vec<_>>().join("\n")
}
