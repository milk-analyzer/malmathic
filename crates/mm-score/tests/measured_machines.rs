use std::path::{Path, PathBuf};

use mm_score::machine::{self, Machine};
use mm_score::weights::feature;
use mm_score::Weights;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("mm-score lives two directories below the repository root")
        .to_path_buf()
}

fn population_of(path: &Path) -> Option<(usize, f64)> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));
    let candidates = value["candidates"].as_array()?;
    let prior = candidates.first()?["prior_log_odds"].as_f64()?;
    Some((candidates.len(), prior))
}

fn for_each_dataset(check: impl Fn(&str, &Machine, usize, f64)) {
    let root = repo_root();
    let mut seen = 0;
    for (rel, table) in machine::MEASURED_MACHINES {
        let path = root.join(rel);
        let Some((count, prior)) = population_of(&path) else {
            eprintln!("SKIPPED: {rel} is not present at {}", path.display());
            continue;
        };
        seen += 1;
        check(rel, table, count, prior);
    }
    assert!(
        seen > 0,
        "not one dataset was readable, so this test measured nothing. That is the state the \
         whole suite was in before this file existed, and it must not be reported as a pass."
    );
}

#[test]
#[ignore = "needs the VM_TESTS datasets, which are not published; run with --ignored where they exist"]
fn the_recorded_populations_still_match_the_reports() {
    for_each_dataset(|rel, table, count, prior| {
        assert_eq!(
            table.candidates, count,
            "{rel} holds {count} candidates, but `mm_score::machine::MEASURED_MACHINES` records \
             {} ({}, counted {}). A dataset changing size moves the prior and therefore the \
             headroom under every weight in the table — update the constant, then re-read every \
             rationale that quotes this machine.",
            table.candidates, table.what, table.measured,
        );
        let implied = -(table.effective_population as f64).ln();
        assert!(
            (prior - implied).abs() < 0.001,
            "{rel} records a prior of {prior:.4}, which is -ln({:.0}), but \
             `MEASURED_MACHINES` says it priced against {} candidates (-ln = {implied:.4}). \
             The prior is what the reporting threshold is compared against, so this field \
             must be the population the run really used.",
            (-prior).exp(),
            table.effective_population,
        );
    });
}

#[test]
#[ignore = "needs the VM_TESTS datasets, which are not published; run with --ignored where they exist"]
fn no_av_verdict_convicts_alone_on_any_dataset_in_the_tree() {
    let weights = Weights::embedded();
    let most = weights.max_log_lr_in_group("antivirus");
    for_each_dataset(|rel, table, count, _| {
        let prior = table.prior();
        let alone = prior + most;
        assert!(
            alone < 0.0,
            "on {rel} ({count} candidates, prior {prior:.4}) an antivirus verdict ALONE reaches \
             {alone:+.4} log-odds — p = {:.4}. A file Defender dealt with months ago is a \
             present accusation on this machine.",
            1.0 / (1.0 + (-alone).exp()),
        );
        let with_companion = alone + machine::CHEAPEST_UBIQUITOUS_ROW;
        assert!(
            with_companion < 0.0,
            "on {rel} ({count} candidates) an antivirus verdict plus one +{:.1} row that fires on \
             a third of the volume reaches {with_companion:+.4} log-odds — p = {:.4}.",
            machine::CHEAPEST_UBIQUITOUS_ROW,
            1.0 / (1.0 + (-with_companion).exp()),
        );
    });
}

#[test]
#[ignore = "needs the VM_TESTS datasets, which are not published; run with --ignored where they exist"]
fn no_undeclared_row_convicts_alone_on_any_dataset_in_the_tree() {
    let weights = Weights::embedded();
    for_each_dataset(|rel, table, count, _| {
        let prior = table.prior();
        for (name, w) in weights.all() {
            if w.convicts_alone.is_some() {
                continue;
            }
            let reached = prior + w.log_lr + machine::CHEAPEST_UBIQUITOUS_ROW;
            assert!(
                reached < 0.0,
                "on {rel} ({count} candidates, prior {prior:.4}) the row `{name}` at {:+} plus \
                 one +{:.1} companion reaches {reached:+.4} log-odds with nothing else against \
                 the file, and does not declare `convicts_alone`.",
                w.log_lr,
                machine::CHEAPEST_UBIQUITOUS_ROW,
            );
        }
    });
}

#[test]
fn the_njrat_findings_survive_on_the_dataset_that_holds_them() {
    let root = repo_root();
    let path = root.join("VM_TESTS/test_4/report.json");
    let Some((count, _)) = population_of(&path) else {
        eprintln!("SKIPPED: VM_TESTS/test_4/report.json is not present");
        return;
    };
    let weights = Weights::embedded();
    let ln_n = (count as f64).ln();

    let downloads: f64 = [
        feature::QUARANTINED_BY_AV,
        feature::RANDOM_LOOKING_NAME,
        feature::EXECUTABLE_RARE_FOR_ZONE,
        feature::UNSIGNED_IN_USER_ZONE,
        feature::NAME_UNIQUE_ON_MACHINE,
    ]
    .iter()
    .map(|f| weights.get(f).unwrap().log_lr)
    .sum();

    let server: f64 = [
        feature::PERSISTENCE_TARGETS_SCRATCH_SPACE,
        feature::LONE_EXECUTABLE_AMONG_DOCUMENTS,
        feature::PERSISTENCE_RUN_KEY,
        feature::UNSIGNED_IN_USER_ZONE,
        feature::NAME_UNIQUE_ON_MACHINE,
    ]
    .iter()
    .map(|f| weights.get(f).unwrap().log_lr)
    .sum();

    for (what, evidence) in
        [("the Downloads copy", downloads), ("Windows\\TEMP\\server.exe", server)]
    {
        assert!(
            evidence > ln_n,
            "{what} carries {evidence:+} against a machine of {count} candidates (ln = \
             {ln_n:.4}), so it no longer clears the reporting threshold. VM_TESTS/test_4 must \
             keep both njRAT findings — that is the detection end of the constraint."
        );
    }

    let without_av = downloads - weights.get(feature::QUARANTINED_BY_AV).unwrap().log_lr;
    assert!(
        without_av > 6.0,
        "the Downloads copy carries only {without_av:+} once the antivirus row is removed; the \
         finding would then rest on Defender's opinion alone."
    );
}
