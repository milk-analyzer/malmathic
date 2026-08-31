use std::path::PathBuf;

use mm_core::Candidate;
use mm_score::window::{Detection, IncidentWindow};

const CASE_ENV: &str = "MM_CASE_JSON";
const REPORTING_THRESHOLD: f64 = 0.5;

const NAIVE_FLOOR: f64 = 0.45;

fn reference_candidates() -> Vec<Candidate> {
    let named = std::env::var(CASE_ENV).unwrap_or_else(|_| {
        panic!(
            "{CASE_ENV} is not set. This test measures the incident window against a real \
             clean machine's candidates, and no case file ships with this repository: point \
             {CASE_ENV} at a report.json from a machine you believe is clean."
        )
    });
    let path = PathBuf::from(named);
    assert!(path.exists(), "{CASE_ENV} names {}, which does not exist", path.display());
    let text = std::fs::read_to_string(&path).expect("the case file must be readable");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("the case file must be valid JSON");
    let candidates = value.get("candidates").expect("a report.json has a candidates array").clone();
    serde_json::from_value(candidates).expect("candidates must deserialise into mm-core")
}

#[test]
#[ignore = "set MM_CASE_JSON to a clean machine's report.json; none ships here"]
fn no_incident_window_forms_on_the_reference_machine() {
    let candidates = reference_candidates();

    let strongest = candidates.iter().map(Candidate::probability).fold(0.0f64, f64::max);
    eprintln!("{} candidates, strongest p = {strongest:.3}", candidates.len());

    let detection = IncidentWindow::detect(&candidates, REPORTING_THRESHOLD);
    eprintln!("detection: {}", detection.describe());

    match detection {
        Detection::NoSeed { strongest: s } => {
            assert!(s < REPORTING_THRESHOLD);
            assert!((s - strongest).abs() < 1e-12);
        }
        Detection::Found(window) => panic!(
            "a window formed on a machine with no finding: {} — it would hand +1.8 to {} \
             candidates",
            window.describe(),
            window.members()
        ),
        other => panic!(
            "the window was declined for the wrong reason ({}); on a machine with no finding \
             the refusal must happen at the seeding rule, before any clustering at all",
            other.describe()
        ),
    }
}

#[test]
#[ignore = "set MM_CASE_JSON to a clean machine's report.json; none ships here"]
fn the_naive_design_would_have_manufactured_a_finding_here() {
    let mut candidates = reference_candidates();

    let top = candidates
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.logit().partial_cmp(&b.1.logit()).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)
        .expect("the reference machine has candidates");

    let before = candidates[top].probability();
    if before >= REPORTING_THRESHOLD {
        eprintln!("SKIPPED: this case file already has a finding, so there is nothing to fake");
        return;
    }

    let lift = -candidates[top].logit() + 0.001;
    candidates[top].evidence.push(mm_core::Evidence::new("forced", lift, "the naive seeding rule"));

    let detection = IncidentWindow::detect(&candidates, REPORTING_THRESHOLD);
    let window = match &detection {
        Detection::Found(w) => w,
        other => {
            eprintln!("SKIPPED: even forced, no burst formed here ({})", other.describe());
            return;
        }
    };

    let seeded_by_itself = candidates[top]
        .observations
        .iter()
        .filter_map(|o| match &o.kind {
            mm_core::ObservationKind::FileExists { created, .. } => *created,
            _ => None,
        })
        .any(|t| window.contains(t));

    let after = 1.0 / (1.0 + (-(candidates[top].logit() - lift + 1.8)).exp());
    eprintln!(
        "naive window {} — the seed's own creation time is inside it: {seeded_by_itself}; \
         it scored {before:.4} before and {after:.4} after collecting +1.8, and the window \
         would offer that to {} candidates",
        window.describe(),
        window.members()
    );
    assert!(
        seeded_by_itself,
        "the point of the measurement is that a naive window contains its own seed"
    );
    assert!(
        after >= NAIVE_FLOOR,
        "the naive rule lifted this machine's strongest benign file from {before:.4} only to \
         {after:.4}, which is below the floor the rationale claims for it"
    );
}
