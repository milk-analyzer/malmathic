use mm_core::{
    ArtifactSource, FileHash, NormalizedPath, Observation, ObservationKind, PersistenceKind,
};
use mm_score::baseline::BaselineBuilder;
use mm_score::{Baseline, Weights};

fn path(p: &str) -> NormalizedPath {
    NormalizedPath::parse(p).unwrap()
}

fn baseline(with_decoy: bool) -> Baseline {
    let mut b = BaselineBuilder::new();
    for i in 0..12_000 {
        b.observe(&path(&format!(r"C:\Windows\System32\f{i}.dll")));
    }
    for i in 0..40 {
        b.observe(&path(&format!(r"C:\Users\bob\Documents\report{i}.xlsx")));
    }
    b.observe(&path(r"C:\Users\bob\Documents\svc.exe"));
    if with_decoy {
        for i in 0..6 {
            b.observe(&path(&format!(r"C:\Program Files\App\lib{i}.dll")));
        }
        b.observe(&path(r"C:\Program Files\App\svc.exe"));
    }
    b.build()
}

const PAYLOAD: &str = r"C:\Users\bob\Documents\svc.exe";
const DECOY: &str = r"C:\Program Files\App\svc.exe";

fn observations(with_decoy: bool) -> Vec<Observation> {
    let hash = FileHash::compute(b"the payload's bytes");
    let mut out = Vec::new();
    if with_decoy {
        out.push(
            Observation::about_path(
                ArtifactSource::Amcache,
                path(DECOY),
                ObservationKind::HashRecovered,
            )
            .with_hash(hash.clone()),
        );
    }
    out.push(
        Observation::about_path(
            ArtifactSource::Amcache,
            path(PAYLOAD),
            ObservationKind::HashRecovered,
        )
        .with_hash(hash),
    );
    out.push(Observation::about_path(
        ArtifactSource::Registry { hive: "NTUSER.DAT (bob)".into(), key: r"Run\svc".into() },
        path(PAYLOAD),
        ObservationKind::Persistence { kind: PersistenceKind::RunKey, raw_value: PAYLOAD.into() },
    ));
    out.push(Observation::about_path(
        ArtifactSource::Mft,
        path(PAYLOAD),
        ObservationKind::FileExists {
            size: 90_112,
            created: None,
            modified: None,
            mft_modified: None,
            record: None,
        },
    ));
    out
}

fn score(with_decoy: bool) -> (String, f64, usize) {
    let (l, p, n, _) = score_detailed(with_decoy);
    (l, p, n)
}

fn score_detailed(with_decoy: bool) -> (String, f64, usize, Vec<String>) {
    let b = baseline(with_decoy);
    let mut candidates = mm_score::graph::build(observations(with_decoy), -8.5);
    let n = candidates.len();
    for c in &mut candidates {
        c.evidence = mm_score::extract(c, &b, &Weights::embedded());
    }
    let persisted = candidates
        .iter()
        .find(|c| {
            c.observations.iter().any(|o| matches!(o.kind, ObservationKind::Persistence { .. }))
        })
        .expect("the Run key has to belong to some candidate");
    let features = persisted.evidence.iter().map(|e| e.feature.clone()).collect();
    (persisted.label(), persisted.probability(), n, features)
}

#[test]
fn the_payload_alone_is_scored_at_its_own_path() {
    let (label, p, n) = score(false);
    assert_eq!(label, PAYLOAD);
    assert_eq!(n, 1);
    assert!(p > 0.5, "the payload alone scored {p:.4}");
}

#[test]
fn an_identical_decoy_copy_neither_relocates_nor_exonerates() {
    let (alone_label, alone, _) = score(false);
    let (decoy_label, decoy, n) = score(true);
    assert_eq!(n, 2, "two paths are two candidates");
    assert_eq!(
        decoy_label, alone_label,
        "the report named a path the Run key, the $MFT and one Amcache row never mentioned"
    );
    assert!(decoy > 0.5, "the payload fell below the reporting threshold: {decoy:.4}");

    let (_, _, _, alone_features) = score_detailed(false);
    let (_, _, _, decoy_features) = score_detailed(true);
    let drop: Vec<&String> =
        alone_features.iter().filter(|f| !decoy_features.contains(f)).collect();
    assert_eq!(
        drop,
        vec![&"name_unique_on_machine".to_string()],
        "{alone_features:?} -> {decoy_features:?}"
    );
    assert!(alone > decoy && alone - decoy < 0.1, "{alone:.4} -> {decoy:.4}");
}
