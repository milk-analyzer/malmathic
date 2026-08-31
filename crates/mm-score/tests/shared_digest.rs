use mm_core::{ArtifactSource, Candidate, FileHash, NormalizedPath, Observation, ObservationKind};
use mm_score::baseline::BaselineBuilder;
use mm_score::{Baseline, Weights};

fn path(p: &str) -> NormalizedPath {
    NormalizedPath::parse(p).unwrap()
}

fn baseline() -> Baseline {
    let mut b = BaselineBuilder::new();
    for i in 0..12_000 {
        b.observe(&path(&format!(r"C:\Windows\System32\f{i}.dll")));
    }
    b.build()
}

fn two(a: &str, a_bytes: &[u8], b: &str, b_bytes: &[u8]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (n, (p, bytes)) in [(a, a_bytes), (b, b_bytes)].into_iter().enumerate() {
        let mut c = Candidate::new(mm_core::CandidateId(n as u32), -8.0);
        let mut existence = Observation::about_path(
            ArtifactSource::Mft,
            path(p),
            ObservationKind::FileExists {
                size: bytes.len() as u64,
                created: None,
                modified: None,
                mft_modified: None,
                record: None,
            },
        );
        existence.hash = FileHash::compute(bytes);
        c.observe(existence);
        out.push(c);
    }
    out
}

fn fires(candidates: &[Candidate], which: usize) -> bool {
    let evidence = mm_score::extract(&candidates[which], &baseline(), &Weights::embedded());
    evidence.iter().any(|e| e.feature == "shared_digest_renamed_copy")
}

const PAYLOAD: &[u8] = b"MZ the dropper's bytes, whatever they are";
const OTHER: &[u8] = b"MZ a completely unrelated program";

#[test]
fn a_renamed_copy_in_another_zone_is_evidence_for_both_copies() {
    let mut c = two(
        r"C:\Users\bob\AppData\Roaming\svchost.exe",
        PAYLOAD,
        r"C:\Users\bob\Desktop\954d8fcd6b74d76999f9ec033ca855ff.exe",
        PAYLOAD,
    );
    assert_eq!(mm_score::graph::link_shared_digests(&mut c), 2);
    assert!(fires(&c, 0), "the copy under the system binary's name must collect it");
    assert!(fires(&c, 1), "and so must the one it was copied from — neither is the seed");
}

#[test]
fn a_copy_that_keeps_its_name_is_not_evidence() {
    let mut c = two(
        r"C:\Program Files (x86)\Google\GoogleUpdater\152.0.7933.0\updater.exe",
        PAYLOAD,
        r"C:\Users\bob\AppData\Local\Google\GoogleUpdater\152.0.7933.0\updater.exe",
        PAYLOAD,
    );
    assert_eq!(
        mm_score::graph::link_shared_digests(&mut c),
        2,
        "the FACT is still recorded — the report may still print it"
    );
    assert!(!fires(&c, 0), "an installer's own second copy is not a finding");
    assert!(!fires(&c, 1));
}

#[test]
fn a_rename_within_one_zone_is_not_evidence() {
    let mut c = two(
        r"C:\Program Files\Git\cmd\git.exe",
        PAYLOAD,
        r"C:\Program Files\Git\cmd\scalar.exe",
        PAYLOAD,
    );
    assert_eq!(mm_score::graph::link_shared_digests(&mut c), 2);
    assert!(!fires(&c, 0));
    assert!(!fires(&c, 1));
}

#[test]
fn an_unlocated_name_is_not_a_second_place() {
    let mut c = two(
        r"C:\Program Files\Common Files\VMware\Drivers\vmci\vmci.sys",
        PAYLOAD,
        "vmci.sys",
        PAYLOAD,
    );
    assert_eq!(
        mm_score::graph::link_shared_digests(&mut c),
        0,
        "a bare module name names no place, so nothing may be said about where else the bytes are"
    );
    assert!(!fires(&c, 0));
}

#[test]
fn two_different_files_are_never_linked() {
    let mut c = two(
        r"C:\Users\bob\AppData\Roaming\svchost.exe",
        PAYLOAD,
        r"C:\Users\bob\Desktop\954d8fcd6b74d76999f9ec033ca855ff.exe",
        OTHER,
    );
    assert_eq!(mm_score::graph::link_shared_digests(&mut c), 0);
    assert!(!fires(&c, 0));
}

#[test]
fn running_the_census_twice_says_what_running_it_once_says() {
    let mut c = two(
        r"C:\Users\bob\AppData\Roaming\svchost.exe",
        PAYLOAD,
        r"C:\Users\bob\Desktop\954d8fcd6b74d76999f9ec033ca855ff.exe",
        PAYLOAD,
    );
    mm_score::graph::link_shared_digests(&mut c);
    let once: Vec<usize> = c
        .iter()
        .map(|x| {
            x.observations
                .iter()
                .filter(|o| matches!(o.kind, ObservationKind::SharedDigestElsewhere { .. }))
                .count()
        })
        .collect();
    mm_score::graph::link_shared_digests(&mut c);
    mm_score::graph::link_shared_digests(&mut c);
    let thrice: Vec<usize> = c
        .iter()
        .map(|x| {
            x.observations
                .iter()
                .filter(|o| matches!(o.kind, ObservationKind::SharedDigestElsewhere { .. }))
                .count()
        })
        .collect();
    assert_eq!(once, vec![1, 1]);
    assert_eq!(once, thrice, "the census is a recompute, not an increment");
}

#[test]
fn no_score_is_an_input_so_nothing_can_feed_back() {
    let mut c = two(
        r"C:\Users\bob\AppData\Roaming\svchost.exe",
        PAYLOAD,
        r"C:\Users\bob\Desktop\954d8fcd6b74d76999f9ec033ca855ff.exe",
        PAYLOAD,
    );
    mm_score::graph::link_shared_digests(&mut c);
    let weights = Weights::embedded();
    let baseline = baseline();
    for candidate in c.iter_mut() {
        candidate.evidence = mm_score::extract(candidate, &baseline, &weights);
    }
    let first: Vec<f64> = c.iter().map(|x| x.logit()).collect();
    for _ in 0..3 {
        mm_score::graph::link_shared_digests(&mut c);
        for index in (0..c.len()).rev() {
            c[index].evidence = mm_score::extract(&c[index], &baseline, &weights);
        }
    }
    let again: Vec<f64> = c.iter().map(|x| x.logit()).collect();
    assert_eq!(first, again, "a second pass changed a score, so something reads one");
}

#[test]
fn the_weight_is_what_the_table_says() {
    let mut c = two(
        r"C:\Users\bob\AppData\Roaming\svchost.exe",
        PAYLOAD,
        r"C:\Users\bob\Desktop\954d8fcd6b74d76999f9ec033ca855ff.exe",
        PAYLOAD,
    );
    mm_score::graph::link_shared_digests(&mut c);
    let evidence = mm_score::extract(&c[0], &baseline(), &Weights::embedded());
    let row = evidence
        .iter()
        .find(|e| e.feature == "shared_digest_renamed_copy")
        .expect("the row must fire on this shape");
    assert!((row.log_lr - 3.0).abs() < 1e-9, "the weight is {}", row.log_lr);
    assert!(
        row.log_lr < mm_score::SMALLEST_MACHINE.single_feature_ceiling(),
        "it must not be able to convict alone on the smallest machine any guard may assume, \
         whose ceiling is {:.4}",
        mm_score::SMALLEST_MACHINE.single_feature_ceiling()
    );
    assert!(
        row.detail.contains("954d8fcd"),
        "the analyst must be told WHERE the other copy is: {}",
        row.detail
    );
}
