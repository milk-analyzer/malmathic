use crate::{ArtifactSource, FileHash, HashCheck, NormalizedPath, Observation};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct CandidateId(pub u32);

impl std::fmt::Display for CandidateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "C{:03}", self.0)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    pub feature: String,
    pub log_lr: f64,
    pub detail: String,
    pub sources: Vec<ArtifactSource>,
}

impl Evidence {
    pub fn new(feature: impl Into<String>, log_lr: f64, detail: impl Into<String>) -> Self {
        Evidence { feature: feature.into(), log_lr, detail: detail.into(), sources: Vec::new() }
    }

    pub fn from(mut self, source: ArtifactSource) -> Self {
        self.sources.push(source);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Recovery {
    Intact,
    UnlinkedButPresent { detail: String },
    Confirmed { against: String },
    Unverified { basis: String },
    Partial { detail: String },
}

impl Recovery {
    pub fn is_trustworthy(&self) -> bool {
        matches!(
            self,
            Recovery::Intact | Recovery::UnlinkedButPresent { .. } | Recovery::Confirmed { .. }
        )
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Acquisition {
    NotAttempted,
    Bytes { via: ArtifactSource, size: u64, saved_as: String, recovery: Recovery },
    HashOnly { via: ArtifactSource },
    Withheld { via: ArtifactSource, size: u64, recovery: Recovery },
    Failed { reason: String },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Candidate {
    pub id: CandidateId,
    pub path: Option<NormalizedPath>,
    pub hash: FileHash,
    #[serde(default)]
    pub acquired_hash: Option<FileHash>,
    #[serde(default)]
    pub hash_checks: Vec<HashCheck>,
    pub observations: Vec<Observation>,
    pub evidence: Vec<Evidence>,
    pub prior_log_odds: f64,
    pub acquisition: Acquisition,
}

impl Candidate {
    pub fn new(id: CandidateId, prior_log_odds: f64) -> Self {
        Candidate {
            id,
            path: None,
            hash: FileHash::default(),
            acquired_hash: None,
            hash_checks: Vec::new(),
            observations: Vec::new(),
            evidence: Vec::new(),
            prior_log_odds,
            acquisition: Acquisition::NotAttempted,
        }
    }

    pub fn observe(&mut self, observation: Observation) {
        if self.path.is_none() {
            self.path = observation.path.clone();
        }
        if self.hash.is_empty()
            || observation.hash.is_empty()
            || self.hash.same_file_as(&observation.hash) == Some(true)
        {
            self.hash.merge(&observation.hash);
        }
        self.observations.push(observation);
    }

    pub fn recorded_hash(&self) -> Option<(&ArtifactSource, &FileHash)> {
        self.observations.iter().find(|o| !o.hash.is_empty()).map(|o| (&o.source, &o.hash))
    }

    pub fn record_acquired_hash(&mut self, computed: &FileHash, adopt: bool) {
        let recorded: Vec<(String, FileHash)> = self
            .observations
            .iter()
            .filter(|o| !o.hash.is_empty())
            .map(|o| (o.source.label(), o.hash.clone()))
            .collect();
        for (label, hash) in recorded {
            for check in hash.checked_against(computed, &label) {
                if !self.hash_checks.contains(&check) {
                    self.hash_checks.push(check);
                }
            }
        }
        self.acquired_hash = Some(computed.clone());
        if adopt {
            self.hash.supersede_with(computed);
        }
    }

    pub fn hash_disagreements(&self) -> impl Iterator<Item = &HashCheck> {
        self.hash_checks.iter().filter(|c| !c.agrees)
    }

    pub fn logit(&self) -> f64 {
        self.prior_log_odds + self.evidence.iter().map(|e| e.log_lr).sum::<f64>()
    }

    pub fn probability(&self) -> f64 {
        logistic(self.logit())
    }

    pub fn corroboration(&self) -> usize {
        let mut families: Vec<&str> = self.observations.iter().map(|o| o.source.family()).collect();
        families.sort_unstable();
        families.dedup();
        families.len()
    }

    pub fn absorb(&mut self, other: Candidate) {
        self.path = self.path.take().or(other.path);
        self.hash.merge(&other.hash);
        if let Some(acquired) = other.acquired_hash {
            if self.acquired_hash.is_none() {
                self.hash.supersede_with(&acquired);
                self.acquired_hash = Some(acquired);
            }
        }
        for check in other.hash_checks {
            if !self.hash_checks.contains(&check) {
                self.hash_checks.push(check);
            }
        }
        self.observations.extend(other.observations);
        self.evidence.extend(other.evidence);
    }

    pub fn matches(&self, observation: &Observation) -> bool {
        if !self.hash.is_empty()
            && !observation.hash.is_empty()
            && self.hash.agrees_with(&observation.hash)
        {
            return true;
        }
        match (&self.path, &observation.path) {
            (Some(a), Some(b)) => a.key() == b.key(),
            _ => false,
        }
    }

    pub fn label(&self) -> String {
        if let Some(p) = &self.path {
            return p.display_path().to_string();
        }
        match self.hash.best() {
            Some(h) => format!("<no path known> {h}"),
            None => "<unidentified>".to_string(),
        }
    }
}

pub fn logistic(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObservationKind, PersistenceKind};

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).unwrap()
    }

    fn candidate() -> Candidate {
        Candidate::new(CandidateId(1), (1.0f64 / 10_000.0).ln())
    }

    #[test]
    fn two_artifacts_with_no_algorithm_in_common_do_not_become_one_identity() {
        let old_file = FileHash::compute(b"the file as Amcache saw it");
        let new_file = FileHash::compute(b"the file the Defender log saw");

        let amcache = FileHash::from_sha1_hex(&old_file.sha1_hex().unwrap()).unwrap();
        let defender = FileHash::from_sha256_hex(&new_file.sha256_hex().unwrap()).unwrap();
        assert_eq!(amcache.same_file_as(&defender), None, "nothing in common to compare");

        let mut c = candidate();
        c.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\Users\\bob\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(amcache.clone()),
        );
        c.observe(
            Observation::about_path(
                ArtifactSource::DefenderLog { event_id: 1116 },
                path("C:\\Users\\bob\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(defender.clone()),
        );

        assert_eq!(c.hash.sha1, amcache.sha1, "the first artifact's claim stands");
        assert_eq!(
            c.hash.sha256, None,
            "and the second's must NOT join it: nothing established they are one file"
        );
        assert_eq!(c.observations.len(), 2);
        assert_eq!(c.observations[1].hash.sha256, defender.sha256);
    }

    #[test]
    fn corroborating_artifacts_still_fill_each_others_gaps() {
        let file = FileHash::compute(b"one file, seen twice");
        let by_sha1 = FileHash::from_sha1_hex(&file.sha1_hex().unwrap()).unwrap();
        let mut both = FileHash::from_sha1_hex(&file.sha1_hex().unwrap()).unwrap();
        both.sha256 = file.sha256;

        let mut c = candidate();
        for hash in [by_sha1, both] {
            c.observe(
                Observation::about_path(
                    ArtifactSource::Amcache,
                    path("C:\\Users\\bob\\x.exe"),
                    ObservationKind::HashRecovered,
                )
                .with_hash(hash),
            );
        }
        assert_eq!(c.hash.sha1, file.sha1);
        assert_eq!(c.hash.sha256, file.sha256, "a shared SHA-1 agreed, so the gap fills");
    }

    #[test]
    fn a_contradicting_artifact_contributes_nothing_to_the_identity() {
        let known = FileHash::compute(b"what the candidate already knows");
        let other = FileHash::compute(b"a different file entirely");

        let mut c = candidate();
        c.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\Users\\bob\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(&known.sha1_hex().unwrap()).unwrap()),
        );
        let mut contradicting = FileHash::from_sha1_hex(&other.sha1_hex().unwrap()).unwrap();
        contradicting.md5 = other.md5;
        c.observe(
            Observation::about_path(
                ArtifactSource::DefenderLog { event_id: 1116 },
                path("C:\\Users\\bob\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(contradicting),
        );

        assert_eq!(c.hash.sha1, known.sha1);
        assert_eq!(c.hash.md5, None, "a file known to be a different one fills no gaps");
    }

    #[test]
    fn logistic_is_stable_at_both_extremes() {
        assert!((logistic(0.0) - 0.5).abs() < 1e-12);
        assert!(logistic(1000.0).is_finite() && logistic(1000.0) > 0.999);
        assert!(logistic(-1000.0).is_finite());
        assert!(logistic(-1000.0) >= 0.0);
        assert!((logistic(2.0) + logistic(-2.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn evidence_sums_into_the_logit() {
        let mut c = candidate();
        let prior = c.prior_log_odds;
        c.evidence.push(Evidence::new("a", 2.0, ""));
        c.evidence.push(Evidence::new("b", 3.0, ""));
        assert!((c.logit() - (prior + 5.0)).abs() < 1e-12);
    }

    #[test]
    fn negative_evidence_pulls_the_score_down() {
        let mut c = candidate();
        c.evidence.push(Evidence::new("unsigned", 4.0, ""));
        let raised = c.probability();
        c.evidence.push(Evidence::new("ms_catalog_signed", -8.0, ""));
        assert!(c.probability() < raised);
        assert!(c.probability() < 0.01);
    }

    #[test]
    fn prior_suppresses_isolated_weak_evidence() {
        let mut c = candidate();
        c.evidence.push(Evidence::new("in_temp_dir", 1.5, ""));
        assert!(c.probability() < 0.01, "got {}", c.probability());
    }

    #[test]
    fn stacked_strong_evidence_overcomes_the_prior() {
        let mut c = candidate();
        for f in ["unsigned_in_userdir", "run_key_persistence", "self_deleted", "yara_match"] {
            c.evidence.push(Evidence::new(f, 4.0, ""));
        }
        assert!(c.probability() > 0.8, "got {}", c.probability());
    }

    #[test]
    fn corroboration_counts_families_not_rows() {
        let mut c = candidate();
        for source in [ArtifactSource::Amcache, ArtifactSource::Prefetch, ArtifactSource::ShimCache]
        {
            c.observe(Observation::about_path(
                source,
                path("C:\\x.exe"),
                ObservationKind::Executed { when: None, run_count: None },
            ));
        }
        assert_eq!(c.corroboration(), 1, "three execution artifacts are one family");

        c.observe(Observation::about_path(
            ArtifactSource::Registry { hive: "NTUSER".into(), key: "Run".into() },
            path("C:\\x.exe"),
            ObservationKind::Persistence {
                kind: PersistenceKind::RunKey,
                raw_value: "C:\\x.exe".into(),
            },
        ));
        assert_eq!(c.corroboration(), 2);
    }

    #[test]
    fn matching_works_by_path_or_by_hash() {
        let mut c = candidate();
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path("C:\\Users\\bob\\x.exe"),
            ObservationKind::HashRecovered,
        ));

        let same_path = Observation::about_path(
            ArtifactSource::ShimCache,
            path("\\??\\C:\\Users\\bob\\x.exe"),
            ObservationKind::Executed { when: None, run_count: None },
        );
        assert!(c.matches(&same_path));

        let other = Observation::about_path(
            ArtifactSource::Mft,
            path("C:\\Users\\bob\\y.exe"),
            ObservationKind::HashRecovered,
        );
        assert!(!c.matches(&other));

        c.hash = FileHash::compute(b"payload");
        let by_hash = Observation::about_hash(
            ArtifactSource::DefenderLog { event_id: 1116 },
            FileHash::compute(b"payload"),
            ObservationKind::HashRecovered,
        );
        assert!(c.matches(&by_hash));
    }

    #[test]
    fn absent_identity_never_matches() {
        let c = candidate();
        let o = Observation::about_hash(
            ArtifactSource::DefenderLog { event_id: 1116 },
            FileHash::compute(b"x"),
            ObservationKind::HashRecovered,
        );
        assert!(!c.matches(&o));
    }

    #[test]
    fn absorb_unions_identity_and_evidence() {
        let mut a = candidate();
        a.observe(Observation::about_path(
            ArtifactSource::Mft,
            path("C:\\x.exe"),
            ObservationKind::HashRecovered,
        ));
        a.evidence.push(Evidence::new("a", 1.0, ""));

        let mut b = Candidate::new(CandidateId(2), a.prior_log_odds);
        b.hash = FileHash::compute(b"payload");
        b.evidence.push(Evidence::new("b", 2.0, ""));

        a.absorb(b);
        assert_eq!(a.path.as_ref().unwrap().key(), "\\x.exe");
        assert!(a.hash.sha256.is_some());
        assert_eq!(a.evidence.len(), 2);
    }

    #[test]
    fn label_falls_back_from_path_to_hash() {
        let mut c = candidate();
        assert_eq!(c.label(), "<unidentified>");
        c.hash = FileHash::compute(b"x");
        assert!(c.label().starts_with("<no path known> "));
        c.path = Some(path("C:\\Users\\bob\\x.exe"));
        assert_eq!(c.label(), "C:\\Users\\bob\\x.exe");
    }

    #[test]
    fn bytes_read_this_run_outrank_an_artifacts_claim() {
        let stale = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut c = candidate();
        c.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha1_hex(stale).unwrap()),
        );
        assert_eq!(c.hash.sha1_hex().as_deref(), Some(stale));

        let bytes = FileHash::compute(b"what is at that path now");
        c.record_acquired_hash(&bytes, true);

        assert_eq!(c.hash.sha1_hex(), bytes.sha1_hex());
        assert_eq!(c.acquired_hash.as_ref().unwrap(), &bytes);
        let disagreements: Vec<_> = c.hash_disagreements().collect();
        assert_eq!(disagreements.len(), 1);
        assert_eq!(disagreements[0].recorded, stale);
        assert_eq!(disagreements[0].recorded_by, "Amcache");
    }

    #[test]
    fn unvouched_bytes_are_recorded_without_taking_over_the_identity() {
        let recorded = FileHash::from_sha1_hex(&"bc".repeat(20)).unwrap();
        let mut c = candidate();
        c.observe(
            Observation::about_path(
                ArtifactSource::Amcache,
                path("C:\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(recorded.clone()),
        );

        let fragments = FileHash::compute(b"half of another file");
        c.record_acquired_hash(&fragments, false);

        assert_eq!(c.hash.sha1_hex(), recorded.sha1_hex(), "the identity moved");
        assert!(c.hash.sha256.is_none(), "a digest of fragments became the identity");
        assert_eq!(c.acquired_hash.as_ref().unwrap(), &fragments);
        assert_eq!(c.hash_disagreements().count(), 1);
    }

    #[test]
    fn every_artifact_that_recorded_a_hash_is_checked_and_none_twice() {
        let bytes = FileHash::compute(b"the bytes");
        let mut c = candidate();
        for kind in [ObservationKind::HashRecovered, ObservationKind::HashRecovered] {
            c.observe(
                Observation::about_path(ArtifactSource::Amcache, path("C:\\x.exe"), kind)
                    .with_hash(FileHash::from_sha1_hex(&"aa".repeat(20)).unwrap()),
            );
        }
        c.observe(
            Observation::about_path(
                ArtifactSource::DefenderLog { event_id: 1117 },
                path("C:\\x.exe"),
                ObservationKind::HashRecovered,
            )
            .with_hash(FileHash::from_sha256_hex(&bytes.sha256_hex().unwrap()).unwrap()),
        );

        c.record_acquired_hash(&bytes, true);

        assert_eq!(c.hash_checks.len(), 2, "{:?}", c.hash_checks);
        assert_eq!(c.hash_disagreements().count(), 1);
        assert!(c.hash_checks.iter().any(|k| k.agrees && k.recorded_by.contains("Defender")));
    }

    #[test]
    fn absorb_keeps_the_digest_that_came_from_bytes() {
        let bytes = FileHash::compute(b"payload");
        let mut acquired = Candidate::new(CandidateId(2), -9.2);
        acquired.record_acquired_hash(&bytes, true);

        let mut claim = candidate();
        claim.hash = FileHash::from_sha1_hex(&"aa".repeat(20)).unwrap();
        claim.absorb(acquired);

        assert_eq!(claim.hash.sha1_hex(), bytes.sha1_hex());
        assert_eq!(claim.acquired_hash.as_ref().unwrap(), &bytes);
    }
}
