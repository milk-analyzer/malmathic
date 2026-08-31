pub mod redact;
pub mod text;

use mm_core::{Acquisition, Candidate};
use serde::{Deserialize, Serialize};

pub const DEFAULT_THRESHOLD: f64 = 0.5;

pub const NEAR_MISS_LIMIT: usize = 5;

pub fn evidence_log_odds(candidate: &Candidate) -> f64 {
    candidate.evidence.iter().map(|e| e.log_lr).sum()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum BreakEven {
    AtMost(u64),
    Never,
    Always,
}

pub fn break_even_population(evidence_log_odds: f64, threshold: f64) -> BreakEven {
    const ABSURD: f64 = 1e12;

    const SLACK: f64 = 1.0 + 1e-9;

    if evidence_log_odds.is_nan() || !(0.0..1.0).contains(&threshold) {
        return BreakEven::Never;
    }
    let target = (threshold / (1.0 - threshold)).ln();
    let n = ((evidence_log_odds - target).exp() * SLACK).floor();
    if n.is_nan() {
        return BreakEven::Never;
    }
    if n >= ABSURD {
        return BreakEven::Always;
    }
    if n < 2.0 {
        return BreakEven::Never;
    }
    BreakEven::AtMost(n as u64)
}

pub const CLOSE_CALL_RATIO: f64 = 0.60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CloseCall {
    pub in_band: usize,
    pub break_even: BreakEven,
    pub population: u64,
    pub heads_the_ranking: bool,
}

impl CloseCall {
    pub fn times_too_large(&self) -> Option<f64> {
        match self.break_even {
            BreakEven::AtMost(n) if n > 0 && self.population > n => {
                Some(self.population as f64 / n as f64)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CoverageStatus {
    Read { observations: usize },
    Absent,
    Failed { reason: String },
    NotAvailableHere { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactCoverage {
    pub artifact: String,
    #[serde(flatten)]
    pub status: CoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForeignPath {
    pub path: String,
    pub source: String,
    pub claim: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OtherVolume {
    pub volume: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identified_as: Option<String>,
    pub observations: usize,
    pub paths: Vec<ForeignPath>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub artifacts: Vec<ArtifactCoverage>,
    pub files_enumerated: u64,
    pub deleted_records_seen: u64,
    pub baseline_usable: bool,
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_volumes: Vec<OtherVolume>,
}

impl Coverage {
    pub fn record(&mut self, artifact: impl Into<String>, status: CoverageStatus) {
        self.artifacts.push(ArtifactCoverage { artifact: artifact.into(), status, seconds: None });
    }

    pub fn record_timed(
        &mut self,
        artifact: impl Into<String>,
        status: CoverageStatus,
        seconds: f64,
    ) {
        self.artifacts.push(ArtifactCoverage {
            artifact: artifact.into(),
            status,
            seconds: Some(seconds),
        });
    }

    pub fn measured_seconds(&self) -> f64 {
        self.artifacts.iter().filter_map(|a| a.seconds).sum()
    }

    pub fn slowest_stage(&self) -> Option<(&str, f64)> {
        self.artifacts
            .iter()
            .filter_map(|a| a.seconds.map(|s| (a.artifact.as_str(), s)))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
    }

    pub fn failed_stages(&self) -> Vec<(&str, &str)> {
        self.artifacts
            .iter()
            .filter_map(|a| match &a.status {
                CoverageStatus::Failed { reason } => Some((a.artifact.as_str(), reason.as_str())),
                _ => None,
            })
            .collect()
    }

    pub fn looked_everywhere(&self) -> bool {
        self.failed_stages().is_empty()
            && self.warnings.is_empty()
            && self.other_volumes.is_empty()
            && self.baseline_usable
    }

    pub fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    pub fn total_observations(&self) -> usize {
        self.artifacts
            .iter()
            .map(|a| match a.status {
                CoverageStatus::Read { observations } => observations,
                _ => 0,
            })
            .sum()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Target {
    pub display_name: String,
    pub device_path: String,
    pub volume_serial: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub tool_version: String,
    pub environment: String,
    pub target: Target,
    pub candidates: Vec<Candidate>,
    pub coverage: Coverage,
    pub threshold: f64,
    pub weights_calibrated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enumeration: Option<mm_core::Enumeration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mass_encryption: Option<mm_core::MassEncryption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrival_timeline: Option<mm_core::ArrivalTimeline>,
}

impl Report {
    pub fn new(
        tool_version: impl Into<String>,
        environment: impl Into<String>,
        target: Target,
        mut candidates: Vec<Candidate>,
        coverage: Coverage,
        weights_calibrated: bool,
    ) -> Self {
        candidates.sort_by(|a, b| {
            b.probability()
                .partial_cmp(&a.probability())
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });
        Report {
            tool_version: tool_version.into(),
            environment: environment.into(),
            target,
            candidates,
            coverage,
            threshold: DEFAULT_THRESHOLD,
            weights_calibrated,
            enumeration: None,
            wall_clock_seconds: None,
            case_directory: None,
            mass_encryption: None,
            arrival_timeline: None,
        }
    }

    pub fn set_mass_encryption(&mut self, found: mm_core::MassEncryption) {
        self.mass_encryption = Some(found);
    }

    pub fn set_arrival_timeline(&mut self, timeline: mm_core::ArrivalTimeline) {
        self.arrival_timeline = Some(timeline);
    }

    pub fn set_wall_clock(&mut self, seconds: f64) {
        self.wall_clock_seconds = Some(seconds);
    }

    pub fn set_case_directory(&mut self, path: impl Into<String>) {
        self.case_directory = Some(path.into());
    }

    pub fn set_enumeration(&mut self, enumeration: mm_core::Enumeration) {
        self.enumeration = Some(enumeration);
    }

    pub fn prior_established(&self) -> bool {
        match &self.enumeration {
            Some(enumeration) => enumeration.fraction().is_some(),
            None => true,
        }
    }

    pub fn population(&self) -> u64 {
        let counted = self.candidates.len() as u64;
        match &self.enumeration {
            Some(enumeration) => match enumeration.effective_population(self.candidates.len()) {
                Some(population) => population.round().max(counted as f64) as u64,
                None => counted,
            },
            None => counted,
        }
    }

    pub fn reportable(&self) -> impl Iterator<Item = &Candidate> {
        let established = self.prior_established();
        self.candidates.iter().filter(move |c| established && c.probability() >= self.threshold)
    }

    pub fn reportable_count(&self) -> usize {
        self.reportable().count()
    }

    pub fn found_anything(&self) -> bool {
        self.reportable_count() > 0
    }

    pub fn strongest(&self) -> Option<&Candidate> {
        self.candidates.first()
    }

    pub fn prior_log_odds(&self) -> Option<f64> {
        self.candidates.first().map(|c| c.prior_log_odds)
    }

    pub fn evidence_needed(&self) -> Option<f64> {
        let target = (self.threshold / (1.0 - self.threshold)).ln();
        self.prior_log_odds().map(|prior| target - prior)
    }

    pub fn close_call(&self) -> Option<CloseCall> {
        if self.found_anything() {
            return None;
        }

        if !self.prior_established() {
            return None;
        }

        let counted = self.candidates.len().max(2) as f64;
        let implied = (-self.prior_log_odds()?).exp();
        if !implied.is_finite() || implied < 1.0 {
            return None;
        }

        let mut in_band = 0usize;
        let mut strongest: Option<&Candidate> = None;
        for candidate in &self.candidates {
            if candidate.probability() >= self.threshold {
                continue;
            }
            let evidence = evidence_log_odds(candidate);
            let close = match break_even_population(evidence, self.threshold) {
                BreakEven::Always => true,
                BreakEven::Never => false,
                BreakEven::AtMost(n) => {
                    let n = n as f64;
                    n >= CLOSE_CALL_RATIO * counted && n >= CLOSE_CALL_RATIO * implied
                }
            };
            if !close {
                continue;
            }
            in_band += 1;
            let better = match strongest {
                None => true,
                Some(best) => evidence > evidence_log_odds(best),
            };
            if better {
                strongest = Some(candidate);
            }
        }
        let strongest = strongest?;

        Some(CloseCall {
            in_band,
            break_even: break_even_population(evidence_log_odds(strongest), self.threshold),
            population: self.candidates.len() as u64,
            heads_the_ranking: self
                .candidates
                .first()
                .is_some_and(|first| std::ptr::eq(first, strongest)),
        })
    }

    pub fn near_misses(&self, limit: usize) -> Vec<&Candidate> {
        self.ranked_below().take(limit).collect()
    }

    pub fn ranked_below(&self) -> impl Iterator<Item = &Candidate> {
        self.candidates
            .iter()
            .filter(move |c| c.probability() < self.threshold && evidence_log_odds(c) > 0.0)
    }

    pub fn recovered_samples(&self) -> impl Iterator<Item = &Candidate> {
        self.reportable().filter(|c| matches!(c.acquisition, Acquisition::Bytes { .. }))
    }

    pub fn confirmed_samples(&self) -> impl Iterator<Item = &Candidate> {
        self.reportable().filter(|c| {
            matches!(&c.acquisition, Acquisition::Bytes { recovery, .. } if recovery.is_trustworthy())
        })
    }

    pub fn hash_only_samples(&self) -> impl Iterator<Item = &Candidate> {
        self.reportable().filter(|c| matches!(c.acquisition, Acquisition::HashOnly { .. }))
    }

    pub fn from_json(text: &str) -> serde_json::Result<Report> {
        serde_json::from_str(text)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mm_core::{CandidateId, Evidence, NormalizedPath};

    fn target() -> Target {
        Target {
            display_name: "C:".into(),
            device_path: "\\\\?\\Volume{x}".into(),
            volume_serial: "b1a2c3d4e5f60718".into(),
        }
    }

    fn candidate(id: u32, path: &str, log_lr: f64) -> Candidate {
        let mut c = Candidate::new(CandidateId(id), -9.2);
        c.path = NormalizedPath::parse(path);
        c.evidence.push(Evidence::new("f", log_lr, "because"));
        c
    }

    fn report(candidates: Vec<Candidate>) -> Report {
        Report::new("0.1.0", "live Windows", target(), candidates, Coverage::default(), false)
    }

    #[test]
    fn a_run_that_enumerated_nothing_reports_nothing() {
        let mut r = report(vec![candidate(0, "C:\\a.exe", 20.0), candidate(1, "C:\\b.exe", 4.0)]);
        assert_eq!(r.reportable_count(), 1, "the fixture must have something to withhold");

        r.set_enumeration(mm_core::Enumeration::not_attempted());
        assert!(!r.prior_established());
        assert_eq!(r.reportable_count(), 0, "nothing may be reported without a base rate");
        assert!(!r.found_anything());
        assert_eq!(r.candidates.len(), 2);
        assert!(r.close_call().is_none());
    }

    #[test]
    fn a_walk_that_placed_files_still_states_a_base_rate() {
        let mut r = report(vec![candidate(0, "C:\\a.exe", 20.0)]);
        r.set_enumeration(mm_core::Enumeration::partial(1_000, 900));
        assert!(r.prior_established());
        assert_eq!(r.reportable_count(), 1);
    }

    #[test]
    fn a_report_with_no_enumeration_is_unchanged() {
        let r = report(vec![candidate(0, "C:\\a.exe", 20.0)]);
        assert!(r.enumeration.is_none());
        assert!(r.prior_established());
        assert_eq!(r.reportable_count(), 1);
    }

    #[test]
    fn candidates_come_out_strongest_first() {
        let r = report(vec![
            candidate(0, "C:\\a.exe", 2.0),
            candidate(1, "C:\\b.exe", 20.0),
            candidate(2, "C:\\c.exe", 11.0),
        ]);
        let order: Vec<u32> = r.candidates.iter().map(|c| c.id.0).collect();
        assert_eq!(order, vec![1, 2, 0]);
    }

    #[test]
    fn a_clean_machine_produces_no_findings() {
        let r = report(vec![
            candidate(0, "C:\\Windows\\System32\\a.exe", 1.0),
            candidate(1, "C:\\Windows\\System32\\b.exe", 2.0),
            candidate(2, "C:\\Users\\bob\\c.exe", 4.0),
        ]);
        assert!(!r.found_anything());
        assert_eq!(r.reportable_count(), 0);
        assert_eq!(r.strongest().unwrap().id.0, 2);
    }

    #[test]
    fn a_real_finding_clears_the_threshold() {
        let r = report(vec![candidate(0, "C:\\Users\\bob\\x.exe", 12.0)]);
        assert!(r.found_anything());
        assert_eq!(r.reportable_count(), 1);
    }

    #[test]
    fn the_threshold_sits_at_even_odds() {
        assert!((DEFAULT_THRESHOLD - 0.5).abs() < f64::EPSILON);
        let mut c = Candidate::new(CandidateId(0), -9.2);
        c.path = NormalizedPath::parse("C:\\x.exe");
        assert!(!report(vec![c]).found_anything());
    }

    #[test]
    fn recovered_and_hash_only_samples_are_distinguished() {
        let mut recovered = candidate(0, "C:\\a.exe", 12.0);
        recovered.acquisition = Acquisition::Bytes {
            via: mm_core::ArtifactSource::DefenderQuarantine,
            size: 4096,
            saved_as: "sample/C000.bin".into(),
            recovery: mm_core::Recovery::Intact,
        };
        let mut hash_only = candidate(1, "C:\\b.exe", 12.0);
        hash_only.acquisition = Acquisition::HashOnly { via: mm_core::ArtifactSource::Amcache };
        let unresolved = candidate(2, "C:\\c.exe", 12.0);

        let r = report(vec![recovered, hash_only, unresolved]);
        assert_eq!(r.recovered_samples().count(), 1);
        assert_eq!(r.hash_only_samples().count(), 1);
    }

    #[test]
    fn fragments_count_as_bytes_on_disk_but_never_as_a_confirmed_sample() {
        let mut partial = candidate(0, "C:\\a.exe", 12.0);
        partial.acquisition = Acquisition::Bytes {
            via: mm_core::ArtifactSource::Mft,
            size: 4096,
            saved_as: "sample/C000.bin".into(),
            recovery: mm_core::Recovery::Partial { detail: "3 of 4 clusters reallocated".into() },
        };
        let mut unverified = candidate(1, "C:\\b.exe", 12.0);
        unverified.acquisition = Acquisition::Bytes {
            via: mm_core::ArtifactSource::DefenderQuarantine,
            size: 4096,
            saved_as: "sample/C001.bin".into(),
            recovery: mm_core::Recovery::Unverified { basis: "size matched the entry".into() },
        };
        let mut confirmed = candidate(2, "C:\\c.exe", 12.0);
        confirmed.acquisition = Acquisition::Bytes {
            via: mm_core::ArtifactSource::DefenderQuarantine,
            size: 4096,
            saved_as: "sample/C002.bin".into(),
            recovery: mm_core::Recovery::Confirmed { against: "Amcache".into() },
        };

        let r = report(vec![partial, unverified, confirmed]);
        assert_eq!(r.recovered_samples().count(), 3, "all three wrote a file");
        assert_eq!(r.confirmed_samples().count(), 1, "only one may be called the sample");
    }

    #[test]
    fn weak_candidates_are_excluded_even_when_bytes_were_recovered() {
        let mut weak = candidate(0, "C:\\a.exe", 1.0);
        weak.acquisition = Acquisition::Bytes {
            via: mm_core::ArtifactSource::Mft,
            size: 10,
            saved_as: "x".into(),
            recovery: mm_core::Recovery::Intact,
        };
        assert_eq!(report(vec![weak]).recovered_samples().count(), 0);
    }

    const CLEAN_LAPTOP: (usize, f64) = (17_847, 8.6);
    const CLEAN_VM: (usize, f64) = (2_256, 6.6);
    const CLEAN_VM_WINRE: (usize, f64) = (2_371, 7.5);
    const VM_WITH_DROPPER: (usize, f64) = (2_144, 7.3);
    const LAPTOP_WITH_DROPPER: (usize, f64) = (17_545, 9.6);

    fn volume(n: usize, evidence: f64) -> Report {
        volume_at(n, (1.0 / n.max(2) as f64).ln(), evidence)
    }

    fn volume_at(n: usize, prior: f64, evidence: f64) -> Report {
        let mut candidates = Vec::with_capacity(n);
        if n > 0 {
            let mut top = Candidate::new(CandidateId(0), prior);
            top.path = NormalizedPath::parse("C:\\top.exe");
            top.evidence.push(Evidence::new("measured", evidence, "the strongest thing here"));
            candidates.push(top);
        }
        for i in 1..n {
            let mut c = Candidate::new(CandidateId(i as u32), prior);
            c.path = NormalizedPath::parse(&format!("C:\\f{i}.exe"));
            c.evidence.push(Evidence::new("ordinary", 1.0, "ordinary software"));
            candidates.push(c);
        }
        report(candidates)
    }

    #[test]
    fn neither_clean_machine_is_ever_a_close_call() {
        for (n, evidence) in [CLEAN_LAPTOP, CLEAN_VM] {
            let report = volume(n, evidence);
            assert!(!report.found_anything(), "{n} candidates at {evidence:+}");
            assert_eq!(report.close_call(), None, "{n} candidates at {evidence:+}");
        }
    }

    #[test]
    fn the_close_call_band_cannot_separate_the_clean_winre_run_from_a_dropper() {
        let ratio = |(n, evidence): (usize, f64)| match break_even_population(
            evidence,
            DEFAULT_THRESHOLD,
        ) {
            BreakEven::AtMost(b) => b as f64 / n as f64,
            other => panic!("{other:?} for {n} candidates at {evidence:+}"),
        };

        let clean_winre = ratio(CLEAN_VM_WINRE);
        let closest_dropper = ratio(VM_WITH_DROPPER);
        assert!(
            (clean_winre - 0.7626).abs() < 5e-4,
            "the clean WinRE run's ratio moved to {clean_winre}"
        );
        assert!(
            clean_winre > closest_dropper,
            "the clean WinRE run ({clean_winre:.4}) is no longer closer to the threshold than \
             the dropper the band exists to catch ({closest_dropper:.4}). The inversion this \
             test records is fixed — replace it with CLEAN_VM_WINRE in \
             `neither_clean_machine_is_ever_a_close_call`."
        );

        let report = volume(CLEAN_VM_WINRE.0, CLEAN_VM_WINRE.1);
        assert!(!report.found_anything(), "the clean run still reports nothing, at least");
        assert!(
            report.close_call().is_some(),
            "a clean WinRE volume no longer trips the band — if that was deliberate, this test \
             and the constant's documentation both need rewriting"
        );
    }

    #[test]
    fn the_droppers_the_threshold_missed_are_close_calls() {
        let laptop = volume(LAPTOP_WITH_DROPPER.0, LAPTOP_WITH_DROPPER.1);
        let close = laptop.close_call().expect("the planted dropper came close");
        assert_eq!(close.break_even, BreakEven::AtMost(14_764));
        assert_eq!(close.population, 17_545);
        assert_eq!(close.in_band, 1);
        assert!(close.heads_the_ranking);
        let factor = close.times_too_large().expect("a factor");
        assert!((factor - 1.188).abs() < 0.001, "{factor}");

        let vm = volume(VM_WITH_DROPPER.0, VM_WITH_DROPPER.1);
        let close = vm.close_call().expect("the planted dropper came close");
        assert_eq!(close.break_even, BreakEven::AtMost(1_480));
        assert_eq!(close.population, 2_144);
        let factor = close.times_too_large().expect("a factor");
        assert!((factor - 1.449).abs() < 0.001, "{factor}");
    }

    #[test]
    fn the_band_sits_in_the_measured_gap_and_in_the_middle_of_it() {
        let ratio = |(n, evidence): (usize, f64)| match break_even_population(
            evidence,
            DEFAULT_THRESHOLD,
        ) {
            BreakEven::AtMost(b) => b as f64 / n as f64,
            other => panic!("{other:?} for {n} candidates at {evidence:+}"),
        };

        assert!((ratio(CLEAN_LAPTOP) - 0.3043).abs() < 5e-4, "{}", ratio(CLEAN_LAPTOP));
        assert!((ratio(CLEAN_VM) - 0.3258).abs() < 5e-4, "{}", ratio(CLEAN_VM));
        assert!((ratio(VM_WITH_DROPPER) - 0.6903).abs() < 5e-4, "{}", ratio(VM_WITH_DROPPER));
        assert!(
            (ratio(LAPTOP_WITH_DROPPER) - 0.8415).abs() < 5e-4,
            "{}",
            ratio(LAPTOP_WITH_DROPPER)
        );

        let clean = ratio(CLEAN_LAPTOP).max(ratio(CLEAN_VM));
        let missed = ratio(VM_WITH_DROPPER).min(ratio(LAPTOP_WITH_DROPPER));
        assert!(clean < CLOSE_CALL_RATIO, "a clean machine is in the band: {clean}");
        assert!(CLOSE_CALL_RATIO < missed, "a missed dropper is outside the band: {missed}");

        let middle = (clean * missed).sqrt();
        assert!((middle - 0.4741).abs() < 5e-4, "middle is {middle}");
        assert!(
            (CLOSE_CALL_RATIO / middle).ln() > 0.0,
            "the band has fallen below the middle of the gap, toward the clean machines"
        );
    }

    #[test]
    fn a_run_with_a_finding_has_no_close_call() {
        let report = volume(CLEAN_VM.0, 9.0);
        assert!(report.found_anything());
        assert_eq!(report.close_call(), None);
    }

    #[test]
    fn a_volume_with_no_candidates_has_no_close_call() {
        assert_eq!(report(vec![]).close_call(), None);
    }

    #[test]
    fn every_candidate_in_the_band_is_counted() {
        let prior = (1.0f64 / 100.0).ln();
        let mut candidates: Vec<Candidate> = (0..20)
            .map(|i| {
                let mut c = Candidate::new(CandidateId(i), prior);
                c.path = NormalizedPath::parse(&format!("C:\\Windows\\Temp\\{{g{i}}}\\stub.exe"));
                c.evidence.push(Evidence::new("twin", 4.2, "one evidence set, twenty files"));
                c
            })
            .collect();
        for i in 20..100 {
            let mut c = Candidate::new(CandidateId(i), prior);
            c.path = NormalizedPath::parse(&format!("C:\\f{i}.exe"));
            c.evidence.push(Evidence::new("ordinary", 1.0, "ordinary software"));
            candidates.push(c);
        }
        let report = report(candidates);

        let close = report.close_call().expect("twenty files, all of them in the band");
        assert_eq!(close.in_band, 20);
        assert_eq!(close.break_even, BreakEven::AtMost(66));
        assert_eq!(close.population, 100);
        assert!(close.heads_the_ranking, "ties point at the entry the ranking prints first");
    }

    #[test]
    fn a_report_whose_count_and_base_rate_disagree_is_never_escalated() {
        let counted_close = volume_at(3, -9.8275, 7.7);
        assert!(!counted_close.found_anything());
        assert_eq!(counted_close.close_call(), None);

        let base_rate_close = volume_at(4_000, (1.0f64 / 2_208.0).ln(), 7.6);
        assert!(!base_rate_close.found_anything());
        assert_eq!(base_rate_close.close_call(), None);
    }

    #[test]
    fn no_shortfall_factor_is_invented() {
        let with = |break_even, population| CloseCall {
            in_band: 1,
            break_even,
            population,
            heads_the_ranking: true,
        };
        assert_eq!(with(BreakEven::Always, 10).times_too_large(), None);
        assert_eq!(with(BreakEven::Never, 10).times_too_large(), None);
        assert_eq!(
            with(BreakEven::AtMost(10), 10).times_too_large(),
            None,
            "a break-even population that is not smaller is not a shortfall"
        );
        assert_eq!(with(BreakEven::AtMost(1_000), 2_000).times_too_large(), Some(2.0));
    }

    #[test]
    fn break_even_solves_for_the_largest_machine_that_would_report_it() {
        assert_eq!(break_even_population(1000f64.ln(), 0.5), BreakEven::AtMost(1000));
        assert_eq!(break_even_population(7.7, 0.5), BreakEven::AtMost(2_208));
        let at_most = |e: f64| match break_even_population(e, 0.5) {
            BreakEven::AtMost(n) => n,
            other => panic!("expected a population, got {other:?}"),
        };
        assert!(at_most(9.0) > at_most(8.0));
    }

    #[test]
    fn break_even_accounts_for_the_threshold_it_is_asked_about() {
        assert_eq!(break_even_population(1000f64.ln(), 0.75), BreakEven::AtMost(333));
        assert_eq!(break_even_population(1000f64.ln(), 0.25), BreakEven::AtMost(3_000));
    }

    #[test]
    fn break_even_refuses_to_invent_a_machine_size() {
        assert_eq!(break_even_population(0.0, 0.5), BreakEven::Never);
        assert_eq!(
            break_even_population(0.5, 0.5),
            BreakEven::Never,
            "below the prior's own clamp"
        );
        assert_eq!(break_even_population(1e6, 0.5), BreakEven::Always);
        assert_eq!(break_even_population(f64::NAN, 0.5), BreakEven::Never);
        assert_eq!(break_even_population(f64::INFINITY, 0.5), BreakEven::Always);
    }

    #[test]
    fn evidence_log_odds_excludes_the_base_rate() {
        let small = candidate(0, "C:\\x.exe", 7.7);
        let mut large = small.clone();
        large.prior_log_odds = -9.8275;
        assert!((evidence_log_odds(&small) - evidence_log_odds(&large)).abs() < 1e-12);
        assert!(small.probability() > large.probability());
    }

    #[test]
    fn near_misses_are_the_head_of_the_ranking_and_nothing_else() {
        let mut exculpated = candidate(3, "C:\\Windows\\System32\\clean.exe", -4.0);
        exculpated.evidence.clear();
        exculpated.evidence.push(Evidence::new("signed_by_microsoft", -4.0, "signed"));

        let r = report(vec![
            candidate(0, "C:\\a.exe", 4.0),
            candidate(1, "C:\\b.exe", 3.0),
            candidate(2, "C:\\c.exe", 2.0),
            exculpated,
        ]);

        assert_eq!(r.near_misses(2).iter().map(|c| c.id.0).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(r.ranked_below().count(), 3, "the exculpated candidate is not a near miss");
        assert_eq!(r.near_misses(NEAR_MISS_LIMIT).len(), 3, "the cap does not invent candidates");
    }

    #[test]
    fn a_reportable_candidate_is_never_also_a_near_miss() {
        let r = report(vec![candidate(0, "C:\\a.exe", 12.0), candidate(1, "C:\\b.exe", 4.0)]);
        assert_eq!(r.reportable_count(), 1);
        assert_eq!(
            r.near_misses(NEAR_MISS_LIMIT).iter().map(|c| c.id.0).collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn the_evidence_a_machine_demanded_is_the_negation_of_its_base_rate() {
        let r = report(vec![candidate(0, "C:\\a.exe", 1.0)]);
        let prior = r.prior_log_odds().unwrap();
        assert!((r.evidence_needed().unwrap() + prior).abs() < 1e-12);
        assert_eq!(
            Report::new("0", "e", target(), vec![], Coverage::default(), false).prior_log_odds(),
            None
        );
    }

    #[test]
    fn coverage_sums_observations_from_read_artifacts_only() {
        let mut c = Coverage::default();
        c.record("Amcache", CoverageStatus::Read { observations: 120 });
        c.record("Prefetch", CoverageStatus::Absent);
        c.record("SRUM", CoverageStatus::Failed { reason: "corrupt".into() });
        c.record("process memory", CoverageStatus::NotAvailableHere { reason: "WinRE".into() });
        assert_eq!(c.total_observations(), 120);
        assert_eq!(c.artifacts.len(), 4);
    }

    #[test]
    fn json_round_trips_the_essentials() {
        let r = report(vec![candidate(0, "C:\\Users\\bob\\x.exe", 12.0)]);
        let json = r.to_json();
        assert!(json.contains("\"tool_version\""));
        assert!(json.contains("x.exe"));
        assert!(json.contains("\"weights_calibrated\": false"));
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed["candidates"].is_array());
    }

    #[test]
    fn measured_time_counts_each_stage_exactly_once() {
        let mut c = Coverage::default();
        c.record_timed("$MFT", CoverageStatus::Read { observations: 2_143 }, 84.2);
        c.record("executables installed out of band", CoverageStatus::Read { observations: 861 });
        c.record_timed("code signatures", CoverageStatus::Read { observations: 214 }, 20.4);
        c.record_timed("Prefetch", CoverageStatus::Absent, 0.4);
        assert!((c.measured_seconds() - 105.0).abs() < 1e-9, "{}", c.measured_seconds());
    }

    #[test]
    fn the_slowest_stage_is_the_one_named() {
        let mut c = Coverage::default();
        c.record_timed("Amcache", CoverageStatus::Read { observations: 120 }, 3.0);
        c.record_timed("$MFT", CoverageStatus::Read { observations: 9 }, 84.2);
        c.record_timed("code signatures", CoverageStatus::Read { observations: 4 }, 20.4);
        assert_eq!(c.slowest_stage(), Some(("$MFT", 84.2)));
    }

    #[test]
    fn an_untimed_run_reports_no_time_rather_than_zero() {
        let mut c = Coverage::default();
        c.record("Amcache", CoverageStatus::Read { observations: 120 });
        assert_eq!(c.measured_seconds(), 0.0);
        assert_eq!(c.slowest_stage(), None);
    }

    #[test]
    fn the_json_carries_a_timing_for_every_timed_stage() {
        let mut coverage = Coverage::default();
        coverage.record_timed("$MFT", CoverageStatus::Read { observations: 2 }, 84.25);
        coverage.record("Zone.Identifier (MotW)", CoverageStatus::Read { observations: 0 });
        let report = Report::new("0.1.0", "WinRE", target(), vec![], coverage, false);
        let parsed: serde_json::Value =
            serde_json::from_str(&report.to_json()).expect("valid JSON");
        let artifacts = parsed["coverage"]["artifacts"].as_array().expect("array");
        assert_eq!(artifacts[0]["seconds"].as_f64(), Some(84.25));
        assert!(artifacts[1].get("seconds").is_none(), "{:?}", artifacts[1]);
    }
}
