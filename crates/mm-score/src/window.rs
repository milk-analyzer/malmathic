use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use mm_core::{Candidate, CandidateId, ObservationKind};

pub const BURST_GAP: Duration = Duration::minutes(10);

pub const MAX_BURST_SPAN: Duration = Duration::hours(6);

pub const MAX_MEMBER_FRACTION: f64 = 0.02;

pub const MIN_MEMBERS_ALLOWED: usize = 25;

pub const MIN_DIRECTORY_COHORT: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncidentWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    core_start: DateTime<Utc>,
    core_end: DateTime<Utc>,
    seeds: Vec<CandidateId>,
    explained_by_directory: Vec<CandidateId>,
    explained_directories: usize,
    members: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Detection {
    Found(IncidentWindow),
    NoSeed { strongest: f64 },
    NoTimestamps { seeds: usize },
    NotABurst { span_hours: f64 },
    OrdinaryActivity { members: usize, allowed: usize },
}

impl Detection {
    pub fn window(&self) -> Option<&IncidentWindow> {
        match self {
            Detection::Found(w) => Some(w),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Detection::Found(w) => w.describe(),
            Detection::NoSeed { strongest } => format!(
                "no candidate rose above the reporting threshold (strongest {strongest:.2}), so there was no burst to cluster around"
            ),
            Detection::NoTimestamps { seeds } => format!(
                "{seeds} candidate(s) were strong enough to seed a window, but no artifact recorded a time for any of them"
            ),
            Detection::NotABurst { span_hours } => format!(
                "the strongest candidates' activity spans {span_hours:.1} hours, which is a working day rather than an incident"
            ),
            Detection::OrdinaryActivity { members, allowed } => format!(
                "the burst holds {members} candidates, past the {allowed} at which being created in it stops distinguishing anything"
            ),
        }
    }
}

impl IncidentWindow {
    pub fn detect(candidates: &[Candidate], reporting_threshold: f64) -> Detection {
        let bar = logit(reporting_threshold);
        let bar = if bar.is_finite() { bar } else { 0.0 };

        let mut seeds: Vec<&Candidate> = Vec::new();
        let mut strongest = 0.0f64;
        for candidate in candidates {
            let p = candidate.probability();
            if p > strongest {
                strongest = p;
            }
            if candidate.logit() >= bar {
                seeds.push(candidate);
            }
        }
        if seeds.is_empty() {
            return Detection::NoSeed { strongest };
        }

        let mut moments: Vec<(DateTime<Utc>, usize)> = Vec::new();
        for (n, seed) in seeds.iter().enumerate() {
            for moment in incident_moments(seed) {
                moments.push((moment, n));
            }
        }
        if moments.is_empty() {
            return Detection::NoTimestamps { seeds: seeds.len() };
        }
        moments.sort_by_key(|(t, _)| *t);

        let mut runs: Vec<Vec<(DateTime<Utc>, usize)>> = vec![vec![moments[0]]];
        for moment in moments.into_iter().skip(1) {
            let last = runs.last().and_then(|r| r.last()).map(|(t, _)| *t);
            match last {
                Some(previous) if moment.0 - previous <= BURST_GAP => {
                    runs.last_mut().expect("just matched a non-empty run").push(moment)
                }
                _ => runs.push(vec![moment]),
            }
        }

        let best = runs
            .into_iter()
            .max_by_key(|run| {
                let distinct: HashSet<usize> = run.iter().map(|(_, n)| *n).collect();
                (distinct.len(), run.len(), run.last().map(|(t, _)| *t))
            })
            .expect("at least one run exists because moments was non-empty");

        let core_start = best.first().expect("a run is never empty").0;
        let core_end = best.last().expect("a run is never empty").0;
        let span = core_end - core_start;
        if span > MAX_BURST_SPAN {
            return Detection::NotABurst { span_hours: span.num_seconds() as f64 / 3600.0 };
        }

        let mut seed_ids: Vec<CandidateId> = seeds.iter().map(|c| c.id).collect();
        seed_ids.sort_unstable();
        seed_ids.dedup();

        let mut window = IncidentWindow {
            start: core_start - BURST_GAP,
            end: core_end + BURST_GAP,
            core_start,
            core_end,
            seeds: seed_ids,
            explained_by_directory: Vec::new(),
            explained_directories: 0,
            members: 0,
        };

        let (explained, directories) = co_arrived_directories(candidates, &window);
        window.explained_by_directory = explained;
        window.explained_directories = directories;

        window.members = candidates.iter().filter(|c| window.applies_to(c)).count();

        let allowed = member_allowance(candidates.len());
        if window.members > allowed {
            return Detection::OrdinaryActivity { members: window.members, allowed };
        }
        Detection::Found(window)
    }

    pub fn contains(&self, moment: DateTime<Utc>) -> bool {
        moment >= self.start && moment <= self.end
    }

    pub fn applies_to(&self, candidate: &Candidate) -> bool {
        self.membership(candidate).is_some()
    }

    pub fn membership(&self, candidate: &Candidate) -> Option<DateTime<Utc>> {
        if self.seeds.binary_search(&candidate.id).is_ok() {
            return None;
        }
        if self.explained_by_directory.binary_search(&candidate.id).is_ok() {
            return None;
        }
        creation_time(candidate).filter(|t| self.contains(*t))
    }

    pub fn describe(&self) -> String {
        let minutes = (self.core_end - self.core_start).num_minutes();
        let mut text = format!(
            "{} – {} observed, anchored on {} candidate{}",
            mm_core::filetime::format(self.core_start),
            mm_core::filetime::format(self.core_end),
            self.seeds.len(),
            if self.seeds.len() == 1 { "" } else { "s" },
        );
        if minutes != 0 {
            text.push_str(&format!(" over {minutes} minutes"));
        }
        text.push_str(&format!(
            "; widened to {} – {} by the {}-minute burst gap",
            mm_core::filetime::format(self.start),
            mm_core::filetime::format(self.end),
            BURST_GAP.num_minutes(),
        ));
        text.push_str(&format!(
            "; {} candidate{} created in it",
            self.members,
            if self.members == 1 { "" } else { "s" },
        ));
        if !self.explained_by_directory.is_empty() {
            text.push_str(&format!(
                ", and {} not credited: every executable known in {} director{} was created",
                self.explained_by_directory.len(),
                self.explained_directories,
                if self.explained_directories == 1 { "y" } else { "ies" },
            ));
            text.push_str(" in it too, so the window is not what put them there");
        }
        text
    }

    pub fn summarise(&self) -> String {
        let observed = (self.core_end - self.core_start).num_minutes();
        format!(
            "{} – {}, of which {} minute{} observed and {} assumed at each end",
            mm_core::filetime::format(self.start),
            mm_core::filetime::format(self.end),
            observed,
            if observed == 1 { "" } else { "s" },
            BURST_GAP.num_minutes(),
        )
    }

    pub fn start(&self) -> DateTime<Utc> {
        self.start
    }

    pub fn end(&self) -> DateTime<Utc> {
        self.end
    }

    pub fn members(&self) -> usize {
        self.members
    }

    pub fn seeds(&self) -> &[CandidateId] {
        &self.seeds
    }

    pub fn explained_by_directory(&self) -> &[CandidateId] {
        &self.explained_by_directory
    }

    pub fn explained_directories(&self) -> usize {
        self.explained_directories
    }
}

fn incident_moments(candidate: &Candidate) -> Vec<DateTime<Utc>> {
    let mut moments = Vec::new();
    for observation in &candidate.observations {
        match &observation.kind {
            ObservationKind::FileExists { created: Some(t), .. }
            | ObservationKind::FileDeleted { when: Some(t), .. }
            | ObservationKind::Executed { when: Some(t), .. }
            | ObservationKind::Quarantined { when: Some(t), .. }
            | ObservationKind::AvDetected { when: Some(t), .. } => moments.push(*t),
            _ => {}
        }
    }
    moments
}

fn creation_time(candidate: &Candidate) -> Option<DateTime<Utc>> {
    candidate
        .observations
        .iter()
        .filter_map(|o| match &o.kind {
            ObservationKind::FileExists { created, .. } => *created,
            _ => None,
        })
        .min()
}

fn co_arrived_directories(
    candidates: &[Candidate],
    window: &IncidentWindow,
) -> (Vec<CandidateId>, usize) {
    #[derive(Default)]
    struct Tally {
        dated: usize,
        inside: usize,
        holds_seed: bool,
    }

    let mut directories: std::collections::HashMap<&str, Tally> = std::collections::HashMap::new();
    for candidate in candidates {
        let Some(parent) = candidate.path.as_ref().and_then(|p| p.parent()) else { continue };
        let is_seed = window.seeds.binary_search(&candidate.id).is_ok();
        let Some(created) = creation_time(candidate) else {
            if is_seed {
                directories.entry(parent).or_default().holds_seed = true;
            }
            continue;
        };
        let tally = directories.entry(parent).or_default();
        tally.dated += 1;
        if is_seed {
            tally.holds_seed = true;
        } else if window.contains(created) {
            tally.inside += 1;
        }
    }

    let co_arrived: std::collections::HashSet<&str> = directories
        .iter()
        .filter(|(_, t)| !t.holds_seed && t.inside >= MIN_DIRECTORY_COHORT && t.inside == t.dated)
        .map(|(parent, _)| *parent)
        .collect();

    let mut excluded = Vec::new();
    for candidate in candidates {
        let Some(parent) = candidate.path.as_ref().and_then(|p| p.parent()) else { continue };
        if !co_arrived.contains(parent) {
            continue;
        }
        if window.seeds.binary_search(&candidate.id).is_ok() {
            continue;
        }
        if creation_time(candidate).is_some_and(|t| window.contains(t)) {
            excluded.push(candidate.id);
        }
    }
    excluded.sort_unstable();
    excluded.dedup();
    (excluded, co_arrived.len())
}

fn member_allowance(candidate_count: usize) -> usize {
    ((candidate_count as f64 * MAX_MEMBER_FRACTION) as usize).max(MIN_MEMBERS_ALLOWED)
}

fn logit(probability: f64) -> f64 {
    (probability / (1.0 - probability)).ln()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mm_core::{ArtifactSource, FileHash, NormalizedPath, Observation};

    const THRESHOLD: f64 = 0.5;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).expect("a valid timestamp")
    }

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).expect("a valid path")
    }

    fn candidate(id: u32, logit: f64) -> Candidate {
        let mut c = Candidate::new(CandidateId(id), 0.0);
        c.evidence.push(mm_core::Evidence::new("test", logit, "set by the test"));
        c
    }

    fn with_created(mut c: Candidate, when: DateTime<Utc>) -> Candidate {
        let p = format!("C:\\Users\\bob\\f{}.exe", c.id.0);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(&p),
            ObservationKind::FileExists {
                size: 1024,
                created: Some(when),
                modified: None,
                mft_modified: None,
                record: None,
            },
        ));
        c
    }

    fn with_executed(mut c: Candidate, when: DateTime<Utc>) -> Candidate {
        let p = format!("C:\\Users\\bob\\f{}.exe", c.id.0);
        c.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(&p),
            ObservationKind::Executed { when: Some(when), run_count: Some(1) },
        ));
        c
    }

    #[test]
    fn a_machine_with_nothing_above_the_noise_has_no_window() {
        let candidates: Vec<Candidate> =
            (0..500).map(|i| with_created(candidate(i, -1.2), at(i as i64 * 3))).collect();

        match IncidentWindow::detect(&candidates, THRESHOLD) {
            Detection::NoSeed { strongest } => assert!(strongest < THRESHOLD),
            other => panic!("a window formed on a machine with no finding: {other:?}"),
        }
    }

    #[test]
    fn the_strongest_of_a_weak_field_is_not_a_seed() {
        let mut candidates: Vec<Candidate> =
            (0..50).map(|i| with_created(candidate(i, -4.0), at(i as i64 * 30))).collect();
        candidates.push(with_created(candidate(99, -0.001), at(10)));

        assert!(matches!(IncidentWindow::detect(&candidates, THRESHOLD), Detection::NoSeed { .. }));
    }

    #[test]
    fn no_candidates_at_all_is_not_a_crash() {
        assert!(matches!(IncidentWindow::detect(&[], THRESHOLD), Detection::NoSeed { .. }));
    }

    #[test]
    fn a_degenerate_threshold_does_not_seed_the_whole_machine() {
        let candidates: Vec<Candidate> =
            (0..100).map(|i| with_created(candidate(i, -3.0), at(i as i64))).collect();
        for threshold in [0.0, 1.0, f64::NAN] {
            assert!(
                matches!(IncidentWindow::detect(&candidates, threshold), Detection::NoSeed { .. }),
                "threshold {threshold} seeded a window on a field of weak candidates"
            );
        }
    }

    #[test]
    fn a_seed_with_no_timestamps_says_so() {
        let candidates = vec![candidate(0, 2.0)];
        assert_eq!(
            IncidentWindow::detect(&candidates, THRESHOLD),
            Detection::NoTimestamps { seeds: 1 }
        );
    }

    #[test]
    fn a_lone_seed_gets_a_window_padded_by_the_burst_gap() {
        let mut seed = candidate(0, 3.0);
        seed = with_created(seed, at(0));
        seed = with_executed(seed, at(41));

        let detection = IncidentWindow::detect(&[seed], THRESHOLD);
        let window = detection.window().expect("one strong seed is enough");
        assert_eq!(window.start(), at(0) - BURST_GAP);
        assert_eq!(window.end(), at(41) + BURST_GAP);
        assert_eq!(window.members(), 0, "a seed does not corroborate itself");
    }

    #[test]
    fn neighbours_in_time_are_members_and_distant_files_are_not() {
        let mut candidates = vec![with_executed(candidate(0, 3.0), at(0))];
        candidates.push(with_created(candidate(1, -5.0), at(120)));
        candidates.push(with_created(candidate(2, -5.0), at(-60)));
        candidates.push(with_created(candidate(3, -5.0), at(601)));
        candidates.push(with_created(candidate(4, -5.0), at(86_400)));

        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.members(), 2);
        assert!(window.applies_to(&candidates[1]));
        assert!(window.applies_to(&candidates[2]));
        assert!(!window.applies_to(&candidates[3]));
        assert!(!window.applies_to(&candidates[4]));
    }

    #[test]
    fn an_old_execution_does_not_stretch_the_window_to_cover_a_year() {
        let mut seed = candidate(0, 3.0);
        seed = with_executed(seed, at(-365 * 86_400));
        seed = with_created(seed, at(0));
        seed = with_executed(seed, at(30));

        let detection = IncidentWindow::detect(&[seed], THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.start(), at(0) - BURST_GAP);
        assert_eq!(window.end(), at(30) + BURST_GAP);
    }

    #[test]
    fn the_run_the_most_seeds_sit_in_wins() {
        let candidates = vec![
            with_executed(candidate(0, 3.0), at(0)),
            with_executed(candidate(1, 3.0), at(60)),
            with_executed(candidate(2, 3.0), at(7_200)),
        ];
        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("seeds exist");
        assert_eq!(window.start(), at(0) - BURST_GAP);
        assert_eq!(window.end(), at(60) + BURST_GAP);
    }

    #[test]
    fn a_chain_of_activity_spanning_a_day_is_refused() {
        let mut seed = candidate(0, 3.0);
        for i in 0..160 {
            seed = with_executed(seed, at(i * 540));
        }
        match IncidentWindow::detect(&[seed], THRESHOLD) {
            Detection::NotABurst { span_hours } => assert!(span_hours > 6.0),
            other => panic!("a 24-hour chain was accepted as a burst: {other:?}"),
        }
    }

    #[test]
    fn a_window_covering_a_bulk_creation_event_is_refused() {
        let mut candidates = vec![with_executed(candidate(0, 3.0), at(0))];
        for i in 1..1_000 {
            candidates.push(with_created(candidate(i, -9.0), at(5)));
        }
        match IncidentWindow::detect(&candidates, THRESHOLD) {
            Detection::OrdinaryActivity { members, allowed } => {
                assert!(members > allowed);
                assert_eq!(allowed, member_allowance(candidates.len()));
            }
            other => panic!("a thousand-file burst was accepted: {other:?}"),
        }
    }

    #[test]
    fn a_small_burst_on_a_small_machine_is_not_refused() {
        let mut candidates = vec![with_executed(candidate(0, 3.0), at(0))];
        for i in 1..6 {
            candidates.push(with_created(candidate(i, -9.0), at(5)));
        }
        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        assert_eq!(detection.window().expect("five neighbours is a burst").members(), 5);
    }

    #[test]
    fn the_member_allowance_has_a_floor_and_scales() {
        assert_eq!(member_allowance(0), MIN_MEMBERS_ALLOWED);
        assert_eq!(member_allowance(100), MIN_MEMBERS_ALLOWED);
        assert_eq!(member_allowance(20_241), 404);
    }

    #[test]
    fn a_candidate_with_no_creation_time_is_never_a_member() {
        let seed = with_executed(candidate(0, 3.0), at(0));
        let mut deleted = candidate(1, -5.0);
        deleted.observe(Observation::about_path(
            ArtifactSource::UsnJournal,
            path("C:\\Users\\bob\\gone.exe"),
            ObservationKind::FileDeleted { when: Some(at(30)), record: None, sequence: None },
        ));

        let detection = IncidentWindow::detect(&[seed, deleted.clone()], THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert!(!window.applies_to(&deleted));
        assert_eq!(window.members(), 0);
    }

    #[test]
    fn a_defender_detection_time_can_anchor_a_window_on_its_own() {
        let mut seed = candidate(0, 3.0);
        seed.observe(Observation::about_path(
            ArtifactSource::DefenderLog { event_id: 1117 },
            path("C:\\Users\\bob\\dropper.exe"),
            ObservationKind::Quarantined {
                product: "Windows Defender".into(),
                threat: Some("Trojan:Win32/Wacatac".into()),
                when: Some(at(0)),
                severity: None,
            },
        ));
        let neighbour = with_created(candidate(1, -5.0), at(120));
        let distant = with_created(candidate(2, -5.0), at(86_400));

        let detection =
            IncidentWindow::detect(&[seed, neighbour.clone(), distant.clone()], THRESHOLD);
        let window = detection.window().expect("an AV detection time is a moment");
        assert_eq!(window.start(), at(0) - BURST_GAP);
        assert_eq!(window.end(), at(0) + BURST_GAP);
        assert!(window.applies_to(&neighbour));
        assert!(!window.applies_to(&distant));
    }

    #[test]
    fn a_detection_with_no_time_anchors_nothing() {
        let mut seed = candidate(0, 3.0);
        seed.observe(Observation::about_path(
            ArtifactSource::DefenderLog { event_id: 1116 },
            path("C:\\Users\\bob\\dropper.exe"),
            ObservationKind::AvDetected {
                product: "Windows Defender".into(),
                threat: None,
                when: None,
                severity: None,
            },
        ));
        assert_eq!(
            IncidentWindow::detect(&[seed], THRESHOLD),
            Detection::NoTimestamps { seeds: 1 }
        );
    }

    #[test]
    fn a_modification_time_is_not_an_incident_moment() {
        let mut seed = candidate(0, 3.0);
        seed.observe(Observation::about_path(
            ArtifactSource::Mft,
            path("C:\\Users\\bob\\x.exe"),
            ObservationKind::FileExists {
                size: 1,
                created: None,
                modified: Some(at(0)),
                mft_modified: None,
                record: None,
            },
        ));
        assert_eq!(
            IncidentWindow::detect(&[seed], THRESHOLD),
            Detection::NoTimestamps { seeds: 1 }
        );
    }

    #[test]
    fn a_hash_only_candidate_neither_seeds_nor_scores() {
        let mut seed = with_executed(candidate(0, 3.0), at(0));
        seed.hash = FileHash::compute(b"payload");
        let mut ghost = candidate(1, -5.0);
        ghost.observe(Observation::about_hash(
            ArtifactSource::Amcache,
            FileHash::compute(b"other"),
            ObservationKind::HashRecovered,
        ));

        let detection = IncidentWindow::detect(&[seed, ghost.clone()], THRESHOLD);
        assert!(!detection.window().expect("a seed exists").applies_to(&ghost));
    }

    #[test]
    fn detection_is_deterministic() {
        let candidates =
            vec![with_executed(candidate(0, 3.0), at(0)), with_created(candidate(1, -5.0), at(60))];
        assert_eq!(
            IncidentWindow::detect(&candidates, THRESHOLD),
            IncidentWindow::detect(&candidates, THRESHOLD)
        );
    }

    fn in_dir(mut c: Candidate, dir: &str, when: Option<DateTime<Utc>>) -> Candidate {
        let p = format!("{dir}\\f{}.exe", c.id.0);
        c.observe(Observation::about_path(
            ArtifactSource::Mft,
            path(&p),
            ObservationKind::FileExists {
                size: 1024,
                created: when,
                modified: None,
                mft_modified: None,
                record: None,
            },
        ));
        c
    }

    #[test]
    fn a_directory_that_arrived_whole_is_not_corroborated_by_the_window() {
        let mut candidates =
            vec![in_dir(candidate(0, 3.0), "C:\\Users\\bob\\Downloads", Some(at(0)))];
        for i in 1..5 {
            candidates.push(in_dir(
                candidate(i, -5.0),
                "C:\\ProgramData\\Vendor\\platform\\4.18",
                Some(at(1)),
            ));
        }

        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.members(), 0, "a directory that arrived whole corroborates nothing");
        assert_eq!(window.explained_by_directory().len(), 4);
        assert_eq!(window.explained_directories(), 1);
        for c in &candidates[1..] {
            assert!(!window.applies_to(c));
        }
    }

    #[test]
    fn a_directory_holding_a_seed_keeps_its_members() {
        let vendor = "C:\\Users\\bob\\AppData\\Roaming\\Vendor";
        let mut candidates = vec![in_dir(candidate(0, 3.0), vendor, Some(at(0)))];
        candidates.push(in_dir(candidate(1, -5.0), vendor, Some(at(1))));
        candidates.push(in_dir(candidate(2, -5.0), vendor, Some(at(2))));

        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.members(), 2, "the dropper's own directory is what the window is for");
        assert!(window.explained_by_directory().is_empty());
    }

    #[test]
    fn a_seed_with_no_creation_time_still_exempts_its_directory() {
        let vendor = "C:\\Users\\bob\\AppData\\Roaming\\Vendor";
        let mut seed = candidate(0, 3.0);
        seed.observe(Observation::about_path(
            ArtifactSource::Prefetch,
            path(&format!("{vendor}\\f0.exe")),
            ObservationKind::Executed { when: Some(at(0)), run_count: Some(1) },
        ));
        let candidates = vec![
            seed,
            in_dir(candidate(1, -5.0), vendor, Some(at(1))),
            in_dir(candidate(2, -5.0), vendor, Some(at(2))),
        ];

        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.members(), 2);
        assert!(window.explained_by_directory().is_empty());
    }

    #[test]
    fn a_directory_with_older_files_keeps_its_members() {
        let shared = "C:\\Program Files\\App";
        let mut candidates =
            vec![in_dir(candidate(0, 3.0), "C:\\Users\\bob\\Downloads", Some(at(0)))];
        candidates.push(in_dir(candidate(1, -5.0), shared, Some(at(1))));
        candidates.push(in_dir(candidate(2, -5.0), shared, Some(at(2))));
        candidates.push(in_dir(candidate(3, -5.0), shared, Some(at(-86_400))));

        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.members(), 2);
        assert!(window.explained_by_directory().is_empty());
    }

    #[test]
    fn a_lone_file_in_its_own_directory_still_collects_the_window() {
        let candidates = vec![
            in_dir(candidate(0, 3.0), "C:\\Users\\bob\\Downloads", Some(at(0))),
            in_dir(candidate(1, -5.0), "C:\\ProgramData\\Staging\\a", Some(at(1))),
            in_dir(candidate(2, -5.0), "C:\\ProgramData\\Staging\\b", Some(at(2))),
        ];

        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.members(), 2, "one file per directory is below the cohort");
        assert!(window.explained_by_directory().is_empty());
    }

    #[test]
    fn an_undated_neighbour_neither_supports_nor_blocks_the_exclusion() {
        let dir = "C:\\ProgramData\\Vendor\\platform";
        let candidates = vec![
            in_dir(candidate(0, 3.0), "C:\\Users\\bob\\Downloads", Some(at(0))),
            in_dir(candidate(1, -5.0), dir, Some(at(1))),
            in_dir(candidate(2, -5.0), dir, Some(at(2))),
            in_dir(candidate(3, -5.0), dir, None),
        ];

        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.members(), 0);
        assert_eq!(window.explained_by_directory().len(), 2, "the undated file is not a member");
    }

    #[test]
    fn the_guard_drops_members_rather_than_refusing_the_window() {
        let mut candidates =
            vec![in_dir(candidate(0, 3.0), "C:\\Users\\bob\\Downloads", Some(at(0)))];
        for i in 1..5 {
            candidates.push(in_dir(
                candidate(i, -5.0),
                "C:\\ProgramData\\Vendor\\4.18",
                Some(at(1)),
            ));
        }
        candidates.push(in_dir(candidate(9, -5.0), "C:\\Users\\bob\\Desktop", Some(at(3))));

        let detection = IncidentWindow::detect(&candidates, THRESHOLD);
        let window = detection.window().expect("a seed exists");
        assert_eq!(window.members(), 1);
        assert!(window.applies_to(candidates.last().expect("the desktop file")));
    }

    #[test]
    fn the_description_states_the_inference_and_not_only_the_result() {
        let mut candidates =
            vec![in_dir(candidate(0, 3.0), "C:\\Users\\bob\\Downloads", Some(at(0)))];
        for i in 1..5 {
            candidates.push(in_dir(
                candidate(i, -5.0),
                "C:\\ProgramData\\Vendor\\4.18",
                Some(at(1)),
            ));
        }

        let text = IncidentWindow::detect(&candidates, THRESHOLD).describe();
        assert!(text.contains("observed"), "{text}");
        assert!(text.contains("widened to"), "{text}");
        assert!(text.contains("burst gap"), "{text}");
        assert!(text.contains("4 not credited"), "{text}");
        assert!(text.contains("1 directory"), "{text}");
    }

    #[test]
    fn every_declining_outcome_explains_itself() {
        for detection in [
            Detection::NoSeed { strongest: 0.25 },
            Detection::NoTimestamps { seeds: 2 },
            Detection::NotABurst { span_hours: 19.0 },
            Detection::OrdinaryActivity { members: 1344, allowed: 404 },
        ] {
            assert!(detection.describe().len() > 30, "{detection:?}");
            assert!(detection.window().is_none());
        }
    }
}
