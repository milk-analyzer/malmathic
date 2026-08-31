use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Seek};

use mm_core::NormalizedPath;
use mm_raw::{Fate, Volume};

const MAX_DIRECTORIES: usize = 8192;

#[derive(Clone, Debug)]
pub struct Found {
    pub record: u64,
    pub sequence: u16,
    pub real_size: u64,
    pub created: u64,
    pub modified: u64,
    pub found_in: String,
    pub fate: Fate,
}

impl Found {
    #[must_use]
    pub fn carveable(&self) -> bool {
        matches!(self.fate, Fate::Free)
    }

    #[must_use]
    pub fn stamps(&self) -> String {
        let created = mm_core::from_filetime(self.created);
        let modified = mm_core::from_filetime(self.modified);
        match (created, modified) {
            (Some(c), Some(m)) => format!(
                ". The directory also still holds the file's $FILE_NAME times, which the kernel \
                 writes and SetFileTime cannot reach: created {c}, last written {m}"
            ),
            (Some(c), None) => format!(
                ". The directory also still holds the file's $FILE_NAME creation time, which the \
                 kernel writes and SetFileTime cannot reach: {c}"
            ),
            (None, Some(m)) => format!(
                ". The directory also still holds the file's $FILE_NAME write time, which the \
                 kernel writes and SetFileTime cannot reach: {m}"
            ),
            (None, None) => String::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub wanted: usize,
    pub directories: usize,
    pub resolved: usize,
    pub declined: usize,
    pub slack_bytes: u64,
    pub entries: u64,
    pub live_refused: u64,
    pub ambiguous: usize,
    pub matched: usize,
    pub carveable: usize,
    pub reallocated: usize,
    pub still_there: usize,
}

#[derive(Clone, Debug, Default)]
pub struct RecoveredNames {
    by_path: HashMap<String, Found>,
    pub stats: Stats,
}

impl RecoveredNames {
    #[must_use]
    pub fn get(&self, path: &NormalizedPath) -> Option<&Found> {
        self.by_path.get(path.key())
    }

    #[cfg(test)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    fn insert(&mut self, key: String, found: Found) {
        self.by_path.insert(key, found);
    }

    #[cfg(test)]
    pub fn of(key: &str, found: Found) -> Self {
        let mut out = Self::default();
        out.insert(key.to_string(), found);
        out
    }
}

pub fn harvest<'a, R: Read + Seek>(
    volume: &Volume<R>,
    wanted: impl IntoIterator<Item = &'a NormalizedPath>,
) -> RecoveredNames {
    let mut out = RecoveredNames::default();

    let mut by_directory: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut seen_paths: BTreeSet<&str> = BTreeSet::new();
    for path in wanted {
        if !path.is_located() || !seen_paths.insert(path.key()) {
            continue;
        }
        let (Some(parent), Some(leaf)) = (path.parent(), path.file_name()) else { continue };
        by_directory.entry(parent.to_string()).or_default().insert(leaf.to_string());
    }
    out.stats.wanted = seen_paths.len();
    out.stats.directories = by_directory.len();

    let bounds = volume.slack_bounds();
    for (directory, leaves) in by_directory.iter() {
        if out.stats.resolved >= MAX_DIRECTORIES {
            out.stats.declined += 1;
            continue;
        }
        let Some(record) = volume.resolve(directory) else { continue };
        out.stats.resolved += 1;
        let found = volume.deleted_index_entries(record, &bounds);
        out.stats.slack_bytes += found.stats.slack_bytes;
        out.stats.entries += found.stats.recovered;
        out.stats.live_refused += found.stats.live_seen.saturating_sub(found.stats.live_accepted);

        let mut candidates: BTreeMap<String, Vec<mm_raw::DeletedIndexEntry>> = BTreeMap::new();
        for entry in found.entries {
            if entry.is_dos_name() {
                continue;
            }
            let leaf = entry.name.to_lowercase();
            if !leaves.contains(&leaf) {
                continue;
            }
            candidates.entry(leaf).or_default().push(entry);
        }

        for (leaf, entries) in candidates {
            let distinct: BTreeSet<(u64, u16)> =
                entries.iter().map(|e| (e.record, e.sequence)).collect();
            if distinct.len() > 1 {
                out.stats.ambiguous += 1;
                continue;
            }
            let Some(entry) = entries.first() else { continue };
            let fate = volume.record_fate(entry.record, entry.sequence);
            match fate {
                Fate::Free => out.stats.carveable += 1,
                Fate::Reallocated { .. } | Fate::FreedAgain { .. } => {
                    out.stats.reallocated += 1;
                }
                Fate::StillThere => out.stats.still_there += 1,
                Fate::Unknown => {}
            }
            let key = if directory == "\\" {
                format!("\\{leaf}")
            } else {
                format!("{directory}\\{leaf}")
            };
            out.insert(
                key,
                Found {
                    record: entry.record,
                    sequence: entry.sequence,
                    real_size: entry.real_size,
                    created: entry.created,
                    modified: entry.modified,
                    found_in: entry.found_in.to_string(),
                    fate,
                },
            );
            out.stats.matched += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::testimage::{Builder, Presence, Times, ROOT_RECORD};

    const LONG_NAME: &str = "a-very-long-installer-name-that-leaves-a-large-hole-behind-it.tmp";
    const SAMPLE: &str = "server.exe";
    const SAMPLE_BYTES: usize = 45_056;
    const CREATED: u64 = Times::at(1_778_784_843, 1_234_567);

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).expect("a path")
    }

    fn volume(presence: Presence) -> Volume<Cursor<Vec<u8>>> {
        let mut builder = Builder::with_records(512);
        let system32 = builder.directories(ROOT_RECORD, r"Windows\System32");
        let kernel =
            builder.resident_file(system32, "ntoskrnl.exe", b"MZ the kernel", Presence::Live);
        let temp = builder.directories(ROOT_RECORD, r"Windows\Temp");
        let windows = builder.directory(ROOT_RECORD, "Windows");
        for record in [system32, temp, windows, kernel] {
            builder.set_file_name_times(record, Times::all_at(CREATED));
        }

        let long = builder.file(temp, LONG_NAME, &vec![0u8; 4096], Presence::Live);
        builder.set_file_name_times(long, Times::all_at(CREATED));
        let keep = builder.resident_file(temp, "keep.dll", b"MZ still here", Presence::Live);
        builder.set_file_name_times(keep, Times::all_at(CREATED));
        builder.delete_index_entry(temp, LONG_NAME);

        let sample =
            builder.deleted_index_entry(temp, SAMPLE, &vec![0x90u8; SAMPLE_BYTES], presence);
        builder.set_file_name_times(sample, Times::all_at(CREATED));
        if !matches!(presence, Presence::Deleted) {
            builder.set_sequence(sample, 2);
        }

        Volume::open(Cursor::new(builder.bytes()), "synthetic").expect("the synthetic volume opens")
    }

    #[test]
    fn the_parent_directory_gives_a_vanished_candidate_its_record_and_its_exact_size() {
        let volume = volume(Presence::Deleted);
        let wanted = vec![path("C:\\Windows\\Temp\\server.exe")];
        let found = harvest(&volume, &wanted);

        assert_eq!(found.stats.wanted, 1);
        assert_eq!(found.stats.resolved, 1);
        assert_eq!(found.stats.matched, 1);
        let entry = found.get(&wanted[0]).expect("the entry the directory still remembers");
        assert_eq!(
            entry.real_size, SAMPLE_BYTES as u64,
            "the exact byte length is the prize: it is what a carve checks itself against"
        );
        assert_eq!(
            entry.created, CREATED,
            "the $FILE_NAME creation time, which SetFileTime \
                                            cannot reach"
        );
        assert!(entry.carveable(), "the record is free and still this file's");
        assert_eq!(found.stats.carveable, 1);
    }

    #[test]
    fn a_reallocated_record_is_stated_and_is_never_carved() {
        let volume = volume(Presence::RecordReallocatedTo("innocent.dll"));
        let wanted = vec![path("C:\\Windows\\Temp\\server.exe")];
        let found = harvest(&volume, &wanted);

        let entry = found.get(&wanted[0]).expect("the entry survives the record");
        assert!(
            !entry.carveable(),
            "another file holds the record: its clusters are that file's, not this one's"
        );
        assert_eq!(found.stats.reallocated, 1);
        assert_eq!(found.stats.carveable, 0);
        match &entry.fate {
            Fate::Reallocated { to, .. } => {
                assert_eq!(to.as_deref(), Some("innocent.dll"), "and it says WHICH file")
            }
            other => panic!("expected a stated reallocation, got {other:?}"),
        }
    }

    #[test]
    fn a_live_child_of_the_directory_is_never_offered_as_a_deleted_file() {
        let volume = volume(Presence::Deleted);
        let wanted = vec![path("C:\\Windows\\Temp\\keep.dll")];
        let found = harvest(&volume, &wanted);
        assert_eq!(found.stats.resolved, 1, "the sweep did happen");
        assert!(
            found.get(&wanted[0]).is_none(),
            "keep.dll is a live child; reporting it would put every file on the machine in the \
             report"
        );
    }

    #[test]
    fn a_name_the_directory_never_held_recovers_nothing() {
        let volume = volume(Presence::Deleted);
        let wanted = vec![path("C:\\Windows\\Temp\\never-existed.exe")];
        let found = harvest(&volume, &wanted);
        assert_eq!(found.stats.resolved, 1);
        assert_eq!(found.stats.matched, 0);
        assert!(found.is_empty());
    }

    #[test]
    fn a_path_with_no_directory_on_this_volume_is_swept_for_nothing() {
        let volume = volume(Presence::Deleted);
        let wanted = vec![path("C:\\no\\such\\directory\\gone.exe")];
        let found = harvest(&volume, &wanted);
        assert_eq!(found.stats.wanted, 1);
        assert_eq!(found.stats.directories, 1);
        assert_eq!(found.stats.resolved, 0, "nothing resolves, so nothing is swept");
        assert!(found.is_empty());
    }

    #[test]
    fn an_unlocated_path_is_not_even_a_directory_to_look_in() {
        let volume = volume(Presence::Deleted);
        let wanted = vec![NormalizedPath::unlocated("gone.exe").expect("a bare name")];
        let found = harvest(&volume, &wanted);
        assert_eq!(found.stats.wanted, 0);
        assert_eq!(found.stats.directories, 0);
    }

    #[test]
    fn the_same_path_twice_is_one_directory_and_one_sweep() {
        let volume = volume(Presence::Deleted);
        let wanted = vec![
            path("C:\\Windows\\Temp\\server.exe"),
            path("C:\\Windows\\Temp\\server.exe"),
            path("C:\\Windows\\Temp\\other.exe"),
        ];
        let found = harvest(&volume, &wanted);
        assert_eq!(found.stats.wanted, 2, "the repeat is not a second path");
        assert_eq!(found.stats.directories, 1);
    }

    use mm_core::{
        Acquisition, ArtifactSource, Candidate, CandidateId, Observation, ObservationKind, Recovery,
    };

    use crate::acquire::{
        ClusterMap, OrphanIndex, QuarantineStore, RecycleBinStore, SampleDir, ShadowStore,
    };

    fn case_sample_dir() -> SampleDir {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "malmathic-index-slack-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a case directory");
        SampleDir { path: dir, relative: "sample/unranked", write_out: true }
    }

    fn executed_only(path_str: &str) -> Candidate {
        let mut c = Candidate::new(CandidateId(1), -7.8);
        c.path = NormalizedPath::parse(path_str);
        c.observe(Observation::about_path(
            ArtifactSource::ShimCache,
            NormalizedPath::parse(path_str).unwrap(),
            ObservationKind::Executed { when: None, run_count: None },
        ));
        c
    }

    fn acquire_it(
        volume: &Volume<Cursor<Vec<u8>>>,
        slack: &RecoveredNames,
        candidate: &mut Candidate,
        out: &SampleDir,
    ) -> Acquisition {
        crate::acquire::acquire(
            volume,
            &QuarantineStore::new(),
            &RecycleBinStore::new(),
            &ShadowStore::none(),
            &OrphanIndex::default(),
            slack,
            &crate::acquire::GhostIndex::default(),
            &mut ClusterMap::new(),
            candidate,
            out,
        )
    }

    #[test]
    fn the_parent_directorys_slack_turns_a_vanished_candidate_into_bytes() {
        let volume = volume(Presence::Deleted);
        let mut candidate = executed_only("C:\\Windows\\Temp\\server.exe");
        let slack = harvest(&volume, candidate.path.as_ref());
        assert_eq!(slack.stats.carveable, 1, "the record is free and still this file's");

        let out = case_sample_dir();
        match acquire_it(&volume, &slack, &mut candidate, &out) {
            Acquisition::Bytes { via, size, recovery, .. } => {
                assert_eq!(via, ArtifactSource::Mft);
                assert_eq!(size, SAMPLE_BYTES as u64, "the whole file, not a fragment");
                match recovery {
                    Recovery::Unverified { basis } => assert!(
                        basis.contains("still free and still names this file"),
                        "a carve says what it rests on: {basis}"
                    ),
                    other => {
                        panic!("no artifact recorded a hash, so nothing can confirm: {other:?}")
                    }
                }
            }
            other => panic!("the bytes were on the volume the whole time: {other:?}"),
        }
    }

    #[test]
    fn without_the_recovered_entry_the_same_candidate_yields_nothing() {
        let volume = volume(Presence::Deleted);
        let mut candidate = executed_only("C:\\Windows\\Temp\\server.exe");
        let out = case_sample_dir();
        let nothing = RecoveredNames::default();
        assert!(
            !matches!(
                acquire_it(&volume, &nothing, &mut candidate, &out),
                Acquisition::Bytes { .. }
            ),
            "without the entry there is no record to aim at, and no bytes"
        );
    }

    #[test]
    fn a_reallocated_record_produces_a_refusal_that_names_the_file_holding_it() {
        let volume = volume(Presence::RecordReallocatedTo("innocent.dll"));
        let mut candidate = executed_only("C:\\Windows\\Temp\\server.exe");
        let slack = harvest(&volume, candidate.path.as_ref());
        assert_eq!(slack.stats.carveable, 0);

        let out = case_sample_dir();
        match acquire_it(&volume, &slack, &mut candidate, &out) {
            Acquisition::Failed { reason } => {
                assert!(reason.contains("innocent.dll"), "it names the file: {reason}");
                assert!(
                    reason.contains(&SAMPLE_BYTES.to_string()),
                    "and the exact length the directory still records: {reason}"
                );
                assert!(
                    reason.contains("stated reallocation"),
                    "and says it is a finding, not a failure to look: {reason}"
                );
            }
            other => panic!("another file's clusters must never be offered: {other:?}"),
        }
    }

    #[test]
    fn a_record_still_in_use_is_never_read_as_a_deleted_sample() {
        let volume = volume(Presence::Deleted);
        let real = harvest(&volume, Some(&path("C:\\Windows\\Temp\\server.exe")));
        let entry = real.get(&path("C:\\Windows\\Temp\\server.exe")).expect("the entry").clone();
        let slack = RecoveredNames::of(
            "\\windows\\temp\\server.exe",
            Found { fate: Fate::StillThere, ..entry },
        );

        let mut candidate = executed_only("C:\\Windows\\Temp\\server.exe");
        let out = case_sample_dir();
        match acquire_it(&volume, &slack, &mut candidate, &out) {
            Acquisition::Failed { reason } => assert!(
                reason.contains("IN USE under the same sequence"),
                "the refusal has to say why: {reason}"
            ),
            other => panic!(
                "reading a live file's clusters and calling them a deleted sample is a claim \
                 nobody made: {other:?}"
            ),
        }
    }

    #[test]
    fn a_free_record_is_the_only_fate_a_carve_may_be_aimed_at() {
        let base = Found {
            record: 40,
            sequence: 1,
            real_size: 1024,
            created: 0,
            modified: 0,
            found_in: "MFT record slack".into(),
            fate: Fate::Free,
        };
        assert!(base.carveable());
        assert!(!Found { fate: Fate::StillThere, ..base.clone() }.carveable());
        assert!(!Found { fate: Fate::Unknown, ..base.clone() }.carveable());
        assert!(
            !Found { fate: Fate::FreedAgain { sequence: 3 }, ..base.clone() }.carveable(),
            "the record went round the loop again: its clusters are not this file's"
        );
        assert!(!Found {
            fate: Fate::Reallocated { sequence: 2, to: Some("other.exe".into()) },
            ..base
        }
        .carveable());
    }
}
