use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind};
use mm_raw::usn::{self, Journal, RecordFate, Truncation, Verdict, Window};
use mm_raw::Volume;
use ntfs_core::usn::UsnReason;

pub const MAX_RESOLUTIONS: usize = 4096;

pub const MAX_CREATION_RESOLUTIONS: usize = 4096;

pub const RESOLVE_BUDGET: Duration = Duration::from_secs(30);

const MAX_PATH_DEPTH: usize = 64;

const ROOT_RECORD: u64 = 5;

const NAMESPACE_DOS: u8 = 2;
const ATTR_FILE_NAME: u32 = 0x30;

#[derive(Clone, Debug)]
pub struct State {
    pub verdict: Verdict,
    pub window: Window,
    pub maximum_size: Option<u64>,
    pub created: Option<DateTime<Utc>>,
    pub allocated_bytes: u64,
    pub sparse_bytes: u64,
    pub bytes_read: u64,
    pub truncated: Option<Truncation>,
    pub elapsed: Duration,
    pub records: usize,
    pub creations: usize,
    pub deletions: usize,
}

impl State {
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.verdict {
            Verdict::NoJournal => {
                "\\$Extend\\$UsnJrnl does not resolve on this volume — the change journal \
                 was never enabled, or it has been removed. That is not evidence either \
                 way; what it means is that no deletion on this volume carries a \
                 driver-written time"
                    .to_string()
            }
            Verdict::EmptyOrCleared { reason } => format!(
                "the journal is present and holds no records ({reason}). That is the shape \
                 `fsutil usn deletejournal /d` leaves, and it is also the shape an \
                 administrator resetting the journal leaves — identical from here, so it \
                 is reported and scored against nothing"
            ),
            Verdict::Active { records } => {
                let mut s = format!(
                    "{records} records, {} creations and {} deletions, {} KiB of $J read \
                     ({} KiB allocated, {} KiB sparse)",
                    self.creations,
                    self.deletions,
                    self.bytes_read / 1024,
                    self.allocated_bytes / 1024,
                    self.sparse_bytes / 1024,
                );
                if let (Some(first), Some(last)) = (self.window.first_time, self.window.last_time) {
                    s.push_str(&format!(
                        ", covering {} to {}",
                        mm_core::filetime::format(first),
                        mm_core::filetime::format(last)
                    ));
                }
                s.push_str(&self.scope());
                s
            }
        }
    }

    fn scope(&self) -> String {
        let Some(first) = self.window.first_time else { return String::new() };
        format!(
            ". Records older than {} have been trimmed off the front of $J and were not \
             carved out of unallocated space{}",
            mm_core::filetime::format(first),
            self.maximum_size
                .map(|m| format!(" (the journal is capped at {} MiB)", m / (1024 * 1024)))
                .unwrap_or_default(),
        )
    }

    #[must_use]
    pub fn limits(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(t) = &self.truncated {
            out.push(format!("the USN change journal was read only in part: {}", t.describe()));
        }
        if matches!(self.verdict, Verdict::EmptyOrCleared { .. }) {
            out.push(
                "the USN change journal is present but empty. Clearing it (`fsutil usn \
                 deletejournal /d`) is a documented step in several ransomware families, \
                 and it is also what an administrator resetting the journal does — this \
                 run cannot tell those apart, so it claims neither. What follows either \
                 way is that every deletion on this volume is undated except where a \
                 surviving $MFT record happens to carry a time"
                    .to_string(),
            );
        }
        out
    }
}

#[derive(Clone, Debug)]
pub struct Harvest {
    pub state: State,
    pub observations: Vec<Observation>,
    pub unresolved: usize,
    pub path_refilled: usize,
    pub creations: Vec<(String, DateTime<Utc>)>,
    pub creations_unresolved: usize,
    pub reallocated: usize,
    pub elapsed: Duration,
}

impl Harvest {
    #[must_use]
    pub fn corroboration_summary(&self) -> String {
        let mut s = format!(
            "{} deletion(s) dated from the journal for files this run already knew about",
            self.observations.len()
        );
        if self.reallocated > 0 {
            s.push_str(&format!(
                "; {} of them name an $MFT record that has since been handed to another \
                 file, so nothing of those files survives in the record and no carve is \
                 offered from it",
                self.reallocated
            ));
        }
        if self.path_refilled > 0 {
            s.push_str(&format!(
                "; {} further row(s) name a path that holds a live file today and were not \
                 used — a journal row records an event, not a state",
                self.path_refilled
            ));
        }
        if self.unresolved > 0 {
            s.push_str(&format!(
                "; {} row(s) share a file name with something this run knows but could not \
                 be placed at that path, and were discarded rather than guessed at",
                self.unresolved
            ));
        }
        s
    }

    #[must_use]
    pub fn clock(&self) -> Clock {
        Clock::new(self.creations.clone(), self.state.window.first_time)
    }

    #[must_use]
    pub fn creation_summary(&self) -> String {
        let mut s = format!(
            "{} known path(s) carry a driver-written creation instant. Nothing is \
             scored from these: they exist so a creation time this report already \
             reasons about can be checked against a clock SetFileTime does not reach",
            self.creations.len()
        );
        if self.creations_unresolved > 0 {
            s.push_str(&format!(
                "; {} further creation row(s) share a file name with something this \
                 run knows but could not be placed at that path, and were discarded \
                 rather than guessed at",
                self.creations_unresolved
            ));
        }
        s
    }
}

#[derive(Clone, Debug, Default)]
pub struct Clock {
    creations: HashMap<String, DateTime<Utc>>,
    oldest: Option<DateTime<Utc>>,
}

impl Clock {
    #[must_use]
    pub fn new(creations: Vec<(String, DateTime<Utc>)>, oldest: Option<DateTime<Utc>>) -> Self {
        Clock { creations: creations.into_iter().collect(), oldest }
    }

    #[must_use]
    pub fn created(&self, key: &str) -> Option<DateTime<Utc>> {
        self.creations.get(key).copied()
    }

    #[must_use]
    pub fn oldest(&self) -> Option<DateTime<Utc>> {
        self.oldest
    }

    #[must_use]
    pub fn is_silent(&self) -> bool {
        self.oldest.is_none() && self.creations.is_empty()
    }
}

pub struct KnownPaths<'a> {
    pub known: &'a HashSet<String>,
    pub present: &'a HashSet<String>,
}

pub fn harvest<R: Read + Seek>(volume: &Volume<R>, paths: &KnownPaths<'_>) -> Harvest {
    let started = Instant::now();
    let journal = usn::read_journal(volume);
    let state = summarise(&journal);

    let mut wanted: HashSet<&str> = HashSet::new();
    for key in paths.known {
        if let Some(leaf) = key.rsplit('\\').next() {
            if !leaf.is_empty() {
                wanted.insert(leaf);
            }
        }
    }

    let mut cache: HashMap<u64, Option<String>> = HashMap::new();
    let mut dated: HashMap<String, (DateTime<Utc>, u64, u16)> = HashMap::new();
    let mut resolutions = 0usize;
    let mut unresolved = 0usize;
    let mut path_refilled = 0usize;
    let mut created: HashMap<String, DateTime<Utc>> = HashMap::new();
    let mut creation_resolutions = 0usize;
    let mut creations_unresolved = 0usize;

    for record in &journal.records {
        if record.reason.contains(UsnReason::FILE_CREATE) {
            harvest_creation(
                volume,
                record,
                paths,
                &wanted,
                &mut cache,
                &mut created,
                &mut creation_resolutions,
                &mut creations_unresolved,
                started,
            );
        }
        if !record.reason.contains(UsnReason::FILE_DELETE) {
            continue;
        }
        let leaf = record.filename.to_ascii_lowercase();
        if !wanted.contains(leaf.as_str()) {
            continue;
        }
        if resolutions >= MAX_RESOLUTIONS || started.elapsed() >= RESOLVE_BUDGET {
            break;
        }
        resolutions += 1;

        let Some(directory) = resolve_directory(
            volume,
            record.parent_mft_entry,
            record.parent_mft_sequence,
            &mut cache,
            0,
        ) else {
            unresolved += 1;
            continue;
        };
        let full = if directory == "\\" {
            format!("\\{}", record.filename)
        } else {
            format!("{directory}\\{}", record.filename)
        };
        let Some(path) = NormalizedPath::parse(&full) else {
            unresolved += 1;
            continue;
        };
        if !paths.known.contains(path.key()) {
            unresolved += 1;
            continue;
        }
        if paths.present.contains(path.key()) {
            path_refilled += 1;
            continue;
        }
        match dated.get_mut(path.key()) {
            Some(slot) if slot.0 <= record.timestamp => {}
            Some(slot) => *slot = (record.timestamp, record.mft_entry, record.mft_sequence),
            None => {
                dated.insert(
                    path.key().to_string(),
                    (record.timestamp, record.mft_entry, record.mft_sequence),
                );
            }
        }
    }

    let mut observations = Vec::with_capacity(dated.len());
    let mut reallocated = 0usize;
    let mut keys: Vec<&String> = dated.keys().collect();
    keys.sort();
    for key in keys {
        let (when, entry, sequence) = dated[key];
        if matches!(usn::record_fate(volume, entry, sequence), RecordFate::Reallocated { .. }) {
            reallocated += 1;
        }
        let Some(path) = NormalizedPath::parse(key) else { continue };
        observations.push(Observation::about_path(
            ArtifactSource::UsnJournal,
            path,
            ObservationKind::FileDeleted {
                when: Some(when),
                record: Some(entry),
                sequence: Some(sequence),
            },
        ));
    }

    let mut creations: Vec<(String, DateTime<Utc>)> = created.into_iter().collect();
    creations.sort_by(|a, b| a.0.cmp(&b.0));

    Harvest {
        state,
        observations,
        unresolved,
        path_refilled,
        creations,
        creations_unresolved,
        reallocated,
        elapsed: started.elapsed(),
    }
}

#[allow(clippy::too_many_arguments)]
fn harvest_creation<R: Read + Seek>(
    volume: &Volume<R>,
    record: &ntfs_core::usn::UsnRecord,
    paths: &KnownPaths<'_>,
    wanted: &HashSet<&str>,
    cache: &mut HashMap<u64, Option<String>>,
    created: &mut HashMap<String, DateTime<Utc>>,
    resolutions: &mut usize,
    unresolved: &mut usize,
    started: Instant,
) {
    let leaf = record.filename.to_ascii_lowercase();
    if !wanted.contains(leaf.as_str()) {
        return;
    }
    if *resolutions >= MAX_CREATION_RESOLUTIONS || started.elapsed() >= RESOLVE_BUDGET {
        return;
    }
    *resolutions += 1;
    let Some(directory) =
        resolve_directory(volume, record.parent_mft_entry, record.parent_mft_sequence, cache, 0)
    else {
        *unresolved += 1;
        return;
    };
    let full = if directory == "\\" {
        format!("\\{}", record.filename)
    } else {
        format!("{directory}\\{}", record.filename)
    };
    let Some(path) = NormalizedPath::parse(&full) else {
        *unresolved += 1;
        return;
    };
    if !paths.known.contains(path.key()) {
        *unresolved += 1;
        return;
    }
    match created.get_mut(path.key()) {
        Some(slot) if *slot <= record.timestamp => {}
        Some(slot) => *slot = record.timestamp,
        None => {
            created.insert(path.key().to_string(), record.timestamp);
        }
    }
}

fn summarise(journal: &Journal) -> State {
    let mut creations = 0usize;
    let mut deletions = 0usize;
    for r in &journal.records {
        if r.reason.contains(UsnReason::FILE_CREATE) {
            creations += 1;
        }
        if r.reason.contains(UsnReason::FILE_DELETE) {
            deletions += 1;
        }
    }
    State {
        verdict: journal.verdict(),
        window: journal.window(),
        maximum_size: journal.max.as_ref().map(|m| m.maximum_size),
        created: journal.max.as_ref().and_then(|m| m.created),
        allocated_bytes: journal.allocated_bytes,
        sparse_bytes: journal.sparse_bytes,
        bytes_read: journal.bytes_read,
        truncated: journal.truncated.clone(),
        elapsed: journal.elapsed,
        records: journal.records.len(),
        creations,
        deletions,
    }
}

pub(crate) fn resolve_directory<R: Read + Seek>(
    volume: &Volume<R>,
    record: u64,
    expected_sequence: u16,
    cache: &mut HashMap<u64, Option<String>>,
    depth: usize,
) -> Option<String> {
    if record == ROOT_RECORD {
        return Some("\\".to_string());
    }
    if depth >= MAX_PATH_DEPTH {
        return None;
    }

    let bytes = volume.fs().read_record(record).ok()?;
    let header = ntfs_core::MftRecordHeader::parse(&bytes).ok()?;
    if &header.signature != b"FILE" || !header.is_base_record() {
        return None;
    }
    if expected_sequence != 0 && header.sequence_number != expected_sequence {
        return None;
    }
    if !header.is_in_use() || !header.is_directory() {
        return None;
    }
    if let Some(hit) = cache.get(&record) {
        return hit.clone();
    }

    let attributes =
        ntfs_core::parse_attributes(&bytes, header.first_attribute_offset as usize).ok()?;
    let mut name: Option<String> = None;
    let mut parent: Option<(u64, u16)> = None;
    let mut best_namespace = u8::MAX;
    for attribute in &attributes {
        if attribute.type_code != ATTR_FILE_NAME {
            continue;
        }
        let Some(content) = attribute.resident_content(&bytes) else { continue };
        let Ok(file_name) = ntfs_core::FileName::parse(content) else { continue };
        if file_name.namespace != NAMESPACE_DOS && file_name.namespace < best_namespace {
            best_namespace = file_name.namespace;
            name = Some(file_name.name.clone());
            parent = Some((file_name.parent.record_number, file_name.parent.sequence));
        } else if name.is_none() {
            name = Some(file_name.name.clone());
            parent = Some((file_name.parent.record_number, file_name.parent.sequence));
        }
    }
    let name = name?;
    let (parent_record, parent_sequence) = parent?;

    let resolved = resolve_directory(volume, parent_record, parent_sequence, cache, depth + 1)
        .map(|p| if p == "\\" { format!("\\{name}") } else { format!("{p}\\{name}") });
    cache.insert(record, resolved.clone());
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn state_with(verdict: Verdict) -> State {
        State {
            verdict,
            window: Window::default(),
            maximum_size: None,
            created: None,
            allocated_bytes: 0,
            sparse_bytes: 0,
            bytes_read: 0,
            truncated: None,
            elapsed: Duration::ZERO,
            records: 0,
            creations: 0,
            deletions: 0,
        }
    }

    #[test]
    fn every_journal_state_says_what_it_is() {
        let none = state_with(Verdict::NoJournal);
        assert!(none.summary().contains("does not resolve"), "{}", none.summary());
        assert!(none.limits().is_empty(), "{:?}", none.limits());

        let cleared =
            state_with(Verdict::EmptyOrCleared { reason: "no allocated clusters".into() });
        assert!(cleared.summary().contains("deletejournal"), "{}", cleared.summary());
        let limits = cleared.limits();
        assert_eq!(limits.len(), 1, "{limits:?}");
        assert!(limits[0].contains("cannot tell those apart"), "{}", limits[0]);

        let active =
            State { records: 12, deletions: 3, ..state_with(Verdict::Active { records: 12 }) };
        assert!(active.summary().contains("12 records"), "{}", active.summary());
        assert!(active.summary().contains("3 deletions"), "{}", active.summary());
    }

    #[test]
    fn a_truncated_read_is_stated_as_missing_evidence() {
        let s = State {
            truncated: Some(Truncation::Time(90)),
            ..state_with(Verdict::Active { records: 5 })
        };
        let limits = s.limits();
        assert!(limits.iter().any(|l| l.contains("only in part")), "{limits:?}");
    }

    #[test]
    fn the_window_is_stated_on_the_line_and_never_warned_about() {
        let first = Utc.with_ymd_and_hms(2026, 5, 8, 14, 10, 15).unwrap();
        let s = State {
            window: Window { first_time: Some(first), ..Window::default() },
            maximum_size: Some(32 * 1024 * 1024),
            ..state_with(Verdict::Active { records: 5 })
        };
        let summary = s.summary();
        assert!(summary.contains("trimmed off the front"), "{summary}");
        assert!(summary.contains("32 MiB"), "{summary}");
        assert!(summary.contains("not carved out of unallocated space"), "{summary}");
        assert!(s.limits().is_empty(), "{:?}", s.limits());
    }

    #[test]
    fn declined_rows_are_counted_out_loud() {
        let h = Harvest {
            state: state_with(Verdict::Active { records: 9 }),
            observations: Vec::new(),
            unresolved: 4,
            path_refilled: 7,
            creations: Vec::new(),
            creations_unresolved: 0,
            reallocated: 0,
            elapsed: Duration::ZERO,
        };
        let s = h.corroboration_summary();
        assert!(s.contains("0 deletion"), "{s}");
        assert!(s.contains("7 further row(s)"), "{s}");
        assert!(s.contains("4 row(s)"), "{s}");
        assert!(s.contains("discarded rather than guessed at"), "{s}");
    }

    #[test]
    fn a_reallocated_record_is_stated_as_unrecoverable() {
        let h = Harvest {
            state: state_with(Verdict::Active { records: 9 }),
            observations: Vec::new(),
            unresolved: 0,
            path_refilled: 0,
            creations: Vec::new(),
            creations_unresolved: 0,
            reallocated: 3,
            elapsed: Duration::ZERO,
        };
        let s = h.corroboration_summary();
        assert!(s.contains("handed to another file"), "{s}");
        assert!(s.contains("no carve is offered"), "{s}");
    }
}
