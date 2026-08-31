use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use mm_core::{MassEncryption, NormalizedPath};

use crate::filesystem::FileFacts;

pub const MIN_COHORT_FILES: u64 = 300;

pub const MIN_COHORT_DIRS: usize = 50;

pub const MIN_PRIMARY_EXTENSIONS: usize = 2;

pub const MIN_NOTE_DIRS: usize = 50;

pub const NOTE_COVERAGE: f64 = 0.75;

const MAX_NOTE_DIRS: usize = 4096;
const _: () =
    assert!(MAX_NOTE_DIRS > MIN_NOTE_DIRS, "the cap must never sit below the floor it feeds");

const EXAMPLES: usize = 6;

fn hash(text: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        h ^= u64::from(byte.to_ascii_lowercase());
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

#[derive(Debug, Default)]
struct Cohort {
    files: u64,
    dirs: HashSet<u64>,
    originals: HashMap<Box<str>, u64>,
    examples: Vec<String>,
    earliest: Option<DateTime<Utc>>,
    latest: Option<DateTime<Utc>>,
    roots: HashMap<Box<str>, u64>,
}

#[derive(Debug)]
struct NoteCandidate {
    name: Box<str>,
    size: u64,
    dirs: Vec<u64>,
    alive: bool,
    example: String,
}

#[derive(Debug, Default)]
pub struct Scan {
    cohorts: HashMap<Box<str>, Cohort>,
    notes: HashMap<u64, NoteCandidate>,
    files_seen: u64,
}

impl Scan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, path: &NormalizedPath, facts: &FileFacts) {
        if facts.is_directory || !facts.in_use {
            return;
        }
        let Some(name) = path.file_name() else { return };
        let Some(parent) = path.parent() else { return };
        self.files_seen += 1;
        let dir = hash(parent);

        self.observe_cohort(path, name, dir, facts);
        self.observe_note(path, name, dir, facts);
    }

    fn observe_cohort(&mut self, path: &NormalizedPath, name: &str, dir: u64, facts: &FileFacts) {
        let lower = name.to_ascii_lowercase();
        let parts: Vec<&str> = lower.split('.').collect();
        if parts.len() < 3 {
            return;
        }
        let suffix = parts[parts.len() - 1];
        let primary = parts[parts.len() - 2];
        if !is_extension_like(suffix) || !is_extension_like(primary) {
            return;
        }

        let cohort = self.cohorts.entry(suffix.into()).or_default();
        cohort.files += 1;
        cohort.dirs.insert(dir);
        *cohort.originals.entry(primary.into()).or_default() += 1;
        if cohort.examples.len() < EXAMPLES {
            cohort.examples.push(path.display_path().to_string());
        }
        if let Some(modified) = facts.si_modified {
            cohort.earliest = Some(cohort.earliest.map_or(modified, |e| e.min(modified)));
            cohort.latest = Some(cohort.latest.map_or(modified, |l| l.max(modified)));
        }
        *cohort.roots.entry(top_level(path.display_path()).into()).or_default() += 1;
    }

    fn observe_note(&mut self, path: &NormalizedPath, name: &str, dir: u64, facts: &FileFacts) {
        if facts.size == 0 {
            return;
        }
        let key = hash(name);
        match self.notes.get_mut(&key) {
            Some(note) => {
                if !note.alive {
                    return;
                }
                if note.size != facts.size {
                    note.alive = false;
                    note.dirs = Vec::new();
                    note.dirs.shrink_to_fit();
                    return;
                }
                if note.dirs.len() < MAX_NOTE_DIRS && !note.dirs.contains(&dir) {
                    note.dirs.push(dir);
                }
            }
            None => {
                self.notes.insert(
                    key,
                    NoteCandidate {
                        name: name.to_ascii_lowercase().into(),
                        size: facts.size,
                        dirs: vec![dir],
                        alive: true,
                        example: path.display_path().to_string(),
                    },
                );
            }
        }
    }

    #[must_use]
    pub fn finish(self) -> Option<MassEncryption> {
        let notes: Vec<&NoteCandidate> =
            self.notes.values().filter(|n| n.alive && n.dirs.len() >= MIN_NOTE_DIRS).collect();
        if notes.is_empty() {
            return None;
        }

        let mut best: Option<MassEncryption> = None;
        for (suffix, cohort) in &self.cohorts {
            if cohort.files < MIN_COHORT_FILES
                || cohort.dirs.len() < MIN_COHORT_DIRS
                || cohort.originals.len() < MIN_PRIMARY_EXTENSIONS
            {
                continue;
            }
            for note in &notes {
                if note.name.ends_with(&format!(".{suffix}")) {
                    continue;
                }
                let shared = note.dirs.iter().filter(|d| cohort.dirs.contains(d)).count();
                let coverage = shared as f64 / cohort.dirs.len() as f64;
                if coverage < NOTE_COVERAGE {
                    continue;
                }
                let finding = MassEncryption {
                    extension: suffix.to_string(),
                    files: cohort.files,
                    directories: cohort.dirs.len() as u64,
                    original_extensions: top_counts(&cohort.originals),
                    roots: top_counts(&cohort.roots),
                    examples: cohort.examples.clone(),
                    note_name: note.name.to_string(),
                    note_size: note.size,
                    note_directories: note.dirs.len() as u64,
                    note_coverage: coverage,
                    note_example: note.example.clone(),
                    earliest: cohort.earliest,
                    latest: cohort.latest,
                    files_scanned: self.files_seen,
                };
                if best.as_ref().is_none_or(|b| finding.files > b.files) {
                    best = Some(finding);
                }
            }
        }
        best
    }
}

fn is_extension_like(fragment: &str) -> bool {
    !fragment.is_empty()
        && fragment.len() <= 16
        && fragment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn top_level(path: &str) -> String {
    let path = path.split_once(':').map_or(path, |(_, rest)| rest);
    let mut parts = path.split('\\').filter(|p| !p.is_empty());
    match (parts.next(), parts.next()) {
        (Some(a), Some(b)) => format!("\\{a}\\{b}"),
        (Some(a), None) => format!("\\{a}"),
        _ => "\\".to_string(),
    }
}

fn top_counts(counts: &HashMap<Box<str>, u64>) -> Vec<(String, u64)> {
    let mut rows: Vec<(String, u64)> = counts.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(16);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(files: &[(&str, u64)]) -> Option<MassEncryption> {
        scan_at(files, None)
    }

    fn scan_at(files: &[(&str, u64)], modified: Option<DateTime<Utc>>) -> Option<MassEncryption> {
        let mut scan = Scan::new();
        for (path, size) in files {
            let normalized = NormalizedPath::parse(path).expect("a normal path");
            let facts = facts(*size, modified);
            scan.observe(&normalized, &facts);
        }
        scan.finish()
    }

    fn facts(size: u64, modified: Option<DateTime<Utc>>) -> FileFacts {
        FileFacts {
            record: 0,
            size,
            is_directory: false,
            in_use: true,
            si_created: None,
            si_modified: modified,
            si_mft_modified: None,
            fn_created: None,
            has_ads: false,
            hard_links: 1,
            compact_os: None,
            parent_created: None,
        }
    }

    fn encrypted_volume(
        suffix: &str,
        note: &str,
        note_size: u64,
        dirs: usize,
        per_dir: usize,
    ) -> Vec<(String, u64)> {
        let originals = ["txt", "js", "png", "docx", "json"];
        let mut files = Vec::new();
        for d in 0..dirs {
            for f in 0..per_dir {
                files.push((
                    format!(
                        "C:\\Users\\v\\d{d}\\file{f}.{}.{suffix}",
                        originals[f % originals.len()]
                    ),
                    4096,
                ));
            }
            files.push((format!("C:\\Users\\v\\d{d}\\{note}"), note_size));
        }
        files
    }

    fn borrow(files: &[(String, u64)]) -> Vec<(&str, u64)> {
        files.iter().map(|(p, s)| (p.as_str(), *s)).collect()
    }

    #[test]
    fn a_renamed_cohort_with_a_note_in_every_directory_is_reported() {
        let files = encrypted_volume("fuckazov", "stop_propaganda.txt", 131, 60, 6);
        let finding = scan(&borrow(&files)).expect("this is the machine the module exists for");

        assert_eq!(finding.extension, "fuckazov");
        assert_eq!(finding.files, 360);
        assert_eq!(finding.directories, 60);
        assert_eq!(finding.note_name, "stop_propaganda.txt");
        assert_eq!(finding.note_size, 131);
        assert!(
            (finding.note_coverage - 1.0).abs() < f64::EPSILON,
            "the note is in every directory the cohort touched, got {}",
            finding.note_coverage
        );
        assert!(
            finding.original_extensions.len() >= MIN_PRIMARY_EXTENSIONS,
            "what the files used to be is the evidence that this was a rename"
        );
    }

    #[test]
    fn the_suffix_is_not_matched_against_any_list_of_known_extensions() {
        for suffix in ["fuckazov", "locked", "a7f3e91", "wnry", "zz12"] {
            let files = encrypted_volume(suffix, "READ_ME.txt", 900, 60, 6);
            let finding = scan(&borrow(&files))
                .unwrap_or_else(|| panic!("a per-victim suffix must still be found: {suffix}"));
            assert_eq!(finding.extension, suffix);
        }
    }

    #[test]
    fn the_note_is_recognised_by_shape_and_never_by_its_name_or_content() {
        for note in ["stop_propaganda.txt", "READ_ME.hta", "a.b", "zzz"] {
            let files = encrypted_volume("locked", note, 131, 60, 6);
            let finding = scan(&borrow(&files))
                .unwrap_or_else(|| panic!("a note named {note} is still a note"));
            assert_eq!(finding.note_name, note.to_ascii_lowercase());
        }
    }

    #[test]
    fn a_rename_cohort_with_no_note_is_not_reported() {
        let originals = ["exe", "dll", "sys", "cpl"];
        let mut files = Vec::new();
        for d in 0..80 {
            for f in 0..10 {
                files.push((
                    format!("C:\\Windows\\d{d}\\thing{f}.{}.mui", originals[f % originals.len()]),
                    4096,
                ));
            }
        }
        assert_eq!(
            scan(&borrow(&files)),
            None,
            "`.mui` is the largest cohort on the clean control and must stay silent"
        );
    }

    #[test]
    fn a_note_shaped_file_with_no_rename_cohort_is_not_reported() {
        let mut files = Vec::new();
        for d in 0..400 {
            files.push((format!("C:\\Users\\dev\\proj\\target\\d{d}\\invoked.timestamp"), 48));
            files.push((format!("C:\\Users\\dev\\proj\\target\\d{d}\\lib.rs"), 900 + d));
        }
        assert_eq!(scan(&borrow(&files)), None, "a cargo build tree is not a ransomed machine");
    }

    #[test]
    fn a_cohort_and_a_note_that_share_no_directory_are_not_reported() {
        let mut files = Vec::new();
        for d in 0..80 {
            for f in 0..8 {
                files.push((format!("C:\\Windows\\a{d}\\x{f}.txt.mui"), 4096));
                files.push((format!("C:\\Windows\\a{d}\\x{f}.js.mui"), 4096));
            }
        }
        for d in 0..200 {
            files.push((format!("C:\\Users\\dev\\b{d}\\invoked.timestamp"), 48));
        }
        assert_eq!(
            scan(&borrow(&files)),
            None,
            "coverage is measured against the cohort's OWN directories"
        );
    }

    #[test]
    fn a_note_in_too_few_of_the_cohorts_directories_is_not_reported() {
        let originals = ["txt", "js", "png"];
        let mut files = Vec::new();
        for d in 0..80 {
            for f in 0..8 {
                files.push((format!("C:\\Users\\v\\d{d}\\f{f}.{}.locked", originals[f % 3]), 4096));
            }
            if d % 2 == 0 {
                files.push((format!("C:\\Users\\v\\d{d}\\note.txt"), 131));
            }
        }
        assert_eq!(scan(&borrow(&files)), None, "50% is below the 75% floor");
    }

    #[test]
    fn a_recurring_name_at_varying_sizes_is_not_a_note() {
        let originals = ["txt", "js", "png"];
        let mut files = Vec::new();
        for d in 0..80 {
            for f in 0..8 {
                files.push((format!("C:\\Users\\v\\d{d}\\f{f}.{}.locked", originals[f % 3]), 4096));
            }
            files.push((format!("C:\\Users\\v\\d{d}\\package.json"), 100 + d));
        }
        assert_eq!(scan(&borrow(&files)), None);
    }

    #[test]
    fn an_empty_file_is_not_a_note() {
        let originals = ["txt", "js", "png"];
        let mut files = Vec::new();
        for d in 0..80 {
            for f in 0..8 {
                files.push((format!("C:\\Users\\v\\d{d}\\f{f}.{}.locked", originals[f % 3]), 4096));
            }
            files.push((format!("C:\\Users\\v\\d{d}\\lock"), 0));
        }
        assert_eq!(scan(&borrow(&files)), None);
    }

    #[test]
    fn a_suffix_over_a_single_original_extension_is_a_file_type_not_a_rename() {
        let mut files = Vec::new();
        for d in 0..80 {
            for f in 0..8 {
                files.push((format!("C:\\Users\\v\\d{d}\\f{f}.min.js"), 4096));
            }
            files.push((format!("C:\\Users\\v\\d{d}\\note.txt"), 131));
        }
        assert_eq!(scan(&borrow(&files)), None, "`x.min.js` everywhere is a build convention");
    }

    #[test]
    fn a_cohort_below_the_floors_is_not_reported() {
        let few_dirs = encrypted_volume("locked", "note.txt", 131, 10, 40);
        assert_eq!(scan(&borrow(&few_dirs)), None, "400 files in 10 directories is not mass");

        let few_files = encrypted_volume("locked", "note.txt", 131, 60, 2);
        assert_eq!(scan(&borrow(&few_files)), None, "120 files is below MIN_COHORT_FILES");
    }

    #[test]
    fn the_clean_machines_measured_for_this_module_report_nothing() {
        let mut files: Vec<(String, u64)> = Vec::new();
        for d in 0..300 {
            for (f, ext) in ["exe", "dll", "sys"].iter().enumerate() {
                files.push((format!("C:\\Windows\\System32\\d{d}\\a{f}.{ext}.mui"), 4096));
            }
        }
        for d in 0..500 {
            files.push((format!("C:\\Users\\dev\\t\\d{d}\\invoked.timestamp"), 48));
        }
        for d in 0..500 {
            files.push((format!("C:\\Python\\Lib\\d{d}\\__init__.py"), d));
        }
        for d in 0..200 {
            files.push((format!("C:\\Users\\dev\\c{d}\\cache.lock"), 0));
        }
        assert_eq!(
            scan(&borrow(&files)),
            None,
            "0 findings over 2,562,140 live files is the claim this module ships on"
        );
    }

    #[test]
    fn deleted_records_and_directories_are_not_counted() {
        let files = encrypted_volume("locked", "note.txt", 131, 60, 6);
        let mut scan = Scan::new();
        for (path, size) in &files {
            let normalized = NormalizedPath::parse(path).expect("a normal path");
            let mut f = facts(*size, None);
            f.in_use = false;
            scan.observe(&normalized, &f);
        }
        assert_eq!(scan.finish(), None, "deleted records must not carry a finding");

        let mut scan = Scan::new();
        for (path, size) in &files {
            let normalized = NormalizedPath::parse(path).expect("a normal path");
            let mut f = facts(*size, None);
            f.is_directory = true;
            scan.observe(&normalized, &f);
        }
        assert_eq!(scan.finish(), None, "a directory is not an encrypted file");
    }

    #[test]
    fn the_write_burst_is_reported_but_decides_nothing() {
        let files = encrypted_volume("locked", "note.txt", 131, 60, 6);
        let when =
            DateTime::parse_from_rfc3339("2026-05-09T18:42:16Z").unwrap().with_timezone(&Utc);

        let without = scan(&borrow(&files)).expect("found without any timestamp at all");
        let with = scan_at(&borrow(&files), Some(when)).expect("found with one");

        assert_eq!(without.files, with.files);
        assert_eq!(without.directories, with.directories);
        assert_eq!(without.note_coverage, with.note_coverage);
        assert_eq!(without.window(), None, "no clock, no window, same verdict");
        assert_eq!(with.window(), Some((when, when)));
    }

    #[test]
    fn the_scan_touches_no_candidate_and_no_weight() {
        let files = encrypted_volume("locked", "note.txt", 131, 60, 6);
        let finding = scan(&borrow(&files)).expect("a finding");
        let json = serde_json::to_string(&finding).expect("serialises");
        for forbidden in ["log_odds", "weight", "candidate", "probability", "evidence"] {
            assert!(
                !json.contains(forbidden),
                "a machine-level statement must carry no scoring field, found {forbidden}"
            );
        }
    }

    #[test]
    fn an_empty_volume_is_not_a_finding() {
        assert_eq!(scan(&[]), None);
        assert_eq!(scan(&[("C:\\Users\\v\\a.txt", 10)]), None);
    }
}
