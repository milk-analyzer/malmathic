use std::collections::HashMap;

use mm_core::NormalizedPath;

use crate::zone::{classify, Zone};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirStats {
    pub files: u32,
    pub executables: u32,
    pub compact_os: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NameStats {
    total: u32,
    conventional: u32,
}

#[derive(Debug, Default)]
pub struct Baseline {
    total_files: u64,
    total_executables: u64,
    directories: HashMap<String, DirStats>,
    name_counts: HashMap<u64, NameStats>,
    zone_executables: HashMap<Zone, u64>,
    zone_files: HashMap<Zone, u64>,
    compact_os_files: u64,
    compact_os_executables: u64,
    volume_enumerated: bool,
}

#[derive(Debug, Default)]
pub struct BaselineBuilder {
    baseline: Baseline,
}

impl BaselineBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, path: &NormalizedPath) {
        self.observe_file(path, false);
    }

    pub fn observe_file(&mut self, path: &NormalizedPath, compact_os: bool) {
        let b = &mut self.baseline;
        let executable = path.is_executable_extension();

        if compact_os {
            b.compact_os_files += 1;
            if executable {
                b.compact_os_executables += 1;
            }
        }

        b.total_files += 1;
        b.volume_enumerated = true;
        if executable {
            b.total_executables += 1;
        }

        if let Some(parent) = path.parent() {
            let entry = b.directories.entry(parent.to_string()).or_default();
            entry.files = entry.files.saturating_add(1);
            if executable {
                entry.executables = entry.executables.saturating_add(1);
            }
            if compact_os {
                entry.compact_os = entry.compact_os.saturating_add(1);
            }
        }

        let zone = classify(path);

        if let Some(name) = path.file_name() {
            let entry = b.name_counts.entry(hash_name(name)).or_default();
            entry.total = entry.total.saturating_add(1);
            if zone.is_conventional_for_executables() {
                entry.conventional = entry.conventional.saturating_add(1);
            }
        }

        *b.zone_files.entry(zone).or_insert(0) += 1;
        if executable {
            *b.zone_executables.entry(zone).or_insert(0) += 1;
        }
    }

    pub fn build(self) -> Baseline {
        self.baseline
    }
}

impl Baseline {
    pub fn total_files(&self) -> u64 {
        self.total_files
    }

    pub fn total_executables(&self) -> u64 {
        self.total_executables
    }

    pub fn directory(&self, dir: &str) -> Option<DirStats> {
        self.directories.get(dir).copied()
    }

    pub fn name_occurrences(&self, name: &str) -> u32 {
        self.name_counts.get(&hash_name(name)).map(|s| s.total).unwrap_or(0)
    }

    pub fn name_occurrences_in_conventional_zones(&self, name: &str) -> u32 {
        self.name_counts.get(&hash_name(name)).map(|s| s.conventional).unwrap_or(0)
    }

    pub fn executables_in_zone(&self, zone: Zone) -> u64 {
        self.zone_executables.get(&zone).copied().unwrap_or(0)
    }

    pub fn files_in_zone(&self, zone: Zone) -> u64 {
        self.zone_files.get(&zone).copied().unwrap_or(0)
    }

    pub fn is_lone_executable(&self, path: &NormalizedPath, min_siblings: u32) -> bool {
        if !path.is_executable_extension() {
            return false;
        }
        let Some(parent) = path.parent() else { return false };
        let Some(stats) = self.directory(parent) else { return false };

        stats.executables == 1 && stats.files.saturating_sub(stats.executables) >= min_siblings
    }

    pub fn executable_share_of_directory(&self, dir: &str) -> Option<f64> {
        let stats = self.directory(dir)?;
        if stats.files == 0 {
            return None;
        }
        Some(f64::from(stats.executables) / f64::from(stats.files))
    }

    pub fn zone_rarity(&self, zone: Zone) -> u64 {
        self.executables_in_zone(zone)
    }

    pub fn compact_os_files(&self) -> u64 {
        self.compact_os_files
    }

    pub fn compact_os_executables(&self) -> u64 {
        self.compact_os_executables
    }

    pub fn is_lone_compact_os_file(&self, path: &NormalizedPath) -> Option<bool> {
        let stats = self.directory(path.parent()?)?;
        Some(stats.compact_os <= 1)
    }

    pub fn compact_os_share_of_executables(&self) -> Option<f64> {
        if self.total_executables == 0 {
            return None;
        }
        Some(self.compact_os_executables as f64 / self.total_executables as f64)
    }

    pub fn is_usable(&self) -> bool {
        self.total_files >= 10_000
    }

    pub fn volume_enumerated(&self) -> bool {
        self.volume_enumerated
    }

    pub fn from_completed_walk() -> Baseline {
        Baseline { volume_enumerated: true, ..Baseline::default() }
    }
}

fn hash_name(name: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &str) -> NormalizedPath {
        NormalizedPath::parse(p).unwrap()
    }

    fn baseline_of(paths: &[&str]) -> Baseline {
        let mut b = BaselineBuilder::new();
        for p in paths {
            b.observe(&path(p));
        }
        b.build()
    }

    #[test]
    fn counts_files_and_executables() {
        let b = baseline_of(&[
            "C:\\Windows\\System32\\a.exe",
            "C:\\Windows\\System32\\b.dll",
            "C:\\Users\\bob\\notes.txt",
        ]);
        assert_eq!(b.total_files(), 3);
        assert_eq!(b.total_executables(), 2);
    }

    #[test]
    fn directory_statistics_are_per_directory() {
        let b = baseline_of(&[
            "C:\\Users\\bob\\Documents\\a.docx",
            "C:\\Users\\bob\\Documents\\b.docx",
            "C:\\Users\\bob\\Documents\\payload.exe",
            "C:\\Windows\\System32\\x.exe",
        ]);
        let docs = b.directory("\\users\\bob\\documents").unwrap();
        assert_eq!(docs.files, 3);
        assert_eq!(docs.executables, 1);
        assert!(
            (b.executable_share_of_directory("\\users\\bob\\documents").unwrap() - 1.0 / 3.0).abs()
                < 1e-9
        );
        assert!(b.directory("\\nonexistent").is_none());
    }

    #[test]
    fn a_lone_executable_among_documents_is_detected() {
        let mut paths: Vec<String> =
            (0..40).map(|i| format!("C:\\Users\\bob\\Documents\\report{i}.docx")).collect();
        paths.push("C:\\Users\\bob\\Documents\\invoice.exe".into());
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let b = baseline_of(&refs);

        assert!(b.is_lone_executable(&path("C:\\Users\\bob\\Documents\\invoice.exe"), 10));
    }

    #[test]
    fn an_application_directory_is_not_a_lone_executable() {
        let b = baseline_of(&[
            "C:\\Program Files\\App\\app.exe",
            "C:\\Program Files\\App\\helper.exe",
            "C:\\Program Files\\App\\lib.dll",
            "C:\\Program Files\\App\\readme.txt",
        ]);
        assert!(!b.is_lone_executable(&path("C:\\Program Files\\App\\app.exe"), 10));
    }

    #[test]
    fn a_lone_executable_needs_enough_siblings_to_be_meaningful() {
        let b = baseline_of(&["C:\\tools\\x.exe", "C:\\tools\\readme.txt"]);
        assert!(!b.is_lone_executable(&path("C:\\tools\\x.exe"), 10));
        assert!(b.is_lone_executable(&path("C:\\tools\\x.exe"), 1));
    }

    #[test]
    fn non_executables_are_never_lone_executables() {
        let b = baseline_of(&["C:\\Users\\bob\\Documents\\a.txt"]);
        assert!(!b.is_lone_executable(&path("C:\\Users\\bob\\Documents\\a.txt"), 0));
    }

    #[test]
    fn name_occurrences_distinguish_recurring_system_files() {
        let b = baseline_of(&[
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\WinSxS\\amd64_a\\svchost.exe",
            "C:\\Windows\\WinSxS\\amd64_b\\svchost.exe",
            "C:\\Users\\bob\\AppData\\Roaming\\vmnat.exe",
        ]);
        assert_eq!(b.name_occurrences("svchost.exe"), 3);
        assert_eq!(b.name_occurrences("vmnat.exe"), 1);
        assert_eq!(b.name_occurrences("never-seen.exe"), 0);
    }

    #[test]
    fn name_occurrences_are_also_counted_where_windows_ships_executables() {
        let b = baseline_of(&[
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\WinSxS\\amd64_a\\svchost.exe",
            "C:\\Windows\\WinSxS\\amd64_b\\svchost.exe",
            "C:\\Users\\bob\\AppData\\Roaming\\a\\update.exe",
            "C:\\Users\\bob\\AppData\\Local\\b\\update.exe",
            "C:\\Users\\bob\\Downloads\\update.exe",
        ]);

        assert_eq!(b.name_occurrences("svchost.exe"), 3);
        assert_eq!(b.name_occurrences_in_conventional_zones("svchost.exe"), 3);

        assert_eq!(b.name_occurrences("update.exe"), 3);
        assert_eq!(b.name_occurrences_in_conventional_zones("update.exe"), 0);

        assert_eq!(b.name_occurrences_in_conventional_zones("never-seen.exe"), 0);
    }

    #[test]
    fn the_conventional_count_follows_the_zone_and_not_the_extension() {
        let b = baseline_of(&[
            "C:\\Program Files\\App\\readme.txt",
            "C:\\Users\\bob\\readme.txt",
            "C:\\Windows\\Temp\\readme.txt",
        ]);
        assert_eq!(b.name_occurrences("readme.txt"), 3);
        assert_eq!(b.name_occurrences_in_conventional_zones("readme.txt"), 1);
    }

    #[test]
    fn zone_counts_are_tracked_separately() {
        let b = baseline_of(&[
            "C:\\Windows\\System32\\a.exe",
            "C:\\Windows\\System32\\b.exe",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\c.exe",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\readme.txt",
        ]);
        assert_eq!(b.executables_in_zone(Zone::SystemDir), 2);
        assert_eq!(b.executables_in_zone(Zone::UserTemp), 1);
        assert_eq!(b.files_in_zone(Zone::UserTemp), 2);
        assert_eq!(b.executables_in_zone(Zone::ProgramFiles), 0);
    }

    #[test]
    fn a_thin_baseline_reports_itself_unusable() {
        assert!(!baseline_of(&["C:\\a.exe"]).is_usable());
        assert!(!Baseline::default().is_usable());

        let mut b = BaselineBuilder::new();
        for i in 0..10_000 {
            b.observe(&path(&format!("C:\\Windows\\System32\\f{i}.dll")));
        }
        assert!(b.build().is_usable());
    }

    #[test]
    fn name_hashing_is_stable_and_discriminating() {
        assert_eq!(hash_name("svchost.exe"), hash_name("svchost.exe"));
        assert_ne!(hash_name("svchost.exe"), hash_name("svch0st.exe"));
        assert_ne!(hash_name(""), hash_name("a"));
    }

    #[test]
    fn root_level_files_do_not_break_directory_accounting() {
        let b = baseline_of(&["C:\\payload.exe"]);
        assert_eq!(b.total_executables(), 1);
        assert_eq!(b.directory("\\").map(|s| s.executables), Some(1));
    }
}
