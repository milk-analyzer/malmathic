use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::vmdk::VmdkInfo;

const MAX_SIDECAR: u64 = 4 * 1024 * 1024;

const MAX_SNAPSHOTS: usize = 4096;

const EPOCH_DELTA_MICROS: u64 = 11_644_473_600 * 1_000_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub uid: Option<String>,
    pub display_name: Option<String>,
    pub disk_file: Option<String>,
    pub parent_uid: Option<String>,
    pub created: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default)]
pub struct VmMetadata {
    pub vmsd_path: Option<PathBuf>,
    pub vmx_path: Option<PathBuf>,
    pub vm_name: Option<String>,
    pub current_disks: Vec<String>,
    pub snapshots: Vec<Snapshot>,
}

impl VmMetadata {
    pub fn beside(vmdk: &Path) -> Self {
        let Some(dir) = vmdk.parent().filter(|p| !p.as_os_str().is_empty()) else {
            return VmMetadata::default();
        };
        let stem = vm_stem(vmdk);

        let mut meta = VmMetadata::default();
        if let Some(path) = find_sidecar(dir, stem.as_deref(), "vmsd") {
            if let Some(text) = read_text(&path) {
                meta.snapshots = parse_vmsd(&text);
                meta.vmsd_path = Some(path);
            }
        }
        if let Some(path) = find_sidecar(dir, stem.as_deref(), "vmx") {
            if let Some(text) = read_text(&path) {
                let (name, disks) = parse_vmx(&text);
                meta.vm_name = name;
                meta.current_disks = disks;
                meta.vmx_path = Some(path);
            }
        }
        meta
    }

    pub fn snapshot_for_disk(&self, file_name: &str) -> Option<&Snapshot> {
        self.snapshots
            .iter()
            .find(|s| s.disk_file.as_deref().is_some_and(|d| same_file(d, file_name)))
    }

    pub fn is_current_disk(&self, file_name: &str) -> bool {
        self.current_disks.iter().any(|d| same_file(d, file_name))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Moment {
    Snapshot { name: String, created: Option<DateTime<Utc>> },
    LiveState,
    BaseDisk,
    Unknown,
}

impl Moment {
    pub fn describe(&self) -> String {
        match self {
            Moment::Snapshot { name, created } => match created {
                Some(at) => {
                    format!("snapshot \"{name}\", taken {}", mm_core::filetime::format(*at))
                }
                None => format!("snapshot \"{name}\", taken at an UNKNOWN time"),
            },
            Moment::LiveState => {
                "the live state the VM was last left in, after the newest snapshot".to_string()
            }
            Moment::BaseDisk => "the base disk, before any snapshot was taken".to_string(),
            Moment::Unknown => "a link the sidecars do not name; its moment is UNKNOWN".to_string(),
        }
    }

    fn created(&self) -> Option<DateTime<Utc>> {
        match self {
            Moment::Snapshot { created, .. } => *created,
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NamedLink {
    pub name: String,
    pub cid: String,
    pub parent_cid: String,
    pub moment: Moment,
}

#[derive(Clone, Debug)]
pub struct SnapshotView {
    pub links: Vec<NamedLink>,
    pub metadata: VmMetadata,
}

impl SnapshotView {
    pub fn of(vmdk: &Path, info: &VmdkInfo) -> Self {
        let metadata = VmMetadata::beside(vmdk);
        let links = Self::join(&metadata, info);
        SnapshotView { links, metadata }
    }

    pub fn join(metadata: &VmMetadata, info: &VmdkInfo) -> Vec<NamedLink> {
        let last = info.chain.len().saturating_sub(1);
        info.chain
            .iter()
            .enumerate()
            .map(|(index, link)| {
                let moment = if let Some(snapshot) = metadata.snapshot_for_disk(&link.name) {
                    match &snapshot.display_name {
                        Some(name) => {
                            Moment::Snapshot { name: name.clone(), created: snapshot.created }
                        }
                        None => Moment::Unknown,
                    }
                } else if metadata.is_current_disk(&link.name) {
                    Moment::LiveState
                } else if index == last {
                    Moment::BaseDisk
                } else {
                    Moment::Unknown
                };
                NamedLink {
                    name: link.name.clone(),
                    cid: link.cid.clone(),
                    parent_cid: link.parent_cid.clone(),
                    moment,
                }
            })
            .collect()
    }

    pub fn top(&self) -> Option<&NamedLink> {
        self.links.first()
    }

    pub fn provenance(&self) -> String {
        let Some(top) = self.top() else {
            return "No VMDK chain was read.".to_string();
        };
        let mut line = format!("Read {} — {}", top.name, top.moment.describe());
        match self.links.len() {
            1 => line.push_str(". It has no parent, so this is the whole disk"),
            n => {
                let base = &self.links[n - 1];
                let _ = write!(
                    line,
                    ". Read through {} parent link(s) to the base {}; every grain the newer \
                     links do not hold came from an older one",
                    n - 1,
                    base.name
                );
            }
        }
        line.push('.');
        line
    }

    pub fn describe(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "Snapshot chain ({} link(s), newest first):", self.links.len());
        for (index, link) in self.links.iter().enumerate() {
            let parent = if is_no_parent(&link.parent_cid) {
                "none (base disk)".to_string()
            } else {
                link.parent_cid.clone()
            };
            let _ = writeln!(
                out,
                "  {} {:<34} CID {:<10} parent CID {}",
                if index == 0 { "->" } else { "  " },
                link.name,
                link.cid,
                parent
            );
            let _ = writeln!(out, "       {}", link.moment.describe());
        }
        let _ = writeln!(out, "{}", self.sources());
        out
    }

    pub fn available(&self, dir: &Path) -> String {
        let mut out = String::new();
        if self.metadata.snapshots.is_empty() {
            let _ = writeln!(
                out,
                "No .vmsd beside these disks, so which snapshots exist is UNKNOWN. The chain \
                 above is still verified by CID."
            );
            return out;
        }
        let vm = self.metadata.vm_name.as_deref().unwrap_or("this VM");
        let _ = writeln!(out, "Snapshots of {vm}, oldest first — pass any of these to --image:");
        for snapshot in &self.metadata.snapshots {
            let name = snapshot.display_name.as_deref().unwrap_or("(unnamed)");
            let when = match snapshot.created {
                Some(at) => mm_core::filetime::format(at),
                None => "UNKNOWN time".to_string(),
            };
            let file = snapshot.disk_file.as_deref().unwrap_or("(no disk recorded)");
            let here = snapshot
                .disk_file
                .as_deref()
                .map(|f| dir.join(file_name_of(f)).is_file())
                .unwrap_or(false);
            let _ = writeln!(
                out,
                "  {file:<34} {when}  \"{name}\"{}",
                if here { "" } else { "   [file not present here]" }
            );
        }
        for disk in &self.metadata.current_disks {
            let _ = writeln!(
                out,
                "  {disk:<34} {:<20}  the live state, after the newest snapshot",
                "now"
            );
        }
        out
    }

    fn sources(&self) -> String {
        let mut out = String::new();
        match &self.metadata.vmsd_path {
            Some(path) => {
                let _ = write!(out, "  Snapshot names and times: {}", path.display());
            }
            None => {
                let _ = write!(out, "  Snapshot names and times: UNKNOWN (no .vmsd found)");
            }
        }
        if let Some(path) = &self.metadata.vmx_path {
            let _ = write!(out, "\n  Live disk: {}", path.display());
        }
        out
    }

    pub fn chronological(&self) -> Vec<&NamedLink> {
        self.links.iter().rev().collect()
    }

    pub fn times_agree_with_chain(&self) -> bool {
        let times: Vec<DateTime<Utc>> =
            self.links.iter().rev().filter_map(|l| l.moment.created()).collect();
        times.windows(2).all(|w| w[0] <= w[1])
    }
}

fn is_no_parent(cid: &str) -> bool {
    cid.is_empty() || cid.eq_ignore_ascii_case("ffffffff")
}

fn file_name_of(raw: &str) -> &str {
    raw.rsplit(['/', '\\']).next().unwrap_or(raw)
}

fn same_file(a: &str, b: &str) -> bool {
    file_name_of(a).eq_ignore_ascii_case(file_name_of(b))
}

fn vm_stem(vmdk: &Path) -> Option<String> {
    let stem = vmdk.file_stem()?.to_str()?;
    let trimmed = match stem.rsplit_once('-') {
        Some((head, tail))
            if !head.is_empty() && tail.len() >= 6 && tail.bytes().all(|b| b.is_ascii_digit()) =>
        {
            head
        }
        _ => stem,
    };
    Some(trimmed.to_string())
}

fn find_sidecar(dir: &Path, stem: Option<&str>, ext: &str) -> Option<PathBuf> {
    if let Some(stem) = stem {
        let direct = dir.join(format!("{stem}.{ext}"));
        if direct.is_file() {
            return Some(direct);
        }
    }
    let mut found = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e.eq_ignore_ascii_case(ext)) && path.is_file() {
            if found.is_some() {
                return None;
            }
            found = Some(path);
        }
    }
    found
}

fn read_text(path: &Path) -> Option<String> {
    let length = std::fs::metadata(path).ok()?.len();
    if length > MAX_SIDECAR {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(decode(&bytes))
}

const CP1251_HIGH: [char; 128] = [
    'Ђ', 'Ѓ', '‚', 'ѓ', '„', '…', '†', '‡', '€', '‰', 'Љ', '‹', 'Њ', 'Ќ', 'Ћ', 'Џ', 'ђ', '‘', '’',
    '“', '”', '•', '–', '—', '\u{98}', '™', 'љ', '›', 'њ', 'ќ', 'ћ', 'џ', '\u{a0}', 'Ў', 'ў', 'Ј',
    '¤', 'Ґ', '¦', '§', 'Ё', '©', 'Є', '«', '¬', '\u{ad}', '®', 'Ї', '°', '±', 'І', 'і', 'ґ', 'µ',
    '¶', '·', 'ё', '№', 'є', '»', 'ј', 'Ѕ', 'ѕ', 'ї', 'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ж', 'З', 'И',
    'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы',
    'Ь', 'Э', 'Ю', 'Я', 'а', 'б', 'в', 'г', 'д', 'е', 'ж', 'з', 'и', 'й', 'к', 'л', 'м', 'н', 'о',
    'п', 'р', 'с', 'т', 'у', 'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я',
];

pub fn decode(bytes: &[u8]) -> String {
    let bytes = match bytes.iter().position(|b| *b == 0) {
        Some(end) => &bytes[..end],
        None => bytes,
    };
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes
            .iter()
            .map(|b| if *b < 0x80 { *b as char } else { CP1251_HIGH[(*b - 0x80) as usize] })
            .collect(),
    }
}

fn key_values(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim().trim_start_matches('.').to_ascii_lowercase();
        let value = value.trim();
        let value =
            value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value).to_string();
        map.insert(key, value);
    }
    map
}

pub fn parse_vmsd(text: &str) -> Vec<Snapshot> {
    let kv = key_values(text);
    let declared: usize = kv.get("snapshot.numsnapshots").and_then(|v| v.parse().ok()).unwrap_or(0);
    let limit = declared.min(MAX_SNAPSHOTS);

    let mut out = Vec::new();
    for index in 0..limit {
        let prefix = format!("snapshot{index}.");
        let get =
            |suffix: &str| kv.get(&format!("{prefix}{suffix}")).cloned().filter(|v| !v.is_empty());
        let uid = get("uid");
        let display_name = get("displayname");
        let disk_file = get("disk0.filename");
        if uid.is_none() && display_name.is_none() && disk_file.is_none() {
            continue;
        }
        let created =
            compose_time(get("createtimehigh").as_deref(), get("createtimelow").as_deref());
        out.push(Snapshot { uid, display_name, disk_file, parent_uid: get("parent"), created });
    }
    out
}

pub fn parse_vmx(text: &str) -> (Option<String>, Vec<String>) {
    let kv = key_values(text);
    let name = kv.get("displayname").cloned().filter(|v| !v.is_empty());
    let mut disks: Vec<String> = kv
        .iter()
        .filter(|(k, _)| k.ends_with(".filename"))
        .filter(|(_, v)| v.to_ascii_lowercase().ends_with(".vmdk"))
        .map(|(_, v)| v.clone())
        .collect();
    disks.sort();
    disks.dedup();
    (name, disks)
}

fn compose_time(high: Option<&str>, low: Option<&str>) -> Option<DateTime<Utc>> {
    let high: i64 = high?.trim().parse().ok()?;
    let low: i64 = low?.trim().parse().ok()?;
    let high = u64::try_from(high).ok()?;
    let low = u64::from(low as i32 as u32);
    let micros = high.checked_mul(1u64 << 32)?.checked_add(low)?;
    let ticks = micros.checked_add(EPOCH_DELTA_MICROS)?.checked_mul(10)?;
    mm_core::filetime::from_filetime(ticks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmdk::ChainLink;

    const VMSD: &str = "\
.encoding = \"UTF-8\"
snapshot.lastUID = \"5\"
snapshot.current = \"5\"
snapshot0.uid = \"1\"
snapshot0.displayName = \"Clean win10\"
snapshot0.createTimeHigh = \"414012\"
snapshot0.createTimeLow = \"521060448\"
snapshot0.disk0.fileName = \"WIN11-LAB.vmdk\"
snapshot.numSnapshots = \"2\"
snapshot1.uid = \"2\"
snapshot1.parent = \"1\"
snapshot1.displayName = \"Pre-FLARE Hardened\"
snapshot1.createTimeHigh = \"414017\"
snapshot1.createTimeLow = \"-2145030328\"
snapshot1.disk0.fileName = \"WIN11-LAB-000001.vmdk\"
";

    const VMX: &str = "displayName = \"WIN11-LAB\"\n\
                       nvme0:0.fileName = \"WIN11-LAB-000002.vmdk\"\n\
                       ethernet0.displayName = \"VMnet10\"\n\
                       sata0:1.fileName = \"autoinst.iso\"\n";

    fn link(name: &str, cid: &str, parent: &str) -> ChainLink {
        ChainLink {
            name: name.to_string(),
            cid: cid.to_string(),
            parent_cid: parent.to_string(),
            extents: 1,
        }
    }

    fn view() -> SnapshotView {
        let (vm_name, current_disks) = parse_vmx(VMX);
        let metadata = VmMetadata {
            vmsd_path: Some(PathBuf::from("WIN11-LAB.vmsd")),
            vmx_path: Some(PathBuf::from("WIN11-LAB.vmx")),
            vm_name,
            current_disks,
            snapshots: parse_vmsd(VMSD),
        };
        let info = VmdkInfo {
            create_type: "monolithicSparse".to_string(),
            capacity_bytes: 128_849_018_880,
            grain_bytes: 65_536,
            extents: 1,
            chain: vec![
                link("WIN11-LAB-000002.vmdk", "2e0c3d5e", "9d564758"),
                link("WIN11-LAB-000001.vmdk", "9d564758", "62e01ed9"),
                link("WIN11-LAB.vmdk", "62e01ed9", "ffffffff"),
            ],
        };
        SnapshotView { links: SnapshotView::join(&metadata, &info), metadata }
    }

    #[test]
    fn snapshots_are_read_with_their_names_and_disks() {
        let snaps = parse_vmsd(VMSD);
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].display_name.as_deref(), Some("Clean win10"));
        assert_eq!(snaps[0].disk_file.as_deref(), Some("WIN11-LAB.vmdk"));
        assert_eq!(snaps[1].parent_uid.as_deref(), Some("1"));
    }

    #[test]
    fn a_snapshot_is_matched_to_the_disk_it_froze() {
        let view = view();
        assert_eq!(
            view.links[2].moment,
            Moment::Snapshot {
                name: "Clean win10".to_string(),
                created: parse_vmsd(VMSD)[0].created,
            },
            "the base disk is the first snapshot, not the base-with-no-name"
        );
        assert_eq!(
            view.links[1].moment,
            Moment::Snapshot {
                name: "Pre-FLARE Hardened".to_string(),
                created: parse_vmsd(VMSD)[1].created,
            }
        );
    }

    #[test]
    fn the_disk_the_vmx_names_is_the_live_state() {
        assert_eq!(view().links[0].moment, Moment::LiveState);
    }

    #[test]
    fn the_provenance_names_the_link_and_the_depth() {
        let line = view().provenance();
        assert!(line.contains("WIN11-LAB-000002.vmdk"), "got {line}");
        assert!(line.contains("live state"), "got {line}");
        assert!(line.contains("2 parent link(s)"), "got {line}");
        assert!(line.contains("WIN11-LAB.vmdk"), "got {line}");
    }

    #[test]
    fn an_unnamed_middle_link_is_unknown_not_guessed() {
        let info = VmdkInfo {
            create_type: "monolithicSparse".to_string(),
            capacity_bytes: 1024,
            grain_bytes: 65_536,
            extents: 1,
            chain: vec![
                link("orphan-000009.vmdk", "aaaa", "bbbb"),
                link("orphan.vmdk", "bbbb", "ffffffff"),
            ],
        };
        let view = SnapshotView::of(Path::new("nowhere-at-all/orphan-000009.vmdk"), &info);
        assert_eq!(view.links[0].moment, Moment::Unknown);
        assert_eq!(view.links[1].moment, Moment::BaseDisk);
        assert!(view.describe().contains("UNKNOWN"), "got {}", view.describe());
    }

    #[test]
    fn a_negative_low_word_is_a_bit_pattern_not_a_negative_time() {
        let snaps = parse_vmsd(VMSD);
        let a = snaps[0].created.expect("snapshot 0 has a plausible time");
        let b = snaps[1].created.expect("snapshot 1 has a plausible time");
        assert!(b > a, "the later snapshot must sort later: {a} then {b}");
        assert_eq!(b.format("%Y").to_string(), "2026");
    }

    #[test]
    fn an_implausible_time_is_unknown_rather_than_1601() {
        assert_eq!(compose_time(Some("0"), Some("0")), None);
        assert_eq!(compose_time(Some("999999999"), Some("0")), None);
        assert_eq!(compose_time(None, Some("5")), None);
        assert_eq!(compose_time(Some("nonsense"), Some("5")), None);
    }

    #[test]
    fn the_recorded_times_agree_with_the_chain_order() {
        assert!(view().times_agree_with_chain());
    }

    #[test]
    fn the_vmx_names_the_live_disk() {
        let (name, disks) = parse_vmx(VMX);
        assert_eq!(name.as_deref(), Some("WIN11-LAB"));
        assert_eq!(disks, vec!["WIN11-LAB-000002.vmdk".to_string()]);
    }

    #[test]
    fn the_vm_stem_drops_a_delta_suffix_only() {
        assert_eq!(vm_stem(Path::new("a/WIN11-LAB-000003.vmdk")).as_deref(), Some("WIN11-LAB"));
        assert_eq!(vm_stem(Path::new("a/WIN11-LAB.vmdk")).as_deref(), Some("WIN11-LAB"));
        assert_eq!(vm_stem(Path::new("a/SPLITDISK-s001.vmdk")).as_deref(), Some("SPLITDISK-s001"));
    }

    #[test]
    fn a_vmsd_declaring_absurdly_many_snapshots_does_not_run_away() {
        let text = "snapshot.numSnapshots = \"99999999\"\nsnapshot0.uid = \"1\"\n";
        assert_eq!(parse_vmsd(text).len(), 1);
    }

    #[test]
    #[allow(invalid_from_utf8)]
    fn a_cyrillic_snapshot_name_survives_a_windows_1251_sidecar() {
        let bytes =
            b"snapshot.numSnapshots = \"1\"\nsnapshot0.displayName = \"\xd7\xe8\xf1\xf2\xee\"\n";
        assert!(std::str::from_utf8(bytes).is_err(), "the fixture must not be valid UTF-8");
        let snaps = parse_vmsd(&decode(bytes));
        assert_eq!(snaps[0].display_name.as_deref(), Some("Чисто"));
    }

    #[test]
    fn empty_and_hostile_sidecars_return_nothing_rather_than_panicking() {
        for text in ["", "=", "snapshot.numSnapshots = \"-1\"", "\u{0}", "snapshot0.uid"] {
            assert!(parse_vmsd(text).is_empty(), "on {text:?}");
            let _ = parse_vmx(text);
        }
    }
}
