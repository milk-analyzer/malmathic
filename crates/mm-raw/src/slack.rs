use ntfs_core::{FileName, FileReference};

const ENTRY_HEADER: usize = 0x10;
const FN_FIXED: usize = 0x42;
const ENTRY_MIN: usize = ENTRY_HEADER + FN_FIXED + 2;
const ALIGN: usize = 8;

mod fnf {
    pub const PARENT: usize = 0x00;
    pub const CREATED: usize = 0x08;
    pub const MODIFIED: usize = 0x10;
    pub const MFT_MODIFIED: usize = 0x18;
    pub const ACCESSED: usize = 0x20;
    pub const ALLOCATED_SIZE: usize = 0x28;
    pub const REAL_SIZE: usize = 0x30;
    pub const FLAGS: usize = 0x38;
    pub const NAME_LENGTH: usize = 0x40;
    pub const NAMESPACE: usize = 0x41;
}

mod ief {
    pub const FILE_REFERENCE: usize = 0x00;
    pub const ENTRY_LENGTH: usize = 0x08;
    pub const STREAM_LENGTH: usize = 0x0A;
    pub const FLAGS: usize = 0x0C;
    pub const RESERVED: usize = 0x0E;
    pub const STREAM: usize = 0x10;
}

const IE_SUBNODE: u16 = 0x01;
const IE_LAST: u16 = 0x02;

const ATTRIBUTE_MASK: u32 = 0x3000_0000 | 0x007F_FFFF;

const ATTR_SPARSE: u32 = 0x0000_0200;
const ATTR_COMPRESSED: u32 = 0x0000_0800;

const FORBIDDEN: &[char] = &['\\', '/', ':', '*', '?', '"', '<', '>', '|'];

const MAX_NAME_UNITS: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slack {
    IndexRoot,
    Record,
    IndexBuffer { buffer: u64 },
    FreeIndexBuffer { buffer: u64 },
    Unallocated { offset: u64 },
}

impl std::fmt::Display for Slack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Slack::IndexRoot => write!(f, "$INDEX_ROOT slack"),
            Slack::Record => write!(f, "MFT record slack"),
            Slack::IndexBuffer { buffer } => write!(f, "INDX buffer {buffer} slack"),
            Slack::FreeIndexBuffer { buffer } => write!(f, "free INDX buffer {buffer}"),
            Slack::Unallocated { offset } => write!(f, "carved INDX buffer at offset {offset}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletedIndexEntry {
    pub name: String,
    pub namespace: u8,
    pub record: u64,
    pub sequence: u16,
    pub parent_record: u64,
    pub parent_sequence: u16,
    pub real_size: u64,
    pub allocated_size: u64,
    pub attributes: u32,
    pub created: u64,
    pub modified: u64,
    pub mft_modified: u64,
    pub accessed: u64,
    pub found_in: Slack,
}

impl DeletedIndexEntry {
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.attributes & 0x1000_0000 != 0 || self.attributes & 0x10 != 0
    }

    #[must_use]
    pub fn is_dos_name(&self) -> bool {
        self.namespace == 2
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    pub records: u64,
    pub cluster: u64,
    pub volume_bytes: u64,
    pub parent: Option<u64>,
}

impl Bounds {
    #[must_use]
    pub fn orphan(self) -> Self {
        Bounds { parent: None, ..self }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub slack_bytes: u64,
    pub recovered: u64,
    pub duplicates: u64,
    pub live_seen: u64,
    pub live_accepted: u64,
}

impl SweepStats {
    pub fn add(&mut self, other: SweepStats) {
        self.slack_bytes += other.slack_bytes;
        self.recovered += other.recovered;
        self.duplicates += other.duplicates;
        self.live_seen += other.live_seen;
        self.live_accepted += other.live_accepted;
    }
}

fn le_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

fn dated(ticks: u64) -> bool {
    mm_core::from_filetime(ticks).is_some()
}

#[must_use]
pub fn recover_one(
    node: &[u8],
    pos: usize,
    end: usize,
    bounds: &Bounds,
) -> Option<(DeletedIndexEntry, usize)> {
    try_recover(node, pos, end, bounds).ok()
}

#[must_use]
pub fn why_refused(node: &[u8], pos: usize, end: usize, bounds: &Bounds) -> Option<&'static str> {
    try_recover(node, pos, end, bounds).err()
}

fn try_recover(
    node: &[u8],
    pos: usize,
    end: usize,
    bounds: &Bounds,
) -> std::result::Result<(DeletedIndexEntry, usize), &'static str> {
    let end = end.min(node.len());
    if pos.checked_add(ENTRY_MIN).is_none_or(|need| need > end) {
        return Err("no room for an entry with a name");
    }

    let entry_length = le_u16(node, pos + ief::ENTRY_LENGTH) as usize;
    if entry_length < ENTRY_MIN {
        return Err("entry length below the minimum");
    }
    if !entry_length.is_multiple_of(ALIGN) {
        return Err("entry length not eight-aligned");
    }
    let entry_end = pos.checked_add(entry_length).ok_or("entry length overflows")?;
    if entry_end > end {
        return Err("entry runs past the region");
    }

    let flags = le_u16(node, pos + ief::FLAGS);
    if flags & IE_LAST != 0 {
        return Err("terminal entry, which carries no name");
    }
    if flags & !(IE_SUBNODE | IE_LAST) != 0 {
        return Err("a flag bit NTFS does not set");
    }
    if le_u16(node, pos + ief::RESERVED) != 0 {
        return Err("the reserved word is not zero");
    }

    let stream_length = le_u16(node, pos + ief::STREAM_LENGTH) as usize;
    if stream_length < FN_FIXED + 2 {
        return Err("stream too short for a $FILE_NAME with a name");
    }
    let stream_start = pos + ief::STREAM;
    let stream_end = stream_start.checked_add(stream_length).ok_or("stream length overflows")?;
    if stream_end > entry_end {
        return Err("stream runs past the entry");
    }

    let stream = &node[stream_start..stream_end];
    let name_units = stream[fnf::NAME_LENGTH] as usize;
    if name_units == 0 || name_units > MAX_NAME_UNITS {
        return Err("name length of zero, or past what NTFS stores");
    }
    let key = FN_FIXED + name_units * 2;
    if stream_length < key || stream_length >= key + ALIGN {
        return Err("stream length does not account for the name");
    }
    let padded = (ENTRY_HEADER + key).div_ceil(ALIGN) * ALIGN;
    let expected = if flags & IE_SUBNODE != 0 { padded + ALIGN } else { padded };
    if entry_length != expected {
        return Err("entry length does not match the name it carries");
    }

    let namespace = stream[fnf::NAMESPACE];
    if namespace > 3 {
        return Err("a namespace that does not exist");
    }

    let parsed = FileName::parse(stream).map_err(|_| "the $FILE_NAME does not parse")?;
    if parsed.name.is_empty() {
        return Err("an empty name");
    }
    if parsed.name.chars().any(|c| c == '\u{FFFD}' || (c as u32) < 0x20 || FORBIDDEN.contains(&c)) {
        return Err("a character NTFS does not allow in a name");
    }
    if parsed.name == "." || parsed.name == ".." {
        return Err("the directory's own entry");
    }

    let file = FileReference::from_u64(le_u64(node, pos + ief::FILE_REFERENCE));
    if file.record_number == 0 || file.record_number >= bounds.records {
        return Err("a record number that is not on this volume");
    }
    if file.sequence == 0 {
        return Err("a zero sequence number");
    }
    let parent = FileReference::from_u64(le_u64(stream, fnf::PARENT));
    if parent.record_number >= bounds.records || parent.sequence == 0 {
        return Err("a parent reference that is not on this volume");
    }
    if bounds.parent.is_some_and(|expected| parent.record_number != expected) {
        return Err("a parent that is not the directory these bytes came from");
    }

    let allocated = le_u64(stream, fnf::ALLOCATED_SIZE);
    let real = le_u64(stream, fnf::REAL_SIZE);
    let attributes = le_u32(stream, fnf::FLAGS);
    if attributes & !ATTRIBUTE_MASK != 0 {
        return Err("an attribute bit Windows does not define");
    }
    if allocated > bounds.volume_bytes || real > bounds.volume_bytes {
        return Err("a size larger than the volume");
    }
    let resident =
        bounds.cluster != 0 && allocated < bounds.cluster && allocated == real.div_ceil(8) * 8;
    if bounds.cluster != 0 && !allocated.is_multiple_of(bounds.cluster) && !resident {
        return Err("an allocation that is neither whole clusters nor a resident file's");
    }
    if allocated != 0
        && bounds.cluster != 0
        && !resident
        && attributes & (ATTR_COMPRESSED | ATTR_SPARSE) == 0
        && real.div_ceil(bounds.cluster) * bounds.cluster > allocated
    {
        return Err("an allocation that does not cover the file");
    }

    let created = le_u64(stream, fnf::CREATED);
    let modified = le_u64(stream, fnf::MODIFIED);
    let mft_modified = le_u64(stream, fnf::MFT_MODIFIED);
    let accessed = le_u64(stream, fnf::ACCESSED);
    if !dated(created) || !dated(modified) || !dated(accessed) {
        return Err("a timestamp outside the plausibility window");
    }
    let mft_modified = if dated(mft_modified) { mft_modified } else { 0 };

    Ok((
        DeletedIndexEntry {
            name: parsed.name,
            namespace,
            record: file.record_number,
            sequence: file.sequence,
            parent_record: parent.record_number,
            parent_sequence: parent.sequence,
            real_size: real,
            allocated_size: allocated,
            attributes,
            created,
            modified,
            mft_modified,
            accessed,
            found_in: Slack::IndexRoot,
        },
        entry_length,
    ))
}

const MAX_PER_NODE: usize = 4096;

#[must_use]
pub fn scan(
    node: &[u8],
    start: usize,
    end: usize,
    bounds: &Bounds,
    found_in: Slack,
) -> (Vec<DeletedIndexEntry>, usize) {
    let end = end.min(node.len());
    if start >= end {
        return (Vec::new(), 0);
    }
    let mut out = Vec::new();
    let mut pos = start.div_ceil(ALIGN) * ALIGN;
    while pos + ENTRY_MIN <= end && out.len() < MAX_PER_NODE {
        match recover_one(node, pos, end, bounds) {
            Some((mut entry, length)) => {
                entry.found_in = found_in;
                out.push(entry);
                pos += length;
            }
            None => pos += ALIGN,
        }
    }
    (out, end - start)
}

#[must_use]
pub fn audit_live(node: &[u8], start: usize, end: usize, bounds: &Bounds) -> (u64, u64) {
    let (declared, accepted, _) = audit_live_reasons(node, start, end, bounds);
    (declared, accepted)
}

#[must_use]
pub fn audit_live_reasons(
    node: &[u8],
    start: usize,
    end: usize,
    bounds: &Bounds,
) -> (u64, u64, Vec<&'static str>) {
    let end = end.min(node.len());
    let Ok(entries) = ntfs_core::parse_entries(node, start, end) else {
        return (0, 0, Vec::new());
    };
    let declared = entries.iter().filter(|e| e.file_name.is_some()).count() as u64;

    let mut accepted = 0u64;
    let mut refused = Vec::new();
    let mut pos = start;
    for entry in &entries {
        if pos + ENTRY_HEADER > end {
            break;
        }
        let length = le_u16(node, pos + ief::ENTRY_LENGTH) as usize;
        if length < ENTRY_HEADER || pos + length > end {
            break;
        }
        if entry.file_name.is_some() {
            match why_refused(node, pos, end, bounds) {
                None => accepted += 1,
                Some(why) => {
                    if std::env::var_os("MM_SLACK_DEBUG").is_some() {
                        eprintln!(
                            "RL {why} :: {:?} c={} m={} e={} a={} alloc={} real={}",
                            entry.file_name.as_ref().map(|n| n.name.clone()),
                            le_u64(node, pos + ief::STREAM + fnf::CREATED),
                            le_u64(node, pos + ief::STREAM + fnf::MODIFIED),
                            le_u64(node, pos + ief::STREAM + fnf::MFT_MODIFIED),
                            le_u64(node, pos + ief::STREAM + fnf::ACCESSED),
                            le_u64(node, pos + ief::STREAM + fnf::ALLOCATED_SIZE),
                            le_u64(node, pos + ief::STREAM + fnf::REAL_SIZE)
                        );
                    }
                    log::debug!(
                        "index slack: refused a live entry, {why}: {:?} record {}",
                        entry.file_name.as_ref().map(|n| n.name.as_str()).unwrap_or(""),
                        entry.file_reference.record_number
                    );
                    refused.push(why)
                }
            }
        }
        pos += length;
    }
    (declared, accepted, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 133_909_856_430_000_000;

    fn bounds() -> Bounds {
        Bounds { records: 1_000_000, cluster: 4096, volume_bytes: 64 << 30, parent: Some(42) }
    }

    fn entry(name: &str, record: u64, sequence: u16, parent: u64, real: u64) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let stream_length = FN_FIXED + units.len() * 2;
        let length = (ENTRY_HEADER + stream_length).div_ceil(ALIGN) * ALIGN;
        let mut e = vec![0u8; length];
        let file_ref = record | ((sequence as u64) << 48);
        e[ief::FILE_REFERENCE..ief::FILE_REFERENCE + 8].copy_from_slice(&file_ref.to_le_bytes());
        e[ief::ENTRY_LENGTH..ief::ENTRY_LENGTH + 2].copy_from_slice(&(length as u16).to_le_bytes());
        e[ief::STREAM_LENGTH..ief::STREAM_LENGTH + 2]
            .copy_from_slice(&(stream_length as u16).to_le_bytes());

        let s = ief::STREAM;
        let parent_ref = parent | (1u64 << 48);
        e[s + fnf::PARENT..s + fnf::PARENT + 8].copy_from_slice(&parent_ref.to_le_bytes());
        for at in [fnf::CREATED, fnf::MODIFIED, fnf::MFT_MODIFIED, fnf::ACCESSED] {
            e[s + at..s + at + 8].copy_from_slice(&T.to_le_bytes());
        }
        let allocated = real.div_ceil(4096) * 4096;
        e[s + fnf::ALLOCATED_SIZE..s + fnf::ALLOCATED_SIZE + 8]
            .copy_from_slice(&allocated.to_le_bytes());
        e[s + fnf::REAL_SIZE..s + fnf::REAL_SIZE + 8].copy_from_slice(&real.to_le_bytes());
        e[s + fnf::FLAGS..s + fnf::FLAGS + 4].copy_from_slice(&0x20u32.to_le_bytes());
        e[s + fnf::NAME_LENGTH] = units.len() as u8;
        e[s + fnf::NAMESPACE] = 1;
        for (i, u) in units.iter().enumerate() {
            e[s + FN_FIXED + i * 2..s + FN_FIXED + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        e
    }

    #[test]
    fn a_whole_entry_comes_back_with_every_field() {
        let e = entry("server.exe", 133_583, 7, 42, 45_056);
        let (got, length) = recover_one(&e, 0, e.len(), &bounds()).expect("a valid entry");
        assert_eq!(length, e.len());
        assert_eq!(got.name, "server.exe");
        assert_eq!(got.record, 133_583);
        assert_eq!(got.sequence, 7);
        assert_eq!(got.parent_record, 42);
        assert_eq!(got.real_size, 45_056);
        assert_eq!(got.allocated_size, 45_056);
        assert_eq!(got.created, T);
        assert!(!got.is_directory());
    }

    #[test]
    fn an_entry_is_found_at_an_arbitrary_offset_in_garbage() {
        let e = entry("server.exe", 133_583, 7, 42, 45_056);
        let mut node = vec![0xCDu8; 4096];
        let at = 1_784;
        node[at..at + e.len()].copy_from_slice(&e);
        let (found, swept) = scan(&node, 512, 4096, &bounds(), Slack::IndexBuffer { buffer: 3 });
        assert_eq!(swept, 4096 - 512);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "server.exe");
        assert_eq!(found[0].found_in, Slack::IndexBuffer { buffer: 3 });
    }

    #[test]
    fn a_buffer_of_noise_yields_nothing() {
        let mut node = vec![0u8; 65_536];
        let mut x = 0x1234_5678_9abc_def0u64;
        for byte in node.iter_mut() {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            *byte = (x >> 33) as u8;
        }
        let (found, _) = scan(&node, 0, node.len(), &bounds(), Slack::IndexRoot);
        assert!(found.is_empty(), "invented {} entries from noise", found.len());
    }

    #[test]
    fn zeroes_yield_nothing() {
        let node = vec![0u8; 8192];
        assert!(scan(&node, 0, node.len(), &bounds(), Slack::IndexRoot).0.is_empty());
    }

    #[test]
    fn an_entry_naming_another_directory_is_refused() {
        let e = entry("server.exe", 133_583, 7, 99, 45_056);
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
        assert!(recover_one(&e, 0, e.len(), &bounds().orphan()).is_some());
    }

    #[test]
    fn a_record_number_past_the_mft_is_refused() {
        let e = entry("server.exe", 5_000_000, 7, 42, 4096);
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn a_zero_sequence_is_refused() {
        let e = entry("server.exe", 133, 0, 42, 4096);
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn a_stream_length_that_does_not_account_for_the_name_is_refused() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        let was = le_u16(&e, ief::STREAM_LENGTH);
        e[ief::STREAM_LENGTH..ief::STREAM_LENGTH + 2].copy_from_slice(&(was - 2).to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn an_entry_length_that_is_not_eight_aligned_is_refused() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        let was = le_u16(&e, ief::ENTRY_LENGTH);
        e[ief::ENTRY_LENGTH..ief::ENTRY_LENGTH + 2].copy_from_slice(&(was + 1).to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn an_entry_running_past_the_region_is_refused() {
        let e = entry("server.exe", 133, 7, 42, 4096);
        assert!(recover_one(&e, 0, e.len() - 8, &bounds()).is_none());
    }

    #[test]
    fn a_name_with_a_path_separator_in_it_is_refused() {
        let e = entry("a\\b.exe", 133, 7, 42, 4096);
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
        for bad in [":", "*", "?", "\u{1}"] {
            let e = entry(&format!("x{bad}.exe"), 133, 7, 42, 4096);
            assert!(recover_one(&e, 0, e.len(), &bounds()).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn garbage_in_the_mft_modified_time_alone_costs_only_that_field() {
        let mut e = entry("favicon[1].ico", 133, 7, 42, 4096);
        let s = ief::STREAM;
        e[s + fnf::MFT_MODIFIED..s + fnf::MFT_MODIFIED + 8]
            .copy_from_slice(&455_266_533_636u64.to_le_bytes());
        let (got, _) = recover_one(&e, 0, e.len(), &bounds()).expect("still an entry");
        assert_eq!(got.mft_modified, 0, "UNKNOWN, not a date");
        assert_eq!(got.created, T);
    }

    #[test]
    fn a_timestamp_outside_the_projects_window_is_refused() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        let s = ief::STREAM;
        e[s + fnf::MODIFIED..s + fnf::MODIFIED + 8].copy_from_slice(&1u64.to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn a_modification_before_the_creation_is_kept() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        let s = ief::STREAM;
        e[s + fnf::MODIFIED..s + fnf::MODIFIED + 8]
            .copy_from_slice(&(T - 10_000_000_000).to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_some());
    }

    #[test]
    fn a_resident_files_sub_cluster_allocation_is_accepted() {
        for (real, allocated) in [(73u64, 80u64), (15, 16), (50, 56), (263, 264), (114, 120)] {
            let mut e = entry("desktop.ini", 133, 7, 42, 0);
            let s = ief::STREAM;
            e[s + fnf::REAL_SIZE..s + fnf::REAL_SIZE + 8].copy_from_slice(&real.to_le_bytes());
            e[s + fnf::ALLOCATED_SIZE..s + fnf::ALLOCATED_SIZE + 8]
                .copy_from_slice(&allocated.to_le_bytes());
            assert!(
                recover_one(&e, 0, e.len(), &bounds()).is_some(),
                "refused a resident file of {real} bytes in {allocated}"
            );
        }
        let mut e = entry("desktop.ini", 133, 7, 42, 0);
        let s = ief::STREAM;
        e[s + fnf::REAL_SIZE..s + fnf::REAL_SIZE + 8].copy_from_slice(&73u64.to_le_bytes());
        e[s + fnf::ALLOCATED_SIZE..s + fnf::ALLOCATED_SIZE + 8]
            .copy_from_slice(&96u64.to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn an_allocation_that_is_not_whole_clusters_is_refused() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        let s = ief::STREAM;
        e[s + fnf::ALLOCATED_SIZE..s + fnf::ALLOCATED_SIZE + 8]
            .copy_from_slice(&8200u64.to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn an_allocation_that_does_not_cover_the_file_is_refused() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        let s = ief::STREAM;
        e[s + fnf::REAL_SIZE..s + fnf::REAL_SIZE + 8].copy_from_slice(&9000u64.to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn an_undefined_attribute_bit_is_refused() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        let s = ief::STREAM;
        e[s + fnf::FLAGS..s + fnf::FLAGS + 4].copy_from_slice(&0x0800_0000u32.to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn a_namespace_that_does_not_exist_is_refused() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        e[ief::STREAM + fnf::NAMESPACE] = 4;
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn the_terminal_entry_is_not_an_entry() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        e[ief::FLAGS..ief::FLAGS + 2].copy_from_slice(&IE_LAST.to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn a_flag_bit_ntfs_does_not_set_is_refused() {
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        e[ief::FLAGS..ief::FLAGS + 2].copy_from_slice(&0x0004u16.to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
        let mut e = entry("server.exe", 133, 7, 42, 4096);
        e[ief::RESERVED..ief::RESERVED + 2].copy_from_slice(&1u16.to_le_bytes());
        assert!(recover_one(&e, 0, e.len(), &bounds()).is_none());
    }

    #[test]
    fn a_subnode_entry_is_recovered_with_its_extra_vcn() {
        let base = entry("bin", 133, 7, 42, 0);
        let stream_length = FN_FIXED + 3 * 2;
        let length = (ENTRY_HEADER + stream_length + 8).div_ceil(ALIGN) * ALIGN;
        let mut e = base;
        e.resize(length, 0);
        e[ief::ENTRY_LENGTH..ief::ENTRY_LENGTH + 2].copy_from_slice(&(length as u16).to_le_bytes());
        e[ief::FLAGS..ief::FLAGS + 2].copy_from_slice(&IE_SUBNODE.to_le_bytes());
        e[length - 8..].copy_from_slice(&9u64.to_le_bytes());
        let (got, _) = recover_one(&e, 0, e.len(), &bounds()).expect("a sub-node entry");
        assert_eq!(got.name, "bin");
    }

    #[test]
    fn scanning_terminates_on_any_input() {
        for length in [0u16, 8, 16, 0xFFFF] {
            let mut node = vec![0u8; 512];
            for at in (0..512 - ENTRY_HEADER).step_by(8) {
                node[at + ief::ENTRY_LENGTH..at + ief::ENTRY_LENGTH + 2]
                    .copy_from_slice(&length.to_le_bytes());
            }
            let _ = scan(&node, 0, node.len(), &bounds(), Slack::IndexRoot);
        }
    }

    #[test]
    fn an_empty_or_inverted_region_is_no_sweep() {
        let node = vec![0u8; 64];
        assert_eq!(scan(&node, 32, 32, &bounds(), Slack::IndexRoot).1, 0);
        assert_eq!(scan(&node, 40, 8, &bounds(), Slack::IndexRoot).1, 0);
        assert_eq!(scan(&node, 0, 4096, &bounds(), Slack::IndexRoot).1, 64);
    }

    #[test]
    fn the_validator_accepts_the_live_entries_of_a_node_it_is_shown() {
        let mut node = Vec::new();
        for (i, name) in ["a.exe", "b.dll", "c"].iter().enumerate() {
            node.extend_from_slice(&entry(name, 100 + i as u64, 3, 42, 8192));
        }
        let mut terminal = vec![0u8; ENTRY_HEADER];
        terminal[ief::ENTRY_LENGTH..ief::ENTRY_LENGTH + 2]
            .copy_from_slice(&(ENTRY_HEADER as u16).to_le_bytes());
        terminal[ief::FLAGS..ief::FLAGS + 2].copy_from_slice(&IE_LAST.to_le_bytes());
        let used = node.len() + terminal.len();
        node.extend_from_slice(&terminal);
        node.resize(4096, 0);

        assert_eq!(audit_live(&node, 0, used, &bounds()), (3, 3));
    }
}
