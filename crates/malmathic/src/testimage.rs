#![cfg(test)]

use std::collections::HashMap;
use std::io::Cursor;

use mm_raw::Volume;

pub const SECTOR: usize = 512;
const SECTORS_PER_CLUSTER: u8 = 8;
pub const CLUSTER: usize = SECTOR * SECTORS_PER_CLUSTER as usize;
pub const RECORD: usize = 1024;
pub const INDEX_RECORD: usize = 4096;

const MFT_LCN: u64 = 4;
const MFT_CLUSTERS: u64 = 64;
const TOTAL_CLUSTERS: u64 = 1024;

const RECORDS_PER_CLUSTER: u64 = CLUSTER as u64 / RECORD as u64;

pub const MFT_RECORD: u64 = 0;
pub const ROOT_RECORD: u64 = 5;
pub const BITMAP_RECORD: u64 = 6;

#[allow(clippy::too_many_arguments)]
pub fn usn_record(
    entry: u64,
    sequence: u16,
    parent: u64,
    parent_sequence: u16,
    usn: i64,
    filetime: i64,
    reason: u32,
    name: &str,
) -> Vec<u8> {
    let name_units: Vec<u16> = name.encode_utf16().collect();
    let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let length = (0x3C + name_bytes.len() + 7) & !7;
    let mut r = vec![0u8; length];
    r[0x00..0x04].copy_from_slice(&(length as u32).to_le_bytes());
    r[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
    r[0x06..0x08].copy_from_slice(&0u16.to_le_bytes());
    r[0x08..0x10].copy_from_slice(&(entry | ((sequence as u64) << 48)).to_le_bytes());
    r[0x10..0x18].copy_from_slice(&(parent | ((parent_sequence as u64) << 48)).to_le_bytes());
    r[0x18..0x20].copy_from_slice(&usn.to_le_bytes());
    r[0x20..0x28].copy_from_slice(&filetime.to_le_bytes());
    r[0x28..0x2C].copy_from_slice(&reason.to_le_bytes());
    r[0x38..0x3A].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    r[0x3A..0x3C].copy_from_slice(&0x3Cu16.to_le_bytes());
    r[0x3C..0x3C + name_bytes.len()].copy_from_slice(&name_bytes);
    r
}

pub fn usn_journal_stream(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for record in records {
        let offset = out.len() as i64;
        let mut r = record.clone();
        r[0x18..0x20].copy_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&r);
    }
    out
}

pub fn journal_filetime(seconds_into_2026: i64) -> i64 {
    const Y2026: i64 = 134_116_992_000_000_000;
    Y2026 + seconds_into_2026 * 10_000_000
}
const FIRST_FREE_RECORD: u64 = 16;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_BITMAP: u32 = 0xB0;
const ATTR_REPARSE_POINT: u32 = 0xC0;
const ATTR_LOGGED_UTILITY_STREAM: u32 = 0x100;
const EFS_STREAM: &str = "$EFS";
const EFS_PLACEHOLDER: [u8; 16] = *b"EFS-DDF-PLACEHLD";
const ATTR_END: u32 = 0xFFFF_FFFF;

const INDEX_NAME: &str = "$I30";

const FLAG_IN_USE: u16 = 0x0001;
const FLAG_DIRECTORY: u16 = 0x0002;

const ID_STANDARD_INFORMATION: u16 = 0;
const ID_ATTRIBUTE_LIST: u16 = 1;
const ID_FILE_NAME: u16 = 2;
const ID_INDEX_ROOT: u16 = 3;
const ID_INDEX_ALLOCATION: u16 = 4;
const ID_BITMAP: u16 = 5;

const FILETIME_EPOCH_DELTA_SECS: i64 = 11_644_473_600;
const TICKS_PER_SEC: u64 = 10_000_000;

const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;

const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
const FILE_ATTRIBUTE_DIRECTORY_ON_DISK: u32 = 0x1000_0000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Times {
    pub created: u64,
    pub modified: u64,
    pub mft_modified: u64,
    pub accessed: u64,
}

impl Times {
    pub const UNSET: Times = Times { created: 0, modified: 0, mft_modified: 0, accessed: 0 };

    pub const fn at(unix_seconds: i64, sub_ticks: u32) -> u64 {
        ((unix_seconds + FILETIME_EPOCH_DELTA_SECS) as u64) * TICKS_PER_SEC + sub_ticks as u64
    }

    pub const fn all_at(ticks: u64) -> Times {
        Times { created: ticks, modified: ticks, mft_modified: ticks, accessed: ticks }
    }

    pub const fn record_changed_at(self, ticks: u64) -> Times {
        Times { mft_modified: ticks, ..self }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexLayout {
    Resident,
    RootInExtension,
    WholeIndexInExtension,
    SplitAcrossExtensions,
    AllocationInExtension,
    AllocationFragmentedByVcn,
    LargeInBase,
}

impl IndexLayout {
    fn is_large(self) -> bool {
        self.index_buffers() > 0
    }

    fn index_buffers(self) -> usize {
        match self {
            IndexLayout::Resident | IndexLayout::RootInExtension => 0,
            IndexLayout::AllocationFragmentedByVcn | IndexLayout::LargeInBase => 2,
            _ => 1,
        }
    }

    fn extension_records(self) -> usize {
        match self {
            IndexLayout::Resident | IndexLayout::LargeInBase => 0,
            IndexLayout::SplitAcrossExtensions | IndexLayout::AllocationFragmentedByVcn => 2,
            _ => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    Live,
    Deleted,
    DeletedClustersReused,
    RecordReallocatedTo(&'static str),
    RecordReallocatedClustersFree(&'static str),
    RecordReallocatedClustersOverwritten(&'static str),
}

struct Entry {
    record: u64,
    name: String,
    parent: u64,
    is_directory: bool,
    flags: u16,
    data: Data,
    encrypted: bool,
    streams: Vec<(String, Vec<u8>)>,
    index: IndexLayout,
    extensions: Vec<u64>,
    indx_lcns: Vec<u64>,
    sparse_indx: Vec<u64>,
    damaged_indx: Vec<u64>,
    unused_indx: Vec<u64>,
    no_index_bitmap: bool,
    abandoned_page: Option<u64>,
    claimed_indx: Vec<u64>,
    small_index_flag: bool,
    list_lcn: Option<u64>,
    list_clusters: u64,
    times: Times,
    file_name_times: Times,
    misdirect: Option<u64>,
    name_misdirect: Option<u64>,
    padding: Vec<(u32, u64)>,
    wof: Option<WofBacking>,
    nonresident_stream: Option<(String, u64, u64, u64)>,
    reparse: Option<Vec<u8>>,
    name_in_extension: bool,
    file_name_size: Option<u64>,
    spilled: Vec<(u32, Option<String>)>,
    spill_record: Option<u64>,
    hard_links: u16,
    sequence: u16,
    parent_sequence: u16,
    extra_names: Vec<(u64, u16, String)>,
}

enum Data {
    None,
    Resident(Vec<u8>),
    NonResident { lcn: u64, clusters: u64, real_size: u64 },
    Sparse { real_size: u64 },
}

struct WofBacking {
    algorithm: u32,
    lcn: u64,
    clusters: u64,
    stream_len: u64,
}

struct Placed {
    record: u64,
    type_code: u32,
    id: u16,
    start_vcn: u64,
    bytes: Vec<u8>,
}

pub struct Builder {
    entries: Vec<Entry>,
    ghost_tails: HashMap<u64, Vec<u8>>,
    children: HashMap<u64, Vec<(String, u64)>>,
    deletions: HashMap<u64, Vec<String>>,
    index_facts: HashMap<u64, (u64, u64, Times)>,
    image: Vec<u8>,
    allocated: Vec<bool>,
    next_record: u64,
    next_lcn: u64,
    mft_clusters: u64,
    total_clusters: u64,
}

impl Builder {
    pub fn new() -> Self {
        Self::with_geometry(MFT_CLUSTERS, TOTAL_CLUSTERS)
    }

    pub fn with_records(records: u64) -> Self {
        let mft_clusters = records.div_ceil(RECORDS_PER_CLUSTER).max(MFT_CLUSTERS);
        let total = MFT_LCN + mft_clusters + TOTAL_CLUSTERS;
        Self::with_geometry(mft_clusters, total)
    }

    pub fn with_geometry(mft_clusters: u64, total_clusters: u64) -> Self {
        let first_data_lcn = MFT_LCN + mft_clusters;
        let mut allocated = vec![false; total_clusters as usize];
        for cluster in allocated.iter_mut().take(first_data_lcn as usize) {
            *cluster = true;
        }
        Builder {
            entries: Vec::new(),
            ghost_tails: HashMap::new(),
            children: HashMap::new(),
            deletions: HashMap::new(),
            index_facts: HashMap::new(),
            image: vec![0u8; (total_clusters as usize) * CLUSTER],
            allocated,
            next_record: FIRST_FREE_RECORD,
            next_lcn: first_data_lcn,
            mft_clusters,
            total_clusters,
        }
    }

    fn record_count(&self) -> u64 {
        self.mft_clusters * CLUSTER as u64 / RECORD as u64
    }

    pub fn directory(&mut self, parent: u64, name: &str) -> u64 {
        if let Some(existing) = self.children.get(&parent).and_then(|kids| {
            kids.iter()
                .find(|(child_name, record)| {
                    child_name.eq_ignore_ascii_case(name)
                        && self.entries.iter().any(|e| e.record == *record && e.is_directory)
                })
                .map(|(_, record)| *record)
        }) {
            return existing;
        }

        let record = self.take_record();
        self.children.entry(parent).or_default().push((name.to_string(), record));
        self.children.entry(record).or_default();
        self.entries.push(Entry {
            record,
            name: name.to_string(),
            parent,
            is_directory: true,
            flags: FLAG_IN_USE | FLAG_DIRECTORY,
            data: Data::None,
            streams: Vec::new(),
            encrypted: false,
            index: IndexLayout::Resident,
            extensions: Vec::new(),
            indx_lcns: Vec::new(),
            sparse_indx: Vec::new(),
            damaged_indx: Vec::new(),
            unused_indx: Vec::new(),
            no_index_bitmap: false,
            abandoned_page: None,
            claimed_indx: Vec::new(),
            small_index_flag: false,
            list_lcn: None,
            list_clusters: 1,
            times: Times::UNSET,
            file_name_times: Times::UNSET,
            misdirect: None,
            name_misdirect: None,
            padding: Vec::new(),
            wof: None,
            nonresident_stream: None,
            reparse: None,
            name_in_extension: false,
            file_name_size: None,
            spilled: Vec::new(),
            spill_record: None,
            hard_links: 2,
            sequence: 1,
            parent_sequence: 1,
            extra_names: Vec::new(),
        });
        record
    }

    pub fn spill_file_name(&mut self, record: u64) {
        let is_directory = self
            .entries
            .iter()
            .find(|e| e.record == record)
            .expect("spill_file_name needs a record the builder made")
            .is_directory;
        if !is_directory {
            self.spill_file_attribute(record, ATTR_FILE_NAME, None);
            return;
        }

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("spill_file_name needs a record the builder made");
        assert!(
            entry.index != IndexLayout::Resident,
            "spill_file_name needs a spilled directory; call spill_index first"
        );
        entry.name_in_extension = true;
    }

    pub fn set_file_name_size(&mut self, record: u64, size: u64) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("set_file_name_size needs a record this builder made");
        entry.file_name_size = Some(size);
    }

    pub fn spill_reparse_point(&mut self, record: u64) {
        self.spill_file_attribute(record, ATTR_REPARSE_POINT, None);
    }

    pub fn spill_unnamed_data(&mut self, record: u64) {
        self.spill_file_attribute(record, ATTR_DATA, None);
    }

    pub fn spill_named_stream(&mut self, record: u64, name: &str) {
        self.spill_file_attribute(record, ATTR_DATA, Some(name));
    }

    fn spill_file_attribute(&mut self, record: u64, type_code: u32, name: Option<&str>) {
        let fresh = self.take_record();
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("spilling needs a record this builder made");
        assert!(
            !entry.is_directory,
            "a directory's attributes spill through spill_index, which knows about $I30"
        );
        if entry.spill_record.is_none() {
            entry.spill_record = Some(fresh);
        }
        entry.spilled.push((type_code, name.map(str::to_string)));
    }

    pub fn misdirect_spilled_attributes(&mut self, record: u64, to: u64) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("misdirect_spilled_attributes needs a record this builder made");
        assert!(
            !entry.spilled.is_empty(),
            "nothing has spilled to misdirect; call spill_reparse_point first"
        );
        entry.misdirect = Some(to);
    }

    pub fn junction(&mut self, parent: u64, name: &str, substitute: &str) -> u64 {
        self.reparse_directory(parent, name, &mount_point_reparse(substitute, substitute))
    }

    pub fn directory_symlink(
        &mut self,
        parent: u64,
        name: &str,
        substitute: &str,
        relative: bool,
    ) -> u64 {
        self.reparse_directory(parent, name, &symlink_reparse(substitute, relative))
    }

    pub fn reparse_directory(&mut self, parent: u64, name: &str, content: &[u8]) -> u64 {
        let record = self.directory(parent, name);
        if let Some(entry) = self.entries.iter_mut().find(|e| e.record == record) {
            entry.reparse = Some(content.to_vec());
        }
        record
    }

    pub fn directories(&mut self, parent: u64, path: &str) -> u64 {
        let mut current = parent;
        for component in path.split('\\').filter(|c| !c.is_empty()) {
            current = self.directory(current, component);
        }
        current
    }

    pub fn set_times(&mut self, record: u64, times: Times) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("set_times needs a record this builder made");
        entry.times = times;
        entry.file_name_times = times;
    }

    pub fn set_file_name_times(&mut self, record: u64, times: Times) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("set_file_name_times needs a record this builder made");
        entry.file_name_times = times;
    }

    pub fn set_sequence(&mut self, record: u64, sequence: u16) {
        self.entry_mut(record).sequence = sequence;
    }

    pub fn set_parent_sequence(&mut self, record: u64, sequence: u16) {
        self.entry_mut(record).parent_sequence = sequence;
    }

    pub fn set_every_parent_sequence(&mut self, sequence: u16) {
        for entry in &mut self.entries {
            entry.parent_sequence = sequence;
        }
    }

    pub fn add_link(&mut self, record: u64, parent: u64, parent_sequence: u16, name: &str) {
        self.children.entry(parent).or_default().push((name.to_string(), record));
        let entry = self.entry_mut(record);
        assert!(!entry.is_directory, "NTFS does not hard-link directories");
        entry.extra_names.push((parent, parent_sequence, name.to_string()));
        entry.hard_links = entry.hard_links.max(1) + 1;
    }

    pub fn leave_in_record_slack(
        &mut self,
        record: u64,
        parent: u64,
        name: &str,
        lcn: u64,
        clusters: u64,
        real_size: u64,
    ) {
        let mut tail = file_name_attribute(parent, name, real_size, Times::UNSET);
        tail.extend(non_resident_data(lcn, clusters, real_size));
        self.ghost_tails.insert(record, tail);
    }

    pub fn data_location(&self, record: u64) -> Option<(u64, u64)> {
        self.entries.iter().find(|e| e.record == record).and_then(|e| match &e.data {
            Data::NonResident { lcn, clusters, .. } => Some((*lcn, *clusters)),
            _ => None,
        })
    }

    pub fn set_hard_links(&mut self, record: u64, links: u16) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("set_hard_links needs a record this builder made");
        entry.hard_links = links;
    }

    pub fn spill_index(&mut self, record: u64, layout: IndexLayout) {
        let extensions: Vec<u64> =
            (0..layout.extension_records()).map(|_| self.take_record()).collect();
        let buffers = layout.index_buffers();
        let indx_lcns: Vec<u64> = (0..buffers)
            .map(|i| {
                let lcn = self.take_clusters(if i + 1 < buffers { 2 } else { 1 });
                self.set_allocated(lcn, 1, true);
                lcn
            })
            .collect();

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("spill_index needs a record this builder made");
        assert!(entry.is_directory, "only a directory has index attributes to spill");
        entry.index = layout;
        entry.extensions = extensions;
        entry.indx_lcns = indx_lcns;
    }

    pub fn sparse_index_buffer(&mut self, record: u64, vcn: u64) {
        let entry = self.index_entry(record);
        assert!(
            (vcn as usize) < entry.indx_lcns.len(),
            "vcn {vcn} is past the {} INDX buffers this directory has",
            entry.indx_lcns.len()
        );
        entry.sparse_indx.push(vcn);
    }

    pub fn damage_index_buffer(&mut self, record: u64, vcn: u64) {
        let entry = self.index_entry(record);
        assert!(
            (vcn as usize) < entry.indx_lcns.len(),
            "vcn {vcn} is past the {} INDX buffers this directory has",
            entry.indx_lcns.len()
        );
        entry.damaged_indx.push(vcn);
    }

    pub fn unused_index_buffer(&mut self, record: u64, vcn: u64) {
        let entry = self.index_entry(record);
        assert!(
            (vcn as usize) < entry.indx_lcns.len(),
            "vcn {vcn} is past the {} INDX buffers this directory has",
            entry.indx_lcns.len()
        );
        entry.unused_indx.push(vcn);
    }

    pub fn clear_large_index_flag(&mut self, record: u64) {
        self.index_entry(record).small_index_flag = true;
    }

    pub fn claim_index_buffer_in_use(&mut self, record: u64, vcn: u64) {
        assert!(vcn < 64, "the fixture bitmap is eight bytes");
        self.index_entry(record).claimed_indx.push(vcn);
    }

    pub fn abandon_index_page(&mut self, record: u64) {
        let cluster = self.take_clusters(1);
        let entry = self.index_entry(record);
        assert!(
            !entry.indx_lcns.is_empty(),
            "record {record} has no INDX buffers to abandon a copy of"
        );
        entry.abandoned_page = Some(cluster);
    }

    pub fn drop_index_bitmap(&mut self, record: u64) {
        self.index_entry(record).no_index_bitmap = true;
    }

    fn entry_mut(&mut self, record: u64) -> &mut Entry {
        self.entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("this needs a record the builder made")
    }

    fn index_entry(&mut self, record: u64) -> &mut Entry {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("this needs a record the builder made");
        assert!(
            !entry.indx_lcns.is_empty(),
            "call spill_index with a large layout first: this directory has no INDX buffers"
        );
        entry
    }

    pub fn spill_attribute_list(&mut self, record: u64) {
        self.spill_attribute_list_across(record, 1);
    }

    pub fn spill_attribute_list_across(&mut self, record: u64, clusters: u64) {
        let lcn = self.take_clusters(clusters);
        self.set_allocated(lcn, clusters, true);

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("spill_attribute_list needs a record this builder made");
        assert!(
            entry.index != IndexLayout::Resident || !entry.spilled.is_empty(),
            "there is no $ATTRIBUTE_LIST to move out until something has spilled"
        );
        entry.list_lcn = Some(lcn);
        entry.list_clusters = clusters;
    }

    pub fn misdirect_index(&mut self, record: u64, to: u64) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("misdirect_index needs a record this builder made");
        assert!(
            entry.index != IndexLayout::Resident,
            "there is no $ATTRIBUTE_LIST to misdirect until the index is spilled"
        );
        entry.misdirect = Some(to);
    }

    pub fn misdirect_file_name(&mut self, record: u64, to: u64) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("misdirect_file_name needs a record this builder made");
        assert!(
            entry.name_in_extension,
            "there is no spilled $FILE_NAME to misdirect; call spill_file_name first"
        );
        entry.name_misdirect = Some(to);
    }

    pub fn pad_attribute_list(&mut self, record: u64, targets: &[u64]) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("pad_attribute_list needs a record this builder made");
        assert!(
            entry.index != IndexLayout::Resident,
            "there is no $ATTRIBUTE_LIST to pad until the index is spilled"
        );
        entry.padding.extend(targets.iter().map(|t| (ATTR_INDEX_ROOT, *t)));
    }

    pub fn pad_attribute_list_of(&mut self, record: u64, type_code: u32, targets: &[u64]) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("pad_attribute_list_of needs a record this builder made");
        assert!(
            entry.index != IndexLayout::Resident || !entry.spilled.is_empty(),
            "there is no $ATTRIBUTE_LIST to pad until something has spilled"
        );
        entry.padding.extend(targets.iter().map(|t| (type_code, *t)));
    }

    pub fn bytes(self) -> Vec<u8> {
        self.finish()
    }

    pub fn deleted_index_entry(
        &mut self,
        parent: u64,
        name: &str,
        content: &[u8],
        presence: Presence,
    ) -> u64 {
        let record = self.file(parent, name, content, presence);
        let children = self.children.entry(parent).or_default();
        children.retain(|(_, r)| *r != record);
        children.push((name.to_string(), record));
        self.deletions.entry(parent).or_default().push(name.to_string());
        record
    }

    pub fn delete_index_entry(&mut self, parent: u64, name: &str) {
        assert!(
            self.children.get(&parent).is_some_and(|kids| kids.iter().any(|(n, _)| n == name)),
            "{name} is not indexed in record {parent}"
        );
        self.deletions.entry(parent).or_default().push(name.to_string());
    }

    pub fn file(&mut self, parent: u64, name: &str, content: &[u8], presence: Presence) -> u64 {
        let record = self.take_record();
        let clusters = content.len().div_ceil(CLUSTER).max(1) as u64;
        let lcn = self.take_clusters(clusters);

        let start = (lcn as usize) * CLUSTER;
        self.image[start..start + content.len()].copy_from_slice(content);

        let (flags, name, indexed) = match presence {
            Presence::Live => {
                self.set_allocated(lcn, clusters, true);
                (FLAG_IN_USE, name.to_string(), true)
            }
            Presence::Deleted => (0, name.to_string(), false),
            Presence::DeletedClustersReused => {
                self.set_allocated(lcn, clusters, true);
                (0, name.to_string(), false)
            }
            Presence::RecordReallocatedTo(new_name) => {
                self.set_allocated(lcn, clusters, true);
                (FLAG_IN_USE, new_name.to_string(), false)
            }
            Presence::RecordReallocatedClustersFree(new_name) => {
                (FLAG_IN_USE, new_name.to_string(), false)
            }
            Presence::RecordReallocatedClustersOverwritten(new_name) => {
                self.set_allocated(lcn, clusters, true);
                let over = (lcn as usize) * CLUSTER;
                let span = (clusters as usize) * CLUSTER;
                for (index, byte) in self.image[over..over + span].iter_mut().enumerate() {
                    *byte = (index % 251) as u8;
                }
                (FLAG_IN_USE, new_name.to_string(), false)
            }
        };
        if indexed {
            self.children.entry(parent).or_default().push((name.clone(), record));
        }

        self.entries.push(Entry {
            record,
            name,
            parent,
            is_directory: false,
            flags,
            data: Data::NonResident { lcn, clusters, real_size: content.len() as u64 },
            streams: Vec::new(),
            encrypted: false,
            index: IndexLayout::Resident,
            extensions: Vec::new(),
            indx_lcns: Vec::new(),
            sparse_indx: Vec::new(),
            damaged_indx: Vec::new(),
            unused_indx: Vec::new(),
            no_index_bitmap: false,
            abandoned_page: None,
            claimed_indx: Vec::new(),
            small_index_flag: false,
            list_lcn: None,
            list_clusters: 1,
            times: Times::UNSET,
            file_name_times: Times::UNSET,
            misdirect: None,
            name_misdirect: None,
            padding: Vec::new(),
            wof: None,
            nonresident_stream: None,
            reparse: None,
            name_in_extension: false,
            file_name_size: None,
            spilled: Vec::new(),
            spill_record: None,
            hard_links: 2,
            sequence: 1,
            parent_sequence: 1,
            extra_names: Vec::new(),
        });
        record
    }

    pub fn resident_file(
        &mut self,
        parent: u64,
        name: &str,
        content: &[u8],
        presence: Presence,
    ) -> u64 {
        let record = self.take_record();
        let flags = match presence {
            Presence::Live => FLAG_IN_USE,
            _ => 0,
        };
        if matches!(presence, Presence::Live) {
            self.children.entry(parent).or_default().push((name.to_string(), record));
        }
        self.entries.push(Entry {
            record,
            name: name.to_string(),
            parent,
            is_directory: false,
            flags,
            data: Data::Resident(content.to_vec()),
            streams: Vec::new(),
            encrypted: false,
            index: IndexLayout::Resident,
            extensions: Vec::new(),
            indx_lcns: Vec::new(),
            sparse_indx: Vec::new(),
            damaged_indx: Vec::new(),
            unused_indx: Vec::new(),
            no_index_bitmap: false,
            abandoned_page: None,
            claimed_indx: Vec::new(),
            small_index_flag: false,
            list_lcn: None,
            list_clusters: 1,
            times: Times::UNSET,
            file_name_times: Times::UNSET,
            misdirect: None,
            name_misdirect: None,
            padding: Vec::new(),
            wof: None,
            nonresident_stream: None,
            reparse: None,
            name_in_extension: false,
            file_name_size: None,
            spilled: Vec::new(),
            spill_record: None,
            hard_links: 2,
            sequence: 1,
            parent_sequence: 1,
            extra_names: Vec::new(),
        });
        record
    }

    pub fn census_file(&mut self, parent: u64, name: &str) -> u64 {
        let record = self.take_record();
        self.entries.push(Entry {
            record,
            name: name.to_string(),
            parent,
            is_directory: false,
            flags: FLAG_IN_USE,
            data: Data::Resident(Vec::new()),
            streams: Vec::new(),
            encrypted: false,
            index: IndexLayout::Resident,
            extensions: Vec::new(),
            indx_lcns: Vec::new(),
            sparse_indx: Vec::new(),
            damaged_indx: Vec::new(),
            unused_indx: Vec::new(),
            no_index_bitmap: false,
            abandoned_page: None,
            claimed_indx: Vec::new(),
            small_index_flag: false,
            list_lcn: None,
            list_clusters: 1,
            times: Times::UNSET,
            file_name_times: Times::UNSET,
            misdirect: None,
            name_misdirect: None,
            padding: Vec::new(),
            wof: None,
            nonresident_stream: None,
            reparse: None,
            name_in_extension: false,
            file_name_size: None,
            spilled: Vec::new(),
            spill_record: None,
            hard_links: 2,
            sequence: 1,
            parent_sequence: 1,
            extra_names: Vec::new(),
        });
        record
    }

    pub fn encrypt(&mut self, record: u64) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("encrypt needs a record this builder made");
        entry.encrypted = true;
    }

    pub fn usn_journal(&mut self, max: Option<&[u8]>, journal: &[u8]) -> u64 {
        let extend = self.directory(ROOT_RECORD, "$Extend");
        let record = self.take_record();
        let clusters = journal.len().div_ceil(CLUSTER).max(1) as u64;
        let lcn = self.take_clusters(clusters);
        let start = (lcn as usize) * CLUSTER;
        self.image[start..start + journal.len()].copy_from_slice(journal);
        self.set_allocated(lcn, clusters, true);
        self.children.entry(extend).or_default().push(("$UsnJrnl".to_string(), record));

        self.entries.push(Entry {
            record,
            name: "$UsnJrnl".to_string(),
            parent: extend,
            is_directory: false,
            flags: FLAG_IN_USE,
            data: Data::None,
            streams: max.map(|m| vec![("$Max".to_string(), m.to_vec())]).unwrap_or_default(),
            nonresident_stream: Some(("$J".to_string(), lcn, clusters, journal.len() as u64)),
            encrypted: false,
            index: IndexLayout::Resident,
            extensions: Vec::new(),
            indx_lcns: Vec::new(),
            sparse_indx: Vec::new(),
            damaged_indx: Vec::new(),
            unused_indx: Vec::new(),
            no_index_bitmap: false,
            abandoned_page: None,
            claimed_indx: Vec::new(),
            small_index_flag: false,
            list_lcn: None,
            list_clusters: 1,
            times: Times::UNSET,
            file_name_times: Times::UNSET,
            misdirect: None,
            name_misdirect: None,
            padding: Vec::new(),
            wof: None,
            reparse: None,
            name_in_extension: false,
            file_name_size: None,
            spilled: Vec::new(),
            spill_record: None,
            hard_links: 1,
            sequence: 1,
            parent_sequence: 1,
            extra_names: Vec::new(),
        });
        record
    }

    pub fn alternate_stream(&mut self, record: u64, name: &str, content: &[u8]) {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.record == record)
            .expect("alternate_stream needs a record this builder made");
        entry.streams.push((name.to_string(), content.to_vec()));
    }

    pub fn compact_os_file(
        &mut self,
        parent: u64,
        name: &str,
        uncompressed_size: u64,
        algorithm: u32,
        stream: &[u8],
    ) -> u64 {
        let record = self.take_record();
        let clusters = stream.len().div_ceil(CLUSTER).max(1) as u64;
        let lcn = self.take_clusters(clusters);
        let start = (lcn as usize) * CLUSTER;
        self.image[start..start + stream.len()].copy_from_slice(stream);
        self.set_allocated(lcn, clusters, true);
        self.children.entry(parent).or_default().push((name.to_string(), record));

        self.entries.push(Entry {
            record,
            name: name.to_string(),
            parent,
            is_directory: false,
            flags: FLAG_IN_USE,
            data: Data::Sparse { real_size: uncompressed_size },
            streams: Vec::new(),
            encrypted: false,
            index: IndexLayout::Resident,
            extensions: Vec::new(),
            indx_lcns: Vec::new(),
            sparse_indx: Vec::new(),
            damaged_indx: Vec::new(),
            unused_indx: Vec::new(),
            no_index_bitmap: false,
            abandoned_page: None,
            claimed_indx: Vec::new(),
            small_index_flag: false,
            list_lcn: None,
            list_clusters: 1,
            times: Times::UNSET,
            file_name_times: Times::UNSET,
            misdirect: None,
            name_misdirect: None,
            padding: Vec::new(),
            nonresident_stream: None,
            wof: Some(WofBacking { algorithm, lcn, clusters, stream_len: stream.len() as u64 }),
            reparse: None,
            name_in_extension: false,
            file_name_size: None,
            spilled: Vec::new(),
            spill_record: None,
            hard_links: 2,
            sequence: 1,
            parent_sequence: 1,
            extra_names: Vec::new(),
        });
        record
    }

    pub fn open(self) -> Volume<Cursor<Vec<u8>>> {
        Volume::open(Cursor::new(self.finish()), "synthetic").expect("the synthetic volume opens")
    }

    fn finish(mut self) -> Vec<u8> {
        write_boot_sector(&mut self.image, self.mft_clusters, self.total_clusters);

        self.index_facts = self
            .entries
            .iter()
            .map(|e| {
                let (real_size, allocated) = match &e.data {
                    Data::NonResident { real_size, .. } => {
                        (*real_size, real_size.div_ceil(CLUSTER as u64) * CLUSTER as u64)
                    }
                    Data::Sparse { real_size } => (*real_size, 0),
                    Data::Resident(bytes) => {
                        (bytes.len() as u64, (bytes.len() as u64).div_ceil(8) * 8)
                    }
                    Data::None => (0, 0),
                };
                (e.record, (real_size, allocated, e.file_name_times))
            })
            .collect();

        let mut mft = vec![0u8; (self.record_count() as usize) * RECORD];

        let mut attrs = standard_information(Times::UNSET, false, false);
        attrs.extend(file_name_attribute(ROOT_RECORD, "$MFT", 0, Times::UNSET));
        attrs.extend(non_resident_data(
            MFT_LCN,
            self.mft_clusters,
            self.mft_clusters * CLUSTER as u64,
        ));
        write_record(&mut mft, MFT_RECORD, "$MFT", FLAG_IN_USE, &attrs);

        let mut bitmap = vec![0u8; (self.total_clusters as usize).div_ceil(8)];
        for (cluster, allocated) in self.allocated.iter().enumerate() {
            if *allocated {
                bitmap[cluster / 8] |= 1 << (cluster % 8);
            }
        }
        let mut attrs = standard_information(Times::UNSET, false, false);
        attrs.extend(file_name_attribute(ROOT_RECORD, "$Bitmap", 0, Times::UNSET));
        attrs.extend(resident_attribute(ATTR_DATA, &bitmap));
        write_record(&mut mft, BITMAP_RECORD, "$Bitmap", FLAG_IN_USE, &attrs);

        let root_children = self.children.get(&ROOT_RECORD).cloned().unwrap_or_default();
        let mut attrs = standard_information(Times::UNSET, true, false);
        attrs.extend(file_name_attribute(ROOT_RECORD, ".", 0, Times::UNSET));
        let (root_entries, root_used) = self.entry_index(ROOT_RECORD, &root_children);
        attrs.extend(index_root(&root_entries, root_used));
        write_record(&mut mft, ROOT_RECORD, ".", FLAG_IN_USE | FLAG_DIRECTORY, &attrs);

        let entries = std::mem::take(&mut self.entries);
        for entry in &entries {
            if entry.is_directory && entry.index != IndexLayout::Resident {
                self.write_spilled_directory(&mut mft, entry);
                continue;
            }
            if !entry.spilled.is_empty() {
                write_spilled_file(&mut mft, &mut self.image, entry);
                continue;
            }
            let mut attrs = standard_information(entry.times, entry.is_directory, entry.encrypted);
            attrs.extend(file_name_attribute_seq(
                entry.parent,
                entry.parent_sequence,
                &entry.name,
                entry.file_name_size.unwrap_or_else(|| real_size(&entry.data)),
                entry.file_name_times,
            ));
            for (link_parent, link_sequence, link_name) in &entry.extra_names {
                attrs.extend(file_name_attribute_seq(
                    *link_parent,
                    *link_sequence,
                    link_name,
                    entry.file_name_size.unwrap_or_else(|| real_size(&entry.data)),
                    entry.file_name_times,
                ));
            }
            if entry.is_directory {
                let children = self.children.get(&entry.record).cloned().unwrap_or_default();
                let (bytes, used) = self.entry_index(entry.record, &children);
                attrs.extend(index_root(&bytes, used));
                if let Some(content) = &entry.reparse {
                    attrs.extend(resident_attribute(ATTR_REPARSE_POINT, content));
                }
            } else {
                match &entry.data {
                    Data::None => {}
                    Data::Resident(bytes) => attrs.extend(resident_attribute(ATTR_DATA, bytes)),
                    Data::NonResident { lcn, clusters, real_size } => {
                        attrs.extend(non_resident_data(*lcn, *clusters, *real_size))
                    }
                    Data::Sparse { real_size } => attrs.extend(sparse_data(*real_size)),
                }
                if let Some((name, lcn, clusters, real_size)) = &entry.nonresident_stream {
                    attrs.extend(non_resident_attribute(
                        ATTR_DATA,
                        Some(name),
                        *lcn,
                        *clusters,
                        0,
                        Some((*clusters * CLUSTER as u64, *real_size)),
                        3,
                    ));
                }
                for (stream, content) in &entry.streams {
                    attrs.extend(named_resident_data(stream, content));
                }
                if entry.encrypted {
                    attrs.extend(named_resident_attribute(
                        ATTR_LOGGED_UTILITY_STREAM,
                        EFS_STREAM,
                        &EFS_PLACEHOLDER,
                    ));
                }
                if let Some(wof) = &entry.wof {
                    attrs.extend(non_resident_attribute(
                        ATTR_DATA,
                        Some(mm_raw::wof::STREAM_NAME),
                        wof.lcn,
                        wof.clusters,
                        0,
                        Some((wof.clusters * CLUSTER as u64, wof.stream_len)),
                        1,
                    ));
                    attrs.extend(resident_attribute(
                        ATTR_REPARSE_POINT,
                        &wof_reparse_content(wof.algorithm),
                    ));
                }
            }
            write_record_with_tail(
                &mut mft,
                entry.record,
                &entry.name,
                entry.flags,
                0,
                &attrs,
                self.ghost_tails.get(&entry.record).map_or(&[][..], Vec::as_slice),
            );
            set_hard_link_count(&mut mft, entry.record, entry.hard_links);
        }

        for entry in &entries {
            set_sequence(&mut mft, entry.record, entry.sequence);
        }

        let start = (MFT_LCN as usize) * CLUSTER;
        self.image[start..start + mft.len()].copy_from_slice(&mft);
        self.image
    }

    fn write_spilled_directory(&mut self, mft: &mut [u8], entry: &Entry) {
        let layout = entry.index;
        let children = self.children.get(&entry.record).cloned().unwrap_or_default();
        let (child_entries, child_used) = self.entry_index(entry.record, &children);

        let root = if layout.is_large() {
            named_resident_attribute(
                ATTR_INDEX_ROOT,
                INDEX_NAME,
                &index_root_content(
                    &index_subnode_terminator(0),
                    index_subnode_terminator(0).len(),
                    !entry.small_index_flag,
                ),
            )
        } else {
            index_root(&child_entries, child_used)
        };
        let occupied: Vec<usize> = (0..entry.indx_lcns.len())
            .filter(|vcn| !entry.unused_indx.contains(&(*vcn as u64)))
            .collect();
        for (vcn, lcn) in entry.indx_lcns.iter().enumerate() {
            let mine: Vec<(String, u64)> = match occupied.iter().position(|o| *o == vcn) {
                Some(slot) => children
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| i % occupied.len() == slot)
                    .map(|(_, child)| child.clone())
                    .collect(),
                None => Vec::new(),
            };
            let (mine_entries, mine_used) = self.entry_index(entry.record, &mine);
            let mut buffer = index_buffer(vcn as u64, &mine_entries, mine_used);
            if entry.damaged_indx.contains(&(vcn as u64)) {
                buffer[0x00..0x04].copy_from_slice(b"BAAD");
            }
            let start = *lcn as usize * CLUSTER;
            self.image[start..start + buffer.len()].copy_from_slice(&buffer);
            if vcn == 0 {
                if let Some(free) = entry.abandoned_page {
                    let at = free as usize * CLUSTER;
                    self.image[at..at + buffer.len()].copy_from_slice(&buffer);
                }
            }
        }

        let base = entry.record;
        let ext = &entry.extensions;
        let (root_record, allocation_records): (u64, Vec<u64>) = match layout {
            IndexLayout::Resident => unreachable!("a resident index is not spilled"),
            IndexLayout::RootInExtension | IndexLayout::WholeIndexInExtension => {
                (ext[0], vec![ext[0]])
            }
            IndexLayout::SplitAcrossExtensions => (ext[0], vec![ext[1]]),
            IndexLayout::AllocationInExtension => (base, vec![ext[0]]),
            IndexLayout::AllocationFragmentedByVcn => (base, vec![ext[0], ext[1]]),
            IndexLayout::LargeInBase => (base, vec![base]),
        };

        let mut placed: Vec<Placed> = vec![Placed {
            record: root_record,
            type_code: ATTR_INDEX_ROOT,
            id: ID_INDEX_ROOT,
            start_vcn: 0,
            bytes: with_id(root, ID_INDEX_ROOT),
        }];
        let whole_size = entry.indx_lcns.len() as u64 * INDEX_RECORD as u64;
        let runs: Vec<(Option<u64>, u64)> = entry
            .indx_lcns
            .iter()
            .enumerate()
            .map(|(vcn, lcn)| ((!entry.sparse_indx.contains(&(vcn as u64))).then_some(*lcn), 1))
            .collect();
        if layout == IndexLayout::LargeInBase {
            placed.push(Placed {
                record: base,
                type_code: ATTR_INDEX_ALLOCATION,
                id: ID_INDEX_ALLOCATION,
                start_vcn: 0,
                bytes: non_resident_runs(
                    ATTR_INDEX_ALLOCATION,
                    Some(INDEX_NAME),
                    &runs,
                    0,
                    Some((whole_size, whole_size)),
                    ID_INDEX_ALLOCATION,
                ),
            });
        } else {
            for (vcn, (lcn, clusters)) in runs.iter().enumerate() {
                let record = allocation_records[vcn.min(allocation_records.len() - 1)];
                placed.push(Placed {
                    record,
                    type_code: ATTR_INDEX_ALLOCATION,
                    id: ID_INDEX_ALLOCATION,
                    start_vcn: vcn as u64,
                    bytes: non_resident_runs(
                        ATTR_INDEX_ALLOCATION,
                        Some(INDEX_NAME),
                        &[(*lcn, *clusters)],
                        vcn as u64,
                        (vcn == 0).then_some((whole_size, whole_size)),
                        ID_INDEX_ALLOCATION,
                    ),
                });
            }
        }
        if !entry.indx_lcns.is_empty() && !entry.no_index_bitmap {
            let mut bits = [0u8; 8];
            for vcn in 0..entry.indx_lcns.len() {
                if entry.unused_indx.contains(&(vcn as u64)) {
                    continue;
                }
                bits[vcn / 8] |= 1 << (vcn % 8);
            }
            for vcn in &entry.claimed_indx {
                bits[(*vcn / 8) as usize] |= 1 << (*vcn % 8);
            }
            placed.push(Placed {
                record: *allocation_records.last().expect("a large index has a fragment"),
                type_code: ATTR_BITMAP,
                id: ID_BITMAP,
                start_vcn: 0,
                bytes: with_id(named_resident_attribute(ATTR_BITMAP, INDEX_NAME, &bits), ID_BITMAP),
            });
        }

        let name_record = if entry.name_in_extension { ext[0] } else { base };
        let mut list =
            attribute_list_entry(ATTR_STANDARD_INFORMATION, None, 0, base, ID_STANDARD_INFORMATION);
        list.extend(attribute_list_entry(
            ATTR_FILE_NAME,
            None,
            0,
            entry.name_misdirect.unwrap_or(name_record),
            ID_FILE_NAME,
        ));
        for attribute in &placed {
            let named = entry.misdirect.unwrap_or(attribute.record);
            list.extend(attribute_list_entry(
                attribute.type_code,
                Some(INDEX_NAME),
                attribute.start_vcn,
                named,
                attribute.id,
            ));
        }
        for (type_code, target) in &entry.padding {
            let (name, id) = if *type_code == ATTR_INDEX_ROOT || *type_code == ATTR_INDEX_ALLOCATION
            {
                (Some(INDEX_NAME), ID_INDEX_ROOT)
            } else {
                (None, ID_FILE_NAME)
            };
            list.extend(attribute_list_entry(*type_code, name, 0, *target, id));
        }

        let mut base_attrs = standard_information(entry.times, entry.is_directory, entry.encrypted);
        if layout != IndexLayout::LargeInBase {
            base_attrs.extend(with_id(
                match entry.list_lcn {
                    Some(lcn) => {
                        let span = entry.list_clusters as usize * CLUSTER;
                        assert!(
                            list.len() <= span,
                            "the $ATTRIBUTE_LIST of `{}` needs {} bytes and {span} were allocated",
                            entry.name,
                            list.len()
                        );
                        let start = lcn as usize * CLUSTER;
                        self.image[start..start + list.len()].copy_from_slice(&list);
                        non_resident_attribute(
                            ATTR_ATTRIBUTE_LIST,
                            None,
                            lcn,
                            entry.list_clusters,
                            0,
                            Some((span as u64, list.len() as u64)),
                            ID_ATTRIBUTE_LIST,
                        )
                    }
                    None => resident_attribute(ATTR_ATTRIBUTE_LIST, &list),
                },
                ID_ATTRIBUTE_LIST,
            ));
        }
        let name_attribute = with_id(
            file_name_attribute_seq(
                entry.parent,
                entry.parent_sequence,
                &entry.name,
                0,
                entry.file_name_times,
            ),
            ID_FILE_NAME,
        );
        if !entry.name_in_extension {
            base_attrs.extend_from_slice(&name_attribute);
        } else {
            placed.insert(
                0,
                Placed {
                    record: name_record,
                    type_code: ATTR_FILE_NAME,
                    id: ID_FILE_NAME,
                    start_vcn: 0,
                    bytes: name_attribute,
                },
            );
        }
        for attribute in &placed {
            if attribute.record == base {
                base_attrs.extend_from_slice(&attribute.bytes);
            }
        }
        write_record(mft, base, &entry.name, entry.flags, &base_attrs);
        set_hard_link_count(mft, base, entry.hard_links);

        for extension in ext {
            let mut attrs = Vec::new();
            for attribute in &placed {
                if attribute.record == *extension {
                    attrs.extend_from_slice(&attribute.bytes);
                }
            }
            write_extension_record(mft, *extension, &entry.name, base, &attrs);
        }
    }

    fn entry_index(&self, dir: u64, children: &[(String, u64)]) -> (Vec<u8>, usize) {
        let mut out = Vec::new();
        let mut spans: Vec<(String, usize, usize)> = Vec::new();
        for (name, record) in children {
            let (real_size, allocated, times) =
                self.index_facts.get(record).copied().unwrap_or_default();
            let bytes = index_entry_for(dir, *record, name, real_size, allocated, times);
            spans.push((name.clone(), out.len(), bytes.len()));
            out.extend(bytes);
        }
        out.extend(index_terminator());
        let mut used = out.len();

        for name in self.deletions.get(&dir).into_iter().flatten() {
            let Some(position) = spans.iter().position(|(n, _, _)| n == name) else { continue };
            let (_, at, length) = spans[position].clone();
            out.copy_within(at + length..used, at);
            used -= length;
            spans.remove(position);
            for span in spans.iter_mut().skip(position) {
                span.1 -= length;
            }
        }
        (out, used)
    }

    fn take_record(&mut self) -> u64 {
        let record = self.next_record;
        let capacity = self.record_count();
        assert!(record < capacity, "the synthetic $MFT holds {capacity} records");
        self.next_record += 1;
        record
    }

    fn take_clusters(&mut self, count: u64) -> u64 {
        let lcn = self.next_lcn;
        assert!(lcn + count <= self.total_clusters, "the synthetic volume is full");
        self.next_lcn += count;
        lcn
    }

    fn set_allocated(&mut self, lcn: u64, count: u64, allocated: bool) {
        for cluster in lcn..lcn + count {
            self.allocated[cluster as usize] = allocated;
        }
    }
}

fn write_spilled_file(mft: &mut [u8], image: &mut [u8], entry: &Entry) {
    let base = entry.record;
    let extension = entry.spill_record.expect("a spilled file was given an extension record");

    let mut next_id = ID_FILE_NAME + 1;
    let mut id = || {
        let assigned = next_id;
        next_id += 1;
        assigned
    };

    let mut parts: Vec<(u32, Option<String>, u16, Vec<u8>)> = vec![
        (
            ATTR_STANDARD_INFORMATION,
            None,
            ID_STANDARD_INFORMATION,
            standard_information(entry.times, false, entry.encrypted),
        ),
        (
            ATTR_FILE_NAME,
            None,
            ID_FILE_NAME,
            with_id(
                file_name_attribute_seq(
                    entry.parent,
                    entry.parent_sequence,
                    &entry.name,
                    entry.file_name_size.unwrap_or_else(|| real_size(&entry.data)),
                    entry.file_name_times,
                ),
                ID_FILE_NAME,
            ),
        ),
    ];

    match &entry.data {
        Data::None => {}
        Data::Resident(bytes) => {
            let this = id();
            parts.push((
                ATTR_DATA,
                None,
                this,
                with_id(resident_attribute(ATTR_DATA, bytes), this),
            ));
        }
        Data::NonResident { lcn, clusters, real_size } => {
            let this = id();
            parts.push((
                ATTR_DATA,
                None,
                this,
                with_id(non_resident_data(*lcn, *clusters, *real_size), this),
            ));
        }
        Data::Sparse { real_size } => {
            let this = id();
            parts.push((ATTR_DATA, None, this, with_id(sparse_data(*real_size), this)));
        }
    }
    for (stream, content) in &entry.streams {
        let this = id();
        parts.push((
            ATTR_DATA,
            Some(stream.clone()),
            this,
            with_id(named_resident_data(stream, content), this),
        ));
    }
    if let Some(wof) = &entry.wof {
        let this = id();
        parts.push((
            ATTR_DATA,
            Some(mm_raw::wof::STREAM_NAME.to_string()),
            this,
            non_resident_attribute(
                ATTR_DATA,
                Some(mm_raw::wof::STREAM_NAME),
                wof.lcn,
                wof.clusters,
                0,
                Some((wof.clusters * CLUSTER as u64, wof.stream_len)),
                this,
            ),
        ));
        let this = id();
        parts.push((
            ATTR_REPARSE_POINT,
            None,
            this,
            with_id(
                resident_attribute(ATTR_REPARSE_POINT, &wof_reparse_content(wof.algorithm)),
                this,
            ),
        ));
    }
    if let Some(content) = &entry.reparse {
        let this = id();
        parts.push((
            ATTR_REPARSE_POINT,
            None,
            this,
            with_id(resident_attribute(ATTR_REPARSE_POINT, content), this),
        ));
    }

    let holder = |type_code: u32, name: Option<&str>| {
        let moved = entry.spilled.iter().any(|(t, n)| *t == type_code && n.as_deref() == name);
        if moved {
            extension
        } else {
            base
        }
    };

    let mut list = Vec::new();
    for (type_code, name, attribute_id, _) in &parts {
        let real = holder(*type_code, name.as_deref());
        let named = match entry.misdirect {
            Some(to) if real == extension => to,
            _ => real,
        };
        list.extend(attribute_list_entry(*type_code, name.as_deref(), 0, named, *attribute_id));
    }
    for (type_code, target) in &entry.padding {
        list.extend(attribute_list_entry(*type_code, None, 0, *target, ID_FILE_NAME));
    }

    let mut base_attrs = parts[0].3.clone();
    base_attrs.extend(with_id(
        match entry.list_lcn {
            Some(lcn) => {
                let span = entry.list_clusters as usize * CLUSTER;
                assert!(
                    list.len() <= span,
                    "the $ATTRIBUTE_LIST of `{}` needs {} bytes and {span} were allocated",
                    entry.name,
                    list.len()
                );
                let start = lcn as usize * CLUSTER;
                image[start..start + list.len()].copy_from_slice(&list);
                non_resident_attribute(
                    ATTR_ATTRIBUTE_LIST,
                    None,
                    lcn,
                    entry.list_clusters,
                    0,
                    Some((span as u64, list.len() as u64)),
                    ID_ATTRIBUTE_LIST,
                )
            }
            None => resident_attribute(ATTR_ATTRIBUTE_LIST, &list),
        },
        ID_ATTRIBUTE_LIST,
    ));
    for (type_code, name, _, bytes) in parts.iter().skip(1) {
        if holder(*type_code, name.as_deref()) == base {
            base_attrs.extend_from_slice(bytes);
        }
    }
    write_record(mft, base, &entry.name, entry.flags, &base_attrs);
    set_hard_link_count(mft, base, entry.hard_links);

    let mut extension_attrs = Vec::new();
    for (type_code, name, _, bytes) in &parts {
        if holder(*type_code, name.as_deref()) == extension {
            extension_attrs.extend_from_slice(bytes);
        }
    }
    write_extension_record(mft, extension, &entry.name, base, &extension_attrs);
}

fn real_size(data: &Data) -> u64 {
    match data {
        Data::None => 0,
        Data::Resident(bytes) => bytes.len() as u64,
        Data::NonResident { real_size, .. } => *real_size,
        Data::Sparse { real_size } => *real_size,
    }
}

fn write_boot_sector(image: &mut [u8], mft_clusters: u64, total_clusters: u64) {
    image[0x03..0x0B].copy_from_slice(b"NTFS    ");
    image[0x0B..0x0D].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    image[0x0D] = SECTORS_PER_CLUSTER;
    image[0x28..0x30].copy_from_slice(&(total_clusters * SECTORS_PER_CLUSTER as u64).to_le_bytes());
    image[0x30..0x38].copy_from_slice(&MFT_LCN.to_le_bytes());
    image[0x38..0x40].copy_from_slice(&(MFT_LCN + mft_clusters).to_le_bytes());
    image[0x40] = (-10i8) as u8;
    image[0x44] = (-12i8) as u8;
    image[0x48..0x50].copy_from_slice(&0xB1A2_C3D4_E5F6_0718u64.to_le_bytes());
}

fn set_hard_link_count(mft: &mut [u8], number: u64, links: u16) {
    let offset = (number as usize) * RECORD + 0x12;
    mft[offset..offset + 2].copy_from_slice(&links.to_le_bytes());
}

fn set_sequence(mft: &mut [u8], number: u64, sequence: u16) {
    let offset = (number as usize) * RECORD + 0x10;
    mft[offset..offset + 2].copy_from_slice(&sequence.to_le_bytes());
}

fn write_record(mft: &mut [u8], number: u64, what: &str, flags: u16, attributes: &[u8]) {
    write_record_with_base(mft, number, what, flags, 0, attributes);
}

pub fn record_image(parent: u64, name: &str, lcn: u64, clusters: u64, real_size: u64) -> Vec<u8> {
    let mut attributes = standard_information(Times::UNSET, false, false);
    attributes.extend(file_name_attribute(parent, name, real_size, Times::UNSET));
    attributes.extend(non_resident_data(lcn, clusters, real_size));
    let mut mft = vec![0u8; RECORD];
    write_record(&mut mft, 0, name, FLAG_IN_USE, &attributes);
    for sector in 0..RECORD / SECTOR {
        let tail = (sector + 1) * SECTOR - 2;
        let slot = 0x32 + sector * 2;
        let original = [mft[slot], mft[slot + 1]];
        mft[tail..tail + 2].copy_from_slice(&original);
    }
    mft
}

pub fn log_file(images: &[Vec<u8>]) -> Vec<u8> {
    const PAGE: usize = 4096;
    const USN: u16 = 0x0007;
    let mut log = vec![0u8; PAGE];
    log[0x00..0x04].copy_from_slice(b"RSTR");
    for image in images {
        let mut page = vec![0u8; PAGE];
        page[0x00..0x04].copy_from_slice(b"RCRD");
        page[0x04..0x06].copy_from_slice(&0x28u16.to_le_bytes());
        page[0x06..0x08].copy_from_slice(&9u16.to_le_bytes());
        page[0x40..0x40 + image.len()].copy_from_slice(image);
        page[0x28..0x2a].copy_from_slice(&USN.to_le_bytes());
        for sector in 0..8usize {
            let tail = (sector + 1) * 512 - 2;
            let slot = 0x2a + sector * 2;
            let original = [page[tail], page[tail + 1]];
            page[slot..slot + 2].copy_from_slice(&original);
            page[tail..tail + 2].copy_from_slice(&USN.to_le_bytes());
        }
        log.extend_from_slice(&page);
    }
    log
}

fn write_extension_record(mft: &mut [u8], number: u64, what: &str, base: u64, attributes: &[u8]) {
    write_record_with_base(mft, number, what, FLAG_IN_USE, (1u64 << 48) | base, attributes);
}

fn write_record_with_base(
    mft: &mut [u8],
    number: u64,
    what: &str,
    flags: u16,
    base_record: u64,
    attributes: &[u8],
) {
    write_record_with_tail(mft, number, what, flags, base_record, attributes, &[]);
}

fn write_record_with_tail(
    mft: &mut [u8],
    number: u64,
    what: &str,
    flags: u16,
    base_record: u64,
    attributes: &[u8],
    tail: &[u8],
) {
    const USA_OFFSET: usize = 0x30;
    const USN: u16 = 0x0001;

    let sectors = RECORD / SECTOR;
    let usa_count = sectors + 1;
    let first_attribute = 0x38usize;
    assert!(
        first_attribute + attributes.len() + 4 <= RECORD,
        "record {number} ({what}) needs {} bytes and a record holds {RECORD}",
        first_attribute + attributes.len() + 4
    );

    let mut record = vec![0u8; RECORD];
    record[0x00..0x04].copy_from_slice(b"FILE");
    record[0x04..0x06].copy_from_slice(&(USA_OFFSET as u16).to_le_bytes());
    record[0x06..0x08].copy_from_slice(&(usa_count as u16).to_le_bytes());
    record[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
    record[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
    record[0x14..0x16].copy_from_slice(&(first_attribute as u16).to_le_bytes());
    record[0x16..0x18].copy_from_slice(&flags.to_le_bytes());
    record[0x18..0x1C]
        .copy_from_slice(&((first_attribute + attributes.len() + 4) as u32).to_le_bytes());
    record[0x1C..0x20].copy_from_slice(&(RECORD as u32).to_le_bytes());
    record[0x20..0x28].copy_from_slice(&base_record.to_le_bytes());
    record[0x28..0x2A].copy_from_slice(&((attributes.len() / 8 + 1) as u16).to_le_bytes());
    record[0x2C..0x30].copy_from_slice(&(number as u32).to_le_bytes());

    record[first_attribute..first_attribute + attributes.len()].copy_from_slice(attributes);
    let end = first_attribute + attributes.len();
    record[end..end + 4].copy_from_slice(&ATTR_END.to_le_bytes());

    if !tail.is_empty() {
        let at = align8(end + 4);
        assert!(
            at + tail.len() <= RECORD,
            "record {number} ({what}) has no room for a {}-byte tail",
            tail.len()
        );
        record[at..at + tail.len()].copy_from_slice(tail);
    }

    record[USA_OFFSET..USA_OFFSET + 2].copy_from_slice(&USN.to_le_bytes());
    for sector in 0..sectors {
        let tail = (sector + 1) * SECTOR - 2;
        let original: [u8; 2] = [record[tail], record[tail + 1]];
        let slot = USA_OFFSET + 2 + sector * 2;
        record[slot..slot + 2].copy_from_slice(&original);
        record[tail..tail + 2].copy_from_slice(&USN.to_le_bytes());
    }

    let start = (number as usize) * RECORD;
    mft[start..start + RECORD].copy_from_slice(&record);
}

fn resident_attribute(type_code: u32, content: &[u8]) -> Vec<u8> {
    const CONTENT_OFFSET: usize = 0x18;
    let length = align8(CONTENT_OFFSET + content.len());
    let mut a = vec![0u8; length];
    a[0x00..0x04].copy_from_slice(&type_code.to_le_bytes());
    a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
    a[0x0A..0x0C].copy_from_slice(&(CONTENT_OFFSET as u16).to_le_bytes());
    a[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes());
    a[0x14..0x16].copy_from_slice(&(CONTENT_OFFSET as u16).to_le_bytes());
    a[CONTENT_OFFSET..CONTENT_OFFSET + content.len()].copy_from_slice(content);
    a
}

fn sparse_data(real_size: u64) -> Vec<u8> {
    const RUNS_OFFSET: usize = 0x40;
    const FLAG_SPARSE: u16 = 0x8000;

    let clusters = real_size.div_ceil(CLUSTER as u64).max(1);
    let mut runlist = vec![0x04u8];
    runlist.extend_from_slice(&(clusters as u32).to_le_bytes());
    runlist.push(0);

    let length = align8(RUNS_OFFSET + runlist.len());
    let mut a = vec![0u8; length];
    a[0x00..0x04].copy_from_slice(&ATTR_DATA.to_le_bytes());
    a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
    a[0x08] = 1;
    a[0x0C..0x0E].copy_from_slice(&FLAG_SPARSE.to_le_bytes());
    a[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
    a[0x18..0x20].copy_from_slice(&(clusters - 1).to_le_bytes());
    a[0x20..0x22].copy_from_slice(&(RUNS_OFFSET as u16).to_le_bytes());
    a[0x28..0x30].copy_from_slice(&(clusters * CLUSTER as u64).to_le_bytes());
    a[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
    a[0x38..0x40].copy_from_slice(&real_size.to_le_bytes());
    a[RUNS_OFFSET..RUNS_OFFSET + runlist.len()].copy_from_slice(&runlist);
    a
}

fn wof_reparse_content(algorithm: u32) -> Vec<u8> {
    let mut data = 1u32.to_le_bytes().to_vec();
    data.extend_from_slice(&mm_raw::wof::WOF_PROVIDER_FILE.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&algorithm.to_le_bytes());

    let mut a = mm_raw::wof::IO_REPARSE_TAG_WOF.to_le_bytes().to_vec();
    a.extend_from_slice(&(data.len() as u16).to_le_bytes());
    a.extend_from_slice(&0u16.to_le_bytes());
    a.extend_from_slice(&data);
    a
}

fn mount_point_reparse(substitute: &str, print: &str) -> Vec<u8> {
    let sub: Vec<u8> = substitute.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let pr: Vec<u8> = print.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&(sub.len() as u16).to_le_bytes());
    data.extend_from_slice(&((sub.len() + 2) as u16).to_le_bytes());
    data.extend_from_slice(&(pr.len() as u16).to_le_bytes());
    data.extend_from_slice(&sub);
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(&pr);
    data.extend_from_slice(&[0, 0]);
    reparse_attribute(mm_raw::reparse::IO_REPARSE_TAG_MOUNT_POINT, &data)
}

fn symlink_reparse(substitute: &str, relative: bool) -> Vec<u8> {
    let sub: Vec<u8> = substitute.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut data = Vec::new();
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&(sub.len() as u16).to_le_bytes());
    data.extend_from_slice(&((sub.len() + 2) as u16).to_le_bytes());
    data.extend_from_slice(&(sub.len() as u16).to_le_bytes());
    data.extend_from_slice(&u32::from(relative).to_le_bytes());
    data.extend_from_slice(&sub);
    data.extend_from_slice(&[0, 0]);
    data.extend_from_slice(&sub);
    data.extend_from_slice(&[0, 0]);
    reparse_attribute(mm_raw::reparse::IO_REPARSE_TAG_SYMLINK, &data)
}

fn reparse_attribute(tag: u32, data: &[u8]) -> Vec<u8> {
    let mut a = tag.to_le_bytes().to_vec();
    a.extend_from_slice(&(data.len() as u16).to_le_bytes());
    a.extend_from_slice(&0u16.to_le_bytes());
    a.extend_from_slice(data);
    a
}

fn non_resident_data(lcn: u64, clusters: u64, real_size: u64) -> Vec<u8> {
    const RUNS_OFFSET: usize = 0x40;
    let mut runlist = vec![0x44u8];
    runlist.extend_from_slice(&(clusters as u32).to_le_bytes());
    runlist.extend_from_slice(&(lcn as i32).to_le_bytes());
    runlist.push(0);

    let length = align8(RUNS_OFFSET + runlist.len());
    let mut a = vec![0u8; length];
    a[0x00..0x04].copy_from_slice(&ATTR_DATA.to_le_bytes());
    a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
    a[0x08] = 1;
    a[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
    a[0x18..0x20].copy_from_slice(&(clusters - 1).to_le_bytes());
    a[0x20..0x22].copy_from_slice(&(RUNS_OFFSET as u16).to_le_bytes());
    a[0x28..0x30].copy_from_slice(&(clusters * CLUSTER as u64).to_le_bytes());
    a[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
    a[0x38..0x40].copy_from_slice(&real_size.to_le_bytes());
    a[RUNS_OFFSET..RUNS_OFFSET + runlist.len()].copy_from_slice(&runlist);
    a
}

fn standard_information(times: Times, is_directory: bool, encrypted: bool) -> Vec<u8> {
    const CONTENT: usize = 0x48;
    let mut c = vec![0u8; CONTENT];
    c[0x00..0x08].copy_from_slice(&times.created.to_le_bytes());
    c[0x08..0x10].copy_from_slice(&times.modified.to_le_bytes());
    c[0x10..0x18].copy_from_slice(&times.mft_modified.to_le_bytes());
    c[0x18..0x20].copy_from_slice(&times.accessed.to_le_bytes());
    let mut flags =
        if is_directory { FILE_ATTRIBUTE_DIRECTORY_ON_DISK } else { FILE_ATTRIBUTE_ARCHIVE };
    if encrypted {
        flags |= FILE_ATTRIBUTE_ENCRYPTED;
    }
    c[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
    with_id(resident_attribute(ATTR_STANDARD_INFORMATION, &c), ID_STANDARD_INFORMATION)
}

fn file_name_content_sized(
    parent: u64,
    name: &str,
    real_size: u64,
    allocated_size: u64,
    times: Times,
) -> Vec<u8> {
    let mut c = file_name_content_seq(parent, 1, name, real_size, times);
    c[0x28..0x30].copy_from_slice(&allocated_size.to_le_bytes());
    c
}

fn file_name_content_seq(
    parent: u64,
    parent_sequence: u16,
    name: &str,
    real_size: u64,
    times: Times,
) -> Vec<u8> {
    const FIXED: usize = 0x42;
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut c = vec![0u8; FIXED + units.len() * 2];
    c[0x00..0x08].copy_from_slice(&((u64::from(parent_sequence) << 48) | parent).to_le_bytes());
    c[0x08..0x10].copy_from_slice(&times.created.to_le_bytes());
    c[0x10..0x18].copy_from_slice(&times.modified.to_le_bytes());
    c[0x18..0x20].copy_from_slice(&times.mft_modified.to_le_bytes());
    c[0x20..0x28].copy_from_slice(&times.accessed.to_le_bytes());
    c[0x28..0x30].copy_from_slice(&real_size.to_le_bytes());
    c[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
    c[0x40] = units.len() as u8;
    c[0x41] = 1;
    for (i, unit) in units.iter().enumerate() {
        c[FIXED + i * 2..FIXED + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    c
}

fn file_name_attribute(parent: u64, name: &str, real_size: u64, times: Times) -> Vec<u8> {
    file_name_attribute_seq(parent, 1, name, real_size, times)
}

fn file_name_attribute_seq(
    parent: u64,
    parent_sequence: u16,
    name: &str,
    real_size: u64,
    times: Times,
) -> Vec<u8> {
    resident_attribute(
        ATTR_FILE_NAME,
        &file_name_content_seq(parent, parent_sequence, name, real_size, times),
    )
}

fn index_entry_for(
    parent: u64,
    record: u64,
    name: &str,
    real_size: u64,
    allocated_size: u64,
    times: Times,
) -> Vec<u8> {
    let stream = file_name_content_sized(parent, name, real_size, allocated_size, times);
    let length = align8(0x10 + stream.len());
    let mut e = vec![0u8; length];
    e[0x00..0x08].copy_from_slice(&((1u64 << 48) | record).to_le_bytes());
    e[0x08..0x0A].copy_from_slice(&(length as u16).to_le_bytes());
    e[0x0A..0x0C].copy_from_slice(&(stream.len() as u16).to_le_bytes());
    e[0x10..0x10 + stream.len()].copy_from_slice(&stream);
    e
}

fn index_terminator() -> Vec<u8> {
    let mut e = vec![0u8; 0x10];
    e[0x08..0x0A].copy_from_slice(&0x10u16.to_le_bytes());
    e[0x0C] = 0x02;
    e
}

fn index_subnode_terminator(child_vcn: u64) -> Vec<u8> {
    let mut e = vec![0u8; 0x18];
    e[0x08..0x0A].copy_from_slice(&0x18u16.to_le_bytes());
    e[0x0C] = 0x02 | 0x01;
    e[0x10..0x18].copy_from_slice(&child_vcn.to_le_bytes());
    e
}

fn index_root_content(entries: &[u8], used: usize, large: bool) -> Vec<u8> {
    const HEADER: usize = 0x10;
    let mut content = vec![0u8; HEADER + HEADER + entries.len()];
    content[0x00..0x04].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
    content[0x08..0x0C].copy_from_slice(&(INDEX_RECORD as u32).to_le_bytes());
    content[0x0C] = 1;
    content[0x10..0x14].copy_from_slice(&(HEADER as u32).to_le_bytes());
    content[0x14..0x18].copy_from_slice(&((HEADER + used) as u32).to_le_bytes());
    content[0x18..0x1C].copy_from_slice(&((HEADER + entries.len()) as u32).to_le_bytes());
    content[0x1C..0x20].copy_from_slice(&u32::from(large).to_le_bytes());
    content[0x20..0x20 + entries.len()].copy_from_slice(entries);
    content
}

fn index_root(entries: &[u8], used: usize) -> Vec<u8> {
    named_resident_attribute(ATTR_INDEX_ROOT, INDEX_NAME, &index_root_content(entries, used, false))
}

fn index_buffer(vcn: u64, entries: &[u8], used: usize) -> Vec<u8> {
    const HEADER: usize = 0x18;
    const USA_OFFSET: usize = 0x28;
    const FIRST_ENTRY: usize = 0x40;
    const USN: u16 = 0x0001;

    let sectors = INDEX_RECORD / SECTOR;
    let usa_count = sectors + 1;
    assert!(
        FIRST_ENTRY + entries.len() <= INDEX_RECORD,
        "an INDX buffer holds {INDEX_RECORD} bytes and these entries need {}",
        FIRST_ENTRY + entries.len()
    );

    let mut b = vec![0u8; INDEX_RECORD];
    b[0x00..0x04].copy_from_slice(b"INDX");
    b[0x04..0x06].copy_from_slice(&(USA_OFFSET as u16).to_le_bytes());
    b[0x06..0x08].copy_from_slice(&(usa_count as u16).to_le_bytes());
    b[0x10..0x18].copy_from_slice(&vcn.to_le_bytes());
    b[HEADER..HEADER + 4].copy_from_slice(&((FIRST_ENTRY - HEADER) as u32).to_le_bytes());
    b[HEADER + 4..HEADER + 8]
        .copy_from_slice(&((FIRST_ENTRY - HEADER + used) as u32).to_le_bytes());
    b[HEADER + 8..HEADER + 12].copy_from_slice(&((INDEX_RECORD - HEADER) as u32).to_le_bytes());
    b[FIRST_ENTRY..FIRST_ENTRY + entries.len()].copy_from_slice(entries);

    b[USA_OFFSET..USA_OFFSET + 2].copy_from_slice(&USN.to_le_bytes());
    for sector in 0..sectors {
        let tail = (sector + 1) * SECTOR - 2;
        let original: [u8; 2] = [b[tail], b[tail + 1]];
        let slot = USA_OFFSET + 2 + sector * 2;
        b[slot..slot + 2].copy_from_slice(&original);
        b[tail..tail + 2].copy_from_slice(&USN.to_le_bytes());
    }
    b
}

fn attribute_list_entry(
    type_code: u32,
    name: Option<&str>,
    start_vcn: u64,
    record: u64,
    attribute_id: u16,
) -> Vec<u8> {
    const FIXED: usize = 0x1A;
    let units: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
    let length = align8(FIXED + units.len() * 2);

    let mut e = vec![0u8; length];
    e[0x00..0x04].copy_from_slice(&type_code.to_le_bytes());
    e[0x04..0x06].copy_from_slice(&(length as u16).to_le_bytes());
    e[0x06] = units.len() as u8;
    e[0x07] = FIXED as u8;
    e[0x08..0x10].copy_from_slice(&start_vcn.to_le_bytes());
    e[0x10..0x18].copy_from_slice(&((1u64 << 48) | record).to_le_bytes());
    e[0x18..0x1A].copy_from_slice(&attribute_id.to_le_bytes());
    for (i, unit) in units.iter().enumerate() {
        e[FIXED + i * 2..FIXED + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    e
}

fn with_id(mut attribute: Vec<u8>, id: u16) -> Vec<u8> {
    attribute[0x0E..0x10].copy_from_slice(&id.to_le_bytes());
    attribute
}

fn named_resident_attribute(type_code: u32, name: &str, content: &[u8]) -> Vec<u8> {
    const NAME_OFFSET: usize = 0x18;
    let name_units: Vec<u16> = name.encode_utf16().collect();
    let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let content_offset = align8(NAME_OFFSET + name_bytes.len());
    let length = align8(content_offset + content.len());

    let mut a = vec![0u8; length];
    a[0x00..0x04].copy_from_slice(&type_code.to_le_bytes());
    a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
    a[0x08] = 0;
    a[0x09] = name_units.len() as u8;
    a[0x0A..0x0C].copy_from_slice(&(NAME_OFFSET as u16).to_le_bytes());
    a[0x10..0x14].copy_from_slice(&(content.len() as u32).to_le_bytes());
    a[0x14..0x16].copy_from_slice(&(content_offset as u16).to_le_bytes());
    a[NAME_OFFSET..NAME_OFFSET + name_bytes.len()].copy_from_slice(&name_bytes);
    a[content_offset..content_offset + content.len()].copy_from_slice(content);
    a
}

fn named_resident_data(name: &str, content: &[u8]) -> Vec<u8> {
    named_resident_attribute(ATTR_DATA, name, content)
}

fn non_resident_runs(
    type_code: u32,
    name: Option<&str>,
    runs: &[(Option<u64>, u64)],
    start_vcn: u64,
    sizes: Option<(u64, u64)>,
    id: u16,
) -> Vec<u8> {
    const NAME_OFFSET: usize = 0x40;
    assert!(!runs.is_empty(), "a non-resident attribute covers at least one cluster");
    let name_units: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
    let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let runs_offset = align8(NAME_OFFSET + name_bytes.len());

    let mut runlist = Vec::new();
    let mut previous: i64 = 0;
    let mut clusters = 0u64;
    for (lcn, length) in runs {
        clusters += *length;
        match lcn {
            None => {
                runlist.push(0x04u8);
                runlist.extend_from_slice(&(*length as u32).to_le_bytes());
            }
            Some(lcn) => {
                runlist.push(0x44u8);
                runlist.extend_from_slice(&(*length as u32).to_le_bytes());
                runlist.extend_from_slice(&((*lcn as i64 - previous) as i32).to_le_bytes());
                previous = *lcn as i64;
            }
        }
    }
    runlist.push(0);

    let length = align8(runs_offset + runlist.len());
    let mut a = vec![0u8; length];
    a[0x00..0x04].copy_from_slice(&type_code.to_le_bytes());
    a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
    a[0x08] = 1;
    a[0x09] = name_units.len() as u8;
    a[0x0A..0x0C].copy_from_slice(&(NAME_OFFSET as u16).to_le_bytes());
    a[0x0E..0x10].copy_from_slice(&id.to_le_bytes());
    a[0x10..0x18].copy_from_slice(&start_vcn.to_le_bytes());
    a[0x18..0x20].copy_from_slice(&(start_vcn + clusters - 1).to_le_bytes());
    a[0x20..0x22].copy_from_slice(&(runs_offset as u16).to_le_bytes());
    if let Some((allocated, real_size)) = sizes {
        a[0x28..0x30].copy_from_slice(&allocated.to_le_bytes());
        a[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
        a[0x38..0x40].copy_from_slice(&real_size.to_le_bytes());
    }
    a[NAME_OFFSET..NAME_OFFSET + name_bytes.len()].copy_from_slice(&name_bytes);
    a[runs_offset..runs_offset + runlist.len()].copy_from_slice(&runlist);
    a
}

fn non_resident_attribute(
    type_code: u32,
    name: Option<&str>,
    lcn: u64,
    clusters: u64,
    start_vcn: u64,
    sizes: Option<(u64, u64)>,
    id: u16,
) -> Vec<u8> {
    const NAME_OFFSET: usize = 0x40;
    let name_units: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
    let name_bytes: Vec<u8> = name_units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let runs_offset = align8(NAME_OFFSET + name_bytes.len());

    let mut runlist = vec![0x44u8];
    runlist.extend_from_slice(&(clusters as u32).to_le_bytes());
    runlist.extend_from_slice(&(lcn as i32).to_le_bytes());
    runlist.push(0);

    let length = align8(runs_offset + runlist.len());
    let mut a = vec![0u8; length];
    a[0x00..0x04].copy_from_slice(&type_code.to_le_bytes());
    a[0x04..0x08].copy_from_slice(&(length as u32).to_le_bytes());
    a[0x08] = 1;
    a[0x09] = name_units.len() as u8;
    a[0x0A..0x0C].copy_from_slice(&(NAME_OFFSET as u16).to_le_bytes());
    a[0x0E..0x10].copy_from_slice(&id.to_le_bytes());
    a[0x10..0x18].copy_from_slice(&start_vcn.to_le_bytes());
    a[0x18..0x20].copy_from_slice(&(start_vcn + clusters - 1).to_le_bytes());
    a[0x20..0x22].copy_from_slice(&(runs_offset as u16).to_le_bytes());
    if let Some((allocated, real_size)) = sizes {
        a[0x28..0x30].copy_from_slice(&allocated.to_le_bytes());
        a[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
        a[0x38..0x40].copy_from_slice(&real_size.to_le_bytes());
    }
    a[NAME_OFFSET..NAME_OFFSET + name_bytes.len()].copy_from_slice(&name_bytes);
    a[runs_offset..runs_offset + runlist.len()].copy_from_slice(&runlist);
    a
}

fn align8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_synthetic_volume_reads_back_like_a_real_one() {
        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\bob");
        builder.file(dir, "notes.txt", b"hello from a synthetic volume", Presence::Live);
        let volume = builder.open();

        assert_eq!(volume.cluster_size(), CLUSTER as u64);
        assert!(volume.exists("\\Users\\bob\\notes.txt"));
        assert_eq!(
            volume.read("\\Users\\bob\\notes.txt").unwrap(),
            b"hello from a synthetic volume"
        );
        assert_eq!(volume.list_directory("\\Users"), vec!["bob".to_string()]);
    }

    #[test]
    fn a_deleted_file_leaves_its_record_and_loses_its_directory_entry() {
        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Temp");
        let record = builder.file(dir, "dropper.exe", b"MZ payload", Presence::Deleted);
        let volume = builder.open();

        assert!(!volume.exists("\\Temp\\dropper.exe"));
        let identity = volume.record_identity(record).expect("the record survives");
        assert_eq!(identity.name, "dropper.exe");
        assert!(!identity.in_use);
        assert_eq!(volume.read_record_capped(record, 4096).unwrap(), b"MZ payload");
    }

    #[test]
    fn an_alternate_data_stream_is_read_back_by_name() {
        const MOTW: &[u8] =
            b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=C:\\Users\\analyst\\Downloads\\example-main.zip\x00";

        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\bob\\Downloads");
        let record = builder.file(dir, "setup.exe", b"MZ this is the file itself", Presence::Live);
        builder.alternate_stream(record, "Zone.Identifier", MOTW);
        builder.file(dir, "clean.exe", b"MZ no mark of the web", Presence::Live);
        let volume = builder.open();

        assert_eq!(
            volume.read("\\Users\\bob\\Downloads\\setup.exe").unwrap(),
            b"MZ this is the file itself"
        );

        let stream = volume
            .read_named_stream(
                "\\Users\\bob\\Downloads\\setup.exe",
                mm_harvest::motw::STREAM_NAME,
                mm_harvest::motw::MAX_STREAM_BYTES,
            )
            .expect("the Zone.Identifier stream is readable");
        assert_eq!(stream, MOTW, "the stream did not round-trip byte for byte");

        let path = mm_core::NormalizedPath::parse("C:\\Users\\bob\\Downloads\\setup.exe").unwrap();
        let observations = mm_harvest::motw::harvest(&stream, &path);
        assert_eq!(observations.len(), 1);
        match &observations[0].kind {
            mm_core::ObservationKind::DownloadedFrom { zone, referrer_url, .. } => {
                assert_eq!(*zone, mm_core::UrlZone::Internet);
                assert_eq!(
                    referrer_url.as_deref(),
                    Some("C:\\Users\\analyst\\Downloads\\example-main.zip")
                );
            }
            other => panic!("expected DownloadedFrom, got {other:?}"),
        }

        assert!(
            volume
                .read_named_stream(
                    "\\Users\\bob\\Downloads\\clean.exe",
                    mm_harvest::motw::STREAM_NAME,
                    mm_harvest::motw::MAX_STREAM_BYTES,
                )
                .is_err(),
            "a file with no Zone.Identifier must not yield one"
        );
    }

    #[test]
    fn a_named_stream_read_is_capped() {
        let long = vec![b'A'; 512];
        let mut builder = Builder::new();
        let record = builder.file(ROOT_RECORD, "x.exe", b"MZ", Presence::Live);
        builder.alternate_stream(record, "Zone.Identifier", &long);
        let volume = builder.open();

        let whole = volume.read_named_stream("\\x.exe", "Zone.Identifier", 4096).unwrap();
        assert_eq!(whole.len(), 512);

        let capped = volume.read_named_stream("\\x.exe", "Zone.Identifier", 100).unwrap();
        assert!(capped.len() <= 100, "read {} bytes against a 100-byte cap", capped.len());
    }

    fn facts_for(
        volume: &Volume<Cursor<Vec<u8>>>,
        wanted: &str,
    ) -> mm_harvest::filesystem::FileFacts {
        let mut found = None;
        mm_harvest::filesystem::enumerate(volume, &mut |path, facts| {
            if path.key() == wanted {
                found = Some(mm_harvest::filesystem::FileFacts {
                    record: facts.record,
                    size: facts.size,
                    is_directory: facts.is_directory,
                    in_use: facts.in_use,
                    si_created: facts.si_created,
                    si_modified: facts.si_modified,
                    si_mft_modified: facts.si_mft_modified,
                    fn_created: facts.fn_created,
                    compact_os: facts.compact_os,
                    has_ads: facts.has_ads,
                    hard_links: facts.hard_links,
                    parent_created: facts.parent_created,
                });
            }
        })
        .expect("the walk completes");
        found.unwrap_or_else(|| panic!("{wanted} was not enumerated"))
    }

    #[test]
    fn standard_information_timestamps_reach_the_harvester() {
        let dropped = Times::at(1_773_522_298, 1_234_567);
        let deleted = Times::at(1_773_522_340, 7_654_321);

        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Users\\bob");
        let record = builder.file(dir, "dropper.exe", b"MZ payload", Presence::Deleted);
        builder.set_times(record, Times::all_at(dropped).record_changed_at(deleted));
        builder.file(dir, "quiet.exe", b"MZ", Presence::Live);
        let volume = builder.open();

        let facts = facts_for(&volume, "\\users\\bob\\dropper.exe");
        assert!(!facts.in_use, "the fixture asked for a deleted file");
        let at = |ticks: u64| mm_core::from_filetime(ticks).expect("a plausible date");
        assert_eq!(facts.si_created, Some(at(dropped)));
        assert_eq!(facts.si_modified, Some(at(dropped)));
        assert_eq!(facts.si_mft_modified, Some(at(deleted)), "the deletion time did not survive");
        assert_eq!(
            facts.fn_created,
            Some(at(dropped)),
            "$FN should mirror $SI unless asked otherwise"
        );

        let path = mm_core::NormalizedPath::parse("C:\\Users\\bob\\dropper.exe").unwrap();
        let observations = mm_harvest::filesystem::observations_for(&path, &facts);
        match &observations[0].kind {
            mm_core::ObservationKind::FileDeleted { when, .. } => {
                assert_eq!(*when, Some(at(deleted)))
            }
            other => panic!("expected FileDeleted, got {other:?}"),
        }
        assert!(mm_harvest::filesystem::timestomp_detail(&facts).is_none());

        let quiet = facts_for(&volume, "\\users\\bob\\quiet.exe");
        assert_eq!(quiet.si_created, None);
        assert_eq!(quiet.si_mft_modified, None);
    }

    #[test]
    fn a_stomped_file_is_detected_from_the_bytes_on_the_volume() {
        let forged = Times::at(1_640_995_200, 0);
        let real = Times::at(1_773_522_298, 1_234_567);

        let mut builder = Builder::new();
        let dir = builder.directories(ROOT_RECORD, "Windows\\Temp");
        let record = builder.file(dir, "svchost.exe", b"MZ not really", Presence::Live);
        builder.set_times(record, Times::all_at(forged));
        builder.set_file_name_times(record, Times::all_at(real));
        let volume = builder.open();

        let facts = facts_for(&volume, "\\windows\\temp\\svchost.exe");
        let detail = mm_harvest::filesystem::timestomp_detail(&facts)
            .expect("a four-year backdate on an exact second is the shape this check is for");
        assert!(detail.contains("T1070.006"), "{detail}");
    }

    #[test]
    fn multi_cluster_content_round_trips_exactly() {
        let content: Vec<u8> = (0..=255u8).cycle().take(CLUSTER * 3 + 17).collect();
        let mut builder = Builder::new();
        builder.file(ROOT_RECORD, "big.bin", &content, Presence::Live);
        let volume = builder.open();
        assert_eq!(volume.read("\\big.bin").unwrap(), content);
    }
}
