use std::io::{Read, Seek};

use chrono::{DateTime, Utc};
use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind, Result};
use mm_raw::Volume;
use ntfs_core::{
    parse_attributes, Attribute, AttributeBody, FileName, MftRecordHeader, StandardInformation,
};

use crate::motw;

const FALLBACK_RECORD_SIZE: u64 = 1024;

const MFT_RECORD: u64 = 0;

const FIRST_ORDINARY_RECORD: u64 = 16;

const MAX_RECORDS: u64 = 16_000_000;

const MAX_PATH_DEPTH: usize = 64;

const STALE_LINK_SANITY_SHARE: u64 = 2;

const TIMESTOMP_TOLERANCE_SECONDS: i64 = 3600;

#[derive(Clone)]
pub struct FileFacts {
    pub record: u64,
    pub size: u64,
    pub is_directory: bool,
    pub in_use: bool,
    pub si_created: Option<DateTime<Utc>>,
    pub si_modified: Option<DateTime<Utc>>,
    pub si_mft_modified: Option<DateTime<Utc>>,
    pub fn_created: Option<DateTime<Utc>>,
    pub has_ads: bool,
    pub hard_links: u16,
    pub compact_os: Option<mm_raw::wof::Backing>,
    pub parent_created: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub records_read: u64,
    pub files_seen: u64,
    pub deleted_seen: u64,
    pub unparsable: u64,
    pub records_skipped: u64,
    pub records_unreadable: u64,
    pub extension_records: u64,
    pub extra_links_seen: u64,
    pub unresolved: u64,
    pub unresolved_links: u64,
    pub unresolved_deleted: u64,
    pub unresolved_files_deleted: u64,
    pub orphaned_executables: u64,
    pub orphans_kept: u64,
    pub unresolved_directories: u64,
    pub parent_links_seen: u64,
    pub stale_parent_links: u64,
    pub sequence_check_applied: bool,
    pub junctions_seen: u64,
    pub junctions_followed: u64,
    pub names_recovered: u64,
    pub attribute_lists_seen: u64,
}

impl Stats {
    pub fn files_lost(&self) -> u64 {
        self.unresolved_live()
            .saturating_add(self.unparsable)
            .saturating_add(self.records_unreadable)
    }

    #[must_use]
    pub fn unresolved_live(&self) -> u64 {
        self.unresolved.saturating_sub(self.unresolved_files_deleted)
    }

    pub fn enumeration(&self) -> mm_core::Enumeration {
        mm_core::Enumeration::partial(self.files_seen, self.files_lost())
    }
}

struct ExtraLink {
    record: u32,
    parent: u32,
    parent_sequence: u16,
    name: Box<str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Junction {
    pub record: u64,
    pub at: Option<String>,
    pub target: Option<String>,
    pub substitute: String,
    pub tag: u32,
    pub refusal: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LostReason {
    OutOfRange,
    RecordUnreadable,
    NeverAllocated,
    Condemned,
    ExtensionRecord,
    Unparsable,
    NoNameAndNothingSpilled,
    NameNotRecovered,
    NotADirectory,
    StaleParentReference,
    CycleOrTooDeep,
}

impl LostReason {
    #[must_use]
    fn order(self) -> u8 {
        match self {
            LostReason::OutOfRange => 0,
            LostReason::RecordUnreadable => 1,
            LostReason::NeverAllocated => 2,
            LostReason::Condemned => 3,
            LostReason::ExtensionRecord => 4,
            LostReason::Unparsable => 5,
            LostReason::NoNameAndNothingSpilled => 6,
            LostReason::NameNotRecovered => 7,
            LostReason::NotADirectory => 8,
            LostReason::StaleParentReference => 9,
            LostReason::CycleOrTooDeep => 10,
        }
    }

    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            LostReason::OutOfRange => "the record number is past the end of the $MFT",
            LostReason::RecordUnreadable => "the record would not read off the volume",
            LostReason::NeverAllocated => "the record was never allocated ($MFT slack)",
            LostReason::Condemned => "chkdsk condemned the record (BAAD)",
            LostReason::ExtensionRecord => "the record holds another file's attributes",
            LostReason::Unparsable => "the record carries a FILE signature and would not decode",
            LostReason::NoNameAndNothingSpilled => {
                "the record has no $FILE_NAME and no $ATTRIBUTE_LIST to have moved one into"
            }
            LostReason::NameNotRecovered => {
                "the record's $FILE_NAME is not in its base record and following its \
                 $ATTRIBUTE_LIST did not find one"
            }
            LostReason::NotADirectory => "the record is not a directory",
            LostReason::StaleParentReference => {
                "that parent reference is stale: the record has been reallocated since the \
                 name was written, so the directory the name meant no longer exists"
            }
            LostReason::CycleOrTooDeep => "the parent chain cycles or is too deep to be real",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LostDirectory {
    pub parent: u32,
    pub parent_sequence: u16,
    pub files_lost: u64,
    pub broke_at: u32,
    pub reason: LostReason,
    pub broken_name: Option<String>,
    pub reached: String,
    pub stale: Option<(u16, u16)>,
}

const MAX_LOST_DIRECTORIES: usize = 32;

const MAX_JUNCTIONS: usize = 10_000;

#[derive(Clone, Debug, Default)]
pub struct WalkReport {
    pub stats: Stats,
    pub junctions: Vec<Junction>,
    pub lost: Vec<LostDirectory>,
    pub lost_reasons: Vec<(LostReason, u64, u64)>,
    pub orphans: Vec<OrphanedDeleted>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanedDeleted {
    pub record: u64,
    pub name: Box<str>,
    pub size: u64,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub const MAX_ORPHANS: usize = 8192;

struct IndexEntry {
    parent: u32,
    sequence: u16,
    parent_sequence: u16,
    name: Box<str>,
    is_directory: bool,
    created_filetime: u64,
}

pub fn enumerate<R: Read + Seek>(
    volume: &Volume<R>,
    on_file: &mut dyn FnMut(&NormalizedPath, &FileFacts),
) -> Result<Stats> {
    enumerate_with_progress(volume, on_file, &mut |_, _| {}).map(|report| report.stats)
}

#[must_use]
pub fn facts_for_record<R: Read + Seek>(volume: &Volume<R>, record: u64) -> Option<FileFacts> {
    let bytes = volume.fs().read_record(record).ok()?;
    let entry = parse_single(&bytes)?;
    if entry.is_directory {
        return None;
    }
    Some(FileFacts {
        record,
        size: entry.file_size,
        is_directory: false,
        in_use: entry.is_in_use,
        si_created: entry.si_created,
        si_modified: entry.si_modified,
        si_mft_modified: entry.si_mft_modified,
        fn_created: entry.fn_created,
        has_ads: entry.has_ads,
        hard_links: entry.hard_links,
        compact_os: entry.compact_os,
        parent_created: None,
    })
}

const PROGRESS_EVERY: u64 = 1024;

pub fn enumerate_with_progress<R: Read + Seek>(
    volume: &Volume<R>,
    on_file: &mut dyn FnMut(&NormalizedPath, &FileFacts),
    progress: &mut dyn FnMut(u64, u64),
) -> Result<WalkReport> {
    let record_count = estimate_record_count(volume)?;
    let mut stats = Stats::default();

    let mut index: Vec<Option<IndexEntry>> = Vec::new();
    index.resize_with(record_count as usize, || None);
    let mut facts: Vec<Option<FileFacts>> = Vec::new();
    facts.resize_with(record_count as usize, || None);
    let mut extra_links: Vec<ExtraLink> = Vec::new();
    let mut junction_records: Vec<(u64, mm_raw::reparse::Link)> = Vec::new();

    let steps = record_count.saturating_mul(2);
    for number in 0..record_count {
        if number % PROGRESS_EVERY == 0 {
            progress(number, steps);
        }
        let bytes = match volume.fs().read_record(number) {
            Ok(bytes) => bytes,
            Err(e) => {
                stats.records_skipped += 1;
                if matches!(e, ntfs_core::NtfsError::Io(_)) {
                    stats.records_unreadable += 1;
                }
                continue;
            }
        };
        stats.records_read += 1;

        if !carries_file_signature(&bytes) {
            stats.records_skipped += 1;
            continue;
        }
        if !is_base_record(&bytes) {
            stats.extension_records += 1;
            continue;
        }

        let entry = match parse_single(&bytes) {
            Some(named) if !named.has_attribute_list => named,
            Some(named) => match parse_spilled(volume, number, &bytes) {
                Some(merged) => merged,
                None => named,
            },
            None => match parse_spilled(volume, number, &bytes) {
                Some(entry) => {
                    stats.names_recovered += 1;
                    entry
                }
                None => {
                    stats.unparsable += 1;
                    continue;
                }
            },
        };
        if entry.has_attribute_list {
            stats.attribute_lists_seen += 1;
        }

        let parent = entry.parent_entry.min(u64::from(u32::MAX)) as u32;
        index[number as usize] = Some(IndexEntry {
            parent,
            sequence: entry.sequence,
            parent_sequence: entry.parent_sequence,
            name: entry.filename.clone().into_boxed_str(),
            is_directory: entry.is_directory,
            created_filetime: entry.si_created_filetime,
        });

        if entry.is_directory {
            if let Some(link) = entry.link {
                stats.junctions_seen += 1;
                if junction_records.len() < MAX_JUNCTIONS {
                    junction_records.push((number, link));
                }
            }
        }

        if number >= FIRST_ORDINARY_RECORD && !entry.is_directory {
            for (link_parent, link_sequence, name) in &entry.other_names {
                extra_links.push(ExtraLink {
                    record: number.min(u64::from(u32::MAX)) as u32,
                    parent: (*link_parent).min(u64::from(u32::MAX)) as u32,
                    parent_sequence: *link_sequence,
                    name: name.clone().into_boxed_str(),
                });
            }
        }

        if number >= FIRST_ORDINARY_RECORD && !entry.is_directory {
            facts[number as usize] = Some(FileFacts {
                record: number,
                size: entry.file_size,
                is_directory: entry.is_directory,
                in_use: entry.is_in_use,
                si_created: entry.si_created,
                si_modified: entry.si_modified,
                si_mft_modified: entry.si_mft_modified,
                fn_created: entry.fn_created,
                has_ads: entry.has_ads,
                hard_links: entry.hard_links,
                compact_os: entry.compact_os,
                parent_created: None,
            });
        }
    }

    for (number, slot) in index.iter().enumerate() {
        let Some(entry) = slot.as_ref() else { continue };
        if (number as u64) < FIRST_ORDINARY_RECORD {
            continue;
        }
        stats.parent_links_seen += 1;
        if is_stale(entry.parent_sequence, entry.parent, &index) {
            stats.stale_parent_links += 1;
        }
    }
    for link in &extra_links {
        stats.parent_links_seen += 1;
        if is_stale(link.parent_sequence, link.parent, &index) {
            stats.stale_parent_links += 1;
        }
    }
    stats.sequence_check_applied =
        stats.stale_parent_links.saturating_mul(STALE_LINK_SANITY_SHARE) <= stats.parent_links_seen;
    if !stats.sequence_check_applied {
        for slot in index.iter_mut().flatten() {
            slot.parent_sequence = 0;
        }
        for link in &mut extra_links {
            link.parent_sequence = 0;
        }
    }

    let mut resolved_dirs: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();
    let mut lost_by_parent: std::collections::HashMap<(u32, u16), u64> =
        std::collections::HashMap::new();
    let mut orphans: Vec<OrphanedDeleted> = Vec::new();
    let mut link_cursor = 0usize;
    for number in FIRST_ORDINARY_RECORD..record_count {
        if number % PROGRESS_EVERY == 0 {
            progress(record_count + number, steps);
        }
        while link_cursor < extra_links.len() && u64::from(extra_links[link_cursor].record) < number
        {
            link_cursor += 1;
        }
        let links_from = link_cursor;

        let Some(mut fact) = facts[number as usize].take() else { continue };

        if !fact.in_use {
            stats.deleted_seen += 1;
        }

        let mut placed = false;
        match resolve_path(number as u32, &index, &mut resolved_dirs) {
            Some(path) => {
                placed = true;
                fact.parent_created = index[number as usize]
                    .as_ref()
                    .and_then(|entry| index.get(entry.parent as usize))
                    .and_then(|slot| slot.as_ref())
                    .filter(|parent| parent.is_directory)
                    .and_then(|parent| mm_core::from_filetime(parent.created_filetime));

                stats.files_seen += 1;
                on_file(&path, &fact);
            }
            None => {
                stats.unresolved_links += 1;
                if !fact.in_use {
                    stats.unresolved_deleted += 1;
                }
                if let Some(entry) = index[number as usize].as_ref() {
                    *lost_by_parent.entry((entry.parent, entry.parent_sequence)).or_default() += 1;
                }
            }
        }

        let mut cursor = links_from;
        while cursor < extra_links.len() && u64::from(extra_links[cursor].record) == number {
            let link = &extra_links[cursor];
            cursor += 1;
            let Some(linked) = resolve_link(
                link.parent,
                link.parent_sequence,
                &link.name,
                &index,
                &mut resolved_dirs,
            ) else {
                stats.unresolved_links += 1;
                if !fact.in_use {
                    stats.unresolved_deleted += 1;
                }
                *lost_by_parent.entry((link.parent, link.parent_sequence)).or_default() += 1;
                continue;
            };
            placed = true;
            let mut linked_fact = fact.clone();
            linked_fact.parent_created = index
                .get(link.parent as usize)
                .and_then(|slot| slot.as_ref())
                .filter(|parent| parent.is_directory)
                .and_then(|parent| mm_core::from_filetime(parent.created_filetime));

            stats.files_seen += 1;
            stats.extra_links_seen += 1;
            on_file(&linked, &linked_fact);
        }

        if !placed {
            stats.unresolved += 1;
            if !fact.in_use {
                stats.unresolved_files_deleted += 1;
                if let Some(name) = index[number as usize].as_ref().map(|e| e.name.clone()) {
                    if mm_core::name_is_executable_extension(&name) {
                        stats.orphaned_executables += 1;
                        if orphans.len() < MAX_ORPHANS {
                            orphans.push(OrphanedDeleted {
                                record: number,
                                name: name.to_ascii_lowercase().into_boxed_str(),
                                size: fact.size,
                                deleted_at: fact.si_mft_modified,
                            });
                        }
                    }
                }
            }
        }
    }

    let junctions: Vec<Junction> = junction_records
        .into_iter()
        .map(|(record, link)| resolve_junction(record, &link, &index, &mut resolved_dirs))
        .collect();
    stats.junctions_followed = junctions.iter().filter(|j| j.target.is_some()).count() as u64;

    stats.unresolved_directories = lost_by_parent.len() as u64;
    let mut lost: Vec<LostDirectory> = lost_by_parent
        .into_iter()
        .map(|((parent, sequence), files_lost)| {
            explain_lost(volume, parent, sequence, files_lost, &index, &resolved_dirs)
        })
        .collect();
    lost.sort_by(|a, b| {
        b.files_lost
            .cmp(&a.files_lost)
            .then(a.parent.cmp(&b.parent))
            .then(a.parent_sequence.cmp(&b.parent_sequence))
    });
    let mut reason_totals: std::collections::HashMap<LostReason, (u64, u64)> =
        std::collections::HashMap::new();
    for place in &lost {
        let entry = reason_totals.entry(place.reason).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += place.files_lost;
    }
    let mut lost_reasons: Vec<(LostReason, u64, u64)> = reason_totals
        .into_iter()
        .map(|(reason, (places, files))| (reason, places, files))
        .collect();
    lost_reasons
        .sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)).then(a.0.order().cmp(&b.0.order())));

    lost.truncate(MAX_LOST_DIRECTORIES);

    progress(steps, steps);
    stats.orphans_kept = orphans.len() as u64;
    Ok(WalkReport { stats, junctions, lost, lost_reasons, orphans })
}

fn resolve_junction(
    record: u64,
    link: &mm_raw::reparse::Link,
    index: &[Option<IndexEntry>],
    cache: &mut std::collections::HashMap<u32, String>,
) -> Junction {
    let short = record.min(u64::from(u32::MAX)) as u32;
    let at = index
        .get(short as usize)
        .and_then(|slot| slot.as_ref())
        .filter(|entry| entry.is_directory)
        .and_then(|entry| resolve_directory(short, entry.sequence, index, cache, 0))
        .and_then(|raw| NormalizedPath::parse(&raw))
        .map(|path| path.key().to_string());

    let mut junction = Junction {
        record,
        at: at.clone(),
        target: None,
        substitute: link.substitute.clone(),
        tag: link.tag,
        refusal: None,
    };

    if link.names_a_volume() {
        junction.refusal = Some("it names a mounted volume, not a path on this one");
        return junction;
    }
    if link.names_a_remote_share() {
        junction.refusal = Some("it names a remote share");
        return junction;
    }

    let raw = if link.relative {
        let Some(here) = at.as_deref() else {
            junction.refusal = Some("it is relative and the link's own path is unknown");
            return junction;
        };
        let parent = here.rsplit_once('\\').map_or("\\", |(head, _)| head);
        format!("{}\\{}", if parent.is_empty() { "" } else { parent }, link.substitute)
    } else {
        link.substitute.clone()
    };

    let Some(target) = NormalizedPath::parse(&raw) else {
        junction.refusal = Some("the substitute name does not normalize to a path");
        return junction;
    };
    let key = target.key().to_string();

    if let Some(here) = at.as_deref() {
        if key == here {
            junction.refusal = Some("it points at itself");
            return junction;
        }
        if key.len() > here.len() && key.starts_with(here) && key.as_bytes()[here.len()] == b'\\' {
            junction.refusal = Some("it points into its own subtree");
            return junction;
        }
    } else {
        junction.refusal = Some("the junction's own path could not be reconstructed");
        return junction;
    }

    junction.target = Some(key);
    junction
}

fn explain_lost<R: Read + Seek>(
    volume: &Volume<R>,
    parent: u32,
    parent_sequence: u16,
    files_lost: u64,
    index: &[Option<IndexEntry>],
    cache: &std::collections::HashMap<u32, String>,
) -> LostDirectory {
    const ROOT_RECORD: u32 = 5;

    let mut current = parent;
    let mut expected = parent_sequence;
    for _ in 0..MAX_PATH_DEPTH {
        if current == ROOT_RECORD {
            break;
        }
        let slot = match index.get(current as usize) {
            None => {
                return lost_at(
                    parent,
                    parent_sequence,
                    files_lost,
                    current,
                    LostReason::OutOfRange,
                    None,
                    index,
                    cache,
                )
            }
            Some(slot) => slot,
        };
        let Some(entry) = slot.as_ref() else {
            let reason = diagnose(volume, u64::from(current));
            return lost_at(
                parent,
                parent_sequence,
                files_lost,
                current,
                reason,
                None,
                index,
                cache,
            );
        };
        if is_stale(expected, current, index) {
            return lost_at(
                parent,
                parent_sequence,
                files_lost,
                current,
                LostReason::StaleParentReference,
                Some((expected, entry.sequence)),
                index,
                cache,
            );
        }
        if let Some(reached) = cache.get(&current) {
            return LostDirectory {
                parent,
                parent_sequence,
                files_lost,
                broke_at: current,
                reason: LostReason::CycleOrTooDeep,
                broken_name: Some(entry.name.to_string()),
                reached: reached.clone(),
                stale: None,
            };
        }
        if !entry.is_directory {
            return lost_at(
                parent,
                parent_sequence,
                files_lost,
                current,
                LostReason::NotADirectory,
                None,
                index,
                cache,
            );
        }
        expected = entry.parent_sequence;
        current = entry.parent;
    }
    lost_at(
        parent,
        parent_sequence,
        files_lost,
        current,
        LostReason::CycleOrTooDeep,
        None,
        index,
        cache,
    )
}

fn diagnose<R: Read + Seek>(volume: &Volume<R>, record: u64) -> LostReason {
    let Ok(bytes) = volume.fs().read_record(record) else {
        return LostReason::RecordUnreadable;
    };
    match bytes.get(0..4) {
        Some(b"FILE") => {}
        Some(b"BAAD") => return LostReason::Condemned,
        _ => return LostReason::NeverAllocated,
    }
    let Ok(header) = MftRecordHeader::parse(&bytes) else { return LostReason::Unparsable };
    if !header.is_base_record() {
        return LostReason::ExtensionRecord;
    }
    let Ok(attributes) = parse_attributes(&bytes, header.first_attribute_offset as usize) else {
        return LostReason::Unparsable;
    };
    if attributes.iter().any(|a| a.type_code == ATTR_ATTRIBUTE_LIST) {
        return LostReason::NameNotRecovered;
    }
    LostReason::NoNameAndNothingSpilled
}

#[allow(clippy::too_many_arguments)]
fn lost_at(
    parent: u32,
    parent_sequence: u16,
    files_lost: u64,
    broke_at: u32,
    reason: LostReason,
    stale: Option<(u16, u16)>,
    index: &[Option<IndexEntry>],
    cache: &std::collections::HashMap<u32, String>,
) -> LostDirectory {
    let reached = index
        .get(broke_at as usize)
        .and_then(|slot| slot.as_ref())
        .and_then(|entry| cache.get(&entry.parent))
        .cloned()
        .unwrap_or_default();
    LostDirectory {
        parent,
        parent_sequence,
        files_lost,
        broke_at,
        reason,
        broken_name: index
            .get(broke_at as usize)
            .and_then(|slot| slot.as_ref())
            .map(|entry| entry.name.to_string()),
        reached,
        stale,
    }
}

struct RawRecord {
    filename: String,
    parent_entry: u64,
    parent_sequence: u16,
    sequence: u16,
    is_directory: bool,
    is_in_use: bool,
    file_size: u64,
    has_ads: bool,
    si_created: Option<DateTime<Utc>>,
    si_modified: Option<DateTime<Utc>>,
    si_mft_modified: Option<DateTime<Utc>>,
    fn_created: Option<DateTime<Utc>>,
    si_created_filetime: u64,
    hard_links: u16,
    compact_os: Option<mm_raw::wof::Backing>,
    link: Option<mm_raw::reparse::Link>,
    other_names: Vec<(u64, u16, String)>,
    has_attribute_list: bool,
}

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_REPARSE_POINT: u32 = 0xC0;

const NAMESPACE_DOS: u8 = 2;

fn carries_file_signature(bytes: &[u8]) -> bool {
    matches!(bytes.get(0..4), Some(b"FILE") | Some(b"BAAD"))
}

fn is_base_record(bytes: &[u8]) -> bool {
    MftRecordHeader::parse(bytes).is_ok_and(|header| header.is_base_record())
}

fn parse_single(bytes: &[u8]) -> Option<RawRecord> {
    let (mut record, attributes) = start_record(bytes)?;
    let mut names = NameChoice::new();
    absorb(&mut record, bytes, &attributes, &mut names);
    finish(record, names)
}

fn parse_spilled<R: Read + Seek>(
    volume: &Volume<R>,
    number: u64,
    bytes: &[u8],
) -> Option<RawRecord> {
    const WANTED: &[u32] = &[ATTR_FILE_NAME, ATTR_DATA, ATTR_REPARSE_POINT];

    let (mut record, attributes) = start_record(bytes)?;
    if !record.has_attribute_list {
        return None;
    }
    let mut names = NameChoice::new();
    absorb(&mut record, bytes, &attributes, &mut names);
    if !record.filename.is_empty() && !spilled_wanted(bytes, &attributes, number, WANTED) {
        return None;
    }

    for extension in volume.extension_records(number, WANTED).into_records() {
        let Ok(header) = MftRecordHeader::parse(&extension) else { continue };
        let Ok(attrs) = parse_attributes(&extension, header.first_attribute_offset as usize) else {
            continue;
        };
        absorb(&mut record, &extension, &attrs, &mut names);
    }

    finish(record, names)
}

fn spilled_wanted(bytes: &[u8], attributes: &[Attribute], number: u64, wanted: &[u32]) -> bool {
    let Some(list) = attributes.iter().find(|a| a.type_code == ATTR_ATTRIBUTE_LIST) else {
        return false;
    };
    let Some(content) = list.resident_content(bytes) else {
        return true;
    };
    let Ok(entries) = ntfs_core::parse_attribute_list(content) else {
        return true;
    };
    entries
        .iter()
        .any(|e| wanted.contains(&e.type_code) && e.base_reference.record_number != number)
}

fn start_record(bytes: &[u8]) -> Option<(RawRecord, Vec<Attribute>)> {
    let header = MftRecordHeader::parse(bytes).ok()?;
    if &header.signature != b"FILE" {
        return None;
    }
    if !header.is_base_record() {
        return None;
    }

    let attributes = parse_attributes(bytes, header.first_attribute_offset as usize).ok()?;
    let record = RawRecord {
        filename: String::new(),
        parent_entry: 0,
        parent_sequence: 0,
        sequence: header.sequence_number,
        is_directory: header.is_directory(),
        is_in_use: header.is_in_use(),
        file_size: 0,
        has_ads: false,
        si_created: None,
        si_modified: None,
        si_mft_modified: None,
        fn_created: None,
        si_created_filetime: 0,
        hard_links: header.hard_link_count,
        compact_os: None,
        link: None,
        other_names: Vec::new(),
        has_attribute_list: attributes.iter().any(|a| a.type_code == ATTR_ATTRIBUTE_LIST),
    };
    Some((record, attributes))
}

struct NameChoice {
    best_namespace: u8,
    links: Vec<(u64, u16, String, u8)>,
}

impl NameChoice {
    fn new() -> Self {
        NameChoice { best_namespace: u8::MAX, links: Vec::new() }
    }
}

fn absorb(record: &mut RawRecord, bytes: &[u8], attributes: &[Attribute], names: &mut NameChoice) {
    for attribute in attributes {
        match attribute.type_code {
            ATTR_STANDARD_INFORMATION => {
                if let Some(content) = attribute.resident_content(bytes) {
                    if let Ok(si) = StandardInformation::parse(content) {
                        record.si_created_filetime = si.created.0;
                        record.si_created = mm_core::from_filetime(si.created.0);
                        record.si_modified = mm_core::from_filetime(si.modified.0);
                        record.si_mft_modified = mm_core::from_filetime(si.mft_modified.0);
                    }
                }
            }
            ATTR_FILE_NAME => {
                if let Some(content) = attribute.resident_content(bytes) {
                    if let Ok(fname) = FileName::parse(content) {
                        let better = fname.namespace != NAMESPACE_DOS
                            && (record.filename.is_empty()
                                || fname.namespace < names.best_namespace);
                        if better || record.filename.is_empty() {
                            names.best_namespace = fname.namespace;
                            record.filename = fname.name.clone();
                            record.parent_entry = fname.parent.record_number;
                            record.parent_sequence = fname.parent.sequence;
                            record.fn_created = mm_core::from_filetime(fname.created.0);
                        }
                        if fname.namespace != NAMESPACE_DOS {
                            names.links.push((
                                fname.parent.record_number,
                                fname.parent.sequence,
                                fname.name,
                                fname.namespace,
                            ));
                        }
                    }
                }
            }
            ATTR_DATA => {
                if attribute.name.is_some() {
                    record.has_ads = true;
                    continue;
                }
                let size = match &attribute.body {
                    AttributeBody::Resident { content_length, .. } => u64::from(*content_length),
                    AttributeBody::NonResident { real_size, .. } => *real_size,
                };
                record.file_size = record.file_size.max(size);
            }
            ATTR_REPARSE_POINT => {
                if let Some(content) = attribute.resident_content(bytes) {
                    if let Some(backing) = mm_raw::wof::parse_reparse(content) {
                        record.compact_os = Some(backing);
                    }
                    if let Some(link) = mm_raw::reparse::parse(content) {
                        record.link = Some(link);
                    }
                }
            }
            _ => {}
        }
    }
}

fn finish(mut record: RawRecord, names: NameChoice) -> Option<RawRecord> {
    if record.filename.is_empty() {
        return None;
    }

    let primary = (record.parent_entry, record.parent_sequence, record.filename.as_str());
    let mut seen: Vec<(u64, u16, String)> = Vec::new();
    for (parent, sequence, name, _namespace) in names.links {
        if (parent, sequence, name.as_str()) == primary {
            continue;
        }
        if seen.iter().any(|(p, q, n)| *p == parent && *q == sequence && n == &name) {
            continue;
        }
        seen.push((parent, sequence, name));
    }
    record.other_names = seen;

    Some(record)
}

fn record_size<R: Read + Seek>(volume: &Volume<R>) -> u64 {
    let declared = volume.fs().boot().mft_record_size;
    if (256..=65_536).contains(&declared) {
        declared
    } else {
        FALLBACK_RECORD_SIZE
    }
}

fn is_stale(expected: u16, parent: u32, index: &[Option<IndexEntry>]) -> bool {
    if expected == 0 {
        return false;
    }
    index
        .get(parent as usize)
        .and_then(|slot| slot.as_ref())
        .is_some_and(|entry| entry.sequence != expected)
}

fn resolve_path(
    record: u32,
    index: &[Option<IndexEntry>],
    cache: &mut std::collections::HashMap<u32, String>,
) -> Option<NormalizedPath> {
    let entry = index.get(record as usize)?.as_ref()?;
    let parent_path = resolve_directory(entry.parent, entry.parent_sequence, index, cache, 0)?;

    let full = if parent_path == "\\" {
        format!("\\{}", entry.name)
    } else {
        format!("{}\\{}", parent_path, entry.name)
    };
    NormalizedPath::parse(&full)
}

fn resolve_link(
    parent: u32,
    parent_sequence: u16,
    name: &str,
    index: &[Option<IndexEntry>],
    cache: &mut std::collections::HashMap<u32, String>,
) -> Option<NormalizedPath> {
    let parent_path = resolve_directory(parent, parent_sequence, index, cache, 0)?;
    let full =
        if parent_path == "\\" { format!("\\{name}") } else { format!("{parent_path}\\{name}") };
    NormalizedPath::parse(&full)
}

fn resolve_directory(
    record: u32,
    expected_sequence: u16,
    index: &[Option<IndexEntry>],
    cache: &mut std::collections::HashMap<u32, String>,
    depth: usize,
) -> Option<String> {
    const ROOT_RECORD: u32 = 5;
    if record == ROOT_RECORD {
        return Some("\\".to_string());
    }
    if depth >= MAX_PATH_DEPTH {
        return None;
    }
    if is_stale(expected_sequence, record, index) {
        return None;
    }
    if let Some(hit) = cache.get(&record) {
        return Some(hit.clone());
    }

    let entry = index.get(record as usize)?.as_ref()?;
    if !entry.is_directory {
        return None;
    }
    let parent = resolve_directory(entry.parent, entry.parent_sequence, index, cache, depth + 1)?;
    let path = if parent == "\\" {
        format!("\\{}", entry.name)
    } else {
        format!("{}\\{}", parent, entry.name)
    };
    cache.insert(record, path.clone());
    Some(path)
}

pub fn observations_for(path: &NormalizedPath, fact: &FileFacts) -> Vec<Observation> {
    let mut out = Vec::new();
    if fact.in_use {
        out.push(Observation::about_path(
            ArtifactSource::Mft,
            path.clone(),
            ObservationKind::FileExists {
                size: fact.size,
                created: fact.si_created,
                modified: fact.si_modified,
                mft_modified: fact.si_mft_modified,
                record: Some(fact.record),
            },
        ));
    } else {
        out.push(Observation::about_path(
            ArtifactSource::Mft,
            path.clone(),
            ObservationKind::FileDeleted {
                when: fact.si_mft_modified,
                record: Some(fact.record),
                sequence: None,
            },
        ));
    }

    if let Some(detail) = timestomp_detail(fact) {
        out.push(Observation::about_path(
            ArtifactSource::Mft,
            path.clone(),
            ObservationKind::PeAnomaly { detail },
        ));
    }

    if let Some(backing) = fact.compact_os {
        out.push(Observation::about_path(
            ArtifactSource::Mft,
            path.clone(),
            ObservationKind::CompactOsCompressed {
                algorithm: backing.algorithm_name().to_string(),
                readable: backing.chunk_size().is_some(),
            },
        ));
    }

    out
}

pub fn motw_observations<R: Read + Seek>(
    volume: &Volume<R>,
    path: &NormalizedPath,
    fact: &FileFacts,
) -> Vec<Observation> {
    if !fact.has_ads {
        return Vec::new();
    }
    let Ok(bytes) = volume.read_named_stream(path.key(), motw::STREAM_NAME, motw::MAX_STREAM_BYTES)
    else {
        return Vec::new();
    };
    motw::harvest(&bytes, path)
}

pub fn timestomp_detail(fact: &FileFacts) -> Option<String> {
    let si = fact.si_created?;
    let fnc = fact.fn_created?;
    let changed = fact.si_mft_modified?;

    let skew = (fnc - si).num_seconds();
    if skew <= TIMESTOMP_TOLERANCE_SECONDS {
        return None;
    }

    if changed.timestamp_subsec_nanos() != 0 {
        return None;
    }

    Some(format!(
        "$STANDARD_INFORMATION creation time ({}) predates $FILE_NAME ({}) by {} hours, and the MFT-entry-modified time ({}) lands on an exact second — a field the filesystem writes and SetFileTime cannot reach (T1070.006)",
        mm_core::filetime::format(si),
        mm_core::filetime::format(fnc),
        skew / 3600,
        mm_core::filetime::format(changed)
    ))
}

fn estimate_record_count<R: Read + Seek>(volume: &Volume<R>) -> Result<u64> {
    let cluster = volume.cluster_size().max(1);

    let runs = volume
        .fs()
        .runs_by_record(MFT_RECORD, None)
        .map_err(|e| mm_core::Error::parse(format!("reading the $MFT's own run list: {e}")))?;

    let clusters: u64 = runs.iter().map(|r| r.length).sum();
    let count = clusters.saturating_mul(cluster) / record_size(volume);

    if count == 0 {
        return Err(mm_core::Error::parse("the $MFT reports a size of zero records"));
    }
    Ok(count.min(MAX_RECORDS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(parent: u32, name: &str) -> Option<IndexEntry> {
        Some(entry(parent, 0, name, true))
    }

    fn file(parent: u32, name: &str) -> Option<IndexEntry> {
        Some(entry(parent, 0, name, false))
    }

    fn entry(parent: u32, parent_sequence: u16, name: &str, is_directory: bool) -> IndexEntry {
        IndexEntry {
            parent,
            sequence: 1,
            parent_sequence,
            name: name.into(),
            is_directory,
            created_filetime: 0,
        }
    }

    fn reallocated(entry: Option<IndexEntry>, sequence: u16) -> Option<IndexEntry> {
        entry.map(|e| IndexEntry { sequence, ..e })
    }

    fn sample_index() -> Vec<Option<IndexEntry>> {
        let mut index: Vec<Option<IndexEntry>> = (0..16).map(|_| None).collect();
        index[5] = dir(5, ".");
        index[6] = dir(5, "Users");
        index[7] = dir(6, "bob");
        index[8] = file(7, "x.exe");
        index
    }

    fn record_with_names(links: &[(u64, &str, u8)], is_directory: bool) -> Vec<u8> {
        const RECORD: usize = 1024;
        const FIRST_ATTRIBUTE: usize = 0x38;
        let mut buf = vec![0u8; RECORD];
        buf[0..4].copy_from_slice(b"FILE");
        buf[0x12..0x14].copy_from_slice(&(links.len() as u16).to_le_bytes());
        buf[0x14..0x16].copy_from_slice(&(FIRST_ATTRIBUTE as u16).to_le_bytes());
        let flags: u16 = if is_directory { 0x0003 } else { 0x0001 };
        buf[0x16..0x18].copy_from_slice(&flags.to_le_bytes());

        let mut pos = FIRST_ATTRIBUTE;
        for (id, (parent, name, namespace)) in links.iter().enumerate() {
            let units: Vec<u16> = name.encode_utf16().collect();
            let content_len = 0x42 + units.len() * 2;
            let total = (0x18 + content_len).next_multiple_of(8);

            buf[pos..pos + 4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&(total as u32).to_le_bytes());
            buf[pos + 0x0E..pos + 0x10].copy_from_slice(&(id as u16).to_le_bytes());
            buf[pos + 0x10..pos + 0x14].copy_from_slice(&(content_len as u32).to_le_bytes());
            buf[pos + 0x14..pos + 0x16].copy_from_slice(&0x18u16.to_le_bytes());

            let c = pos + 0x18;
            buf[c..c + 8].copy_from_slice(&parent.to_le_bytes());
            buf[c + 0x40] = units.len() as u8;
            buf[c + 0x41] = *namespace;
            for (i, unit) in units.iter().enumerate() {
                buf[c + 0x42 + i * 2..c + 0x44 + i * 2].copy_from_slice(&unit.to_le_bytes());
            }
            pos += total;
        }
        buf[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        buf
    }

    #[test]
    fn every_hard_link_of_a_record_is_kept_and_the_dos_alias_is_not() {
        const WIN32: u8 = 1;
        const WIN32_AND_DOS: u8 = 3;
        let bytes = record_with_names(
            &[
                (7, "driver.sys", WIN32),
                (7, "DRIVER~1.SYS", NAMESPACE_DOS),
                (9, "driver.sys", WIN32),
            ],
            false,
        );
        let parsed = parse_single(&bytes).expect("record parses");
        assert_eq!(parsed.filename, "driver.sys");
        assert_eq!(parsed.parent_entry, 7);
        assert_eq!(parsed.hard_links, 3);
        assert_eq!(parsed.other_names, vec![(9u64, 0u16, "driver.sys".to_string())]);

        let single = parse_single(&record_with_names(&[(7, "x.exe", WIN32_AND_DOS)], false))
            .expect("record parses");
        assert!(single.other_names.is_empty());
    }

    #[test]
    fn a_record_with_only_a_dos_name_still_yields_it() {
        let parsed = parse_single(&record_with_names(&[(7, "PROGRA~1", NAMESPACE_DOS)], true))
            .expect("record parses");
        assert_eq!(parsed.filename, "PROGRA~1");
        assert!(parsed.other_names.is_empty());
    }

    #[test]
    fn a_repeated_link_is_only_counted_once() {
        let parsed = parse_single(&record_with_names(
            &[(7, "x.exe", 1), (7, "x.exe", 3), (9, "x.exe", 1), (9, "x.exe", 1)],
            false,
        ))
        .expect("record parses");
        assert_eq!(parsed.other_names, vec![(9u64, 0u16, "x.exe".to_string())]);
    }

    #[test]
    fn a_second_link_resolves_under_its_own_directory() {
        let mut index = sample_index();
        index[9] = dir(5, "Windows");
        index[10] = dir(9, "System32");
        let mut cache = std::collections::HashMap::new();
        let linked = resolve_link(10, 0, "driver.sys", &index, &mut cache).unwrap();
        assert_eq!(linked.key(), "\\windows\\system32\\driver.sys");
        assert!(resolve_link(4000, 0, "driver.sys", &index, &mut cache).is_none());
    }

    #[test]
    fn paths_resolve_through_the_parent_chain() {
        let index = sample_index();
        let mut cache = std::collections::HashMap::new();
        let path = resolve_path(8, &index, &mut cache).unwrap();
        assert_eq!(path.key(), "\\users\\bob\\x.exe");
    }

    #[test]
    fn files_directly_in_the_root_resolve() {
        let mut index = sample_index();
        index[9] = file(5, "payload.exe");
        let mut cache = std::collections::HashMap::new();
        assert_eq!(resolve_path(9, &index, &mut cache).unwrap().key(), "\\payload.exe");
    }

    #[test]
    fn directory_paths_are_cached_after_first_resolution() {
        let index = sample_index();
        let mut cache = std::collections::HashMap::new();
        resolve_path(8, &index, &mut cache).unwrap();
        assert_eq!(cache.get(&7).map(String::as_str), Some("\\Users\\bob"));
        assert_eq!(cache.get(&6).map(String::as_str), Some("\\Users"));

        let mut cold = std::collections::HashMap::new();
        assert_eq!(
            resolve_path(8, &index, &mut cold).unwrap().key(),
            resolve_path(8, &index, &mut cache).unwrap().key()
        );
    }

    #[test]
    fn a_parent_cycle_terminates_instead_of_hanging() {
        let mut index: Vec<Option<IndexEntry>> = (0..16).map(|_| None).collect();
        index[5] = dir(5, ".");
        index[6] = dir(7, "a");
        index[7] = dir(6, "b");
        index[8] = file(6, "x.exe");

        let mut cache = std::collections::HashMap::new();
        assert!(resolve_path(8, &index, &mut cache).is_none());
    }

    #[test]
    fn a_missing_or_out_of_range_parent_yields_no_path() {
        let mut index = sample_index();
        index[7] = None;
        let mut cache = std::collections::HashMap::new();
        assert!(resolve_path(8, &index, &mut cache).is_none());

        let index = sample_index();
        let mut cache = std::collections::HashMap::new();
        assert!(resolve_path(9999, &index, &mut cache).is_none());
    }

    #[test]
    fn a_file_is_never_treated_as_a_directory() {
        let mut index = sample_index();
        index[9] = file(8, "child.exe");
        let mut cache = std::collections::HashMap::new();
        assert!(resolve_path(9, &index, &mut cache).is_none());
    }

    #[test]
    fn a_stale_parent_reference_does_not_borrow_the_new_occupants_path() {
        let mut index = sample_index();
        index[7] = reallocated(dir(6, "Temp"), 4);
        index[6] = reallocated(dir(5, "Windows"), 1);
        index[8] = Some(entry(7, 3, "x.exe", false));

        let mut cache = std::collections::HashMap::new();
        assert!(
            resolve_path(8, &index, &mut cache).is_none(),
            "a file was placed under a directory that did not exist when its name was written"
        );

        index[8] = Some(entry(7, 4, "x.exe", false));
        let mut cache = std::collections::HashMap::new();
        assert_eq!(resolve_path(8, &index, &mut cache).unwrap().key(), "\\windows\\temp\\x.exe");
    }

    #[test]
    fn a_stale_reference_is_refused_even_after_the_directory_is_cached() {
        let mut index = sample_index();
        index[6] = reallocated(dir(5, "Windows"), 1);
        index[7] = reallocated(dir(6, "Temp"), 4);
        index[8] = Some(entry(7, 4, "live.exe", false));
        index[9] = Some(entry(7, 3, "leftover.exe", false));

        let mut cache = std::collections::HashMap::new();
        assert_eq!(resolve_path(8, &index, &mut cache).unwrap().key(), "\\windows\\temp\\live.exe");
        assert!(cache.contains_key(&7), "the fixture must have warmed the cache");
        assert!(resolve_path(9, &index, &mut cache).is_none());
    }

    #[test]
    fn a_whole_subtree_below_a_stale_reference_is_refused() {
        let mut index = sample_index();
        index[6] = reallocated(dir(5, "Windows"), 1);
        index[7] = reallocated(dir(6, "Temp"), 4);
        index[8] = Some(entry(7, 3, "old-subdir", true));
        index[9] = Some(entry(8, 1, "deep.exe", false));

        let mut cache = std::collections::HashMap::new();
        assert!(resolve_path(9, &index, &mut cache).is_none());
    }

    #[test]
    fn a_reference_stating_no_sequence_is_taken_as_written() {
        let mut index = sample_index();
        index[7] = reallocated(dir(6, "bob"), 9);
        index[8] = Some(entry(7, 0, "x.exe", false));
        let mut cache = std::collections::HashMap::new();
        assert_eq!(resolve_path(8, &index, &mut cache).unwrap().key(), "\\users\\bob\\x.exe");
    }

    #[test]
    fn staleness_is_only_claimed_where_both_sequences_are_known() {
        let index = sample_index();
        assert!(!is_stale(3, 4000, &index), "out of range is not stale");
        assert!(!is_stale(3, 4, &index), "an unindexed record is not stale");
        assert!(!is_stale(0, 7, &index), "no expectation is not stale");
    }

    fn facts_with(si: Option<DateTime<Utc>>, fnc: Option<DateTime<Utc>>) -> FileFacts {
        FileFacts {
            record: 100,
            size: 1024,
            is_directory: false,
            in_use: true,
            si_created: si,
            si_modified: si,
            si_mft_modified: si,
            fn_created: fnc,
            compact_os: None,
            has_ads: false,
            hard_links: 1,
            parent_created: None,
        }
    }

    fn at(secs: i64) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(secs, 1_234_567)
    }

    fn at_exact_second(secs: i64) -> Option<DateTime<Utc>> {
        DateTime::from_timestamp(secs, 0)
    }

    #[test]
    fn a_backdated_si_creation_time_on_an_exact_second_is_detected() {
        let f = facts_with(at_exact_second(1_600_000_000), at(1_704_067_200));
        let detail = timestomp_detail(&f).expect("should detect");
        assert!(detail.contains("T1070.006"));
    }

    #[test]
    fn ordinary_installed_software_is_not_accused() {
        let f = facts_with(at(1_751_330_608), at(1_755_456_058));
        assert!(timestomp_detail(&f).is_none(), "an installed file was reported as timestomped");
    }

    #[test]
    fn natural_skew_is_not_reported_as_timestomping() {
        assert!(timestomp_detail(&facts_with(at(1_704_067_200), at(1_704_067_200))).is_none());
        assert!(timestomp_detail(&facts_with(at(1_704_067_200), at(1_704_067_201))).is_none());
        assert!(timestomp_detail(&facts_with(at(1_704_067_200), at(1_704_070_700))).is_none());
        assert!(timestomp_detail(&facts_with(at_exact_second(1_704_067_200), at(1_704_070_700)))
            .is_none());
    }

    #[test]
    fn a_later_si_time_is_not_timestomping() {
        assert!(timestomp_detail(&facts_with(at(1_704_067_200), at(1_600_000_000))).is_none());
        assert!(timestomp_detail(&facts_with(at_exact_second(1_704_067_200), at(1_600_000_000)))
            .is_none());
    }

    #[test]
    fn missing_timestamps_never_produce_a_finding() {
        assert!(timestomp_detail(&facts_with(None, at(1_704_067_200))).is_none());
        assert!(timestomp_detail(&facts_with(at(1_704_067_200), None)).is_none());
        assert!(timestomp_detail(&facts_with(None, None)).is_none());
    }

    #[test]
    fn existing_and_deleted_files_emit_different_observations() {
        let path = NormalizedPath::parse("C:\\Users\\bob\\x.exe").unwrap();
        let mut out;

        let mut present = facts_with(at(1_704_067_200), at(1_704_067_200));
        present.in_use = true;
        out = observations_for(&path, &present);
        assert!(matches!(out[0].kind, ObservationKind::FileExists { .. }));

        let mut gone = facts_with(at(1_704_067_200), at(1_704_067_200));
        gone.in_use = false;
        out = observations_for(&path, &gone);
        assert!(matches!(out[0].kind, ObservationKind::FileDeleted { .. }));
        assert!(
            !out.iter().any(|o| matches!(o.kind, ObservationKind::FileExists { .. })),
            "a free record must never claim the file is on the volume: {out:?}"
        );
    }

    #[test]
    fn junk_records_are_rejected_cleanly() {
        assert!(parse_single(&[]).is_none());
        assert!(parse_single(&[0u8; 1024]).is_none());
        assert!(parse_single(&[0xFFu8; 512]).is_none());
        let mut almost = vec![0u8; 1024];
        almost[..4].copy_from_slice(b"BAAD");
        assert!(parse_single(&almost).is_none());
    }
}
