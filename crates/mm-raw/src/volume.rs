use std::io::{Read, Seek, SeekFrom};

use mm_core::{Error, Result};
use ntfs_core::{
    parse_attributes, Attribute, AttributeBody, IndexEntry, MftRecordHeader, NtfsFs, Run,
};

use crate::classify::{classify, VolumeKind};
use crate::index::InUse;
use crate::shared::SharedReader;
use crate::slack;
use crate::slack::{Bounds, Slack, SweepStats};
use crate::wof;

const WINDOWS_MARKERS: &[&str] =
    &["\\Windows\\System32\\config\\SYSTEM", "\\Windows\\System32\\ntoskrnl.exe"];

const ROOT_RECORD: u64 = 5;
pub const LOG_FILE: &str = "\\$LogFile";
const NAMESPACE_DOS: u8 = 2;

pub struct Volume<R: Read + Seek> {
    fs: NtfsFs<SharedReader<R>>,
    raw: SharedReader<R>,
    kind: VolumeKind,
}

enum WofLookup {
    NotBacked,
    Backed(wof::Backing, u64),
    LengthUnknown(wof::Backing),
    Unaccounted,
}

const UNACCOUNTED: &str = "this file's $ATTRIBUTE_LIST names records that do not belong to \
     it, or more of them than any file has, so some attribute of it is unaccounted for and \
     its bytes cannot be established";

#[must_use]
pub fn describes_an_unaccounted_attribute_list(message: &str) -> bool {
    message.contains("$ATTRIBUTE_LIST names records")
        || message.contains("more of them than any file has")
}

#[derive(Clone, Debug, Default)]
pub struct Spill {
    records: Vec<Vec<u8>>,
    refused: u32,
}

impl Spill {
    #[must_use]
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    #[must_use]
    pub fn into_records(self) -> Vec<Vec<u8>> {
        self.records
    }

    #[must_use]
    pub fn refused(&self) -> u32 {
        self.refused
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.refused == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub name: String,
    pub record: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordIdentity {
    pub name: String,
    pub in_use: bool,
    pub size: u64,
}

impl<R: Read + Seek> Volume<R> {
    pub fn open(reader: R, name: &str) -> Result<Self> {
        let raw = SharedReader::new(reader);

        let mut boot = raw.clone();
        let mut sector = [0u8; 512];
        boot.seek(SeekFrom::Start(0)).map_err(|e| Error::io(format!("seeking {name}"), e))?;
        boot.read_exact(&mut sector)
            .map_err(|e| Error::io(format!("reading boot sector of {name}"), e))?;

        let kind = classify(&sector);
        match kind {
            VolumeKind::Ntfs => {}
            VolumeKind::BitLocker => return Err(Error::VolumeLocked(name.to_string())),
            other => {
                return Err(Error::parse(format!("{name} is {}, not NTFS", other.label())));
            }
        }

        let fs = NtfsFs::open(raw.clone())
            .map_err(|e| Error::parse(format!("opening NTFS on {name}: {e}")))?;

        Ok(Volume { fs, raw, kind })
    }

    pub fn kind(&self) -> VolumeKind {
        self.kind
    }

    pub fn cluster_size(&self) -> u64 {
        self.fs.boot().cluster_size()
    }

    pub fn total_clusters(&self) -> u64 {
        let boot = self.fs.boot();
        let per_cluster = u64::from(boot.sectors_per_cluster);
        if per_cluster == 0 {
            return 0;
        }
        boot.total_sectors / per_cluster
    }

    pub fn read_clusters(&self, lcn: u64, buf: &mut [u8]) -> Result<()> {
        let cluster_size = self.cluster_size();
        if cluster_size == 0 {
            return Err(Error::parse("this volume declares a zero-byte cluster".to_string()));
        }
        let total = self.total_clusters();
        let wanted = (buf.len() as u64).div_ceil(cluster_size);
        let end = lcn.checked_add(wanted).ok_or_else(|| {
            Error::parse(format!("a cluster read at {lcn} for {wanted} clusters overflows"))
        })?;
        if end > total {
            return Err(Error::parse(format!(
                "a cluster read at {lcn} for {wanted} cluster(s) runs past the {total} clusters                  this volume declares"
            )));
        }
        let offset = lcn.checked_mul(cluster_size).ok_or_else(|| {
            Error::parse(format!("cluster {lcn} is past the end of an addressable volume"))
        })?;
        let mut reader = self.raw.clone();
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| Error::io(format!("seeking to cluster {lcn}"), e))?;
        reader
            .read_exact(buf)
            .map_err(|e| Error::io(format!("reading {} bytes at cluster {lcn}", buf.len()), e))
    }

    pub fn serial(&self) -> u64 {
        self.fs.boot().volume_serial
    }

    pub fn resolve(&self, path: &str) -> Option<u64> {
        let mut current = ROOT_RECORD;
        for component in path.split(['\\', '/']).filter(|c| !c.is_empty()) {
            let record = self.index_record(current)?;
            let entries = match self.directory_entries(&record) {
                Ok(entries) => entries,
                Err(e) => {
                    log::warn!("resolving {path}: {e}");
                    return None;
                }
            };

            let folded = component.to_lowercase();
            current = entries.iter().find_map(|e| {
                let name = e.file_name.as_ref()?;
                let matches = name.name.to_lowercase() == folded
                    || (name.namespace == NAMESPACE_DOS
                        && name.name.eq_ignore_ascii_case(component));
                matches.then_some(e.file_reference.record_number)
            })?;
        }
        Some(current)
    }

    fn index_record(&self, record_number: u64) -> Option<Vec<u8>> {
        const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
        const MAX_CANDIDATES: usize = 8;

        let base = self.fs.read_record(record_number).ok()?;
        let (_, base_attrs) = parsed_record(&base)?;

        let Some(list) = base_attrs.iter().find(|a| a.type_code == ATTR_ATTRIBUTE_LIST) else {
            return base_attrs.iter().any(|a| a.type_code == ATTR_INDEX_ROOT).then_some(base);
        };

        let content = self.attribute_value(&base, list, MAX_ATTRIBUTE_LIST_BYTES)?;
        let entries = ntfs_core::parse_attribute_list(&content).ok()?;

        let mut index = IndexPieces::default();
        if index.collect(&base, &base_attrs).is_none() {
            log::warn!(
                "record {record_number}: index attributes in the base record could not be read,                  so the directory is refused rather than listed short"
            );
            return None;
        }

        let mut visited: Vec<u64> = Vec::new();
        for entry in entries
            .iter()
            .filter(|e| e.type_code == ATTR_INDEX_ROOT || e.type_code == ATTR_INDEX_ALLOCATION)
        {
            let number = entry.base_reference.record_number;
            if number == record_number || visited.contains(&number) {
                continue;
            }
            if visited.len() == MAX_CANDIDATES {
                break;
            }
            visited.push(number);

            let Ok(record) = self.fs.read_record(number) else { continue };
            let Some((header, attrs)) = parsed_record(&record) else { continue };
            if !extends(&header, record_number) {
                continue;
            }
            if index.collect(&record, &attrs).is_none() {
                log::warn!(
                    "record {record_number}: index attributes in extension record {number} could                      not be read, so the directory is refused rather than listed short"
                );
                return None;
            }
        }

        let assembled = index.assemble(&base, self.fs.boot().cluster_size());
        if assembled.is_none() {
            log::warn!(
                "record {record_number}: its index attributes do not assemble into one index, so                  the directory is refused rather than listed short"
            );
        }
        assembled
    }

    pub fn directory_entries(&self, record: &[u8]) -> Result<Vec<IndexEntry>> {
        let (_, attributes) = parsed_record(record)
            .ok_or_else(|| Error::parse("this directory record does not parse".to_string()))?;

        let root_attribute =
            attributes.iter().find(|a| a.type_code == ATTR_INDEX_ROOT).ok_or_else(|| {
                Error::parse("not a directory: record has no $INDEX_ROOT".to_string())
            })?;
        let root_content = root_attribute
            .resident_content(record)
            .ok_or_else(|| Error::parse("$INDEX_ROOT content out of bounds".to_string()))?;
        let root = ntfs_core::IndexRoot::parse(root_content)
            .map_err(|e| Error::parse(format!("reading $INDEX_ROOT: {e}")))?;

        let mut entries: Vec<IndexEntry> =
            root.entries.into_iter().filter(|e| e.file_name.is_some()).collect();

        let allocation = attributes.iter().find(|a| a.type_code == ATTR_INDEX_ALLOCATION);

        if !root.is_large {
            let Some(_) = allocation else { return Ok(entries) };
            let Some(bits) = self.index_bitmap(record, &attributes) else {
                return Err(Error::parse(
                    "this directory lists short: its $INDEX_ROOT says it has no index buffers \
                     while it still carries an $INDEX_ALLOCATION, and it has no readable $I30 \
                     $BITMAP to say whether any of them is in use"
                        .to_string(),
                ));
            };
            if bits.iter().any(|byte| *byte != 0) {
                return Err(Error::parse(
                    "this directory lists short: its $INDEX_ROOT says it has no index buffers \
                     and its $I30 $BITMAP says at least one is in use"
                        .to_string(),
                ));
            }
            return Ok(entries);
        }

        let allocation = allocation.ok_or_else(|| {
            Error::parse(
                "the $INDEX_ROOT says this directory has index buffers and no \
                     $INDEX_ALLOCATION could be found for it"
                    .to_string(),
            )
        })?;

        let value = self.attribute_value(record, allocation, MAX_INDEX_BYTES).ok_or_else(|| {
            Error::parse("the $INDEX_ALLOCATION of this directory could not be read".to_string())
        })?;

        if let AttributeBody::NonResident { real_size, .. } = allocation.body {
            if (value.len() as u64) < real_size {
                return Err(Error::parse(format!(
                    "this directory lists short: its $INDEX_ALLOCATION declares {real_size} bytes \
                     and {} could be read",
                    value.len()
                )));
            }
        }

        let boot = self.fs.boot();
        let index_record_size = boot.index_record_size as usize;
        if index_record_size < 4 {
            return Err(Error::parse(format!(
                "the boot sector declares a {index_record_size}-byte index record"
            )));
        }

        let mut read_back = vec![false; value.len() / index_record_size];
        for (buffer, ok) in read_back.iter_mut().enumerate() {
            let at = buffer * index_record_size;
            let window = &value[at..at + index_record_size];
            if &window[..4] != b"INDX" {
                continue;
            }
            let mut owned = window.to_vec();
            let parsed = ntfs_core::parse_index_buffer(
                &mut owned,
                index_record_size,
                boot.bytes_per_sector as usize,
            )
            .map_err(|e| Error::parse(format!("reading INDX buffer {buffer}: {e}")))?;
            *ok = true;
            entries.extend(parsed.into_iter().filter(|e| e.file_name.is_some()));
        }

        let bitmap = self.index_bitmap(record, &attributes);

        if let Some(why) = crate::index::incompleteness(&read_back, bitmap.as_deref().map(InUse)) {
            return Err(Error::parse(format!("this directory lists short: {why}")));
        }

        Ok(entries)
    }

    fn index_bitmap(&self, record: &[u8], attributes: &[Attribute]) -> Option<Vec<u8>> {
        let attribute = attributes
            .iter()
            .find(|a| a.type_code == ATTR_BITMAP && a.name.as_deref() == Some(INDEX_NAME))?;
        self.attribute_value(record, attribute, MAX_INDEX_BITMAP_BYTES)
    }

    pub fn extension_records(&self, record_number: u64, wanted: &[u32]) -> Spill {
        self.follow_attribute_list(record_number, Some(wanted))
    }

    #[must_use]
    pub fn spilled_records(&self, record_number: u64) -> Spill {
        self.follow_attribute_list(record_number, None)
    }

    fn follow_attribute_list(&self, record_number: u64, wanted: Option<&[u32]>) -> Spill {
        const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
        const MAX_EXTENSION_RECORDS: usize = 16;

        fn opaque() -> Spill {
            Spill { records: Vec::new(), refused: 1 }
        }

        let Ok(base) = self.fs.read_record(record_number) else { return opaque() };
        let Some((_, base_attrs)) = parsed_record(&base) else { return opaque() };
        let Some(list) = base_attrs.iter().find(|a| a.type_code == ATTR_ATTRIBUTE_LIST) else {
            return Spill::default();
        };
        if let AttributeBody::NonResident { real_size, .. } = list.body {
            if real_size > MAX_ATTRIBUTE_LIST_BYTES {
                return opaque();
            }
        }
        let Some(content) = self.attribute_value(&base, list, MAX_ATTRIBUTE_LIST_BYTES) else {
            return opaque();
        };
        let Ok(entries) = ntfs_core::parse_attribute_list(&content) else { return opaque() };

        let mut visited: Vec<u64> = Vec::new();
        let mut spill = Spill::default();
        for entry in
            entries.iter().filter(|e| wanted.is_none_or(|types| types.contains(&e.type_code)))
        {
            let number = entry.base_reference.record_number;
            if number == record_number || visited.contains(&number) {
                continue;
            }
            if visited.len() == MAX_EXTENSION_RECORDS {
                spill.refused = spill.refused.saturating_add(1);
                continue;
            }
            visited.push(number);

            let Ok(record) = self.fs.read_record(number) else {
                spill.refused = spill.refused.saturating_add(1);
                continue;
            };
            let Some((header, _)) = parsed_record(&record) else {
                spill.refused = spill.refused.saturating_add(1);
                continue;
            };
            if !extends(&header, record_number) {
                spill.refused = spill.refused.saturating_add(1);
                continue;
            }
            spill.records.push(record);
        }
        spill
    }

    pub(crate) fn attribute_value(
        &self,
        record: &[u8],
        attribute: &Attribute,
        max_bytes: u64,
    ) -> Option<Vec<u8>> {
        let AttributeBody::NonResident { real_size, .. } = attribute.body else {
            return attribute.resident_content(record).map(<[u8]>::to_vec);
        };
        let runs = ntfs_core::data::attribute_runlist(record, attribute).ok()?;
        let mut reader = self.raw.clone();
        ntfs_core::data::read_runs_capped(
            &mut reader,
            &runs,
            self.fs.boot().cluster_size(),
            real_size,
            max_bytes,
        )
        .ok()
    }

    pub fn exists(&self, path: &str) -> bool {
        self.resolve(path).is_some()
    }

    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.read_capped(path, usize::MAX)
    }

    pub fn read_capped(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let record = self
            .resolve(path)
            .ok_or_else(|| Error::parse(format!("{path} does not resolve on this volume")))?;
        self.read_file_data(record, max_bytes)
            .map_err(|e| Error::parse(format!("reading {path}: {e}")))
    }

    pub fn read_named_stream(&self, path: &str, stream: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let record = self
            .resolve(path)
            .ok_or_else(|| Error::parse(format!("{path} does not resolve on this volume")))?;
        if matches!(self.wof_lookup(record), WofLookup::Unaccounted) {
            return Err(Error::parse(format!("reading {path}:{stream}: {UNACCOUNTED}")));
        }
        self.fs
            .read_data_by_record(record, Some(stream), max_bytes as u64)
            .map_err(|e| Error::parse(format!("reading {path}:{stream}: {e}")))
    }

    pub fn is_windows_install(&self) -> bool {
        WINDOWS_MARKERS.iter().all(|m| self.exists(m))
    }

    pub fn why_not_windows(&self) -> String {
        let Some(root) = self.index_record(ROOT_RECORD) else {
            return "the root directory record carries no index".to_string();
        };
        let root_entries = match self.directory_entries(&root) {
            Ok(entries) => entries.len(),
            Err(e) => return format!("the root directory index is unreadable: {e}"),
        };

        for marker in WINDOWS_MARKERS {
            let mut current = ROOT_RECORD;
            let mut walked = String::new();
            for component in marker.split('\\').filter(|c| !c.is_empty()) {
                let Some(record) = self.index_record(current) else {
                    return format!(
                        "{walked}\\ has no reachable $INDEX_ROOT, not even through its \
                         $ATTRIBUTE_LIST — record {current} {}",
                        match self.record_identity(current) {
                            Some(id) => format!(
                                "calls itself `{}` ({})",
                                id.name,
                                if id.in_use { "in use" } else { "free" }
                            ),
                            None => "has no readable $FILE_NAME".to_string(),
                        }
                    );
                };
                let entries = match self.directory_entries(&record) {
                    Ok(entries) => entries,
                    Err(e) => {
                        let identity = match self.record_identity(current) {
                            Some(id) => format!(
                                "record {current} calls itself `{}` ({}, {} bytes)",
                                id.name,
                                if id.in_use { "in use" } else { "free" },
                                id.size
                            ),
                            None => format!("record {current} has no readable $FILE_NAME"),
                        };
                        let boot = self.fs.boot();
                        return format!(
                            "listing {walked}\\ failed: {e}; {identity}; volume geometry: \
                             {}-byte sectors, {}-byte clusters, {}-byte index records",
                            boot.bytes_per_sector,
                            boot.cluster_size(),
                            boot.index_record_size
                        );
                    }
                };
                let folded = component.to_lowercase();
                match entries.iter().find_map(|e| {
                    let name = e.file_name.as_ref()?;
                    (name.name.to_lowercase() == folded).then_some(e.file_reference.record_number)
                }) {
                    Some(next) => {
                        current = next;
                        walked.push('\\');
                        walked.push_str(component);
                    }
                    None => {
                        return format!(
                            "{walked}\\ lists {} entries but none named `{component}` \
                             (root holds {root_entries})",
                            entries.len()
                        );
                    }
                }
            }
        }
        format!("both markers resolve, so this should have been a Windows volume (root holds {root_entries} entries)")
    }

    pub fn read_record_capped(&self, record: u64, max_bytes: usize) -> Result<Vec<u8>> {
        self.read_file_data(record, max_bytes)
            .map_err(|e| Error::parse(format!("reading MFT record {record}: {e}")))
    }

    fn read_file_data(&self, record: u64, max_bytes: usize) -> Result<Vec<u8>> {
        let (backing, uncompressed) = match self.wof_lookup(record) {
            WofLookup::NotBacked => {
                return self
                    .fs
                    .read_data_by_record(record, None, max_bytes as u64)
                    .map_err(|e| Error::parse(format!("{e}")))
            }
            WofLookup::Unaccounted => return Err(Error::parse(UNACCOUNTED.to_string())),
            WofLookup::LengthUnknown(_) => {
                return Err(Error::parse(wof::Unreadable::NoLength.to_string()))
            }
            WofLookup::Backed(backing, uncompressed) => (backing, uncompressed),
        };

        let stream_cap =
            uncompressed.min(wof::MAX_OUTPUT as u64).saturating_add(uncompressed / 256 + 64 * 1024);
        let stream = self
            .fs
            .read_data_by_record(record, Some(wof::STREAM_NAME), stream_cap)
            .map_err(|e| {
                Error::parse(
                    wof::Unreadable::NoStream(format!("could not be read: {e}")).to_string(),
                )
            })?;

        wof::decompress(&stream, uncompressed, backing, max_bytes)
            .map_err(|why| Error::parse(why.to_string()))
    }

    #[must_use]
    pub fn wof_backing(&self, record: u64) -> Option<(wof::Backing, u64)> {
        match self.wof_lookup(record) {
            WofLookup::Backed(backing, size) => Some((backing, size)),
            WofLookup::NotBacked | WofLookup::LengthUnknown(_) | WofLookup::Unaccounted => None,
        }
    }

    fn wof_lookup(&self, record: u64) -> WofLookup {
        const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
        const ATTR_DATA: u32 = 0x80;
        const ATTR_FILE_NAME: u32 = 0x30;
        const ATTR_REPARSE_POINT: u32 = 0xC0;

        fn backing_in(bytes: &[u8], attrs: &[Attribute]) -> Option<wof::Backing> {
            let reparse = attrs.iter().find(|a| a.type_code == ATTR_REPARSE_POINT)?;
            wof::parse_reparse(reparse.resident_content(bytes)?)
        }

        fn data_size_in(attrs: &[Attribute]) -> Option<u64> {
            attrs
                .iter()
                .find(|a| a.type_code == ATTR_DATA && a.name.is_none())
                .and_then(|a| match a.body {
                    AttributeBody::NonResident { start_vcn: 0, real_size, .. } => Some(real_size),
                    _ => None,
                })
                .filter(|n| *n > 0)
        }

        fn name_size_in(bytes: &[u8], attrs: &[Attribute]) -> Option<u64> {
            attrs
                .iter()
                .filter(|a| a.type_code == ATTR_FILE_NAME)
                .filter_map(|a| ntfs_core::FileName::parse(a.resident_content(bytes)?).ok())
                .map(|n| n.real_size)
                .max()
                .filter(|n| *n > 0)
        }

        let Ok(bytes) = self.fs.read_record(record) else { return WofLookup::NotBacked };
        let Some((_, attrs)) = parsed_record(&bytes) else { return WofLookup::NotBacked };
        let spilled = attrs.iter().any(|a| a.type_code == ATTR_ATTRIBUTE_LIST);

        let mut extensions: Vec<Vec<u8>> = Vec::new();
        if spilled {
            let spill = self.spilled_records(record);
            if !spill.is_complete() {
                return WofLookup::Unaccounted;
            }
            extensions = spill.into_records();
        }

        let backing = match backing_in(&bytes, &attrs) {
            Some(backing) => backing,
            None if !spilled => return WofLookup::NotBacked,
            None => {
                match extensions
                    .iter()
                    .find_map(|r| parsed_record(r).and_then(|(_, a)| backing_in(r, &a)))
                {
                    Some(backing) => backing,
                    None => return WofLookup::NotBacked,
                }
            }
        };

        let mut size = data_size_in(&attrs);
        if size.is_none() && spilled {
            for extension in &extensions {
                if let Some((_, ext_attrs)) = parsed_record(extension) {
                    size = size.or_else(|| data_size_in(&ext_attrs));
                }
            }
        }
        let size = size.or_else(|| {
            let mut best = name_size_in(&bytes, &attrs);
            for extension in &extensions {
                if let Some((_, ext_attrs)) = parsed_record(extension) {
                    best = best.max(name_size_in(extension, &ext_attrs));
                }
            }
            best
        });

        match size {
            Some(size) => WofLookup::Backed(backing, size),
            None => WofLookup::LengthUnknown(backing),
        }
    }

    pub fn read_run_data(&self, runs: &[Run], real_size: u64, max_bytes: usize) -> Result<Vec<u8>> {
        let cluster_size = self.cluster_size();
        if cluster_size == 0 {
            return Err(Error::parse("this volume declares a zero-byte cluster".to_string()));
        }
        let mut reader = self.raw.clone();
        ntfs_core::data::read_runs_capped(
            &mut reader,
            runs,
            cluster_size,
            real_size,
            max_bytes as u64,
        )
        .map_err(|e| Error::parse(format!("reading the clusters a runlist names: {e}")))
    }

    pub fn ghost_in_record_slack(&self, record: u64) -> Option<crate::ghost::Ghost> {
        let bytes = self.fs.read_record(record).ok()?;
        crate::ghost::in_record_slack(&bytes, record)
    }

    pub fn read_log_file(&self, max_bytes: usize) -> Result<Vec<u8>> {
        self.read_capped(LOG_FILE, max_bytes)
    }

    #[must_use]
    pub fn data_runs(&self, record: u64) -> Vec<Run> {
        let stream = match self.wof_lookup(record) {
            WofLookup::Backed(backing, _) | WofLookup::LengthUnknown(backing)
                if backing.is_file_provider() =>
            {
                Some(wof::STREAM_NAME)
            }
            WofLookup::Unaccounted => return Vec::new(),
            _ => None,
        };
        self.fs.runs_by_record(record, stream).unwrap_or_default()
    }

    pub fn list_directory_entries(&self, path: &str) -> Vec<DirectoryEntry> {
        match self.list_directory_entries_checked(path) {
            Ok(entries) => entries,
            Err(e) => {
                log::warn!("{e}");
                Vec::new()
            }
        }
    }

    pub fn list_directory_entries_checked(&self, path: &str) -> Result<Vec<DirectoryEntry>> {
        let Some(record_number) = self.resolve(path) else { return Ok(Vec::new()) };
        let Some(record) = self.index_record(record_number) else { return Ok(Vec::new()) };
        self.entries_of_index(&record).map_err(|e| Error::parse(format!("listing {path}: {e}")))
    }

    pub fn list_directory_entries_of_record(
        &self,
        record_number: u64,
    ) -> Result<Vec<DirectoryEntry>> {
        let Some(record) = self.index_record(record_number) else {
            return Err(Error::parse(format!(
                "listing MFT record {record_number}: it holds no readable directory index"
            )));
        };
        self.entries_of_index(&record)
            .map_err(|e| Error::parse(format!("listing MFT record {record_number}: {e}")))
    }

    fn entries_of_index(&self, record: &[u8]) -> Result<Vec<DirectoryEntry>> {
        Ok(self
            .directory_entries(record)?
            .into_iter()
            .filter_map(|e| {
                let name = e.file_name?;
                (name.namespace != NAMESPACE_DOS && name.name != "." && name.name != "..")
                    .then_some(DirectoryEntry {
                        name: name.name,
                        record: e.file_reference.record_number,
                    })
            })
            .collect())
    }

    pub fn list_directory(&self, path: &str) -> Vec<String> {
        self.list_directory_entries(path).into_iter().map(|e| e.name).collect()
    }

    pub fn read_directory_files(
        &self,
        directory: &str,
        max_bytes_each: usize,
        accept: impl Fn(&str) -> bool,
    ) -> Vec<(String, Vec<u8>)> {
        self.list_directory_entries(directory)
            .into_iter()
            .filter(|e| accept(&e.name))
            .filter_map(|e| {
                self.read_record_capped(e.record, max_bytes_each).ok().map(|bytes| (e.name, bytes))
            })
            .collect()
    }

    pub fn record_identity(&self, record: u64) -> Option<RecordIdentity> {
        const NAMESPACE_DOS: u8 = 2;
        const ATTR_FILE_NAME: u32 = 0x30;
        const ATTR_DATA: u32 = 0x80;

        let bytes = self.fs.read_record(record).ok()?;
        let header = ntfs_core::MftRecordHeader::parse(&bytes).ok()?;
        if &header.signature != b"FILE" || !header.is_base_record() {
            return None;
        }
        let attributes =
            ntfs_core::parse_attributes(&bytes, header.first_attribute_offset as usize).ok()?;

        let mut name: Option<String> = None;
        let mut best_namespace = u8::MAX;
        let mut size = 0u64;
        for attribute in &attributes {
            match attribute.type_code {
                ATTR_FILE_NAME => {
                    let Some(content) = attribute.resident_content(&bytes) else { continue };
                    let Ok(file_name) = ntfs_core::FileName::parse(content) else { continue };
                    if file_name.namespace != NAMESPACE_DOS && file_name.namespace < best_namespace
                    {
                        best_namespace = file_name.namespace;
                        name = Some(file_name.name);
                    } else if name.is_none() {
                        name = Some(file_name.name);
                    }
                }
                ATTR_DATA if attribute.name.is_none() => {
                    size = match &attribute.body {
                        ntfs_core::AttributeBody::Resident { content_length, .. } => {
                            u64::from(*content_length)
                        }
                        ntfs_core::AttributeBody::NonResident { real_size, .. } => *real_size,
                    };
                }
                _ => {}
            }
        }

        Some(RecordIdentity { name: name?, in_use: header.is_in_use(), size })
    }

    pub fn is_efs_encrypted(&self, record: u64) -> bool {
        const ENCRYPTED: u32 = 0x4000;
        const ATTR_STANDARD_INFORMATION: u32 = 0x10;
        const ATTR_LOGGED_UTILITY_STREAM: u32 = 0x100;
        const EFS_STREAM: &str = "$EFS";

        let Ok(bytes) = self.fs.read_record(record) else { return false };
        let Ok(header) = ntfs_core::MftRecordHeader::parse(&bytes) else { return false };
        if &header.signature != b"FILE" {
            return false;
        }
        let Ok(attributes) =
            ntfs_core::parse_attributes(&bytes, header.first_attribute_offset as usize)
        else {
            return false;
        };

        for attribute in &attributes {
            match attribute.type_code {
                ATTR_STANDARD_INFORMATION => {
                    let Some(content) = attribute.resident_content(&bytes) else { continue };
                    let Ok(si) = ntfs_core::StandardInformation::parse(content) else { continue };
                    if si.file_attributes & ENCRYPTED != 0 {
                        return true;
                    }
                }
                ATTR_LOGGED_UTILITY_STREAM if attribute.name.as_deref() == Some(EFS_STREAM) => {
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    pub fn path_is_efs_encrypted(&self, path: &str) -> bool {
        self.resolve(path).is_some_and(|record| self.is_efs_encrypted(record))
    }

    pub fn fs(&self) -> &NtfsFs<SharedReader<R>> {
        &self.fs
    }

    pub fn length(&self) -> u64 {
        self.total_clusters().saturating_mul(self.cluster_size())
    }

    pub fn reader_handle(&self) -> SharedReader<R> {
        let mut handle = self.raw.clone();
        let _ = std::io::Seek::seek(&mut handle, std::io::SeekFrom::Start(0));
        handle
    }

    pub fn shadow_copies(&self) -> crate::vss::Catalog {
        let length = self.length();
        if length == 0 {
            return crate::vss::Catalog::default();
        }
        let mut handle = self.reader_handle();
        crate::vss::read_catalog(&mut handle, length)
    }

    pub fn slack_bounds(&self) -> Bounds {
        let cluster = self.cluster_size();
        let records = self
            .fs
            .runs_by_record(MFT_RECORD, None)
            .ok()
            .map(|runs| {
                let clusters: u64 = runs.iter().map(|r| r.length).sum();
                clusters.saturating_mul(cluster) / self.fs.boot().mft_record_size.max(1)
            })
            .unwrap_or(0)
            .min(MAX_MFT_RECORDS);
        Bounds { records, cluster, volume_bytes: self.length(), parent: None }
    }

    pub fn deleted_index_entries(&self, record_number: u64, bounds: &Bounds) -> Recovered {
        let mut found = Recovered::default();
        let bounds = Bounds { parent: Some(record_number), ..*bounds };

        let mut live: Vec<(u64, String)> = Vec::new();

        if let Ok(base) = self.fs.read_record(record_number) {
            if let Some((header, _)) = parsed_record(&base) {
                if !header.is_base_record() {
                    return found;
                }
                let used = header.used_size as usize;
                if used >= MIN_RECORD_USED && used < base.len() {
                    let (entries, swept) =
                        slack::scan(&base, used, base.len(), &bounds, Slack::Record);
                    found.stats.slack_bytes += swept as u64;
                    found.entries.extend(entries);
                }
            }
        }

        let Some(record) = self.index_record(record_number) else { return found };
        let Some((_, attributes)) = parsed_record(&record) else { return found };

        if let Some(root) = attributes.iter().find(|a| a.type_code == ATTR_INDEX_ROOT) {
            if let Some(content) = root.resident_content(&record) {
                self.sweep_index_node(content, INDEX_ROOT_HEADER, Slack::IndexRoot, &bounds)
                    .apply(&mut found, &mut live);
            }
        }

        let Some(allocation) = attributes.iter().find(|a| a.type_code == ATTR_INDEX_ALLOCATION)
        else {
            found.finish(&live);
            return found;
        };
        let Some(value) = self.attribute_value(&record, allocation, MAX_INDEX_BYTES) else {
            found.finish(&live);
            return found;
        };

        let boot = self.fs.boot();
        let index_record_size = boot.index_record_size as usize;
        let sector_size = boot.bytes_per_sector as usize;
        if index_record_size < INDX_HEADER + INDEX_HEADER || sector_size == 0 {
            found.finish(&live);
            return found;
        }
        let bitmap = self.index_bitmap(&record, &attributes);

        for buffer in 0..(value.len() / index_record_size) {
            if found.entries.len() >= MAX_RECOVERED_PER_DIRECTORY {
                break;
            }
            let at = buffer * index_record_size;
            let window = &value[at..at + index_record_size];
            if &window[..4] != b"INDX" {
                continue;
            }
            let mut owned = window.to_vec();
            if ntfs_core::apply_fixup(&mut owned, sector_size).is_err() {
                continue;
            }
            let in_use = bitmap.as_deref().map(InUse).is_none_or(|bits| bits.is_set(buffer));
            let found_in = if in_use {
                Slack::IndexBuffer { buffer: buffer as u64 }
            } else {
                Slack::FreeIndexBuffer { buffer: buffer as u64 }
            };
            if in_use {
                self.sweep_index_node(&owned, INDX_HEADER, found_in, &bounds)
                    .apply(&mut found, &mut live);
            } else {
                let (entries, swept) = slack::scan(
                    &owned,
                    INDX_HEADER + INDEX_HEADER,
                    index_record_size,
                    &bounds,
                    found_in,
                );
                found.stats.slack_bytes += swept as u64;
                found.entries.extend(entries);
            }
        }

        found.finish(&live);
        found
    }

    pub fn carved_index_entries(
        &self,
        bitmap: &[u8],
        bounds: &Bounds,
        max_clusters: u64,
    ) -> CarvedIndex {
        const CHUNK_CLUSTERS: u64 = 1024;

        let mut out = CarvedIndex::default();
        let cluster = self.cluster_size();
        let boot = self.fs.boot();
        let index_record_size = boot.index_record_size as usize;
        let sector_size = boot.bytes_per_sector as usize;
        if cluster == 0 || sector_size == 0 || index_record_size < INDX_HEADER + INDEX_HEADER {
            out.stopped =
                Some("this volume's geometry does not describe an index record".to_string());
            return out;
        }
        let per_cluster = (cluster as usize / index_record_size).max(1);
        let clusters_per_page = (index_record_size as u64).div_ceil(cluster);
        let total = self.total_clusters();
        let bounds = bounds.orphan();

        let mut buffer = vec![0u8; (CHUNK_CLUSTERS * cluster) as usize];
        let mut seen: Vec<(u64, u16, String)> = Vec::new();
        let mut lcn = 0u64;
        while lcn < total {
            if out.scanned_clusters >= max_clusters {
                out.stopped = Some(format!(
                    "stopped after {max_clusters} clusters, having looked at none of the {} \
                     clusters from {lcn} on",
                    total - lcn
                ));
                break;
            }
            if is_allocated(bitmap, lcn) {
                lcn += 1;
                continue;
            }
            let mut run = 0u64;
            while run < CHUNK_CLUSTERS
                && lcn + run < total
                && !is_allocated(bitmap, lcn + run)
                && out.scanned_clusters + run < max_clusters
            {
                run += 1;
            }
            if run < clusters_per_page {
                lcn += run.max(1);
                continue;
            }
            let want = (run * cluster) as usize;
            if self.read_clusters(lcn, &mut buffer[..want]).is_err() {
                out.stopped = Some(format!("clusters {lcn}..{} could not be read", lcn + run));
                break;
            }
            out.scanned_clusters += run;
            out.bytes_read += want as u64;

            for page in 0..(want / index_record_size) {
                if index_record_size < cluster as usize && page % per_cluster != 0 {
                    continue;
                }
                let at = page * index_record_size;
                if &buffer[at..at + 4] != b"INDX" {
                    continue;
                }
                out.buffers += 1;
                let mut owned = buffer[at..at + index_record_size].to_vec();
                if ntfs_core::apply_fixup(&mut owned, sector_size).is_err() {
                    continue;
                }
                out.fixed_up += 1;
                let offset = lcn * cluster + at as u64;
                let (entries, swept) = slack::scan(
                    &owned,
                    INDX_HEADER + INDEX_HEADER,
                    index_record_size,
                    &bounds,
                    Slack::Unallocated { offset },
                );
                out.stats.slack_bytes += swept as u64;
                let Some(first) = entries.first().map(|e| e.parent_record) else { continue };
                if entries.iter().any(|e| e.parent_record != first) {
                    out.disagreeing_pages += 1;
                    continue;
                }
                for entry in entries {
                    let key = (entry.record, entry.sequence, entry.name.clone());
                    if seen.contains(&key) {
                        out.stats.duplicates += 1;
                        continue;
                    }
                    seen.push(key);
                    out.entries.push(entry);
                }
                if out.entries.len() >= MAX_RECOVERED_PER_DIRECTORY {
                    out.stopped = Some(format!(
                        "stopped after {MAX_RECOVERED_PER_DIRECTORY} recovered entries"
                    ));
                    out.stats.recovered = out.entries.len() as u64;
                    return out;
                }
            }
            lcn += run;
        }
        out.stats.recovered = out.entries.len() as u64;
        out
    }

    pub fn record_fate(&self, record: u64, sequence: u16) -> Fate {
        let Ok(bytes) = self.fs.read_record(record) else { return Fate::Unknown };
        let Ok(header) = MftRecordHeader::parse(&bytes) else { return Fate::Unknown };
        if &header.signature != b"FILE" || !header.is_base_record() {
            return Fate::Unknown;
        }
        let now = header.sequence_number;
        if !header.is_in_use() {
            return if now == sequence || now == sequence.wrapping_add(1) {
                Fate::Free
            } else {
                Fate::FreedAgain { sequence: now }
            };
        }
        if now == sequence {
            Fate::StillThere
        } else {
            Fate::Reallocated {
                sequence: now,
                to: self.record_identity(record).map(|identity| identity.name),
            }
        }
    }

    fn sweep_index_node(
        &self,
        node: &[u8],
        base: usize,
        found_in: Slack,
        bounds: &Bounds,
    ) -> NodeSweep {
        let mut sweep = NodeSweep::default();
        if base + INDEX_HEADER > node.len() {
            return sweep;
        }
        let u32at = |o: usize| -> usize {
            u32::from_le_bytes([
                node[base + o],
                node[base + o + 1],
                node[base + o + 2],
                node[base + o + 3],
            ]) as usize
        };
        let first_entry = u32at(0x00);
        let used = u32at(0x04);
        let live_start = base.saturating_add(first_entry);
        let live_end = base.saturating_add(used);
        if live_start < base + INDEX_HEADER || live_end > node.len() || live_start > live_end {
            return sweep;
        }

        let (declared, accepted, refused) =
            slack::audit_live_reasons(node, live_start, live_end, bounds);
        sweep.stats.live_seen = declared;
        sweep.stats.live_accepted = accepted;
        sweep.refused = refused;
        if let Ok(entries) = ntfs_core::parse_entries(node, live_start, live_end) {
            for entry in entries {
                if let Some(name) = entry.file_name {
                    sweep.live.push((entry.file_reference.record_number, name.name));
                }
            }
        }

        let (entries, swept) = slack::scan(node, live_end, node.len(), bounds, found_in);
        sweep.stats.slack_bytes = swept as u64;
        sweep.entries = entries;
        sweep
    }
}

#[derive(Default)]
struct NodeSweep {
    entries: Vec<slack::DeletedIndexEntry>,
    live: Vec<(u64, String)>,
    stats: SweepStats,
    refused: Vec<&'static str>,
}

impl NodeSweep {
    fn apply(self, found: &mut Recovered, live: &mut Vec<(u64, String)>) {
        found.stats.add(self.stats);
        found.entries.extend(self.entries);
        found.refused_live.extend(self.refused);
        live.extend(self.live);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fate {
    Free,
    FreedAgain { sequence: u16 },
    StillThere,
    Reallocated { sequence: u16, to: Option<String> },
    Unknown,
}

impl Fate {
    #[must_use]
    pub fn is_gone(&self) -> bool {
        matches!(self, Fate::Free | Fate::FreedAgain { .. } | Fate::Reallocated { .. })
    }
}

impl std::fmt::Display for Fate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fate::Free => write!(f, "its $MFT record is free and still carries its sequence"),
            Fate::FreedAgain { sequence } => {
                write!(f, "its $MFT record is free and has since been reused: sequence {sequence}")
            }
            Fate::StillThere => write!(f, "its $MFT record is still this file's"),
            Fate::Reallocated { sequence, to } => match to {
                Some(name) => write!(
                    f,
                    "its $MFT record has been REALLOCATED to `{name}` (sequence {sequence})"
                ),
                None => {
                    write!(f, "its $MFT record has been REALLOCATED (sequence {sequence})")
                }
            },
            Fate::Unknown => write!(f, "its $MFT record could not be read"),
        }
    }
}

fn is_allocated(bitmap: &[u8], cluster: u64) -> bool {
    let byte = (cluster / 8) as usize;
    bitmap.get(byte).is_none_or(|bits| bits & (1 << (cluster % 8)) != 0)
}

#[derive(Clone, Debug, Default)]
pub struct CarvedIndex {
    pub entries: Vec<slack::DeletedIndexEntry>,
    pub stats: SweepStats,
    pub scanned_clusters: u64,
    pub bytes_read: u64,
    pub buffers: u64,
    pub fixed_up: u64,
    pub disagreeing_pages: u64,
    pub stopped: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Recovered {
    pub entries: Vec<slack::DeletedIndexEntry>,
    pub stats: SweepStats,
    pub refused_live: Vec<&'static str>,
}

impl Recovered {
    fn finish(&mut self, live: &[(u64, String)]) {
        let before = self.entries.len();
        let mut seen: Vec<(u64, u16, String)> = Vec::new();
        self.entries.retain(|e| {
            if live.iter().any(|(r, n)| *r == e.record && n == &e.name) {
                return false;
            }
            let key = (e.record, e.sequence, e.name.clone());
            if seen.contains(&key) {
                return false;
            }
            seen.push(key);
            true
        });
        self.stats.recovered = self.entries.len() as u64;
        self.stats.duplicates = (before - self.entries.len()) as u64;
    }
}

impl<R: Read + Seek> std::fmt::Debug for Volume<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Volume")
            .field("kind", &self.kind)
            .field("cluster_size", &self.cluster_size())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn fake_volume(oem: &[u8; 8]) -> Cursor<Vec<u8>> {
        let mut data = vec![0u8; 4096];
        data[3..11].copy_from_slice(oem);
        Cursor::new(data)
    }

    #[test]
    fn locked_bitlocker_reports_a_locked_volume() {
        let err = Volume::open(fake_volume(b"-FVE-FS-"), "\\\\.\\HarddiskVolume2").unwrap_err();
        assert!(
            matches!(err, Error::VolumeLocked(ref v) if v == "\\\\.\\HarddiskVolume2"),
            "got {err:?}"
        );
        assert!(err.to_string().contains("manage-bde"));
    }

    #[test]
    fn non_ntfs_volumes_are_rejected_by_name() {
        let err = Volume::open(fake_volume(b"EXFAT   "), "vol").unwrap_err();
        assert!(err.to_string().contains("exFAT"), "got {err}");
    }

    #[test]
    fn truncated_volume_errors_cleanly() {
        let err = Volume::open(Cursor::new(vec![0u8; 16]), "vol").unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "got {err:?}");
    }

    #[test]
    fn ntfs_signature_without_a_filesystem_fails_to_open() {
        assert!(Volume::open(fake_volume(b"NTFS    "), "vol").is_err());
    }
}

fn parsed_record(record: &[u8]) -> Option<(MftRecordHeader, Vec<Attribute>)> {
    let header = MftRecordHeader::parse(record).ok()?;
    if &header.signature != b"FILE" {
        return None;
    }
    let attributes = parse_attributes(record, header.first_attribute_offset as usize).ok()?;
    Some((header, attributes))
}

fn extends(header: &MftRecordHeader, base: u64) -> bool {
    const RECORD_NUMBER: u64 = 0x0000_FFFF_FFFF_FFFF;
    header.base_record != 0 && header.base_record & RECORD_NUMBER == base
}

const MAX_ATTRIBUTE_LIST_BYTES: u64 = 64 * 1024;

const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_BITMAP: u32 = 0xB0;

const MFT_RECORD: u64 = 0;

const MAX_MFT_RECORDS: u64 = 16_000_000;

const MIN_RECORD_USED: usize = 0x38;

const INDEX_ROOT_HEADER: usize = 0x10;
const INDX_HEADER: usize = 0x18;
const INDEX_HEADER: usize = 0x10;

const MAX_RECOVERED_PER_DIRECTORY: usize = 100_000;
const INDEX_NAME: &str = "$I30";

const MAX_INDEX_BITMAP_BYTES: u64 = 64 * 1024;

const MAX_INDEX_BYTES: u64 = 16 * 1024 * 1024;

const MAX_INDEX_RUNS: usize = 16 * 1024;

struct Fragment {
    start_vcn: u64,
    runs: Vec<Run>,
    bytes: Vec<u8>,
    name: Option<String>,
}

#[derive(Default)]
struct IndexPieces {
    root: Option<Vec<u8>>,
    bitmap: Option<Vec<u8>>,
    whole: Option<Vec<u8>>,
    fragments: Vec<Fragment>,
}

impl IndexPieces {
    fn collect(&mut self, record: &[u8], attrs: &[Attribute]) -> Option<()> {
        let has_root = attrs.iter().any(|a| a.type_code == ATTR_INDEX_ROOT);
        let has_allocation = attrs.iter().any(|a| a.type_code == ATTR_INDEX_ALLOCATION);
        if has_root && has_allocation && self.whole.is_none() {
            self.whole = attrs
                .iter()
                .any(|a| a.type_code == ATTR_BITMAP && a.name.as_deref() == Some(INDEX_NAME))
                .then(|| record.to_vec());
        }

        for attr in attrs {
            match attr.type_code {
                ATTR_INDEX_ROOT if self.root.is_none() => {
                    let Some(bytes) = raw_attribute(record, attr) else { continue };
                    self.root = Some(bytes.to_vec());
                }
                ATTR_BITMAP
                    if self.bitmap.is_none() && attr.name.as_deref() == Some(INDEX_NAME) =>
                {
                    let Some(bytes) = raw_attribute(record, attr) else { continue };
                    self.bitmap = Some(bytes.to_vec());
                }
                ATTR_INDEX_ALLOCATION => {
                    let AttributeBody::NonResident { start_vcn, .. } = attr.body else {
                        return None;
                    };
                    let bytes = raw_attribute(record, attr)?;
                    let runs = ntfs_core::data::attribute_runlist(record, attr).ok()?;
                    self.fragments.push(Fragment {
                        start_vcn,
                        runs,
                        bytes: bytes.to_vec(),
                        name: attr.name.clone(),
                    });
                }
                _ => {}
            }
        }
        Some(())
    }

    fn assemble(self, base: &[u8], cluster_size: u64) -> Option<Vec<u8>> {
        if self.fragments.len() <= 1 {
            if let Some(record) = self.whole {
                return Some(record);
            }
        }

        let root = self.root?;
        let allocation = match self.fragments.len() {
            0 => None,
            1 => Some(self.fragments[0].bytes.clone()),
            _ => Some(combine_fragments(&self.fragments, cluster_size)?),
        };
        let mut attributes: Vec<&[u8]> = vec![&root];
        if let Some(allocation) = &allocation {
            attributes.push(allocation);
        }
        if let (Some(bitmap), true) = (&self.bitmap, allocation.is_some()) {
            attributes.push(bitmap);
        }
        synthesise_index_record(base, &attributes)
    }
}

fn combine_fragments(fragments: &[Fragment], cluster_size: u64) -> Option<Vec<u8>> {
    if cluster_size == 0 {
        return None;
    }

    let mut ordered: Vec<&Fragment> = fragments.iter().collect();
    ordered.sort_by_key(|f| f.start_vcn);

    let mut runs: Vec<Run> = Vec::new();
    let mut vcn: u64 = 0;
    for fragment in ordered {
        if fragment.start_vcn < vcn {
            continue;
        }
        if fragment.start_vcn > vcn {
            return None;
        }
        for run in &fragment.runs {
            if runs.len() == MAX_INDEX_RUNS {
                return None;
            }
            runs.push(*run);
            vcn = vcn.checked_add(run.length)?;
        }
    }

    let clusters = vcn;
    if clusters == 0 {
        return None;
    }
    let size = clusters.checked_mul(cluster_size)?.min(MAX_INDEX_BYTES);
    let name = fragments.iter().find_map(|f| f.name.clone());
    encode_index_allocation(name.as_deref(), &runs, clusters, size)
}

fn encode_index_allocation(
    name: Option<&str>,
    runs: &[Run],
    clusters: u64,
    size: u64,
) -> Option<Vec<u8>> {
    const HEADER: usize = 0x40;

    let units: Vec<u16> = name.unwrap_or("$I30").encode_utf16().collect();
    let name_length = u8::try_from(units.len()).ok()?;
    let name_bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let runs_offset = align8(HEADER.checked_add(name_bytes.len())?);

    let mut runlist: Vec<u8> = Vec::with_capacity(runs.len() * 17 + 1);
    let mut previous: i128 = 0;
    for run in runs {
        match run.lcn {
            None => {
                runlist.push(0x08);
                runlist.extend_from_slice(&run.length.to_le_bytes());
            }
            Some(lcn) => {
                let delta = i64::try_from(i128::from(lcn) - previous).ok()?;
                previous = i128::from(lcn);
                runlist.push(0x88);
                runlist.extend_from_slice(&run.length.to_le_bytes());
                runlist.extend_from_slice(&delta.to_le_bytes());
            }
        }
    }
    runlist.push(0);

    let length = align8(runs_offset.checked_add(runlist.len())?);
    let mut a = vec![0u8; length];
    a[0x00..0x04].copy_from_slice(&ATTR_INDEX_ALLOCATION.to_le_bytes());
    a[0x04..0x08].copy_from_slice(&u32::try_from(length).ok()?.to_le_bytes());
    a[0x08] = 1;
    a[0x09] = name_length;
    a[0x0A..0x0C].copy_from_slice(&(HEADER as u16).to_le_bytes());
    a[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
    a[0x18..0x20].copy_from_slice(&(clusters - 1).to_le_bytes());
    a[0x20..0x22].copy_from_slice(&u16::try_from(runs_offset).ok()?.to_le_bytes());
    a[0x28..0x30].copy_from_slice(&size.to_le_bytes());
    a[0x30..0x38].copy_from_slice(&size.to_le_bytes());
    a[0x38..0x40].copy_from_slice(&size.to_le_bytes());
    a[HEADER..HEADER + name_bytes.len()].copy_from_slice(&name_bytes);
    a[runs_offset..runs_offset + runlist.len()].copy_from_slice(&runlist);
    Some(a)
}

fn align8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

fn raw_attribute<'a>(record: &'a [u8], attr: &Attribute) -> Option<&'a [u8]> {
    record.get(attr.offset..attr.offset.checked_add(attr.length as usize)?)
}

fn synthesise_index_record(base: &[u8], attributes: &[&[u8]]) -> Option<Vec<u8>> {
    const USED_SIZE: usize = 0x18;
    const ALLOCATED_SIZE: usize = 0x1C;
    const END_MARKER: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

    let header = MftRecordHeader::parse(base).ok()?;
    let header_len = header.first_attribute_offset as usize;
    if header_len < ALLOCATED_SIZE + 4 || header_len > base.len() {
        return None;
    }

    let body: usize = attributes.iter().map(|a| a.len()).sum();
    let used = header_len.checked_add(body)?.checked_add(END_MARKER.len())?;
    let allocated = used.max(base.len());

    let mut out = vec![0u8; allocated];
    out[..header_len].copy_from_slice(&base[..header_len]);
    let mut at = header_len;
    for attribute in attributes {
        out[at..at + attribute.len()].copy_from_slice(attribute);
        at += attribute.len();
    }
    out[at..at + END_MARKER.len()].copy_from_slice(&END_MARKER);

    out[USED_SIZE..USED_SIZE + 4].copy_from_slice(&(used as u32).to_le_bytes());
    out[ALLOCATED_SIZE..ALLOCATED_SIZE + 4].copy_from_slice(&(allocated as u32).to_le_bytes());
    Some(out)
}
