use std::collections::HashSet;

use chrono::{DateTime, Utc};

use mm_core::{ArtifactSource, FileHash, NormalizedPath, Observation, ObservationKind};

use crate::Harvested;

const BASE_BLOCK_LEN: usize = 4096;

const KEY_HIVE_ENTRY: u16 = 0x0004;
const KEY_COMP_NAME: u16 = 0x0020;
const VALUE_COMP_NAME: u16 = 0x0001;

const DATA_RESIDENT: u32 = 0x8000_0000;
const BIG_DATA_SEGMENT: usize = 16_344;

const MAX_VALUE_BYTES: usize = 1 << 20;
const MAX_VALUES: usize = 16_384;
const MAX_SUBKEYS: usize = 1 << 20;
const MAX_LIST_DEPTH: u32 = 4;
const BUDGET: u64 = 8_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Schema {
    InventoryApplicationFile,
    InventoryDriverBinary,
    LegacyFile,
}

const CONTAINERS: [(&str, Schema); 3] = [
    ("InventoryApplicationFile", Schema::InventoryApplicationFile),
    ("InventoryDriverBinary", Schema::InventoryDriverBinary),
    ("File", Schema::LegacyFile),
];

pub fn harvest(hive: &[u8]) -> Harvested {
    let mut out = Harvested::new();
    let bins = Bins::new(hive);

    let mut seen_entries: HashSet<u32> = HashSet::new();
    let mut missing: Vec<(&str, Schema)> = CONTAINERS.to_vec();

    if let Some(root) = root_offset(&bins) {
        let mut starts = vec![root];
        if let Some(inner) = child_named(&bins, root, "Root") {
            if inner != root {
                starts.push(inner);
            }
        }

        let mut walked: HashSet<u32> = HashSet::new();
        for (name, schema) in CONTAINERS {
            for &start in &starts {
                let Some(container) = child_named(&bins, start, name) else {
                    continue;
                };
                missing.retain(|(missed, _)| *missed != name);
                if walked.insert(container) {
                    walk_container(&bins, container, schema, &mut seen_entries, &mut out);
                }
            }
        }
    }

    if !missing.is_empty() {
        log::debug!("amcache: {} container(s) unreachable; scanning the bins", missing.len());
        carve_containers(&bins, &missing, &mut seen_entries, &mut out);
    }

    out
}

struct Bins<'a> {
    bytes: &'a [u8],
    budget: std::cell::Cell<u64>,
}

struct Key {
    name: String,
    name_complete: bool,
    timestamp: u64,
    subkeys_list: u32,
    value_count: u32,
    values_list: u32,
}

enum Value {
    Text(String),
    Number(u64),
    Bytes(Vec<u8>),
}

impl<'a> Bins<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Bins { bytes, budget: std::cell::Cell::new(BUDGET) }
    }

    fn spend(&self, n: u64) -> bool {
        let left = self.budget.get();
        if left < n {
            self.budget.set(0);
            false
        } else {
            self.budget.set(left - n);
            true
        }
    }

    fn exhausted(&self) -> bool {
        self.budget.get() == 0
    }

    fn cell(&self, offset: u32) -> Option<&'a [u8]> {
        if !self.spend(1) {
            return None;
        }
        self.probe(offset).map(|(data, _)| data)
    }

    fn probe(&self, offset: u32) -> Option<(&'a [u8], bool)> {
        if offset == u32::MAX {
            return None;
        }
        let start = BASE_BLOCK_LEN.checked_add(offset as usize)?;
        let raw = le_i32(self.bytes, start)?;
        let len = i64::from(raw).unsigned_abs();
        if len < 8 || !len.is_multiple_of(8) {
            return None;
        }
        let len = usize::try_from(len).ok()?;
        let end = start.checked_add(len)?;
        if end > self.bytes.len() {
            return None;
        }
        let data_start = start.checked_add(4)?;
        Some((self.bytes.get(data_start..end)?, raw < 0))
    }

    fn key(&self, offset: u32) -> Option<Key> {
        key_from(self.cell(offset)?)
    }

    fn is_root_key(&self, offset: u32) -> Option<bool> {
        let data = self.cell(offset)?;
        if data.get(..2) != Some(&b"nk"[..]) {
            return None;
        }
        Some(le_u16(data, 0x02)? & KEY_HIVE_ENTRY != 0)
    }

    fn subkeys(&self, key: &Key) -> Vec<u32> {
        let mut out = Vec::new();
        let mut lists = HashSet::new();
        let mut keys = HashSet::new();
        self.collect_list(key.subkeys_list, 0, &mut lists, &mut keys, &mut out);
        out
    }

    fn collect_list(
        &self,
        offset: u32,
        depth: u32,
        lists: &mut HashSet<u32>,
        keys: &mut HashSet<u32>,
        out: &mut Vec<u32>,
    ) {
        if depth > MAX_LIST_DEPTH || out.len() >= MAX_SUBKEYS || !lists.insert(offset) {
            return;
        }
        let Some(data) = self.cell(offset) else {
            return;
        };
        let Some(count) = le_u16(data, 0x02) else {
            return;
        };
        let (stride, indirect) = match data.get(..2) {
            Some(b"lf") | Some(b"lh") => (8usize, false),
            Some(b"li") => (4, false),
            Some(b"ri") => (4, true),
            _ => return,
        };
        let body = data.get(4..).unwrap_or(&[]);
        let items = (count as usize).min(body.len() / stride);
        for index in 0..items {
            if out.len() >= MAX_SUBKEYS || !self.spend(1) {
                return;
            }
            let Some(target) = index.checked_mul(stride).and_then(|at| le_u32(body, at)) else {
                return;
            };
            if indirect {
                self.collect_list(target, depth + 1, lists, keys, out);
            } else if keys.insert(target) {
                out.push(target);
            }
        }
    }

    fn values(&self, key: &Key) -> Vec<(String, Value)> {
        let Some(data) = self.cell(key.values_list) else {
            return Vec::new();
        };
        let items = (key.value_count as usize).min(data.len() / 4).min(MAX_VALUES);
        let mut seen = HashSet::new();
        let mut out = Vec::with_capacity(items.min(64));
        for index in 0..items {
            if !self.spend(1) {
                break;
            }
            let Some(offset) = index.checked_mul(4).and_then(|at| le_u32(data, at)) else {
                break;
            };
            if !seen.insert(offset) {
                continue;
            }
            if let Some(value) = self.value(offset) {
                out.push(value);
            }
        }
        out
    }

    fn value(&self, offset: u32) -> Option<(String, Value)> {
        let data = self.cell(offset)?;
        if data.get(..2) != Some(&b"vk"[..]) {
            return None;
        }
        let name_len = le_u16(data, 0x02)? as usize;
        let raw_size = le_u32(data, 0x04)?;
        let data_offset = le_u32(data, 0x08)?;
        let data_type = le_u32(data, 0x0c)?;
        let flags = le_u16(data, 0x10)?;
        let name_end = 0x14usize.checked_add(name_len)?;
        let name_bytes = data.get(0x14..name_end)?;
        let name = decode_name(name_bytes, flags & VALUE_COMP_NAME != 0);

        let size = (raw_size & !DATA_RESIDENT) as usize;
        let bytes = if raw_size & DATA_RESIDENT != 0 {
            data.get(0x08..0x08 + size.min(4))?.to_vec()
        } else {
            self.value_bytes(data_offset, size)?
        };
        Some((name, decode_value(data_type, &bytes)))
    }

    fn value_bytes(&self, offset: u32, size: usize) -> Option<Vec<u8>> {
        let size = size.min(MAX_VALUE_BYTES);
        let cell = self.cell(offset)?;

        if size > BIG_DATA_SEGMENT && cell.get(..2) == Some(&b"db"[..]) {
            let segments = le_u16(cell, 0x02)? as usize;
            let list = self.cell(le_u32(cell, 0x04)?)?;
            let items = segments.min(list.len() / 4);
            let mut out: Vec<u8> = Vec::new();
            for index in 0..items {
                if out.len() >= size || !self.spend(1) {
                    break;
                }
                let Some(at) = index.checked_mul(4).and_then(|at| le_u32(list, at)) else {
                    break;
                };
                let Some(chunk) = self.cell(at) else {
                    continue;
                };
                let take = chunk.len().min(BIG_DATA_SEGMENT).min(size - out.len());
                out.extend_from_slice(chunk.get(..take).unwrap_or_default());
            }
            return Some(out);
        }

        Some(cell.get(..size.min(cell.len()))?.to_vec())
    }
}

fn key_from(data: &[u8]) -> Option<Key> {
    if data.get(..2) != Some(&b"nk"[..]) {
        return None;
    }
    let flags = le_u16(data, 0x02)?;
    let name_len = le_u16(data, 0x48)? as usize;
    let name_at = 0x4cusize;
    let name_end = name_at.checked_add(name_len)?;
    let (name_bytes, name_complete) = match data.get(name_at..name_end) {
        Some(bytes) => (bytes, true),
        None => (data.get(name_at..).unwrap_or(&[]), false),
    };
    Some(Key {
        name: decode_name(name_bytes, flags & KEY_COMP_NAME != 0),
        name_complete,
        timestamp: le_u64(data, 0x04)?,
        subkeys_list: le_u32(data, 0x1c)?,
        value_count: le_u32(data, 0x24)?,
        values_list: le_u32(data, 0x28)?,
    })
}

fn root_offset(bins: &Bins<'_>) -> Option<u32> {
    let declared = le_u32(bins.bytes, 0x24);

    if base_block_is_intact(bins.bytes) {
        if let Some(offset) = declared {
            if bins.key(offset).is_some() {
                return Some(offset);
            }
        }
    }

    if let Some(offset) = declared {
        if bins.is_root_key(offset) == Some(true) {
            return Some(offset);
        }
    }

    scan_for_root(bins)
}

fn base_block_is_intact(hive: &[u8]) -> bool {
    let Some(block) = hive.get(..BASE_BLOCK_LEN) else {
        return false;
    };
    if block.get(..4) != Some(&b"regf"[..]) {
        return false;
    }
    if le_u32(block, 0x14) != Some(1) {
        return false;
    }
    if !matches!(le_u32(block, 0x18), Some(0..=6)) {
        return false;
    }
    if le_u32(block, 0x1c) != Some(0) {
        return false;
    }
    match le_u32(block, 0x28) {
        Some(size) if size.is_multiple_of(BASE_BLOCK_LEN as u32) => {}
        _ => return false,
    }

    let mut xor = 0u32;
    for word in 0..127usize {
        xor ^= word.checked_mul(4).and_then(|at| le_u32(block, at)).unwrap_or(0);
    }
    let expected = match xor {
        0xffff_ffff => 0xffff_fffe,
        0 => 1,
        other => other,
    };
    le_u32(block, 0x1fc) == Some(expected)
}

fn scan_for_root(bins: &Bins<'_>) -> Option<u32> {
    let mut fallback = None;
    for offset in cell_starts(bins.bytes) {
        let Some((data, allocated)) = bins.probe(offset) else {
            continue;
        };
        if data.get(..2) != Some(&b"nk"[..]) {
            continue;
        }
        if le_u16(data, 0x02).is_none_or(|flags| flags & KEY_HIVE_ENTRY == 0) {
            continue;
        }
        if allocated {
            return Some(offset);
        }
        fallback = fallback.or(Some(offset));
    }
    fallback
}

fn cell_starts(hive: &[u8]) -> impl Iterator<Item = u32> {
    let steps = hive.len().saturating_sub(BASE_BLOCK_LEN) / 8;
    (0..steps).filter_map(|step| u32::try_from(step.checked_mul(8)?).ok())
}

fn child_named(bins: &Bins<'_>, parent: u32, name: &str) -> Option<u32> {
    let key = bins.key(parent)?;
    bins.subkeys(&key)
        .into_iter()
        .find(|&offset| bins.key(offset).is_some_and(|child| child.name.eq_ignore_ascii_case(name)))
}

fn walk_container(
    bins: &Bins<'_>,
    container: u32,
    schema: Schema,
    seen: &mut HashSet<u32>,
    out: &mut Harvested,
) {
    let Some(key) = bins.key(container) else {
        return;
    };

    if schema == Schema::LegacyFile {
        for volume in bins.subkeys(&key) {
            if bins.exhausted() {
                return;
            }
            let Some(volume_key) = bins.key(volume) else {
                continue;
            };
            for entry in bins.subkeys(&volume_key) {
                read_entry(bins, entry, schema, seen, out);
            }
        }
    } else {
        for entry in bins.subkeys(&key) {
            read_entry(bins, entry, schema, seen, out);
        }
    }
}

fn read_entry(
    bins: &Bins<'_>,
    offset: u32,
    schema: Schema,
    seen: &mut HashSet<u32>,
    out: &mut Harvested,
) {
    if !seen.insert(offset) || !bins.spend(4) {
        return;
    }
    let Some(entry) = bins.key(offset) else {
        return;
    };
    let values = bins.values(&entry);

    let (path_value, hash_value) = match schema {
        Schema::InventoryApplicationFile => ("LowerCaseLongPath", "FileId"),
        Schema::InventoryDriverBinary => ("DriverName", "DriverId"),
        Schema::LegacyFile => ("15", "101"),
    };

    let path = string_value(&values, path_value)
        .or_else(|| {
            let usable = schema == Schema::InventoryDriverBinary
                && entry.name_complete
                && entry.name.contains('\\');
            usable.then(|| entry.name.clone())
        })
        .and_then(|raw| NormalizedPath::parse(&raw));

    let hash = string_value(&values, hash_value)
        .and_then(|raw| FileHash::from_amcache_file_id(&raw))
        .unwrap_or_default();

    let when = mm_core::from_filetime(entry.timestamp).or_else(|| {
        if schema == Schema::LegacyFile {
            integer_value(&values, "17").and_then(mm_core::from_filetime)
        } else {
            None
        }
    });

    emit(out, path, hash, when);
}

fn carve_containers(
    bins: &Bins<'_>,
    wanted: &[(&str, Schema)],
    seen: &mut HashSet<u32>,
    out: &mut Harvested,
) {
    for offset in cell_starts(bins.bytes) {
        if bins.exhausted() {
            return;
        }
        let Some((data, _)) = bins.probe(offset) else {
            continue;
        };
        let Some(key) = key_from(data) else {
            continue;
        };
        if !key.name_complete {
            continue;
        }
        for &(name, schema) in wanted {
            if key.name.eq_ignore_ascii_case(name) {
                log::debug!("amcache: carved container {name} at {offset:#x}");
                walk_container(bins, offset, schema, seen, out);
                break;
            }
        }
    }
}

fn emit(
    out: &mut Harvested,
    path: Option<NormalizedPath>,
    hash: FileHash,
    when: Option<DateTime<Utc>>,
) {
    if path.is_none() && hash.is_empty() {
        return;
    }

    out.push(Observation {
        source: ArtifactSource::Amcache,
        kind: ObservationKind::Executed { when, run_count: None },
        path: path.clone(),
        hash: hash.clone(),
    });

    if !hash.is_empty() {
        out.push(Observation {
            source: ArtifactSource::Amcache,
            kind: ObservationKind::HashRecovered,
            path,
            hash,
        });
    }
}

fn string_value(values: &[(String, Value)], name: &str) -> Option<String> {
    let text = match named(values, name)? {
        Value::Text(text) => text.clone(),
        Value::Bytes(bytes) => salvage_text(bytes)?,
        Value::Number(_) => return None,
    };
    let text = text.trim_end_matches('\0').trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn salvage_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let text = decode_utf16(bytes);
    let body = text.trim_end_matches('\0');
    if body.is_empty() || body.chars().any(|c| c.is_control() || c == char::REPLACEMENT_CHARACTER) {
        return None;
    }
    Some(text)
}

fn integer_value(values: &[(String, Value)], name: &str) -> Option<u64> {
    match named(values, name)? {
        Value::Number(value) => Some(*value),
        Value::Bytes(bytes) => match bytes.len() {
            8 => Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)),
            4 => Some(u64::from(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))),
            _ => None,
        },
        Value::Text(text) => text.trim_end_matches('\0').trim().parse().ok(),
    }
}

fn named<'a>(values: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    values
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn decode_value(data_type: u32, bytes: &[u8]) -> Value {
    match data_type {
        1 | 2 | 6 => Value::Text(decode_utf16(bytes)),
        7 => {
            let all = decode_utf16(bytes);
            Value::Text(all.split('\0').next().unwrap_or_default().to_string())
        }
        4 => match le_u32(bytes, 0) {
            Some(value) => Value::Number(u64::from(value)),
            None => Value::Bytes(bytes.to_vec()),
        },
        5 => match bytes.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()) {
            Some(raw) => Value::Number(u64::from(u32::from_be_bytes(raw))),
            None => Value::Bytes(bytes.to_vec()),
        },
        11 => match le_u64(bytes, 0) {
            Some(value) => Value::Number(value),
            None => Value::Bytes(bytes.to_vec()),
        },
        _ => Value::Bytes(bytes.to_vec()),
    }
}

fn decode_name(bytes: &[u8], single_byte: bool) -> String {
    if single_byte {
        bytes.iter().map(|&b| b as char).collect()
    } else {
        decode_utf16(bytes)
    }
}

fn decode_utf16(bytes: &[u8]) -> String {
    let units = bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes);
    char::decode_utf16(units).map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
}

fn le_u16(buf: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_le_bytes(buf.get(at..end)?.try_into().ok()?))
}

fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(buf.get(at..end)?.try_into().ok()?))
}

fn le_i32(buf: &[u8], at: usize) -> Option<i32> {
    le_u32(buf, at).map(|value| value as i32)
}

fn le_u64(buf: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_le_bytes(buf.get(at..end)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    const EMPTY_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const FT_2024: u64 = (1_704_067_200 + 11_644_473_600) * 10_000_000;
    const FT_2023: u64 = (1_686_830_400 + 11_644_473_600) * 10_000_000;

    enum Val {
        Sz(&'static str, String),
        MultiSz(&'static str, Vec<String>),
        Dword(&'static str, u32),
        Qword(&'static str, u64),
        Binary(&'static str, Vec<u8>),
        Mistyped(&'static str, u32, Vec<u8>),
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ListKind {
        FastLeaf,
        HashLeaf,
        IndexLeaf,
        IndexRootOfHashLeaves,
    }

    struct Key {
        name: String,
        timestamp: u64,
        values: Vec<Val>,
        children: Vec<Key>,
        list: ListKind,
    }

    impl Key {
        fn new(name: &str) -> Self {
            Key {
                name: name.into(),
                timestamp: FT_2024,
                values: Vec::new(),
                children: Vec::new(),
                list: ListKind::FastLeaf,
            }
        }
        fn listed_as(mut self, list: ListKind) -> Self {
            self.list = list;
            self
        }
        fn at(mut self, timestamp: u64) -> Self {
            self.timestamp = timestamp;
            self
        }
        fn sz(mut self, name: &'static str, value: &str) -> Self {
            self.values.push(Val::Sz(name, value.into()));
            self
        }
        fn val(mut self, value: Val) -> Self {
            self.values.push(value);
            self
        }
        fn dword(mut self, name: &'static str, value: u32) -> Self {
            self.values.push(Val::Dword(name, value));
            self
        }
        fn qword(mut self, name: &'static str, value: u64) -> Self {
            self.values.push(Val::Qword(name, value));
            self
        }
        fn child(mut self, child: Key) -> Self {
            self.children.push(child);
            self
        }
    }

    struct Bins {
        buf: Vec<u8>,
    }

    impl Bins {
        fn new() -> Self {
            Bins { buf: vec![0u8; 32] }
        }

        fn alloc(&mut self, content: &[u8]) -> u32 {
            let offset = self.buf.len();
            let size = (content.len() + 4).div_ceil(8) * 8;
            let stored = -(size as i32);
            self.buf.extend_from_slice(&stored.to_le_bytes());
            self.buf.extend_from_slice(content);
            self.buf.resize(offset + size, 0);
            offset as u32
        }
    }

    fn utf16(text: &str) -> Vec<u8> {
        let mut raw: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        raw.extend_from_slice(&[0, 0]);
        raw
    }

    fn value_cell(name: &str, data_type: u32, data_size: u32, data_offset: u32) -> Vec<u8> {
        let mut cell = Vec::new();
        cell.extend_from_slice(b"vk");
        cell.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cell.extend_from_slice(&data_size.to_le_bytes());
        cell.extend_from_slice(&data_offset.to_le_bytes());
        cell.extend_from_slice(&data_type.to_le_bytes());
        cell.extend_from_slice(&1u16.to_le_bytes());
        cell.extend_from_slice(&0u16.to_le_bytes());
        cell.extend_from_slice(name.as_bytes());
        cell
    }

    fn build_value(bins: &mut Bins, value: &Val) -> u32 {
        let (name, data_type, raw): (&str, u32, Vec<u8>) = match value {
            Val::Sz(name, text) => (name, 1, utf16(text)),
            Val::MultiSz(name, parts) => {
                let mut raw = Vec::new();
                for part in parts {
                    raw.extend_from_slice(&utf16(part));
                }
                raw.extend_from_slice(&[0, 0]);
                (name, 7, raw)
            }
            Val::Dword(name, v) => (name, 4, v.to_le_bytes().to_vec()),
            Val::Qword(name, v) => (name, 11, v.to_le_bytes().to_vec()),
            Val::Binary(name, bytes) => (name, 3, bytes.clone()),
            Val::Mistyped(name, kind, bytes) => (name, *kind, bytes.clone()),
        };
        let data_offset = bins.alloc(&raw);
        bins.alloc(&value_cell(name, data_type, raw.len() as u32, data_offset))
    }

    fn leaf(bins: &mut Bins, magic: &[u8; 2], items: &[(u32, &str)]) -> u32 {
        let mut content = Vec::new();
        content.extend_from_slice(magic);
        content.extend_from_slice(&(items.len() as u16).to_le_bytes());
        for (offset, name) in items {
            content.extend_from_slice(&offset.to_le_bytes());
            if magic != b"li" {
                let mut hint = [0u8; 4];
                for (slot, byte) in hint.iter_mut().zip(name.as_bytes()) {
                    *slot = *byte;
                }
                content.extend_from_slice(&hint);
            }
        }
        bins.alloc(&content)
    }

    fn build_key(bins: &mut Bins, key: &Key, is_root: bool) -> u32 {
        let value_offsets: Vec<u32> = key.values.iter().map(|v| build_value(bins, v)).collect();
        let values_list = if value_offsets.is_empty() {
            u32::MAX
        } else {
            let mut content = Vec::new();
            for offset in &value_offsets {
                content.extend_from_slice(&offset.to_le_bytes());
            }
            bins.alloc(&content)
        };

        let child_offsets: Vec<(u32, &str)> = key
            .children
            .iter()
            .map(|child| (build_key(bins, child, false), child.name.as_str()))
            .collect();

        let subkeys_list = if child_offsets.is_empty() {
            u32::MAX
        } else {
            match key.list {
                ListKind::FastLeaf => leaf(bins, b"lf", &child_offsets),
                ListKind::HashLeaf => leaf(bins, b"lh", &child_offsets),
                ListKind::IndexLeaf => leaf(bins, b"li", &child_offsets),
                ListKind::IndexRootOfHashLeaves => {
                    let split = child_offsets.len().div_ceil(2);
                    let leaves: Vec<u32> = child_offsets
                        .chunks(split.max(1))
                        .map(|chunk| leaf(bins, b"lh", chunk))
                        .collect();
                    let mut content = Vec::new();
                    content.extend_from_slice(b"ri");
                    content.extend_from_slice(&(leaves.len() as u16).to_le_bytes());
                    for offset in &leaves {
                        content.extend_from_slice(&offset.to_le_bytes());
                    }
                    bins.alloc(&content)
                }
            }
        };

        let name = key.name.as_bytes();
        let mut flags = KEY_COMP_NAME;
        if is_root {
            flags |= KEY_HIVE_ENTRY;
        }

        let mut cell = Vec::new();
        cell.extend_from_slice(b"nk");
        cell.extend_from_slice(&flags.to_le_bytes());
        cell.extend_from_slice(&key.timestamp.to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&(child_offsets.len() as u32).to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        cell.extend_from_slice(&subkeys_list.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&(value_offsets.len() as u32).to_le_bytes());
        cell.extend_from_slice(&values_list.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        for _ in 0..5 {
            cell.extend_from_slice(&0u32.to_le_bytes());
        }
        cell.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cell.extend_from_slice(&0u16.to_le_bytes());
        cell.extend_from_slice(name);
        bins.alloc(&cell)
    }

    fn put32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn wrap(mut bins: Vec<u8>, root_offset: u32) -> Vec<u8> {
        let pad = (BASE_BLOCK_LEN - bins.len() % BASE_BLOCK_LEN) % BASE_BLOCK_LEN;
        bins.resize(bins.len() + pad, 0);
        let bins_size = bins.len() as u32;

        let mut header = Vec::new();
        header.extend_from_slice(b"hbin");
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&bins_size.to_le_bytes());
        header.extend_from_slice(&0u64.to_le_bytes());
        header.extend_from_slice(&FT_2024.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        bins[..32].copy_from_slice(&header);

        let mut block = vec![0u8; BASE_BLOCK_LEN];
        block[..4].copy_from_slice(b"regf");
        put32(&mut block, 0x04, 1);
        put32(&mut block, 0x08, 1);
        block[0x0c..0x14].copy_from_slice(&FT_2024.to_le_bytes());
        put32(&mut block, 0x14, 1);
        put32(&mut block, 0x18, 5);
        put32(&mut block, 0x1c, 0);
        put32(&mut block, 0x20, 1);
        put32(&mut block, 0x24, root_offset);
        put32(&mut block, 0x28, bins_size);
        put32(&mut block, 0x2c, 1);

        let mut xor = 0u32;
        for word in 0..127 {
            xor ^= le_u32(&block, word * 4).unwrap_or(0);
        }
        let checksum = match xor {
            0xffff_ffff => 0xffff_fffe,
            0 => 1,
            other => other,
        };
        put32(&mut block, 0x1fc, checksum);

        block.extend_from_slice(&bins);
        block
    }

    fn build_hive(root: &Key) -> Vec<u8> {
        let mut bins = Bins::new();
        let root_offset = build_key(&mut bins, root, true);
        wrap(bins.buf, root_offset)
    }

    fn win10_hive() -> Vec<u8> {
        build_hive(
            &Key::new("Root").child(
                Key::new("InventoryApplicationFile")
                    .child(
                        Key::new("evil.exe|a1b2c3d4e5f60718")
                            .at(FT_2024)
                            .sz("LowerCaseLongPath", "c:\\users\\bob\\appdata\\roaming\\evil.exe")
                            .sz("FileId", &format!("0000{EMPTY_SHA1}"))
                            .sz("Name", "evil.exe")
                            .sz("Publisher", "")
                            .sz("LinkDate", "05/16/2019 16:07:29")
                            .qword("Size", 73_728)
                            .dword("IsPeFile", 1)
                            .dword("IsOsComponent", 0),
                    )
                    .child(
                        Key::new("notepad.exe|0f0e0d0c0b0a0908")
                            .at(FT_2023)
                            .sz("LowerCaseLongPath", "c:\\windows\\system32\\notepad.exe")
                            .sz("FileId", &format!("0000{}", "b".repeat(40)))
                            .sz("ProductName", "microsoft® windows® operating system"),
                    ),
            ),
        )
    }

    fn win7_hive() -> Vec<u8> {
        build_hive(
            &Key::new("CMI-CreateHive{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}").child(
                Key::new("Root").child(
                    Key::new("File").child(
                        Key::new("{c9b0a5f2-0000-0000-0000-100000000000}").child(
                            Key::new("10000000000c5")
                                .at(FT_2023)
                                .sz("0", "Evil Product")
                                .sz("1", "Evil Corp")
                                .sz("15", "c:\\temp\\dropper.exe")
                                .sz("101", &format!("0000{EMPTY_SHA1}"))
                                .qword("17", FT_2024)
                                .dword("f", 1_557_936_449),
                        ),
                    ),
                ),
            ),
        )
    }

    fn executed(out: &Harvested) -> Vec<&Observation> {
        out.iter().filter(|o| matches!(o.kind, ObservationKind::Executed { .. })).collect()
    }

    fn recovered(out: &Harvested) -> Vec<&Observation> {
        out.iter().filter(|o| matches!(o.kind, ObservationKind::HashRecovered)).collect()
    }

    fn keys_of(out: &Harvested) -> Vec<String> {
        executed(out).iter().filter_map(|o| o.path.as_ref().map(|p| p.key().to_string())).collect()
    }

    fn harvest_within(bytes: Vec<u8>, limit: Duration) -> Option<Harvested> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(harvest(&bytes));
        });
        rx.recv_timeout(limit).ok()
    }

    const PATIENCE: Duration = Duration::from_secs(30);

    #[test]
    fn windows_10_entries_yield_path_and_sha1() {
        let out = harvest(&win10_hive());

        let runs = executed(&out);
        assert_eq!(runs.len(), 2, "one Executed per entry");
        let evil = runs
            .iter()
            .find(|o| o.path.as_ref().unwrap().file_name() == Some("evil.exe"))
            .expect("evil.exe");
        assert_eq!(evil.path.as_ref().unwrap().key(), "\\users\\bob\\appdata\\roaming\\evil.exe");
        assert_eq!(evil.hash.sha1_hex().as_deref(), Some(EMPTY_SHA1));
        assert_eq!(
            evil.timestamp(),
            Some(DateTime::from_timestamp(1_704_067_200, 0).unwrap()),
            "the key's last-write time is the execution time"
        );

        assert_eq!(recovered(&out).len(), 2, "one HashRecovered per hashed entry");
        assert!(out.iter().all(|o| o.source == ArtifactSource::Amcache));
        assert!(out.iter().all(|o| o.identifies_something()));
    }

    #[test]
    fn windows_7_numbered_values_yield_path_and_sha1() {
        let out = harvest(&win7_hive());

        let runs = executed(&out);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].path.as_ref().unwrap().key(), "\\temp\\dropper.exe");
        assert_eq!(runs[0].hash.sha1_hex().as_deref(), Some(EMPTY_SHA1));
        assert_eq!(runs[0].timestamp(), Some(DateTime::from_timestamp(1_686_830_400, 0).unwrap()));
        assert_eq!(recovered(&out).len(), 1);
    }

    #[test]
    fn both_schemas_are_read_from_one_hive() {
        let hive = build_hive(
            &Key::new("Root")
                .child(
                    Key::new("InventoryApplicationFile").child(
                        Key::new("new.exe|1111111111111111")
                            .sz("LowerCaseLongPath", "c:\\new.exe")
                            .sz("FileId", &format!("0000{EMPTY_SHA1}")),
                    ),
                )
                .child(
                    Key::new("File").child(
                        Key::new("{11111111-2222-3333-4444-555555555555}").child(
                            Key::new("2000000000001")
                                .sz("15", "c:\\old.exe")
                                .sz("101", &format!("0000{}", "c".repeat(40))),
                        ),
                    ),
                ),
        );

        let keys = keys_of(&harvest(&hive));
        assert!(keys.iter().any(|k| k == "\\new.exe"), "{keys:?}");
        assert!(keys.iter().any(|k| k == "\\old.exe"), "{keys:?}");
    }

    #[test]
    fn every_subkey_list_layout_walks() {
        for layout in [
            ListKind::FastLeaf,
            ListKind::HashLeaf,
            ListKind::IndexLeaf,
            ListKind::IndexRootOfHashLeaves,
        ] {
            let mut container = Key::new("InventoryApplicationFile").listed_as(layout);
            for n in 0..9 {
                container = container.child(
                    Key::new(&format!("m{n}.exe|{n}"))
                        .sz("LowerCaseLongPath", &format!("c:\\m{n}.exe"))
                        .sz("FileId", &format!("0000{EMPTY_SHA1}")),
                );
            }
            let out = harvest(&build_hive(&Key::new("Root").child(container)));
            assert_eq!(executed(&out).len(), 9, "layout did not walk fully");
            assert_eq!(recovered(&out).len(), 9);
        }
    }

    #[test]
    fn a_file_id_without_the_zero_prefix_still_parses() {
        let hive = build_hive(
            &Key::new("Root").child(
                Key::new("InventoryApplicationFile").child(
                    Key::new("bare.exe|1")
                        .sz("LowerCaseLongPath", "c:\\bare.exe")
                        .sz("FileId", &EMPTY_SHA1.to_uppercase()),
                ),
            ),
        );
        let out = harvest(&hive);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].hash.sha1_hex().as_deref(), Some(EMPTY_SHA1));
    }

    #[test]
    fn driver_binaries_are_harvested() {
        let hive = build_hive(
            &Key::new("Root").child(
                Key::new("InventoryDriverBinary")
                    .child(
                        Key::new("c:\\windows\\system32\\drivers\\vuln.sys")
                            .sz("DriverName", "c:\\windows\\system32\\drivers\\vuln.sys")
                            .sz("DriverId", &format!("0000{EMPTY_SHA1}")),
                    )
                    .child(Key::new("c:\\windows\\system32\\drivers\\nameless.sys")),
            ),
        );

        let keys = keys_of(&harvest(&hive));
        assert!(keys.iter().any(|k| k == "\\windows\\system32\\drivers\\vuln.sys"), "{keys:?}");
        assert!(keys.iter().any(|k| k == "\\windows\\system32\\drivers\\nameless.sys"), "{keys:?}");
        assert_eq!(recovered(&harvest(&hive)).len(), 1);
    }

    #[test]
    fn a_hash_with_no_path_is_still_reported() {
        let hive = build_hive(
            &Key::new("Root").child(
                Key::new("InventoryApplicationFile")
                    .child(Key::new("gone.exe|9999").sz("FileId", &format!("0000{EMPTY_SHA1}"))),
            ),
        );

        let out = harvest(&hive);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|o| o.path.is_none()));
        assert!(out.iter().all(|o| o.hash.sha1_hex().as_deref() == Some(EMPTY_SHA1)));
        assert!(out.iter().all(|o| o.identifies_something()));
    }

    #[test]
    fn entries_naming_nothing_are_skipped() {
        let hive = build_hive(
            &Key::new("Root").child(
                Key::new("InventoryApplicationFile")
                    .child(Key::new("orphan.exe|1234").sz("ProductName", "whatever"))
                    .child(Key::new("empty.exe|5678").sz("LowerCaseLongPath", "")),
            ),
        );
        assert!(harvest(&hive).is_empty());
    }

    #[test]
    fn a_malformed_file_id_loses_only_the_hash() {
        let hive = build_hive(
            &Key::new("Root").child(
                Key::new("InventoryApplicationFile").child(
                    Key::new("evil.exe|1")
                        .sz("LowerCaseLongPath", "c:\\evil.exe")
                        .sz("FileId", "0000not-a-hash"),
                ),
            ),
        );

        let out = harvest(&hive);
        assert_eq!(out.len(), 1, "path survives, hash does not");
        assert!(out[0].hash.is_empty());
        assert_eq!(out[0].path.as_ref().unwrap().key(), "\\evil.exe");
    }

    #[test]
    fn an_unusable_key_timestamp_falls_back_or_reports_nothing() {
        let hive = build_hive(
            &Key::new("Root").child(
                Key::new("File").child(
                    Key::new("{0-0}")
                        .child(
                            Key::new("with_value_17")
                                .at(0)
                                .sz("15", "c:\\a.exe")
                                .qword("17", FT_2024),
                        )
                        .child(Key::new("without").at(0).sz("15", "c:\\b.exe")),
                ),
            ),
        );

        let out = harvest(&hive);
        let with = executed(&out)
            .into_iter()
            .find(|o| o.path.as_ref().unwrap().key() == "\\a.exe")
            .unwrap();
        assert_eq!(with.timestamp(), Some(DateTime::from_timestamp(1_704_067_200, 0).unwrap()));

        let without = executed(&out)
            .into_iter()
            .find(|o| o.path.as_ref().unwrap().key() == "\\b.exe")
            .unwrap();
        assert_eq!(without.timestamp(), None);
    }

    #[test]
    fn the_link_date_is_never_used_as_an_execution_time() {
        let hive =
            build_hive(&Key::new("Root").child(Key::new("File").child(Key::new("{0-0}").child(
                Key::new("only_link_date").at(0).sz("15", "c:\\a.exe").dword("f", 1_557_936_449),
            ))));
        assert_eq!(executed(&harvest(&hive))[0].timestamp(), None);
    }

    #[test]
    fn value_17_is_read_from_every_width_it_is_written_in() {
        for value in [Val::Qword("17", FT_2024), Val::Binary("17", FT_2024.to_le_bytes().to_vec())]
        {
            let hive = build_hive(&Key::new("Root").child(Key::new("File").child(
                Key::new("{0-0}").child(Key::new("e").at(0).sz("15", "c:\\a.exe").val(value)),
            )));
            assert_eq!(
                executed(&harvest(&hive))[0].timestamp(),
                Some(DateTime::from_timestamp(1_704_067_200, 0).unwrap())
            );
        }
    }

    #[test]
    fn every_string_encoding_of_a_path_decodes() {
        let cases: Vec<(Val, &str)> = vec![
            (Val::Sz("LowerCaseLongPath", "c:\\a.exe".into()), "\\a.exe"),
            (Val::Mistyped("LowerCaseLongPath", 2, utf16("c:\\b.exe")), "\\b.exe"),
            (
                Val::MultiSz("LowerCaseLongPath", vec!["c:\\c.exe".into(), "ignored".into()]),
                "\\c.exe",
            ),
            (Val::Mistyped("LowerCaseLongPath", 3, utf16("c:\\d.exe")), "\\d.exe"),
        ];
        for (value, expected) in cases {
            let hive = build_hive(
                &Key::new("Root")
                    .child(Key::new("InventoryApplicationFile").child(Key::new("e|1").val(value))),
            );
            let keys = keys_of(&harvest(&hive));
            assert!(keys.iter().any(|k| k == expected), "{expected} missing from {keys:?}");
        }
    }

    #[test]
    fn a_data_size_larger_than_its_cell_does_not_read_the_next_cell() {
        let mut bins = Bins::new();
        let raw = utf16("c:\\a.exe");
        let data = bins.alloc(&raw);
        let _ = bins.alloc(&utf16("STOWAWAY"));
        let vk = bins.alloc(&value_cell("LowerCaseLongPath", 1, 4096, data));
        let values = bins.alloc(&vk.to_le_bytes());
        let entry = build_node(&mut bins, "e|1", KEY_COMP_NAME, FT_2024, 0, u32::MAX, 1, values);
        let list = leaf(&mut bins, b"lf", &[(entry, "e")]);
        let container = build_container(&mut bins, "InventoryApplicationFile", 1, list);
        let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
        let root = build_root(&mut bins, root_list);

        let keys = keys_of(&harvest(&wrap(bins.buf, root)));
        assert_eq!(keys, vec!["\\a.exe".to_string()], "over-read past the value's cell");
    }

    #[test]
    fn binary_data_is_not_mistaken_for_a_path() {
        let hive = build_hive(
            &Key::new("Root").child(
                Key::new("InventoryApplicationFile").child(
                    Key::new("e|1")
                        .val(Val::Binary("LowerCaseLongPath", vec![0x01, 0x00, 0x02, 0x00]))
                        .val(Val::Binary("FileId", vec![0xde, 0xad, 0xbe, 0xef])),
                ),
            ),
        );
        assert!(harvest(&hive).is_empty());
    }

    #[test]
    fn a_value_split_across_big_data_segments_reassembles() {
        let mut bins = Bins::new();
        let long = format!("c:\\{}\\x.exe", "d".repeat(9_000));
        let raw = utf16(&long);
        let segments: Vec<u32> =
            raw.chunks(BIG_DATA_SEGMENT).map(|chunk| bins.alloc(chunk)).collect();
        assert!(segments.len() >= 2, "fixture must actually be split");

        let mut list = Vec::new();
        for offset in &segments {
            list.extend_from_slice(&offset.to_le_bytes());
        }
        let list_offset = bins.alloc(&list);

        let mut db = Vec::new();
        db.extend_from_slice(b"db");
        db.extend_from_slice(&(segments.len() as u16).to_le_bytes());
        db.extend_from_slice(&list_offset.to_le_bytes());
        let db_offset = bins.alloc(&db);

        let vk = bins.alloc(&value_cell("LowerCaseLongPath", 1, raw.len() as u32, db_offset));
        let values = bins.alloc(&vk.to_le_bytes());

        let entry = {
            let mut cell = Vec::new();
            cell.extend_from_slice(b"nk");
            cell.extend_from_slice(&KEY_COMP_NAME.to_le_bytes());
            cell.extend_from_slice(&FT_2024.to_le_bytes());
            cell.extend_from_slice(&0u32.to_le_bytes());
            cell.extend_from_slice(&u32::MAX.to_le_bytes());
            cell.extend_from_slice(&0u32.to_le_bytes());
            cell.extend_from_slice(&0u32.to_le_bytes());
            cell.extend_from_slice(&u32::MAX.to_le_bytes());
            cell.extend_from_slice(&u32::MAX.to_le_bytes());
            cell.extend_from_slice(&1u32.to_le_bytes());
            cell.extend_from_slice(&values.to_le_bytes());
            cell.extend_from_slice(&u32::MAX.to_le_bytes());
            cell.extend_from_slice(&u32::MAX.to_le_bytes());
            for _ in 0..5 {
                cell.extend_from_slice(&0u32.to_le_bytes());
            }
            cell.extend_from_slice(&3u16.to_le_bytes());
            cell.extend_from_slice(&0u16.to_le_bytes());
            cell.extend_from_slice(b"e|1");
            bins.alloc(&cell)
        };
        let container_list = leaf(&mut bins, b"lf", &[(entry, "e|1")]);
        let container = build_container(&mut bins, "InventoryApplicationFile", 1, container_list);
        let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
        let root = build_root(&mut bins, root_list);

        let out = harvest(&wrap(bins.buf, root));
        assert_eq!(executed(&out).len(), 1);
        assert_eq!(
            executed(&out)[0].path.as_ref().unwrap().key().len(),
            long.len() - 2,
            "the whole path came back"
        );
    }

    fn build_container(bins: &mut Bins, name: &str, subkeys: u32, list: u32) -> u32 {
        build_node(bins, name, KEY_COMP_NAME, FT_2024, subkeys, list, 0, u32::MAX)
    }

    fn build_root(bins: &mut Bins, list: u32) -> u32 {
        build_node(bins, "Root", KEY_COMP_NAME | KEY_HIVE_ENTRY, FT_2024, 1, list, 0, u32::MAX)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_node(
        bins: &mut Bins,
        name: &str,
        flags: u16,
        timestamp: u64,
        subkey_count: u32,
        subkeys_list: u32,
        value_count: u32,
        values_list: u32,
    ) -> u32 {
        let mut cell = Vec::new();
        cell.extend_from_slice(b"nk");
        cell.extend_from_slice(&flags.to_le_bytes());
        cell.extend_from_slice(&timestamp.to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&subkey_count.to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        cell.extend_from_slice(&subkeys_list.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&value_count.to_le_bytes());
        cell.extend_from_slice(&values_list.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        for _ in 0..5 {
            cell.extend_from_slice(&0u32.to_le_bytes());
        }
        cell.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cell.extend_from_slice(&0u16.to_le_bytes());
        cell.extend_from_slice(name.as_bytes());
        bins.alloc(&cell)
    }

    #[test]
    fn nothing_is_filtered_for_being_boring() {
        let keys = keys_of(&harvest(&win10_hive()));
        assert!(keys.iter().any(|k| k == "\\windows\\system32\\notepad.exe"));
    }

    #[test]
    fn a_hive_without_amcache_keys_yields_nothing() {
        let hive =
            build_hive(&Key::new("Root").child(Key::new("DeviceCensus").sz("OSVersion", "10.0")));
        assert!(harvest(&hive).is_empty());
    }

    #[test]
    fn a_zero_length_buffer_yields_nothing() {
        assert!(harvest(&[]).is_empty());
    }

    #[test]
    fn buffers_that_are_not_hives_yield_nothing() {
        assert!(harvest(b"not a hive at all").is_empty());
        assert!(harvest(&[0u8]).is_empty());
        assert!(harvest(&vec![0u8; 8192]).is_empty());
        assert!(harvest(&vec![0xffu8; 8192]).is_empty());
        let mut noise = vec![0u8; 16384];
        for (i, byte) in noise.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        assert!(harvest(&noise).len() <= 1024, "noise must not explode");
    }

    #[test]
    fn truncation_at_every_single_length_never_fails() {
        let hive = win10_hive();
        for cut in 0..=hive.len() {
            let _ = harvest(&hive[..cut]);
        }
    }

    #[test]
    fn a_corrupt_base_block_is_recovered_from() {
        for smash_at in [0x00usize, 0x04, 0x14, 0x18, 0x1c, 0x28, 0x1fc] {
            let mut hive = win10_hive();
            put32(&mut hive, smash_at, 0xdead_beef);
            let out = harvest(&hive);
            assert_eq!(executed(&out).len(), 2, "smashed base block field {smash_at:#x}");
        }
    }

    #[test]
    fn a_wiped_base_block_is_recovered_from() {
        let mut hive = win10_hive();
        hive[..BASE_BLOCK_LEN].fill(0);
        assert_eq!(executed(&harvest(&hive)).len(), 2);
    }

    #[test]
    fn a_destroyed_root_still_yields_its_containers() {
        let mut hive = win10_hive();
        hive[..BASE_BLOCK_LEN].fill(0);
        let root_at = hive.windows(4).position(|w| w == b"Root").expect("fixture has a Root key");
        let nk_at = root_at - 76;
        hive[nk_at..nk_at + 2].copy_from_slice(b"XX");
        assert_eq!(executed(&harvest(&hive)).len(), 2, "carving did not recover the entries");
    }

    #[test]
    fn a_container_the_tree_lost_is_carved_back_without_duplicates() {
        let mut hive = build_hive(
            &Key::new("Root")
                .child(
                    Key::new("InventoryApplicationFile").child(
                        Key::new("new.exe|1")
                            .sz("LowerCaseLongPath", "c:\\new.exe")
                            .sz("FileId", &format!("0000{EMPTY_SHA1}")),
                    ),
                )
                .child(
                    Key::new("File").child(
                        Key::new("{1-1}").child(
                            Key::new("2000000000001")
                                .sz("15", "c:\\old.exe")
                                .sz("101", &format!("0000{}", "c".repeat(40))),
                        ),
                    ),
                ),
        );
        assert_eq!(executed(&harvest(&hive)).len(), 2);

        let root = le_u32(&hive, 0x24).unwrap();
        let root_cell = BASE_BLOCK_LEN + root as usize + 4;
        let list_cell = BASE_BLOCK_LEN + le_u32(&hive, root_cell + 0x1c).unwrap() as usize + 4;
        hive[root_cell + 0x14..root_cell + 0x18].copy_from_slice(&1u32.to_le_bytes());
        hive[list_cell + 2..list_cell + 4].copy_from_slice(&1u16.to_le_bytes());

        let out = harvest(&hive);
        let keys = keys_of(&out);
        assert_eq!(keys.iter().filter(|k| *k == "\\new.exe").count(), 1, "{keys:?}");
        assert_eq!(keys.iter().filter(|k| *k == "\\old.exe").count(), 1, "{keys:?}");
    }

    #[test]
    fn one_broken_entry_does_not_cost_its_siblings() {
        let mut container = Key::new("InventoryApplicationFile");
        for n in 0..40 {
            container = container.child(
                Key::new(&format!("m{n:02}.exe|{n}"))
                    .sz("LowerCaseLongPath", &format!("c:\\m{n:02}.exe"))
                    .sz("FileId", &format!("0000{EMPTY_SHA1}")),
            );
        }
        let clean = build_hive(&Key::new("Root").child(container));
        assert_eq!(executed(&harvest(&clean)).len(), 40);

        let target = clean
            .windows(11)
            .position(|w| w == b"m20.exe|20\0" || w.starts_with(b"m20.exe|20"))
            .expect("fixture entry");
        let nk_at = target - 76;
        for (label, patch) in [
            ("magic", (nk_at, vec![0x5a, 0x5a])),
            ("flags", (nk_at + 2, vec![0xff, 0xff])),
            ("name length", (nk_at + 0x48, vec![0xff, 0xff])),
            ("cell size", (nk_at - 4, vec![0x01, 0x00, 0x00, 0x00])),
            ("values list", (nk_at + 0x28, vec![0xff, 0xff, 0x7f, 0x7f])),
        ] {
            let mut hive = clean.clone();
            let (at, bytes) = patch;
            hive[at..at + bytes.len()].copy_from_slice(&bytes);
            let survivors = executed(&harvest(&hive)).len();
            assert!(
                survivors >= 39,
                "breaking the {label} of one entry cost {} of 40 entries",
                40 - survivors
            );
        }
    }

    #[test]
    fn absurd_counts_and_offsets_never_fail() {
        let clean = win10_hive();
        for poison in [0xffff_ffffu32, 0x7fff_ffff, 0x8000_0000, 0xdead_beef, 1, 0] {
            let mut at = BASE_BLOCK_LEN;
            while at + 4 <= clean.len() {
                let mut hive = clean.clone();
                put32(&mut hive, at, poison);
                let _ = harvest(&hive);
                at += 4;
            }
        }
    }

    #[test]
    fn exhaustive_single_byte_corruption_never_fails() {
        let clean = build_hive(
            &Key::new("Root").child(
                Key::new("InventoryApplicationFile").child(
                    Key::new("e.exe|1")
                        .sz("LowerCaseLongPath", "c:\\e.exe")
                        .sz("FileId", &format!("0000{EMPTY_SHA1}")),
                ),
            ),
        );
        for at in BASE_BLOCK_LEN..clean.len() {
            for mask in [0xffu8, 0x01, 0x80] {
                let mut hive = clean.clone();
                hive[at] ^= mask;
                let _ = harvest(&hive);
            }
        }
    }

    #[test]
    fn self_referential_structures_terminate() {
        let mut bins = Bins::new();
        let here = bins.buf.len() as u32;
        let list = bins.alloc(&{
            let mut c = Vec::new();
            c.extend_from_slice(b"lf");
            c.extend_from_slice(&1u16.to_le_bytes());
            c.extend_from_slice(&here.to_le_bytes());
            c.extend_from_slice(&[0; 4]);
            c
        });
        let container = build_container(&mut bins, "InventoryApplicationFile", 1, list);
        let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
        let root = build_root(&mut bins, root_list);
        assert!(harvest_within(wrap(bins.buf, root), PATIENCE).is_some(), "self-list hung");

        let mut bins = Bins::new();
        let node = build_container(&mut bins, "File", 1, u32::MAX);
        let list = leaf(&mut bins, b"lf", &[(node, "File")]);
        let field = node as usize + 4 + 0x1c;
        bins.buf[field..field + 4].copy_from_slice(&list.to_le_bytes());
        let root_list = leaf(&mut bins, b"lf", &[(node, "File")]);
        let root = build_root(&mut bins, root_list);
        assert!(harvest_within(wrap(bins.buf, root), PATIENCE).is_some(), "self-key hung");
    }

    #[test]
    fn nested_index_roots_terminate() {
        let mut bins = Bins::new();
        let here = bins.buf.len() as u32;
        let ri = bins.alloc(&{
            let mut c = Vec::new();
            c.extend_from_slice(b"ri");
            c.extend_from_slice(&2u16.to_le_bytes());
            c.extend_from_slice(&here.to_le_bytes());
            c.extend_from_slice(&(here + 8).to_le_bytes());
            c
        });
        let inner = bins.alloc(&{
            let mut c = Vec::new();
            c.extend_from_slice(b"ri");
            c.extend_from_slice(&1u16.to_le_bytes());
            c.extend_from_slice(&ri.to_le_bytes());
            c
        });
        let _ = inner;
        let container = build_container(&mut bins, "InventoryApplicationFile", 9, ri);
        let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
        let root = build_root(&mut bins, root_list);
        assert!(harvest_within(wrap(bins.buf, root), PATIENCE).is_some(), "nested ri hung");
    }

    #[test]
    fn a_small_hive_cannot_name_billions_of_subkeys() {
        let mut bins = Bins::new();
        let entry = build_container(&mut bins, "e.exe|1", 0, u32::MAX);
        let mut leaf_cell = Vec::new();
        leaf_cell.extend_from_slice(b"lh");
        leaf_cell.extend_from_slice(&2000u16.to_le_bytes());
        for _ in 0..2000 {
            leaf_cell.extend_from_slice(&entry.to_le_bytes());
            leaf_cell.extend_from_slice(&[0; 4]);
        }
        let lh = bins.alloc(&leaf_cell);
        let mut ri_cell = Vec::new();
        ri_cell.extend_from_slice(b"ri");
        ri_cell.extend_from_slice(&2000u16.to_le_bytes());
        for _ in 0..2000 {
            ri_cell.extend_from_slice(&lh.to_le_bytes());
        }
        let ri = bins.alloc(&ri_cell);
        let container = build_container(&mut bins, "InventoryApplicationFile", 4_000_000, ri);
        let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
        let root = build_root(&mut bins, root_list);

        let started = std::time::Instant::now();
        let out = harvest_within(wrap(bins.buf, root), PATIENCE).expect("hung");
        assert!(out.is_empty(), "the repeated entry names nothing, so it reports nothing");
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    #[test]
    fn counts_larger_than_their_cell_are_clamped() {
        for count in [u32::MAX, 0x7fff_ffff, 0x0010_0000, 1] {
            let mut bins = Bins::new();
            let entry = build_container(&mut bins, "e.exe|1", 0, u32::MAX);
            let list = bins.alloc(&{
                let mut c = Vec::new();
                c.extend_from_slice(b"lf");
                c.extend_from_slice(&0xffffu16.to_le_bytes());
                c.extend_from_slice(&entry.to_le_bytes());
                c.extend_from_slice(&[0; 4]);
                c
            });
            let container = build_container(&mut bins, "InventoryApplicationFile", count, list);
            let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
            let root = build_root(&mut bins, root_list);
            assert!(
                harvest_within(wrap(bins.buf, root), PATIENCE).is_some(),
                "hung at count {count:#x}"
            );
        }

        for count in [u32::MAX, 0x7fff_ffff, 0x0010_0000] {
            let mut bins = Bins::new();
            let entry =
                build_node(&mut bins, "e.exe|1", KEY_COMP_NAME, FT_2024, 0, u32::MAX, count, 0);
            let list = leaf(&mut bins, b"lf", &[(entry, "e")]);
            let container = build_container(&mut bins, "InventoryApplicationFile", 1, list);
            let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
            let root = build_root(&mut bins, root_list);
            assert!(
                harvest_within(wrap(bins.buf, root), PATIENCE).is_some(),
                "hung at value count {count:#x}"
            );
        }
    }

    #[test]
    fn hostile_offsets_are_refused() {
        for list_offset in [0u32, 1, 8, 0x7fff_ffff, u32::MAX, 0xffff_fff8, 0x8000_0000] {
            let mut bins = Bins::new();
            let container = build_container(&mut bins, "InventoryApplicationFile", 5, list_offset);
            let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
            let root = build_root(&mut bins, root_list);
            assert!(
                harvest_within(wrap(bins.buf, root), PATIENCE).is_some(),
                "hung at list offset {list_offset:#x}"
            );
        }
    }

    #[test]
    fn hostile_value_data_is_refused() {
        for (size, offset) in [
            (0xffff_ffffu32, 0u32),
            (0x7fff_ffff, 0),
            (0x0000_ffff, 0x7fff_0000),
            (16_345, 0),
            (0x8000_0005, 0),
            (0x8000_0004, 0xffff_ffff),
            (0, 0xffff_ffff),
            (0xffff, u32::MAX),
        ] {
            let mut bins = Bins::new();
            let vk = bins.alloc(&value_cell("LowerCaseLongPath", 1, size, offset));
            let values = bins.alloc(&vk.to_le_bytes());
            let entry =
                build_node(&mut bins, "e.exe|1", KEY_COMP_NAME, FT_2024, 0, u32::MAX, 1, values);
            let list = leaf(&mut bins, b"lf", &[(entry, "e")]);
            let container = build_container(&mut bins, "InventoryApplicationFile", 1, list);
            let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
            let root = build_root(&mut bins, root_list);
            assert!(
                harvest_within(wrap(bins.buf, root), PATIENCE).is_some(),
                "hung at ({size:#x}, {offset:#x})"
            );
        }
    }

    #[test]
    fn a_hostile_big_data_block_is_refused() {
        let mut bins = Bins::new();
        let segment_list = bins.alloc(&[0xffu8; 16]);
        let mut db = Vec::new();
        db.extend_from_slice(b"db");
        db.extend_from_slice(&0xffffu16.to_le_bytes());
        db.extend_from_slice(&segment_list.to_le_bytes());
        let db_offset = bins.alloc(&db);
        let vk = bins.alloc(&value_cell("LowerCaseLongPath", 1, 20_000, db_offset));
        let values = bins.alloc(&vk.to_le_bytes());
        let entry =
            build_node(&mut bins, "e.exe|1", KEY_COMP_NAME, FT_2024, 0, u32::MAX, 1, values);
        let list = leaf(&mut bins, b"lf", &[(entry, "e")]);
        let container = build_container(&mut bins, "InventoryApplicationFile", 1, list);
        let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
        let root = build_root(&mut bins, root_list);
        assert!(harvest_within(wrap(bins.buf, root), PATIENCE).is_some(), "hung");
    }

    #[test]
    fn a_truncated_key_name_never_becomes_a_path() {
        let mut bins = Bins::new();
        let mut cell = Vec::new();
        cell.extend_from_slice(b"nk");
        cell.extend_from_slice(&KEY_COMP_NAME.to_le_bytes());
        cell.extend_from_slice(&FT_2024.to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&0u32.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        cell.extend_from_slice(&u32::MAX.to_le_bytes());
        for _ in 0..5 {
            cell.extend_from_slice(&0u32.to_le_bytes());
        }
        cell.extend_from_slice(&0xffffu16.to_le_bytes());
        cell.extend_from_slice(&0u16.to_le_bytes());
        cell.extend_from_slice(b"c:\\windows\\system32\\drivers\\evil.sys");
        let entry = bins.alloc(&cell);
        let list = leaf(&mut bins, b"lf", &[(entry, "e")]);
        let container = build_container(&mut bins, "InventoryDriverBinary", 1, list);
        let root_list = leaf(&mut bins, b"lf", &[(container, "c")]);
        let root = build_root(&mut bins, root_list);
        assert!(
            harvest(&wrap(bins.buf, root)).is_empty(),
            "a name the hive could not finish must not be reported as a path"
        );
    }

    #[test]
    fn a_valid_header_over_garbage_yields_nothing_and_returns() {
        let mut bins = Bins::new();
        let root = build_root(&mut bins, 0x800);
        bins.buf.resize(16_384, 0);
        for (i, byte) in bins.buf[0x400..].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(97).wrapping_add(13);
        }
        assert!(harvest_within(wrap(bins.buf, root), PATIENCE).is_some(), "hung");
    }

    #[test]
    fn random_input_never_fails_and_never_hangs() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..200 {
            let len = 4096 + (next() as usize % 20_000);
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if round % 2 == 0 {
                buf[..4].copy_from_slice(b"regf");
            }
            assert!(harvest_within(buf, PATIENCE).is_some(), "hung on random input, round {round}");
        }
    }

    #[test]
    fn registry_value_types_decode() {
        let text = utf16("c:\\a.exe");
        assert!(
            matches!(decode_value(1, &text), Value::Text(t) if t.trim_end_matches('\0') == "c:\\a.exe")
        );
        assert!(
            matches!(decode_value(2, &text), Value::Text(t) if t.trim_end_matches('\0') == "c:\\a.exe")
        );
        assert!(
            matches!(decode_value(6, &text), Value::Text(t) if t.trim_end_matches('\0') == "c:\\a.exe")
        );

        let mut multi = utf16("first");
        multi.extend_from_slice(&utf16("second"));
        multi.extend_from_slice(&[0, 0]);
        assert!(matches!(decode_value(7, &multi), Value::Text(t) if t == "first"));

        assert!(matches!(decode_value(4, &7u32.to_le_bytes()), Value::Number(7)));
        assert!(matches!(decode_value(5, &7u32.to_be_bytes()), Value::Number(7)));
        assert!(
            matches!(decode_value(11, &FT_2024.to_le_bytes()), Value::Number(v) if v == FT_2024)
        );
        assert!(matches!(decode_value(3, &[1, 2, 3]), Value::Bytes(b) if b == vec![1, 2, 3]));
        assert!(matches!(decode_value(0xdead, &[9]), Value::Bytes(b) if b == vec![9]));
        assert!(matches!(decode_value(11, &[1, 2]), Value::Bytes(_)));
        assert!(matches!(decode_value(1, &[0x41, 0x00, 0x42]), Value::Text(t) if t == "A"));
    }

    #[test]
    fn an_entry_in_a_freed_cell_is_still_read() {
        let mut hive = win10_hive();
        let name_at = hive.windows(8).position(|w| w == b"evil.exe").expect("fixture entry");
        let size_at = name_at - 76 - 4;
        let size = i32::from_le_bytes(hive[size_at..size_at + 4].try_into().unwrap());
        assert!(size < 0, "fixture cell should start out allocated");
        hive[size_at..size_at + 4].copy_from_slice(&(-size).to_le_bytes());

        let keys = keys_of(&harvest(&hive));
        assert!(
            keys.iter().any(|k| k == "\\users\\bob\\appdata\\roaming\\evil.exe"),
            "a freed entry cell must still be read: {keys:?}"
        );
    }

    #[test]
    fn a_large_hive_with_no_base_block_still_reports_everything() {
        let mut bins = Bins::new();
        bins.buf.resize(8 * 1024 * 1024, 0);
        let mut container = Key::new("InventoryApplicationFile");
        for n in 0..50 {
            container = container.child(
                Key::new(&format!("m{n:02}.exe|{n}"))
                    .sz("LowerCaseLongPath", &format!("c:\\m{n:02}.exe"))
                    .sz("FileId", &format!("0000{EMPTY_SHA1}")),
            );
        }
        let root_offset = build_key(&mut bins, &Key::new("Root").child(container), true);
        let mut hive = wrap(bins.buf, root_offset);
        hive[..BASE_BLOCK_LEN].fill(0);

        let out = harvest_within(hive, PATIENCE).expect("hung");
        assert_eq!(executed(&out).len(), 50, "the scan starved the walk of budget");
    }

    #[test]
    fn the_recovery_scan_finishes_on_a_large_hive() {
        let buf = vec![0u8; 64 * 1024 * 1024];
        let started = std::time::Instant::now();
        assert!(harvest_within(buf, PATIENCE).is_some(), "recovery scan hung");
        assert!(started.elapsed() < Duration::from_secs(20), "took {:?}", started.elapsed());
    }
}
