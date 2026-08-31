use std::collections::HashSet;

use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind};

use crate::Harvested;

const VALUE_NAME: &str = "AppCompatCache";

const CACHE_KEY_PATHS: [&str; 2] =
    ["Control\\Session Manager\\AppCompatCache", "Control\\Session Manager\\AppCompatibility"];

pub fn harvest(system_hive: &[u8]) -> Harvested {
    let mut out = Vec::new();
    let mut seen: HashSet<(String, u64)> = HashSet::new();

    for blob in collect_blobs(system_hive) {
        for entry in parse_cache(&blob) {
            let Some(path) = NormalizedPath::parse(&entry.path) else {
                continue;
            };
            if !seen.insert((path.key().to_string(), entry.last_modified)) {
                continue;
            }
            out.push(Observation::about_path(
                ArtifactSource::ShimCache,
                path,
                ObservationKind::Executed {
                    when: mm_core::from_filetime(entry.last_modified),
                    run_count: None,
                },
            ));
        }
    }
    out
}

const BASE_BLOCK_SIZE: usize = 4096;
const BIG_DATA_SEGMENT_SIZE: usize = 16344;
const VK_HEADER_LEN: usize = 20;
const REG_BINARY: u32 = 3;
const VALUE_COMP_NAME: u16 = 0x0001;

const KEY_COMP_NAME: u16 = 0x0020;
const MAX_LIST_ENTRIES: usize = u16::MAX as usize;

const MAX_CELL_VISITS: u32 = 1 << 20;

const CARVE_BUDGET_RATIO: usize = 1;

const MAX_CACHE_SOURCES: usize = 4096;

struct BlobSink {
    out: Vec<Vec<u8>>,
    seen_blobs: HashSet<Vec<u8>>,
    seen_sources: HashSet<(u32, u32)>,
    budget: usize,
}

impl BlobSink {
    fn new(hive_len: usize) -> Self {
        BlobSink {
            out: Vec::new(),
            seen_blobs: HashSet::new(),
            seen_sources: HashSet::new(),
            budget: hive_len.saturating_mul(CARVE_BUDGET_RATIO),
        }
    }

    fn exhausted(&self) -> bool {
        self.budget == 0 || self.seen_sources.len() >= MAX_CACHE_SOURCES
    }

    fn take(&mut self, hive: &[u8], target: VkTarget) {
        if self.exhausted() {
            return;
        }
        if !self.seen_sources.insert((target.data_offset, target.size)) {
            return;
        }
        if target.size as usize > self.budget {
            return;
        }
        let Some(blob) = vk_data(hive, &target) else { return };
        self.budget = self.budget.saturating_sub(blob.len().max(1));
        if self.seen_blobs.insert(blob.clone()) {
            self.out.push(blob);
        }
    }

    fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    fn into_vec(self) -> Vec<Vec<u8>> {
        self.out
    }
}

fn collect_blobs(hive: &[u8]) -> Vec<Vec<u8>> {
    let mut sink = BlobSink::new(hive.len());
    hive_tree_values(hive, &mut sink);
    if sink.is_empty() {
        carve_cache_values(hive, &mut sink);
    }
    sink.into_vec()
}

fn hive_tree_values(bytes: &[u8], sink: &mut BlobSink) {
    let Some(root) = root_cell(bytes) else {
        log::debug!("shimcache: no readable root key, falling back to carving");
        return;
    };

    let mut visits = MAX_CELL_VISITS;
    for (name, cell) in subkeys_within(bytes, root, &mut visits) {
        let name = name.to_ascii_lowercase();
        if !name.starts_with("controlset") && !name.starts_with("currentcontrolset") {
            continue;
        }
        for key_path in CACHE_KEY_PATHS {
            let Some(cache_key) = descend(bytes, cell, key_path, &mut visits) else { continue };
            binary_values(bytes, cache_key, VALUE_NAME, sink);
        }
    }
}

fn root_cell(b: &[u8]) -> Option<usize> {
    b.starts_with(b"regf").then_some(())?;
    let cell = BASE_BLOCK_SIZE.checked_add(u32_at(b, 0x24)? as usize)?;
    cell_payload(b, cell)?.starts_with(b"nk").then_some(cell)
}

fn descend(b: &[u8], cell: usize, path: &str, visits: &mut u32) -> Option<usize> {
    let mut cell = cell;
    for component in path.split('\\') {
        cell = subkeys_within(b, cell, visits)
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(component))
            .map(|(_, child)| child)?;
    }
    Some(cell)
}

#[cfg(test)]
fn subkeys(b: &[u8], nk_cell: usize) -> Vec<(String, usize)> {
    let mut visits = MAX_CELL_VISITS;
    subkeys_within(b, nk_cell, &mut visits)
}

fn subkeys_within(b: &[u8], nk_cell: usize, visits: &mut u32) -> Vec<(String, usize)> {
    fn collect(
        b: &[u8],
        list_cell: usize,
        depth: u32,
        visits: &mut u32,
        out: &mut Vec<(String, usize)>,
    ) {
        if depth > 2 || out.len() >= MAX_LIST_ENTRIES || *visits == 0 {
            return;
        }
        let Some(list) = cell_payload(b, list_cell) else { return };
        let Some(kind) = list.get(..2) else { return };
        let Some(count) = u16_at(list, 2).map(usize::from) else { return };

        let stride = match kind {
            k if k == b"lf" || k == b"lh" => 8,
            k if k == b"li" || k == b"ri" => 4,
            _ => return,
        };

        for i in 0..count.min(MAX_LIST_ENTRIES) {
            if *visits == 0 {
                log::debug!("shimcache: hive walk budget exhausted, stopping");
                return;
            }
            *visits -= 1;

            let Some(offset) = i.checked_mul(stride).and_then(|at| u32_at(list, 4 + at)) else {
                break;
            };
            let Some(cell) = BASE_BLOCK_SIZE.checked_add(offset as usize) else { break };
            if kind == b"ri".as_slice() {
                collect(b, cell, depth + 1, visits, out);
            } else if let Some(name) = key_name(b, cell) {
                out.push((name, cell));
            }
            if out.len() >= MAX_LIST_ENTRIES {
                break;
            }
        }
    }

    let mut out = Vec::new();
    let Some(nk) = key_node(b, nk_cell) else { return out };
    if nk.subkey_count == 0 || nk.subkeys_list == u32::MAX {
        return out;
    }
    let Some(list_cell) = BASE_BLOCK_SIZE.checked_add(nk.subkeys_list as usize) else {
        return out;
    };
    collect(b, list_cell, 0, visits, &mut out);
    out
}

struct KeyNode<'a> {
    flags: u16,
    subkey_count: u32,
    subkeys_list: u32,
    value_count: u32,
    values_list: u32,
    name: &'a [u8],
}

fn key_node(b: &[u8], cell: usize) -> Option<KeyNode<'_>> {
    let nk = cell_payload(b, cell)?;
    nk.starts_with(b"nk").then_some(())?;
    let name_len = u16_at(nk, 72)? as usize;
    Some(KeyNode {
        flags: u16_at(nk, 2)?,
        subkey_count: u32_at(nk, 20)?,
        subkeys_list: u32_at(nk, 28)?,
        value_count: u32_at(nk, 36)?,
        values_list: u32_at(nk, 40)?,
        name: nk.get(76..76usize.checked_add(name_len)?)?,
    })
}

fn key_name(b: &[u8], cell: usize) -> Option<String> {
    let nk = key_node(b, cell)?;
    Some(decode_name(nk.name, nk.flags & KEY_COMP_NAME != 0))
}

fn decode_name(bytes: &[u8], ascii: bool) -> String {
    if ascii {
        bytes.iter().map(|&c| c as char).collect()
    } else {
        utf16le_string(bytes)
    }
}

fn binary_values(b: &[u8], key_cell: usize, want: &str, sink: &mut BlobSink) {
    let Some(nk) = key_node(b, key_cell) else { return };
    if nk.value_count == 0 || nk.values_list == u32::MAX {
        return;
    }
    let Some(list_cell) = BASE_BLOCK_SIZE.checked_add(nk.values_list as usize) else {
        return;
    };
    let Some(list) = cell_payload(b, list_cell) else { return };

    for i in 0..nk.value_count.min(MAX_LIST_ENTRIES as u32) as usize {
        if sink.exhausted() {
            break;
        }
        let Some(offset) = i.checked_mul(4).and_then(|at| u32_at(list, at)) else { break };
        let Some(vk_cell) = BASE_BLOCK_SIZE.checked_add(offset as usize) else { break };
        let Some(vk) = cell_payload(b, vk_cell) else { continue };
        if let Some(target) = vk_target(vk, want) {
            sink.take(b, target);
        }
    }
}

fn carve_cache_values(bytes: &[u8], sink: &mut BlobSink) {
    let start = if bytes.len() > BASE_BLOCK_SIZE { BASE_BLOCK_SIZE } else { 0 };
    let mut i = start;
    while i + VK_HEADER_LEN <= bytes.len() {
        if sink.exhausted() {
            break;
        }
        if bytes[i] == b'v' && bytes[i + 1] == b'k' {
            if let Some(target) = vk_target(&bytes[i..], VALUE_NAME) {
                sink.take(bytes, target);
            }
        }
        i += 1;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VkTarget {
    data_offset: u32,
    size: u32,
}

fn vk_target(vk: &[u8], want: &str) -> Option<VkTarget> {
    vk.starts_with(b"vk").then_some(())?;
    let name_len = u16_at(vk, 2)? as usize;
    let raw_data_size = u32_at(vk, 4)?;
    let data_offset = u32_at(vk, 8)?;
    let data_type = u32_at(vk, 12)?;
    let flags = u16_at(vk, 16)?;

    if data_type != REG_BINARY {
        return None;
    }

    if raw_data_size & 0x8000_0000 != 0 {
        return None;
    }
    if raw_data_size == 0 {
        return None;
    }

    let name = vk.get(VK_HEADER_LEN..VK_HEADER_LEN.checked_add(name_len)?)?;
    if !decode_name(name, flags & VALUE_COMP_NAME != 0).eq_ignore_ascii_case(want) {
        return None;
    }
    Some(VkTarget { data_offset, size: raw_data_size })
}

fn vk_data(b: &[u8], target: &VkTarget) -> Option<Vec<u8>> {
    let size = target.size as usize;
    if size == 0 || size > b.len() {
        return None;
    }
    let cell = BASE_BLOCK_SIZE.checked_add(target.data_offset as usize)?;
    let payload = cell_payload(b, cell)?;

    if size > BIG_DATA_SEGMENT_SIZE && payload.starts_with(b"db") {
        return read_big_data(b, payload, size);
    }
    let taken = payload.get(..size.min(payload.len()))?;
    (!taken.is_empty()).then(|| taken.to_vec())
}

fn read_big_data(b: &[u8], db: &[u8], size: usize) -> Option<Vec<u8>> {
    let segment_count = u16_at(db, 2)? as usize;
    let list_cell = BASE_BLOCK_SIZE.checked_add(u32_at(db, 4)? as usize)?;
    let list = cell_payload(b, list_cell)?;

    let mut buf: Vec<u8> = Vec::new();
    for i in 0..segment_count {
        if buf.len() >= size {
            break;
        }
        let Some(offset) = i.checked_mul(4).and_then(|at| u32_at(list, at)) else {
            break;
        };
        let Some(segment) =
            BASE_BLOCK_SIZE.checked_add(offset as usize).and_then(|cell| cell_payload(b, cell))
        else {
            break;
        };
        let want = (size - buf.len()).min(BIG_DATA_SEGMENT_SIZE).min(segment.len());
        buf.extend_from_slice(&segment[..want]);
    }
    (!buf.is_empty()).then_some(buf)
}

fn cell_payload(b: &[u8], cell: usize) -> Option<&[u8]> {
    let raw = i32::from_le_bytes(b.get(cell..cell.checked_add(4)?)?.try_into().ok()?);
    if raw >= 0 {
        return None;
    }
    let len = (raw.unsigned_abs() as usize).checked_sub(4)?;
    let from = cell.checked_add(4)?;
    let to = from.checked_add(len)?.min(b.len());
    b.get(from..to)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CacheEntry {
    path: String,
    last_modified: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Xp,
    Nt52,
    Win7,
    Win8,
    Win10,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    Win80,
    Win81,
    Win10,
}

impl Body {
    fn timestamp_gap(self) -> usize {
        match self {
            Body::Win80 => 8,
            Body::Win81 => 10,
            Body::Win10 => 0,
        }
    }

    fn fixed_len(self) -> usize {
        self.timestamp_gap() + 8 + 4
    }
}

fn parse_cache(blob: &[u8]) -> Vec<CacheEntry> {
    let Some((format, header_size)) = detect(blob) else {
        return match salvage_start(blob) {
            Some(offset) => parse_tagged(blob, offset, Format::Win10),
            None => Vec::new(),
        };
    };

    match format {
        Format::Xp => parse_xp(blob),
        Format::Nt52 | Format::Win7 => parse_fixed(blob, format, header_size),
        Format::Win8 | Format::Win10 => {
            let entries = parse_tagged(blob, header_size, format);
            if entries.is_empty() {
                if let Some(offset) = salvage_start(blob) {
                    if offset != header_size {
                        return parse_tagged(blob, offset, format);
                    }
                }
            }
            entries
        }
    }
}

fn detect(blob: &[u8]) -> Option<(Format, usize)> {
    let signature = u32_at(blob, 0)?;
    match signature {
        0xDEAD_BEEF => Some((Format::Xp, 0x190)),
        0xBADC_0FFE => Some((Format::Nt52, 0x08)),
        0xBADC_0FEE => Some((Format::Win7, 0x80)),
        0x0000_0080 => Some((Format::Win8, 0x80)),
        0x0000_0030 | 0x0000_0034 => Some((Format::Win10, signature as usize)),
        other if (0x10..=0x1000).contains(&other) && is_record_at(blob, other as usize) => {
            Some((Format::Win10, other as usize))
        }
        _ => None,
    }
}

fn tag_at(b: &[u8], off: usize) -> Option<&[u8]> {
    b.get(off..off.checked_add(4)?)
}

fn is_record_at(b: &[u8], off: usize) -> bool {
    tag_at(b, off).is_some_and(|tag| tag == b"00ts".as_slice() || tag == b"10ts".as_slice())
}

fn salvage_start(blob: &[u8]) -> Option<usize> {
    let limit = blob.len().min(0x2000);
    (0..limit).step_by(4).find(|&off| is_record_at(blob, off))
}

fn parse_tagged(blob: &[u8], start: usize, format: Format) -> Vec<CacheEntry> {
    let mut entries = Vec::new();
    let mut offset = start;

    while let Some(tag) = tag_at(blob, offset) {
        let preferred = if tag == b"00ts".as_slice() {
            if format == Format::Win8 {
                Body::Win80
            } else {
                Body::Win10
            }
        } else if tag == b"10ts".as_slice() {
            if format == Format::Win8 {
                Body::Win81
            } else {
                Body::Win10
            }
        } else {
            break;
        };

        let Some(body_size) = u32_at(blob, offset + 8) else { break };
        let Some(body_start) = offset.checked_add(12) else { break };

        let end = body_start.checked_add(body_size as usize).filter(|end| *end <= blob.len());
        match end {
            Some(end) => {
                if let Some(entry) = parse_body(&blob[body_start..end], preferred, true) {
                    entries.push(entry);
                }
                offset = end;
            }
            None => {
                let Some(rest) = blob.get(body_start..) else { break };
                if let Some(entry) = parse_body(rest, preferred, false) {
                    entries.push(entry);
                }
                break;
            }
        }
    }
    entries
}

fn parse_body(body: &[u8], preferred: Body, exact: bool) -> Option<CacheEntry> {
    let path_size = u16_at(body, 0)? as usize;
    if path_size == 0 {
        return None;
    }
    let path_end = 2usize.checked_add(path_size)?;
    let path = utf16le_string(body.get(2..path_end)?);
    if path.is_empty() {
        return None;
    }

    let alternatives = match preferred {
        Body::Win10 => [Body::Win10, Body::Win81, Body::Win80],
        Body::Win81 => [Body::Win81, Body::Win10, Body::Win80],
        Body::Win80 => [Body::Win80, Body::Win81, Body::Win10],
    };

    let measured = |layout: Body| -> Option<(u64, usize)> {
        let at = path_end.checked_add(layout.timestamp_gap())?;
        let last_modified = u64_at(body, at)?;
        let data_size = u32_at(body, at + 8)?;
        let claimed = path_end.checked_add(layout.fixed_len())?.checked_add(data_size as usize)?;
        Some((last_modified, claimed))
    };

    let plausible = |ticks: u64| mm_core::from_filetime(ticks).is_some();

    for layout in alternatives {
        if let Some((last_modified, claimed)) = measured(layout) {
            if claimed == body.len() && plausible(last_modified) {
                return Some(CacheEntry { path, last_modified });
            }
        }
    }
    for layout in alternatives {
        if let Some((last_modified, claimed)) = measured(layout) {
            if claimed <= body.len() && plausible(last_modified) {
                return Some(CacheEntry { path, last_modified });
            }
        }
    }
    for layout in alternatives {
        if let Some((last_modified, claimed)) = measured(layout) {
            if claimed == body.len() {
                return Some(CacheEntry { path, last_modified });
            }
        }
    }

    if exact {
        return Some(CacheEntry { path, last_modified: 0 });
    }
    let at = path_end.checked_add(preferred.timestamp_gap())?;
    Some(CacheEntry { path, last_modified: u64_at(body, at).unwrap_or(0) })
}

fn parse_xp(blob: &[u8]) -> Vec<CacheEntry> {
    const HEADER: usize = 0x190;
    const ENTRY: usize = 552;
    const PATH_BYTES: usize = 528;

    let mut entries = Vec::new();
    let mut offset = HEADER;
    while let Some(slot) = blob.get(offset..offset.saturating_add(ENTRY)) {
        let path = utf16le_string(&slot[..PATH_BYTES]);
        if !path.is_empty() {
            entries.push(CacheEntry { path, last_modified: u64_at(slot, PATH_BYTES).unwrap_or(0) });
        }
        offset += ENTRY;
    }
    entries
}

#[derive(Clone, Copy)]
struct Fixed {
    entry_size: usize,
    wide: bool,
    data_offset_at: Option<usize>,
}

impl Fixed {
    fn timestamp_offset(&self) -> usize {
        if self.wide {
            16
        } else {
            8
        }
    }

    fn path_offset(&self, entry: &[u8]) -> Option<usize> {
        if self.wide {
            u64_at(entry, 8)?.try_into().ok()
        } else {
            Some(u32_at(entry, 4)? as usize)
        }
    }

    fn data_offset(&self, entry: &[u8]) -> Option<usize> {
        let at = self.data_offset_at?;
        if self.wide {
            u64_at(entry, at)?.try_into().ok()
        } else {
            Some(u32_at(entry, at)? as usize)
        }
    }
}

fn shapes(format: Format) -> [Fixed; 2] {
    match format {
        Format::Win7 => [
            Fixed { entry_size: 32, wide: false, data_offset_at: Some(28) },
            Fixed { entry_size: 48, wide: true, data_offset_at: Some(40) },
        ],
        _ => [
            Fixed { entry_size: 24, wide: false, data_offset_at: None },
            Fixed { entry_size: 32, wide: true, data_offset_at: None },
        ],
    }
}

fn parse_fixed(blob: &[u8], format: Format, header_size: usize) -> Vec<CacheEntry> {
    let candidates = shapes(format);
    let mut best: Vec<CacheEntry> = Vec::new();

    for shape in candidates {
        let entries = walk_fixed(blob, header_size, shape, true);
        if entries.len() > best.len() {
            best = entries;
        }
    }
    if !best.is_empty() {
        return best;
    }

    let wide = blob.get(header_size..).is_some_and(|first| {
        u32_at(first, 4) == Some(0) && u64_at(first, 8).is_some_and(|v| v != 0)
    });
    walk_fixed(blob, header_size, candidates[usize::from(wide)], false)
}

fn walk_fixed(blob: &[u8], header_size: usize, shape: Fixed, strict: bool) -> Vec<CacheEntry> {
    let mut entries = Vec::new();
    let mut offset = header_size;
    let mut limit = blob.len();

    while offset.saturating_add(shape.entry_size) <= limit {
        let Some(entry) = blob.get(offset..offset + shape.entry_size) else { break };
        if let Some((parsed, path_offset)) =
            parse_fixed_entry(blob, entry, shape, header_size, strict)
        {
            for pointer in [Some(path_offset), shape.data_offset(entry)].into_iter().flatten() {
                if pointer > offset && pointer <= blob.len() {
                    limit = limit.min(pointer);
                }
            }
            entries.push(parsed);
        }
        offset += shape.entry_size;
    }
    entries
}

fn parse_fixed_entry(
    blob: &[u8],
    entry: &[u8],
    shape: Fixed,
    header_size: usize,
    strict: bool,
) -> Option<(CacheEntry, usize)> {
    let path_size = u16_at(entry, 0)? as usize;
    let maximum_path_size = u16_at(entry, 2)? as usize;
    if path_size == 0 {
        return None;
    }
    if strict && maximum_path_size != path_size.checked_add(2)? {
        return None;
    }
    let path_offset = shape.path_offset(entry)?;
    if path_offset < header_size {
        return None;
    }
    let path = utf16le_string(blob.get(path_offset..path_offset.checked_add(path_size)?)?);
    if path.is_empty() {
        return None;
    }
    Some((
        CacheEntry { path, last_modified: u64_at(entry, shape.timestamp_offset()).unwrap_or(0) },
        path_offset,
    ))
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off.checked_add(8)?)?.try_into().ok()?))
}

fn utf16le_string(bytes: &[u8]) -> String {
    let units: Vec<u16> =
        bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes).collect();
    let end = units.iter().position(|&unit| unit == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS_2024: u64 = (1_704_067_200 + 11_644_473_600) * 10_000_000;
    const TS_2020: u64 = (1_592_222_400 + 11_644_473_600) * 10_000_000;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    fn paths(entries: &[CacheEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.path.as_str()).collect()
    }

    fn tree_values(hive: &[u8]) -> Vec<Vec<u8>> {
        let mut sink = BlobSink::new(hive.len());
        hive_tree_values(hive, &mut sink);
        sink.into_vec()
    }

    fn tagged_record(tag: &[u8; 4], path: &str, ts: u64, layout: Body, data: &[u8]) -> Vec<u8> {
        let path_bytes = utf16(path);
        let mut body = Vec::new();
        body.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        body.extend_from_slice(&path_bytes);
        match layout {
            Body::Win80 => {
                body.extend_from_slice(&1u32.to_le_bytes());
                body.extend_from_slice(&2u32.to_le_bytes());
            }
            Body::Win81 => {
                body.extend_from_slice(&1u32.to_le_bytes());
                body.extend_from_slice(&2u32.to_le_bytes());
                body.extend_from_slice(&0u16.to_le_bytes());
            }
            Body::Win10 => {}
        }
        body.extend_from_slice(&ts.to_le_bytes());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(data);

        let mut out = Vec::new();
        out.extend_from_slice(tag);
        out.extend_from_slice(&0xdead_beefu32.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn win10_blob(header_size: u32, entries: &[(&str, u64)]) -> Vec<u8> {
        let mut blob = vec![0u8; header_size as usize];
        blob[..4].copy_from_slice(&header_size.to_le_bytes());
        let count_at = if header_size == 0x34 { 0x28 } else { 0x24 };
        blob[count_at..count_at + 4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for &(path, ts) in entries {
            blob.extend_from_slice(&tagged_record(b"10ts", path, ts, Body::Win10, &[]));
        }
        blob
    }

    fn win8_blob(tag: &[u8; 4], layout: Body, entries: &[(&str, u64)]) -> Vec<u8> {
        let mut blob = vec![0u8; 0x80];
        blob[..4].copy_from_slice(&0x80u32.to_le_bytes());
        for &(path, ts) in entries {
            blob.extend_from_slice(&tagged_record(tag, path, ts, layout, &[]));
        }
        blob
    }

    fn fixed_blob(format: Format, wide: bool, entries: &[(&str, u64)]) -> Vec<u8> {
        let (signature, header_size) = match format {
            Format::Nt52 => (0xBADC_0FFEu32, 0x08usize),
            _ => (0xBADC_0FEEu32, 0x80usize),
        };
        let shape = shapes(format)[usize::from(wide)];

        let mut header = vec![0u8; header_size];
        header[..4].copy_from_slice(&signature.to_le_bytes());
        header[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());

        let table_len = shape.entry_size * entries.len();
        let mut table = vec![0u8; table_len];
        let mut strings: Vec<u8> = Vec::new();

        for (i, (path, ts)) in entries.iter().copied().enumerate() {
            let path_bytes = utf16(path);
            let path_offset = header_size + table_len + strings.len();
            let slot = &mut table[i * shape.entry_size..(i + 1) * shape.entry_size];
            slot[0..2].copy_from_slice(&(path_bytes.len() as u16).to_le_bytes());
            slot[2..4].copy_from_slice(&((path_bytes.len() + 2) as u16).to_le_bytes());
            if wide {
                slot[8..16].copy_from_slice(&(path_offset as u64).to_le_bytes());
                slot[16..24].copy_from_slice(&ts.to_le_bytes());
            } else {
                slot[4..8].copy_from_slice(&(path_offset as u32).to_le_bytes());
                slot[8..16].copy_from_slice(&ts.to_le_bytes());
            }
            strings.extend_from_slice(&path_bytes);
            strings.extend_from_slice(&[0, 0]);
        }

        let mut blob = header;
        blob.extend_from_slice(&table);
        blob.extend_from_slice(&strings);
        blob
    }

    fn xp_blob(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut blob = vec![0u8; 0x190];
        blob[..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        blob[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        blob[8..12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for &(path, ts) in entries {
            let mut slot = vec![0u8; 552];
            let path_bytes = utf16(path);
            slot[..path_bytes.len()].copy_from_slice(&path_bytes);
            slot[528..536].copy_from_slice(&ts.to_le_bytes());
            slot[536..544].copy_from_slice(&4096u64.to_le_bytes());
            slot[544..552].copy_from_slice(&ts.to_le_bytes());
            blob.extend_from_slice(&slot);
        }
        blob
    }

    #[test]
    fn windows_11_and_1607_header_parses() {
        let blob = win10_blob(
            0x34,
            &[("\\??\\C:\\Windows\\System32\\cmd.exe", TS_2024), ("\\??\\C:\\evil.exe", TS_2020)],
        );
        assert_eq!(detect(&blob), Some((Format::Win10, 0x34)));
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["\\??\\C:\\Windows\\System32\\cmd.exe", "\\??\\C:\\evil.exe"]);
        assert_eq!(entries[0].last_modified, TS_2024);
        assert_eq!(entries[1].last_modified, TS_2020);
    }

    #[test]
    fn windows_10_pre_1607_header_parses() {
        let blob = win10_blob(0x30, &[("\\??\\C:\\a.exe", TS_2024)]);
        assert_eq!(detect(&blob), Some((Format::Win10, 0x30)));
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["\\??\\C:\\a.exe"]);
        assert_eq!(entries[0].last_modified, TS_2024);
    }

    #[test]
    fn windows_8_0_entries_parse() {
        let blob = win8_blob(b"00ts", Body::Win80, &[("\\??\\C:\\eight.exe", TS_2020)]);
        assert_eq!(detect(&blob), Some((Format::Win8, 0x80)));
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["\\??\\C:\\eight.exe"]);
        assert_eq!(entries[0].last_modified, TS_2020);
    }

    #[test]
    fn windows_8_1_entries_parse() {
        let blob = win8_blob(b"10ts", Body::Win81, &[("\\??\\C:\\eightone.exe", TS_2024)]);
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["\\??\\C:\\eightone.exe"]);
        assert_eq!(entries[0].last_modified, TS_2024);
    }

    #[test]
    fn body_layout_is_verified_not_assumed() {
        let mut blob = vec![0u8; 0x34];
        blob[..4].copy_from_slice(&0x34u32.to_le_bytes());
        blob.extend_from_slice(&tagged_record(b"10ts", "C:\\x.exe", TS_2024, Body::Win81, &[]));
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["C:\\x.exe"]);
        assert_eq!(entries[0].last_modified, TS_2024, "layout must be re-derived");
    }

    #[test]
    fn records_with_shim_data_parse() {
        let mut blob = vec![0u8; 0x34];
        blob[..4].copy_from_slice(&0x34u32.to_le_bytes());
        blob.extend_from_slice(&tagged_record(
            b"10ts",
            "C:\\withdata.exe",
            TS_2024,
            Body::Win10,
            &[0xaa; 24],
        ));
        blob.extend_from_slice(&tagged_record(b"10ts", "C:\\after.exe", TS_2020, Body::Win10, &[]));
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["C:\\withdata.exe", "C:\\after.exe"]);
        assert_eq!(entries[0].last_modified, TS_2024);
        assert_eq!(entries[1].last_modified, TS_2020);
    }

    #[test]
    fn windows_7_32bit_parses() {
        let blob = fixed_blob(Format::Win7, false, &[("\\??\\C:\\seven32.exe", TS_2020)]);
        assert_eq!(detect(&blob), Some((Format::Win7, 0x80)));
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["\\??\\C:\\seven32.exe"]);
        assert_eq!(entries[0].last_modified, TS_2020);
    }

    #[test]
    fn windows_7_64bit_parses() {
        let blob = fixed_blob(
            Format::Win7,
            true,
            &[("\\??\\C:\\seven64.exe", TS_2024), ("\\??\\C:\\other.exe", TS_2020)],
        );
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["\\??\\C:\\seven64.exe", "\\??\\C:\\other.exe"]);
        assert_eq!(entries[0].last_modified, TS_2024);
        assert_eq!(entries[1].last_modified, TS_2020);
    }

    #[test]
    fn vista_and_2003_parse_in_both_bitnesses() {
        for wide in [false, true] {
            let blob = fixed_blob(Format::Nt52, wide, &[("\\??\\C:\\vista.exe", TS_2020)]);
            assert_eq!(detect(&blob), Some((Format::Nt52, 0x08)));
            let entries = parse_cache(&blob);
            assert_eq!(paths(&entries), ["\\??\\C:\\vista.exe"], "wide={wide}");
            assert_eq!(entries[0].last_modified, TS_2020);
        }
    }

    #[test]
    fn windows_xp_parses() {
        let blob = xp_blob(&[
            ("C:\\WINDOWS\\system32\\notepad.exe", TS_2020),
            ("C:\\Documents and Settings\\bob\\evil.exe", TS_2024),
        ]);
        assert_eq!(detect(&blob), Some((Format::Xp, 0x190)));
        let entries = parse_cache(&blob);
        assert_eq!(
            paths(&entries),
            ["C:\\WINDOWS\\system32\\notepad.exe", "C:\\Documents and Settings\\bob\\evil.exe"]
        );
        assert_eq!(entries[0].last_modified, TS_2020);
        assert_eq!(entries[1].last_modified, TS_2024);
    }

    #[test]
    fn unknown_header_size_pointing_at_a_record_is_accepted() {
        let mut blob = vec![0u8; 0x40];
        blob[..4].copy_from_slice(&0x40u32.to_le_bytes());
        blob.extend_from_slice(&tagged_record(
            b"10ts",
            "C:\\future.exe",
            TS_2024,
            Body::Win10,
            &[],
        ));
        assert_eq!(detect(&blob), Some((Format::Win10, 0x40)));
        assert_eq!(paths(&parse_cache(&blob)), ["C:\\future.exe"]);
    }

    #[test]
    fn zero_length_buffer_yields_nothing() {
        assert!(parse_cache(&[]).is_empty());
        assert!(harvest(&[]).is_empty());
        assert!(detect(&[]).is_none());
        assert!(salvage_start(&[]).is_none());
    }

    #[test]
    fn every_truncation_of_every_format_is_survivable() {
        let blobs = [
            win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("C:\\b.exe", TS_2020)]),
            win10_blob(0x30, &[("C:\\a.exe", TS_2024)]),
            win8_blob(b"00ts", Body::Win80, &[("C:\\a.exe", TS_2024)]),
            win8_blob(b"10ts", Body::Win81, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Win7, false, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Win7, true, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Nt52, false, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Nt52, true, &[("C:\\a.exe", TS_2024)]),
            xp_blob(&[("C:\\a.exe", TS_2024)]),
        ];
        for blob in &blobs {
            for len in 0..blob.len() {
                let _ = parse_cache(&blob[..len]);
            }
        }
    }

    #[test]
    fn truncation_only_ever_loses_entries() {
        let blob = win10_blob(
            0x34,
            &[("C:\\a.exe", TS_2024), ("C:\\b.exe", TS_2024), ("C:\\c.exe", TS_2024)],
        );
        assert_eq!(parse_cache(&blob).len(), 3);
        for len in 0..blob.len() {
            assert!(parse_cache(&blob[..len]).len() <= 3);
        }
    }

    #[test]
    fn absurd_record_length_does_not_overflow() {
        let mut blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
        let at = 0x34 + 8;
        blob[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_cache(&blob).len() <= 1);
    }

    #[test]
    fn zero_length_record_does_not_spin() {
        let mut blob = vec![0u8; 0x34];
        blob[..4].copy_from_slice(&0x34u32.to_le_bytes());
        for _ in 0..4 {
            blob.extend_from_slice(b"10ts");
            blob.extend_from_slice(&0u32.to_le_bytes());
            blob.extend_from_slice(&0u32.to_le_bytes());
        }
        assert!(parse_cache(&blob).is_empty());
    }

    #[test]
    fn absurd_path_size_is_rejected() {
        let mut blob = vec![0u8; 0x34];
        blob[..4].copy_from_slice(&0x34u32.to_le_bytes());
        blob.extend_from_slice(b"10ts");
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&16u32.to_le_bytes());
        blob.extend_from_slice(&u16::MAX.to_le_bytes());
        blob.extend_from_slice(&[0u8; 14]);
        assert!(parse_cache(&blob).is_empty());
    }

    #[test]
    fn absurd_header_entry_count_is_ignored() {
        let mut blob = xp_blob(&[("C:\\a.exe", TS_2024)]);
        blob[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        blob[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(paths(&parse_cache(&blob)), ["C:\\a.exe"]);

        let mut blob = fixed_blob(Format::Win7, false, &[("C:\\a.exe", TS_2024)]);
        blob[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(paths(&parse_cache(&blob)), ["C:\\a.exe"]);

        let mut blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("C:\\b.exe", TS_2020)]);
        blob[0x28..0x2c].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(paths(&parse_cache(&blob)), ["C:\\a.exe", "C:\\b.exe"]);
    }

    #[test]
    fn wild_path_offset_drops_one_record_not_the_cache() {
        let mut blob =
            fixed_blob(Format::Win7, false, &[("C:\\a.exe", TS_2024), ("C:\\b.exe", TS_2020)]);
        blob[0x84..0x88].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(paths(&parse_cache(&blob)), ["C:\\b.exe"]);
    }

    #[test]
    fn unrecognised_signature_yields_nothing() {
        assert!(parse_cache(&[0xff; 4096]).is_empty());
        assert!(parse_cache(b"not a shimcache at all").is_empty());
        assert!(parse_cache(&[0u8; 4096]).is_empty());
    }

    #[test]
    fn destroyed_header_falls_back_to_record_scanning() {
        let mut blob = win10_blob(0x34, &[("C:\\survivor.exe", TS_2024)]);
        blob[..4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(detect(&blob).is_none());
        let entries = parse_cache(&blob);
        assert_eq!(paths(&entries), ["C:\\survivor.exe"]);
        assert_eq!(entries[0].last_modified, TS_2024);
    }

    #[test]
    fn single_byte_corruption_never_panics() {
        let blobs = [
            win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("C:\\b.exe", TS_2020)]),
            win8_blob(b"00ts", Body::Win80, &[("C:\\a.exe", TS_2024)]),
            win8_blob(b"10ts", Body::Win81, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Win7, true, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Nt52, false, &[("C:\\a.exe", TS_2024)]),
            xp_blob(&[("C:\\a.exe", TS_2024)]),
        ];
        for blob in &blobs {
            for i in 0..blob.len() {
                for byte in [0x00u8, 0xff, 0x80, 0x7f] {
                    let mut damaged = blob.clone();
                    damaged[i] = byte;
                    let _ = parse_cache(&damaged);
                }
            }
        }
    }

    #[test]
    fn observations_are_executed_from_shimcache_with_no_run_count() {
        let hive =
            hive_with_cache(&win10_blob(0x34, &[("\\??\\C:\\Users\\bob\\evil.exe", TS_2024)]));
        let out = harvest(&hive);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, ArtifactSource::ShimCache);
        assert_eq!(out[0].path.as_ref().unwrap().key(), "\\users\\bob\\evil.exe");
        assert_eq!(out[0].path.as_ref().unwrap().raw(), "\\??\\C:\\Users\\bob\\evil.exe");
        assert!(out[0].hash.is_empty(), "shimcache never knows a hash");
        match &out[0].kind {
            ObservationKind::Executed { when, run_count } => {
                assert!(run_count.is_none(), "shimcache never counts runs");
                assert_eq!(mm_core::filetime::format(when.unwrap()), "2024-01-01 00:00:00Z");
            }
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn missing_timestamp_still_yields_the_path() {
        let hive = hive_with_cache(&win10_blob(0x34, &[("C:\\nots.exe", 0)]));
        let out = harvest(&hive);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].kind, ObservationKind::Executed { when: None, .. }));
    }

    #[test]
    fn identical_rows_from_several_control_sets_collapse() {
        let hive = hive_with_cache_copies(&win10_blob(0x34, &[("C:\\a.exe", TS_2024)]), 3);
        assert_eq!(harvest(&hive).len(), 1);
    }

    #[test]
    fn same_path_different_timestamps_are_both_kept() {
        let hive =
            hive_with_cache(&win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("C:\\a.exe", TS_2020)]));
        assert_eq!(harvest(&hive).len(), 2);
    }

    #[test]
    fn ordinary_system_paths_are_not_filtered_out() {
        let hive = hive_with_cache(&win10_blob(
            0x34,
            &[
                ("\\??\\C:\\Windows\\System32\\svchost.exe", TS_2024),
                ("\\??\\C:\\Users\\bob\\AppData\\Roaming\\x.exe", TS_2024),
            ],
        ));
        assert_eq!(harvest(&hive).len(), 2);
    }

    #[test]
    fn garbage_hives_yield_nothing_without_panicking() {
        assert!(harvest(&[]).is_empty());
        assert!(harvest(&[0u8; 16]).is_empty());
        assert!(harvest(&[0xffu8; 8192]).is_empty());
        assert!(harvest(b"regf").is_empty());
        let mut almost = vec![0u8; 8192];
        almost[..4].copy_from_slice(b"regf");
        assert!(harvest(&almost).is_empty());
    }

    #[test]
    fn truncated_hive_is_survivable() {
        let hive = hive_with_cache(&win10_blob(0x34, &[("C:\\a.exe", TS_2024)]));
        for len in (0..hive.len()).step_by(97) {
            let _ = harvest(&hive[..len]);
        }
    }

    fn cell(payload: &[u8]) -> Vec<u8> {
        let size = 4 + payload.len();
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&(-(size as i32)).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn vk_record(name: &str, data_offset: u32, data_size: u32) -> Vec<u8> {
        let mut vk = Vec::new();
        vk.extend_from_slice(b"vk");
        vk.extend_from_slice(&(name.len() as u16).to_le_bytes());
        vk.extend_from_slice(&data_size.to_le_bytes());
        vk.extend_from_slice(&data_offset.to_le_bytes());
        vk.extend_from_slice(&REG_BINARY.to_le_bytes());
        vk.extend_from_slice(&VALUE_COMP_NAME.to_le_bytes());
        vk.extend_from_slice(&0u16.to_le_bytes());
        vk.extend_from_slice(name.as_bytes());
        vk
    }

    fn hive_with_cache_copies(blob: &[u8], copies: usize) -> Vec<u8> {
        let mut bins: Vec<u8> = Vec::new();
        let mut vks: Vec<Vec<u8>> = Vec::new();

        for _ in 0..copies {
            if blob.len() > BIG_DATA_SEGMENT_SIZE {
                let offsets: Vec<u32> = blob
                    .chunks(BIG_DATA_SEGMENT_SIZE)
                    .map(|chunk| {
                        let at = bins.len() as u32;
                        bins.extend_from_slice(&cell(chunk));
                        at
                    })
                    .collect();

                let mut list = Vec::new();
                for offset in &offsets {
                    list.extend_from_slice(&offset.to_le_bytes());
                }
                let list_at = bins.len() as u32;
                bins.extend_from_slice(&cell(&list));

                let mut db = Vec::new();
                db.extend_from_slice(b"db");
                db.extend_from_slice(&(offsets.len() as u16).to_le_bytes());
                db.extend_from_slice(&list_at.to_le_bytes());
                let db_at = bins.len() as u32;
                bins.extend_from_slice(&cell(&db));

                vks.push(vk_record(VALUE_NAME, db_at, blob.len() as u32));
            } else {
                let data_at = bins.len() as u32;
                bins.extend_from_slice(&cell(blob));
                vks.push(vk_record(VALUE_NAME, data_at, blob.len() as u32));
            }
        }
        for vk in vks {
            bins.extend_from_slice(&cell(&vk));
        }

        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[..4].copy_from_slice(b"regf");
        hive.extend_from_slice(&bins);
        hive
    }

    fn hive_with_cache(blob: &[u8]) -> Vec<u8> {
        hive_with_cache_copies(blob, 1)
    }

    #[test]
    fn carver_recovers_a_plain_value() {
        let blob = win10_blob(0x34, &[("C:\\carved.exe", TS_2024)]);
        assert_eq!(collect_blobs(&hive_with_cache(&blob)), vec![blob]);
    }

    #[test]
    fn carver_reassembles_big_data() {
        let names: Vec<String> = (0..600).map(|i| format!("C:\\dir{i}\\program{i}.exe")).collect();
        let entries: Vec<(&str, u64)> = names.iter().map(|n| (n.as_str(), TS_2024)).collect();
        let blob = win10_blob(0x34, &entries);
        assert!(blob.len() > 2 * BIG_DATA_SEGMENT_SIZE, "fixture must span segments");

        let hive = hive_with_cache(&blob);
        assert_eq!(collect_blobs(&hive), vec![blob]);
        assert_eq!(harvest(&hive).len(), 600);
    }

    #[test]
    fn carver_ignores_values_with_other_names() {
        let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
        let mut bins = cell(&blob);
        bins.extend_from_slice(&cell(&vk_record("SomethingElse", 0, blob.len() as u32)));
        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[..4].copy_from_slice(b"regf");
        hive.extend_from_slice(&bins);
        assert!(collect_blobs(&hive).is_empty());
    }

    #[test]
    fn carver_survives_a_vk_pointing_into_nowhere() {
        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[..4].copy_from_slice(b"regf");
        hive.extend_from_slice(&cell(&vk_record(VALUE_NAME, u32::MAX, u32::MAX / 2)));
        assert!(collect_blobs(&hive).is_empty());
        assert!(harvest(&hive).is_empty());
    }

    #[test]
    fn free_cells_are_not_read_as_data() {
        let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
        let mut bins = cell(&blob);
        let size = i32::from_le_bytes(bins[..4].try_into().unwrap());
        bins[..4].copy_from_slice(&(-size).to_le_bytes());
        bins.extend_from_slice(&cell(&vk_record(VALUE_NAME, 0, blob.len() as u32)));
        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[..4].copy_from_slice(b"regf");
        hive.extend_from_slice(&bins);
        assert!(collect_blobs(&hive).is_empty());
    }

    fn push_cell(bins: &mut Vec<u8>, payload: &[u8]) -> u32 {
        let at = bins.len();
        let mut size = 4 + payload.len();
        if !size.is_multiple_of(8) {
            size += 8 - size % 8;
        }
        bins.extend_from_slice(&(-(size as i32)).to_le_bytes());
        bins.extend_from_slice(payload);
        bins.resize(at + size, 0);
        at as u32
    }

    fn nk_payload(
        name: &str,
        flags: u16,
        subkey_count: u32,
        subkeys_offset: u32,
        value_count: u32,
        values_offset: u32,
    ) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"nk");
        p.extend_from_slice(&flags.to_le_bytes());
        p.extend_from_slice(&TS_2024.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&subkey_count.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&subkeys_offset.to_le_bytes());
        p.extend_from_slice(&u32::MAX.to_le_bytes());
        p.extend_from_slice(&value_count.to_le_bytes());
        p.extend_from_slice(&values_offset.to_le_bytes());
        for _ in 0..7 {
            p.extend_from_slice(&0u32.to_le_bytes());
        }
        p.extend_from_slice(&(name.len() as u16).to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(name.as_bytes());
        p
    }

    fn index_leaf(children: &[u32]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"li");
        p.extend_from_slice(&(children.len() as u16).to_le_bytes());
        for child in children {
            p.extend_from_slice(&child.to_le_bytes());
        }
        p
    }

    const HIVE_ENTRY: u16 = 0x0004 | 0x0008;
    const COMP_NAME: u16 = KEY_COMP_NAME;

    fn control_set(bins: &mut Vec<u8>, name: &str, path: &str, blob: &[u8]) -> u32 {
        let data_at = push_cell(bins, blob);
        let vk_at = push_cell(bins, &vk_record(VALUE_NAME, data_at, blob.len() as u32));
        let value_list_at = push_cell(bins, &vk_at.to_le_bytes());

        let components: Vec<&str> = path.split('\\').collect();
        let leaf_name = components.last().copied().unwrap_or(VALUE_NAME);
        let mut child =
            push_cell(bins, &nk_payload(leaf_name, COMP_NAME, 0, u32::MAX, 1, value_list_at));
        for component in components.iter().rev().skip(1) {
            let list = push_cell(bins, &index_leaf(&[child]));
            child = push_cell(bins, &nk_payload(component, COMP_NAME, 1, list, 0, u32::MAX));
        }
        let list = push_cell(bins, &index_leaf(&[child]));
        push_cell(bins, &nk_payload(name, COMP_NAME, 1, list, 0, u32::MAX))
    }

    fn system_hive(blobs: &[(&str, &[u8])]) -> Vec<u8> {
        system_hive_at("Control\\Session Manager\\AppCompatCache", blobs)
    }

    fn system_hive_at(path: &str, blobs: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bins: Vec<u8> = Vec::new();
        bins.extend_from_slice(b"hbin");
        bins.extend_from_slice(&0u32.to_le_bytes());
        bins.extend_from_slice(&0u32.to_le_bytes());
        bins.resize(32, 0);

        let mut children: Vec<u32> =
            blobs.iter().map(|(name, blob)| control_set(&mut bins, name, path, blob)).collect();
        children
            .push(push_cell(&mut bins, &nk_payload("Select", COMP_NAME, 0, u32::MAX, 0, u32::MAX)));

        let leaf = push_cell(&mut bins, &index_leaf(&children));
        let root_at = push_cell(
            &mut bins,
            &nk_payload("ROOT", COMP_NAME | HIVE_ENTRY, children.len() as u32, leaf, 0, u32::MAX),
        );

        let padded = bins.len().div_ceil(BASE_BLOCK_SIZE) * BASE_BLOCK_SIZE;
        bins.resize(padded, 0);
        bins[8..12].copy_from_slice(&(padded as u32).to_le_bytes());

        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[0..4].copy_from_slice(b"regf");
        hive[4..8].copy_from_slice(&1u32.to_le_bytes());
        hive[8..12].copy_from_slice(&1u32.to_le_bytes());
        hive[12..20].copy_from_slice(&TS_2024.to_le_bytes());
        hive[20..24].copy_from_slice(&1u32.to_le_bytes());
        hive[24..28].copy_from_slice(&5u32.to_le_bytes());
        hive[28..32].copy_from_slice(&0u32.to_le_bytes());
        hive[32..36].copy_from_slice(&1u32.to_le_bytes());
        hive[36..40].copy_from_slice(&root_at.to_le_bytes());
        hive[40..44].copy_from_slice(&(padded as u32).to_le_bytes());
        hive[44..48].copy_from_slice(&1u32.to_le_bytes());

        let mut xor = 0u32;
        for i in 0..127 {
            xor ^= u32::from_le_bytes(hive[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let checksum = match xor {
            0xffff_ffff => 0xffff_fffe,
            0 => 1,
            other => other,
        };
        hive[508..512].copy_from_slice(&checksum.to_le_bytes());

        hive.extend_from_slice(&bins);
        hive
    }

    #[test]
    fn well_formed_hive_is_read_through_the_key_tree() {
        let one = win10_blob(0x34, &[("\\??\\C:\\Windows\\System32\\one.exe", TS_2024)]);
        let two = win10_blob(0x34, &[("\\??\\C:\\Users\\bob\\two.exe", TS_2020)]);
        let hive = system_hive(&[("ControlSet001", &one), ("ControlSet002", &two)]);

        let blobs = tree_values(&hive);
        assert_eq!(blobs, vec![one, two], "both control sets must be read");

        let mut keys: Vec<String> =
            harvest(&hive).iter().map(|o| o.path.as_ref().unwrap().key().to_string()).collect();
        keys.sort();
        assert_eq!(keys, ["\\users\\bob\\two.exe", "\\windows\\system32\\one.exe"]);
    }

    #[test]
    fn windows_xp_key_name_is_also_searched() {
        assert!(CACHE_KEY_PATHS.contains(&"Control\\Session Manager\\AppCompatibility"));
        let blob = xp_blob(&[("C:\\WINDOWS\\evil.exe", TS_2020)]);
        let hive = system_hive_at(
            "Control\\Session Manager\\AppCompatibility",
            &[("ControlSet001", &blob)],
        );
        assert_eq!(tree_values(&hive), vec![blob]);
        assert_eq!(harvest(&hive).len(), 1);
    }

    #[test]
    fn duplicate_control_sets_do_not_double_count() {
        let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
        let hive = system_hive(&[("ControlSet001", &blob), ("ControlSet002", &blob)]);
        assert_eq!(tree_values(&hive).len(), 1);
        assert_eq!(collect_blobs(&hive).len(), 1);
        assert_eq!(harvest(&hive).len(), 1);
    }

    #[test]
    fn hive_without_a_cache_yields_nothing() {
        let hive = system_hive(&[]);
        assert!(root_cell(&hive).is_some());
        assert!(harvest(&hive).is_empty());
    }

    #[test]
    fn destroyed_tree_still_yields_the_cache_by_carving() {
        let blob = win10_blob(0x34, &[("C:\\still-here.exe", TS_2024)]);
        let mut hive = system_hive(&[("ControlSet001", &blob)]);
        hive[36..40].copy_from_slice(&0u32.to_le_bytes());
        assert!(root_cell(&hive).is_none());
        assert!(tree_values(&hive).is_empty());

        let out = harvest(&hive);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path.as_ref().unwrap().key(), "\\still-here.exe");
    }

    #[test]
    fn self_referential_subkey_list_terminates() {
        let mut bins: Vec<u8> = vec![0u8; 32];
        let list_at = bins.len() as u32;
        let mut ri = Vec::new();
        ri.extend_from_slice(b"ri");
        ri.extend_from_slice(&1u16.to_le_bytes());
        ri.extend_from_slice(&list_at.to_le_bytes());
        push_cell(&mut bins, &ri);
        let root_at = push_cell(&mut bins, &nk_payload("ROOT", COMP_NAME, 1, list_at, 0, u32::MAX));

        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[0..4].copy_from_slice(b"regf");
        hive[36..40].copy_from_slice(&root_at.to_le_bytes());
        hive.extend_from_slice(&bins);

        assert!(subkeys(&hive, root_cell(&hive).unwrap()).is_empty());
        assert!(harvest(&hive).is_empty());
    }

    #[test]
    fn truncated_well_formed_hive_never_panics() {
        let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
        let hive = system_hive(&[("ControlSet001", &blob)]);
        for len in (0..hive.len()).step_by(23) {
            let _ = harvest(&hive[..len]);
        }
    }

    #[test]
    fn randomly_damaged_hives_never_panic() {
        let blob =
            win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("\\??\\C:\\Users\\bob\\b.exe", TS_2020)]);
        let pristine = system_hive(&[("ControlSet001", &blob), ("ControlSet002", &blob)]);
        let expected = harvest(&pristine).len();
        assert_eq!(expected, 2);

        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        for _ in 0..5_000 {
            let mut damaged = pristine.clone();
            for _ in 0..(1 + next() % 40) {
                let at = next() % damaged.len();
                damaged[at] = next() as u8;
            }
            let _ = harvest(&damaged);
        }
    }

    #[test]
    fn root_cell_lookup_rejects_the_obvious() {
        assert!(root_cell(&[]).is_none());
        assert!(root_cell(&[0u8; 4096]).is_none());
        let mut b = vec![0u8; 8192];
        b[..4].copy_from_slice(b"regf");
        assert!(root_cell(&b).is_none(), "root cell must actually be a key node");
    }

    const HOSTILE_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

    fn within_budget(what: &str, body: impl FnOnce()) {
        let started = std::time::Instant::now();
        body();
        let took = started.elapsed();
        assert!(took < HOSTILE_BUDGET, "{what} took {took:?}, budget {HOSTILE_BUDGET:?}");
    }

    fn hive_around(bins: Vec<u8>, root: u32) -> Vec<u8> {
        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[0..4].copy_from_slice(b"regf");
        hive[36..40].copy_from_slice(&root.to_le_bytes());
        hive.extend_from_slice(&bins);
        hive
    }

    #[test]
    fn self_referential_ri_with_a_full_list_terminates() {
        let mut bins: Vec<u8> = vec![0u8; 32];
        let list_at = bins.len() as u32;
        let mut ri = Vec::new();
        ri.extend_from_slice(b"ri");
        ri.extend_from_slice(&u16::MAX.to_le_bytes());
        for _ in 0..u16::MAX {
            ri.extend_from_slice(&list_at.to_le_bytes());
        }
        push_cell(&mut bins, &ri);
        let root_at = push_cell(&mut bins, &nk_payload("ROOT", COMP_NAME, 1, list_at, 0, u32::MAX));
        let hive = hive_around(bins, root_at);

        within_budget("self-referential ri", || {
            assert!(subkeys(&hive, root_cell(&hive).unwrap()).is_empty());
            assert!(harvest(&hive).is_empty());
        });
    }

    #[test]
    fn nested_full_ri_lists_terminate() {
        let mut bins: Vec<u8> = vec![0u8; 32];
        let mut level = {
            let mut li = Vec::new();
            li.extend_from_slice(b"li");
            li.extend_from_slice(&u16::MAX.to_le_bytes());
            for _ in 0..u16::MAX {
                li.extend_from_slice(&0u32.to_le_bytes());
            }
            push_cell(&mut bins, &li)
        };
        for _ in 0..3 {
            let mut ri = Vec::new();
            ri.extend_from_slice(b"ri");
            ri.extend_from_slice(&u16::MAX.to_le_bytes());
            for _ in 0..u16::MAX {
                ri.extend_from_slice(&level.to_le_bytes());
            }
            level = push_cell(&mut bins, &ri);
        }
        let root_at = push_cell(&mut bins, &nk_payload("ROOT", COMP_NAME, 1, level, 0, u32::MAX));
        let hive = hive_around(bins, root_at);

        within_budget("nested ri", || {
            let _ = harvest(&hive);
        });
    }

    #[test]
    fn a_hive_that_is_all_control_sets_terminates() {
        let mut bins: Vec<u8> = vec![0u8; 32];
        let dead = 0u32;
        let mut li = Vec::new();
        li.extend_from_slice(b"li");
        li.extend_from_slice(&u16::MAX.to_le_bytes());
        for _ in 0..u16::MAX {
            li.extend_from_slice(&dead.to_le_bytes());
        }
        let li_at = push_cell(&mut bins, &li);
        let cs = push_cell(
            &mut bins,
            &nk_payload("ControlSet001", COMP_NAME, u32::MAX, li_at, 0, u32::MAX),
        );
        let mut top = Vec::new();
        top.extend_from_slice(b"li");
        top.extend_from_slice(&u16::MAX.to_le_bytes());
        for _ in 0..u16::MAX {
            top.extend_from_slice(&cs.to_le_bytes());
        }
        let top_at = push_cell(&mut bins, &top);
        let root_at =
            push_cell(&mut bins, &nk_payload("ROOT", COMP_NAME, u32::MAX, top_at, 0, u32::MAX));
        let hive = hive_around(bins, root_at);

        within_budget("all-control-sets hive", || {
            assert!(harvest(&hive).is_empty());
        });
    }

    #[test]
    fn subkey_list_pointing_at_itself_or_its_key_terminates() {
        let mut bins: Vec<u8> = vec![0u8; 32];
        let nk_at = bins.len() as u32;
        push_cell(&mut bins, &nk_payload("ROOT", COMP_NAME, 4, nk_at, 0, u32::MAX));
        let hive = hive_around(bins, nk_at);
        within_budget("self-pointing subkey list", || {
            assert!(harvest(&hive).is_empty());
        });
    }

    #[test]
    fn many_vks_naming_one_big_value_do_not_exhaust_memory() {
        let names: Vec<String> =
            (0..40_000).map(|i| format!(r"C:\dir{i}\program{i}.exe")).collect();
        let entries: Vec<(&str, u64)> = names.iter().map(|n| (n.as_str(), TS_2024)).collect();
        let blob = win10_blob(0x34, &entries);
        assert!(blob.len() > 2_000_000, "fixture must be big enough to matter");

        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive.extend_from_slice(&cell(&blob));
        let vk = vk_record(VALUE_NAME, 0, blob.len() as u32);
        for _ in 0..20_000 {
            hive.extend_from_slice(&vk);
        }

        within_budget("vk swarm", || {
            let blobs = collect_blobs(&hive);
            assert_eq!(blobs, vec![blob.clone()]);
        });
    }

    #[test]
    fn vks_naming_distinct_overlapping_cells_stay_bounded() {
        let filler = vec![0xabu8; 3_000_000];
        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive.extend_from_slice(&cell(&filler));
        let mut vks = Vec::new();
        for i in 0..5_000u32 {
            vks.extend_from_slice(&vk_record(VALUE_NAME, 0, 1_000_000 + i));
        }
        hive.extend_from_slice(&vks);

        within_budget("overlapping vk swarm", || {
            let blobs = collect_blobs(&hive);
            let total: usize = blobs.iter().map(Vec::len).sum();
            assert!(
                total <= hive.len().saturating_mul(CARVE_BUDGET_RATIO) + filler.len(),
                "carved {total} bytes out of a {} byte hive",
                hive.len()
            );
        });
    }

    #[test]
    fn big_data_with_repeated_segments_stays_bounded() {
        let segment = vec![0xcdu8; BIG_DATA_SEGMENT_SIZE];
        let mut bins: Vec<u8> = Vec::new();
        let seg_at = bins.len() as u32;
        bins.extend_from_slice(&cell(&segment));

        let mut list = Vec::new();
        for _ in 0..u16::MAX {
            list.extend_from_slice(&seg_at.to_le_bytes());
        }
        let list_at = bins.len() as u32;
        bins.extend_from_slice(&cell(&list));

        let mut db = Vec::new();
        db.extend_from_slice(b"db");
        db.extend_from_slice(&u16::MAX.to_le_bytes());
        db.extend_from_slice(&list_at.to_le_bytes());
        let db_at = bins.len() as u32;
        bins.extend_from_slice(&cell(&db));

        bins.extend_from_slice(&cell(&vk_record(VALUE_NAME, db_at, u32::MAX / 2)));

        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[..4].copy_from_slice(b"regf");
        hive.extend_from_slice(&bins);

        within_budget("big-data bomb", || {
            let total: usize = collect_blobs(&hive).iter().map(Vec::len).sum();
            assert!(
                total <= hive.len(),
                "reassembled {total} bytes from a {} byte hive",
                hive.len()
            );
        });
    }

    #[test]
    fn self_referential_value_data_terminates() {
        let mut bins: Vec<u8> = Vec::new();
        let db_at = bins.len() as u32;
        let mut db = Vec::new();
        db.extend_from_slice(b"db");
        db.extend_from_slice(&u16::MAX.to_le_bytes());
        db.extend_from_slice(&db_at.to_le_bytes());
        bins.extend_from_slice(&cell(&db));
        bins.extend_from_slice(&cell(&vk_record(VALUE_NAME, db_at, 1_000_000)));
        let vk_at = 0u32;
        bins.extend_from_slice(&cell(&vk_record(VALUE_NAME, vk_at, 4096)));

        let mut hive = vec![0u8; BASE_BLOCK_SIZE];
        hive[..4].copy_from_slice(b"regf");
        hive.extend_from_slice(&bins);
        within_budget("self-referential value data", || {
            let _ = harvest(&hive);
        });
    }

    #[test]
    fn crafted_filenames_cannot_forge_records_in_the_string_area() {
        for format in [Format::Win7, Format::Nt52] {
            for wide in [false, true] {
                let names: Vec<String> = (0..40)
                    .map(|i| format!("\\??\\C:\\a{i}ac\u{0088}\u{0000}\u{0000}rogue\u{0000}"))
                    .collect();
                let entries: Vec<(&str, u64)> =
                    names.iter().map(|n| (n.as_str(), TS_2024)).collect();
                let blob = fixed_blob(format, wide, &entries);
                let got = parse_cache(&blob);
                assert_eq!(
                    got.len(),
                    40,
                    "{format:?} wide={wide}: forged {:?}",
                    got.iter().skip(40).map(|e| e.path.clone()).collect::<Vec<_>>()
                );
                for (entry, name) in got.iter().zip(&names) {
                    assert!(name.starts_with(&entry.path), "{:?} is not a prefix", entry.path);
                    assert!(!entry.path.contains("rogue"));
                }
            }
        }
    }

    #[test]
    fn fixed_formats_stop_at_the_end_of_the_record_table() {
        for format in [Format::Win7, Format::Nt52] {
            for wide in [false, true] {
                let names: Vec<String> =
                    (0..200).map(|i| format!(r"\??\C:\Windows\System32\prog{i}ac.exe")).collect();
                let entries: Vec<(&str, u64)> =
                    names.iter().map(|n| (n.as_str(), TS_2020)).collect();
                let blob = fixed_blob(format, wide, &entries);
                assert_eq!(parse_cache(&blob).len(), 200, "{format:?} wide={wide}");
            }
        }
    }

    #[test]
    fn the_win7_data_region_is_not_walked_as_records() {
        const HEADER: usize = 0x80;
        const ENTRY: usize = 32;
        let real: Vec<String> = (0..24).map(|i| format!(r"\??\C:\real{i}.exe")).collect();
        let lure = utf16(r"\??\C:\FORGED.exe");

        let table_len = ENTRY * real.len();
        let data_len = ENTRY * real.len();
        let mut table = vec![0u8; table_len];
        let mut data = vec![0u8; data_len];
        let mut strings: Vec<u8> = Vec::new();
        let strings_at = HEADER + table_len + data_len;

        let lure_at = strings_at;
        strings.extend_from_slice(&lure);
        strings.extend_from_slice(&[0, 0]);

        for (i, name) in real.iter().enumerate() {
            let path = utf16(name);
            let path_at = strings_at + strings.len();
            let slot = &mut table[i * ENTRY..(i + 1) * ENTRY];
            slot[0..2].copy_from_slice(&(path.len() as u16).to_le_bytes());
            slot[2..4].copy_from_slice(&((path.len() + 2) as u16).to_le_bytes());
            slot[4..8].copy_from_slice(&(path_at as u32).to_le_bytes());
            slot[8..16].copy_from_slice(&TS_2024.to_le_bytes());
            slot[24..28].copy_from_slice(&(ENTRY as u32).to_le_bytes());
            slot[28..32].copy_from_slice(&((HEADER + table_len + i * ENTRY) as u32).to_le_bytes());
            strings.extend_from_slice(&path);
            strings.extend_from_slice(&[0, 0]);

            let forged = &mut data[i * ENTRY..(i + 1) * ENTRY];
            forged[0..2].copy_from_slice(&(lure.len() as u16).to_le_bytes());
            forged[2..4].copy_from_slice(&((lure.len() + 2) as u16).to_le_bytes());
            forged[4..8].copy_from_slice(&(lure_at as u32).to_le_bytes());
            forged[8..16].copy_from_slice(&TS_2020.to_le_bytes());
        }

        let mut blob = vec![0u8; HEADER];
        blob[..4].copy_from_slice(&0xBADC_0FEEu32.to_le_bytes());
        blob[4..8].copy_from_slice(&(real.len() as u32).to_le_bytes());
        blob.extend_from_slice(&table);
        blob.extend_from_slice(&data);
        blob.extend_from_slice(&strings);

        let got = parse_cache(&blob);
        assert!(
            got.iter().all(|e| !e.path.contains("FORGED")),
            "the data region was walked as records: {:?}",
            got.iter().filter(|e| e.path.contains("FORGED")).collect::<Vec<_>>()
        );
        assert_eq!(got.len(), real.len());
    }

    #[test]
    fn a_backwards_path_offset_does_not_truncate_the_table() {
        let names: Vec<String> = (0..8).map(|i| format!(r"\??\C:\p{i}.exe")).collect();
        let entries: Vec<(&str, u64)> = names.iter().map(|n| (n.as_str(), TS_2024)).collect();
        let mut blob = fixed_blob(Format::Win7, false, &entries);
        blob[0x84..0x88].copy_from_slice(&0x80u32.to_le_bytes());
        let got = parse_cache(&blob);
        assert!(got.len() >= 7, "expected the other seven records, got {}", got.len());
    }

    #[test]
    fn a_padded_record_body_keeps_its_timestamp() {
        for (header, layout, tag) in [
            (0x34u32, Body::Win10, b"10ts"),
            (0x30, Body::Win10, b"10ts"),
            (0x80, Body::Win81, b"10ts"),
            (0x80, Body::Win80, b"00ts"),
        ] {
            for pad in [2usize, 8, 16] {
                let mut blob = vec![0u8; header as usize];
                blob[..4].copy_from_slice(&header.to_le_bytes());
                let mut rec = tagged_record(tag, r"C:\pad.exe", TS_2024, layout, &[]);
                let body_len = u32::from_le_bytes(rec[8..12].try_into().unwrap());
                rec[8..12].copy_from_slice(&(body_len + pad as u32).to_le_bytes());
                rec.resize(rec.len() + pad, 0);
                blob.extend_from_slice(&rec);

                let got = parse_cache(&blob);
                assert_eq!(paths(&got), [r"C:\pad.exe"], "header {header:#x} pad {pad}");
                assert_eq!(
                    got[0].last_modified, TS_2024,
                    "header {header:#x} pad {pad}: timestamp lost"
                );
            }
        }
    }

    #[test]
    fn a_bad_layout_never_supplies_a_timestamp() {
        let mut body = Vec::new();
        let path = utf16(r"C:\x.exe");
        body.extend_from_slice(&(path.len() as u16).to_le_bytes());
        body.extend_from_slice(&path);
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&[0xaa; 7]);

        let mut blob = vec![0u8; 0x34];
        blob[..4].copy_from_slice(&0x34u32.to_le_bytes());
        blob.extend_from_slice(b"10ts");
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(body.len() as u32).to_le_bytes());
        blob.extend_from_slice(&body);

        let got = parse_cache(&blob);
        assert_eq!(paths(&got), [r"C:\x.exe"], "the path survives");
        assert_eq!(got[0].last_modified, 0, "no date may be invented from flags");
    }

    #[test]
    fn extreme_field_values_never_panic_and_never_multiply_entries() {
        let originals = [
            win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("C:\\b.exe", TS_2020)]),
            win10_blob(0x30, &[("C:\\a.exe", TS_2024)]),
            win8_blob(b"00ts", Body::Win80, &[("C:\\a.exe", TS_2024)]),
            win8_blob(b"10ts", Body::Win81, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Win7, false, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Win7, true, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Nt52, false, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Nt52, true, &[("C:\\a.exe", TS_2024)]),
            xp_blob(&[("C:\\a.exe", TS_2024)]),
        ];
        let pokes: [u32; 8] =
            [0, 1, 2, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, u32::MAX, 0xdead_beef];

        for blob in &originals {
            let baseline = parse_cache(blob).len();
            for at in (0..blob.len().saturating_sub(4)).step_by(2) {
                for poke in pokes {
                    let mut damaged = blob.clone();
                    damaged[at..at + 4].copy_from_slice(&poke.to_le_bytes());
                    let got = parse_cache(&damaged);
                    assert!(
                        got.len() <= baseline.max(4) + damaged.len() / 24,
                        "poke {poke:#x} at {at} produced {} entries",
                        got.len()
                    );
                }
            }
        }
    }

    #[test]
    fn truncation_at_every_single_offset_is_survivable() {
        let blobs = [
            win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("C:\\b.exe", TS_2020)]),
            win8_blob(b"00ts", Body::Win80, &[("C:\\a.exe", TS_2024)]),
            win8_blob(b"10ts", Body::Win81, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Win7, true, &[("C:\\a.exe", TS_2024)]),
            fixed_blob(Format::Nt52, false, &[("C:\\a.exe", TS_2024)]),
            xp_blob(&[("C:\\a.exe", TS_2024)]),
        ];
        for blob in &blobs {
            let whole = parse_cache(blob).len();
            for len in 0..=blob.len() {
                assert!(parse_cache(&blob[..len]).len() <= whole);
            }
        }
        let hive = system_hive(&[("ControlSet001", &win10_blob(0x34, &[("C:\\a.exe", TS_2024)]))]);
        for len in 0..=hive.len() {
            let _ = harvest(&hive[..len]);
        }
    }

    #[test]
    fn tiny_inputs_of_every_shape_are_survivable() {
        let signatures: [u32; 8] =
            [0xDEAD_BEEF, 0xBADC_0FFE, 0xBADC_0FEE, 0x80, 0x30, 0x34, 0x10, 0x1000];
        for signature in signatures {
            let mut blob = signature.to_le_bytes().to_vec();
            blob.extend_from_slice(b"10ts\0\0\0\0\x04\0\0\0\x02\0A\0");
            blob.extend_from_slice(&[0xff; 48]);
            for len in 0..=blob.len() {
                let _ = parse_cache(&blob[..len]);
                let _ = harvest(&blob[..len]);
            }
        }
        for len in 0..=64 {
            let _ = harvest(&vec![0xffu8; len]);
            let _ = harvest(&vec![0u8; len]);
            let mut regf = b"regf".to_vec();
            regf.resize(len.max(4), 0xcc);
            let _ = harvest(&regf);
        }
    }

    #[test]
    fn tagged_records_always_advance() {
        for body_len in [0u32, 1, 4, 11, 12, u32::MAX, u32::MAX - 11] {
            let mut blob = vec![0u8; 0x34];
            blob[..4].copy_from_slice(&0x34u32.to_le_bytes());
            for _ in 0..64 {
                blob.extend_from_slice(b"10ts");
                blob.extend_from_slice(&0u32.to_le_bytes());
                blob.extend_from_slice(&body_len.to_le_bytes());
                blob.extend_from_slice(&[0x41; 16]);
            }
            within_budget("tagged walk", || {
                let _ = parse_cache(&blob);
            });
        }
    }

    #[test]
    fn a_wild_root_offset_is_survivable() {
        let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
        let hive = system_hive(&[("ControlSet001", &blob)]);
        for root in [0u32, 1, 4, 0x7fff_ffff, 0x8000_0000, u32::MAX, hive.len() as u32] {
            let mut damaged = hive.clone();
            damaged[36..40].copy_from_slice(&root.to_le_bytes());
            within_budget("wild root", || {
                let _ = harvest(&damaged);
            });
        }
    }

    #[test]
    fn wild_key_node_fields_are_survivable() {
        let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
        let pristine = system_hive(&[("ControlSet001", &blob)]);
        let nk_offsets: Vec<usize> = (BASE_BLOCK_SIZE..pristine.len() - 2)
            .filter(|&i| &pristine[i..i + 2] == b"nk")
            .collect();
        assert!(!nk_offsets.is_empty());

        for &nk in &nk_offsets {
            for field in [20usize, 28, 36, 40] {
                for poke in [0u32, 1, u32::MAX, 0x8000_0000, 0xffff] {
                    if nk + field + 4 > pristine.len() {
                        continue;
                    }
                    let mut damaged = pristine.clone();
                    damaged[nk + field..nk + field + 4].copy_from_slice(&poke.to_le_bytes());
                    within_budget("wild nk", || {
                        let _ = harvest(&damaged);
                    });
                }
            }
            if nk + 74 <= pristine.len() {
                for poke in [0u16, 1, u16::MAX] {
                    let mut damaged = pristine.clone();
                    damaged[nk + 72..nk + 74].copy_from_slice(&poke.to_le_bytes());
                    let _ = harvest(&damaged);
                }
            }
        }
    }

    #[test]
    fn field_directed_fuzzing_of_a_real_hive_terminates() {
        let blob =
            win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("\\??\\C:\\Users\\bob\\b.exe", TS_2020)]);
        let pristine = system_hive(&[("ControlSet001", &blob), ("ControlSet002", &blob)]);

        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        let interesting: [u32; 6] = [0, 1, u16::MAX as u32, 0xffff_ffff, 0x8000_0000, 0x0000_1000];

        let started = std::time::Instant::now();
        for _ in 0..3_000 {
            let mut damaged = pristine.clone();
            for _ in 0..(1 + next() % 6) {
                let at = (next() % (damaged.len() - 4)) & !3;
                let value = interesting[next() % interesting.len()];
                damaged[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            let _ = harvest(&damaged);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(60),
                "field-directed fuzzing is not terminating quickly enough"
            );
        }
    }

    #[test]
    fn a_real_hive_costs_a_negligible_fraction_of_the_visit_budget() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_hive");
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("skipping: no reference hive at {path}");
            return;
        };
        let mut visits = MAX_CELL_VISITS;
        let root = root_cell(&bytes).expect("real hive has a root");
        for (_, cell) in subkeys_within(&bytes, root, &mut visits) {
            for key_path in CACHE_KEY_PATHS {
                let _ = descend(&bytes, cell, key_path, &mut visits);
            }
        }
        let spent = MAX_CELL_VISITS - visits;
        assert!(
            spent * 100 < MAX_CELL_VISITS,
            "a real hive spent {spent} of {MAX_CELL_VISITS} visits — budget is too tight"
        );
    }

    #[test]
    fn a_full_cache_in_three_control_sets_is_within_the_blob_budget() {
        let names: Vec<String> =
            (0..1024).map(|i| format!(r"\??\C:\Windows\System32\binary{i:04}.exe")).collect();
        let entries: Vec<(&str, u64)> = names.iter().map(|n| (n.as_str(), TS_2024)).collect();
        let a = win10_blob(0x34, &entries);
        let b = win10_blob(0x34, &entries[..900]);
        let c = win10_blob(0x34, &entries[..800]);
        let hive =
            system_hive(&[("ControlSet001", &a), ("ControlSet002", &b), ("ControlSet003", &c)]);
        assert_eq!(collect_blobs(&hive).len(), 3);
        assert_eq!(harvest(&hive).len(), 1024);
    }

    mod heavy {
        use super::*;

        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                self.0 >> 17
            }
            fn below(&mut self, n: usize) -> usize {
                if n == 0 {
                    0
                } else {
                    (self.next() as usize) % n
                }
            }
            fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
                xs[self.below(xs.len())]
            }
        }

        const SIGS: [u32; 10] =
            [0xDEAD_BEEF, 0xBADC_0FFE, 0xBADC_0FEE, 0x80, 0x30, 0x34, 0x10, 0x1000, 0x0F, 0x1001];
        const WORDS: [u32; 9] =
            [0, 1, 2, 4, 0xffff, 0x8000_0000, 0xffff_ffff, 0x0000_1000, 0x7fff_ffff];

        #[test]
        #[ignore]
        fn blob_soup() {
            let mut r = Rng(0xC0FF_EE00_1234_5678);
            for round in 0..300_000u32 {
                let len = r.below(600) + 4;
                let mut blob: Vec<u8> = (0..len).map(|_| r.next() as u8).collect();
                blob[..4].copy_from_slice(&r.pick(&SIGS).to_le_bytes());
                for _ in 0..r.below(8) {
                    let at = r.below(len.saturating_sub(4));
                    let at = at & !3;
                    if at + 4 <= len {
                        if r.next().is_multiple_of(2) {
                            blob[at..at + 4].copy_from_slice(if r.next().is_multiple_of(2) {
                                b"10ts"
                            } else {
                                b"00ts"
                            });
                        } else {
                            blob[at..at + 4].copy_from_slice(&r.pick(&WORDS).to_le_bytes());
                        }
                    }
                }
                let started = std::time::Instant::now();
                let _ = parse_cache(&blob);
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(5),
                    "round {round} was slow"
                );
            }
        }

        #[test]
        #[ignore]
        fn hive_soup() {
            let mut r = Rng(0x5EED_1234_ABCD_0001);
            let tags: [[u8; 2]; 7] = [*b"nk", *b"vk", *b"lf", *b"lh", *b"li", *b"ri", *b"db"];
            for round in 0..120_000u32 {
                let bins = r.below(3000) + 32;
                let mut hive = vec![0u8; BASE_BLOCK_SIZE];
                hive.extend((0..bins).map(|_| r.next() as u8));
                if !r.next().is_multiple_of(8) {
                    hive[..4].copy_from_slice(b"regf");
                }
                hive[36..40].copy_from_slice(&(r.below(bins + 64) as u32).to_le_bytes());
                for _ in 0..r.below(24) {
                    let at = BASE_BLOCK_SIZE + (r.below(bins.saturating_sub(8)) & !3);
                    if at + 8 > hive.len() {
                        continue;
                    }
                    match r.below(3) {
                        0 => {
                            let size = -((r.below(400) as i32 + 8) & !7);
                            hive[at..at + 4].copy_from_slice(&size.to_le_bytes());
                        }
                        1 => hive[at..at + 2].copy_from_slice(&r.pick(&tags)),
                        _ => hive[at..at + 4].copy_from_slice(&r.pick(&WORDS).to_le_bytes()),
                    }
                }
                if r.next().is_multiple_of(4) {
                    let at = BASE_BLOCK_SIZE + r.below(bins.saturating_sub(40));
                    if at + 34 <= hive.len() {
                        let vk = {
                            let mut v = Vec::new();
                            v.extend_from_slice(b"vk");
                            v.extend_from_slice(&(VALUE_NAME.len() as u16).to_le_bytes());
                            v.extend_from_slice(&(r.next() as u32).to_le_bytes());
                            v.extend_from_slice(&(r.below(bins + 4096) as u32).to_le_bytes());
                            v.extend_from_slice(&REG_BINARY.to_le_bytes());
                            v.extend_from_slice(&VALUE_COMP_NAME.to_le_bytes());
                            v.extend_from_slice(&0u16.to_le_bytes());
                            v.extend_from_slice(VALUE_NAME.as_bytes());
                            v
                        };
                        hive[at..at + vk.len()].copy_from_slice(&vk);
                    }
                }
                let started = std::time::Instant::now();
                let _ = harvest(&hive);
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(5),
                    "round {round} was slow"
                );
            }
        }

        #[test]
        #[ignore]
        fn real_structure_mutation() {
            let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024), ("C:\\b.exe", TS_2020)]);
            let pristine = system_hive(&[("ControlSet001", &blob), ("ControlSet002", &blob)]);
            let mut r = Rng(0xFEED_FACE_0BAD_C0DE);
            for round in 0..200_000u32 {
                let mut d = pristine.clone();
                for _ in 0..(1 + r.below(10)) {
                    let at = r.below(d.len() - 4) & !3;
                    match r.below(4) {
                        0 => d[at..at + 4].copy_from_slice(&r.pick(&WORDS).to_le_bytes()),
                        1 => d[at..at + 4].copy_from_slice(&(r.next() as u32).to_le_bytes()),
                        2 => d[at..at + 2].copy_from_slice(&(r.next() as u16).to_le_bytes()),
                        _ => d[at] = r.next() as u8,
                    }
                }
                let started = std::time::Instant::now();
                let _ = harvest(&d);
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(5),
                    "round {round} was slow"
                );
            }
        }

        #[test]
        #[ignore]
        fn exhaustive_hive_truncation() {
            let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
            let hive = system_hive(&[("ControlSet001", &blob)]);
            for len in 0..=hive.len() {
                let _ = harvest(&hive[..len]);
            }
            let real = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_hive");
            if let Ok(bytes) = std::fs::read(real) {
                for len in (0..=bytes.len()).step_by(7) {
                    let _ = harvest(&bytes[..len]);
                }
            }
        }
    }

    fn nt_hive2_root_subkeys(bytes: &[u8]) -> Vec<String> {
        use nt_hive2::{CleanHive, Hive, HiveParseMode};
        let mut hive: Hive<std::io::Cursor<&[u8]>, CleanHive> =
            Hive::new(std::io::Cursor::new(bytes), HiveParseMode::NormalWithBaseBlock).unwrap();
        let root = hive.root_key_node().unwrap();
        let mut names: Vec<String> = root
            .subkeys(&mut hive)
            .unwrap()
            .iter()
            .map(|k| k.borrow().name().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn synthetic_hive_agrees_with_nt_hive2() {
        let blob = win10_blob(0x34, &[("C:\\a.exe", TS_2024)]);
        let hive = system_hive(&[("ControlSet001", &blob), ("ControlSet002", &blob)]);

        let mut mine: Vec<String> =
            subkeys(&hive, root_cell(&hive).unwrap()).into_iter().map(|(n, _)| n).collect();
        mine.sort();
        assert_eq!(mine, ["ControlSet001", "ControlSet002", "Select"]);
        assert_eq!(mine, nt_hive2_root_subkeys(&hive));
    }

    #[test]
    fn real_hive_agrees_with_nt_hive2() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/reference_hive");
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("skipping: no reference hive at {path}");
            return;
        };
        let mut mine: Vec<String> =
            subkeys(&bytes, root_cell(&bytes).expect("real hive has a root"))
                .into_iter()
                .map(|(name, _)| name)
                .collect();
        mine.sort();
        assert!(!mine.is_empty(), "a real hive has subkeys");
        assert_eq!(mine, nt_hive2_root_subkeys(&bytes));

        assert!(harvest(&bytes).is_empty());
    }
}
