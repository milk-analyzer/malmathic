use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};

const VSS_IDENTIFIER: [u8; 16] = [
    0x6b, 0x87, 0x08, 0x38, 0x76, 0xc1, 0x48, 0x4e, 0xb7, 0xae, 0x04, 0x04, 0x6e, 0x6c, 0xc7, 0x52,
];

const VOLUME_HEADER_OFFSET: u64 = 0x1e00;

pub const BLOCK_SIZE: u64 = 0x4000;

const TYPE_VOLUME_HEADER: u32 = 1;
const TYPE_CATALOG: u32 = 2;
const TYPE_STORE_BLOCK_LIST: u32 = 3;

const ENTRY_STORE_INFO: u64 = 2;
const ENTRY_STORE_LOCATION: u64 = 3;

const DESCRIPTOR_FORWARDER: u32 = 0x1;
const DESCRIPTOR_OVERLAY: u32 = 0x2;
const DESCRIPTOR_UNUSED: u32 = 0x4;

const MAX_CATALOG_BLOCKS: usize = 256;

const MAX_BLOCK_LIST_BLOCKS: usize = 16_384;

const MAX_BLOCK_DESCRIPTORS: usize = 2_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowCopy {
    pub id: String,
    pub sequence: u64,
    pub created: Option<DateTime<Utc>>,
    pub volume_size: u64,
    pub store_header_offset: u64,
    pub block_list_offset: u64,
    pub block_range_offset: u64,
    pub bitmap_offset: u64,
    pub store_file_record: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Catalog {
    pub copies: Vec<ShadowCopy>,
    pub refused: Vec<String>,
}

impl Catalog {
    pub fn is_empty(&self) -> bool {
        self.copies.is_empty()
    }

    pub fn newest(&self) -> Option<&ShadowCopy> {
        self.copies.first()
    }

    pub fn coverage(&self) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
        let mut times: Vec<DateTime<Utc>> = self.copies.iter().filter_map(|c| c.created).collect();
        times.sort();
        match (times.first(), times.last()) {
            (Some(a), Some(b)) => Some((*a, *b)),
            _ => None,
        }
    }
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3], b[o + 4], b[o + 5], b[o + 6], b[o + 7]])
}

fn guid(b: &[u8], o: usize) -> String {
    let mut tail = String::with_capacity(12);
    for byte in &b[o + 10..o + 16] {
        tail.push_str(&format!("{byte:02x}"));
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{tail}",
        le32(b, o),
        u16::from_le_bytes([b[o + 4], b[o + 5]]),
        u16::from_le_bytes([b[o + 6], b[o + 7]]),
        b[o + 8],
        b[o + 9],
    )
}

fn filetime(raw: u64) -> Option<DateTime<Utc>> {
    if raw == 0 {
        return None;
    }
    let secs = (raw / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((raw % 10_000_000) * 100) as u32;
    match Utc.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(t) => Some(t),
        _ => None,
    }
}

fn read_block<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    expected_type: u32,
    volume_size: u64,
) -> Result<Vec<u8>, String> {
    if offset >= volume_size || volume_size - offset < BLOCK_SIZE {
        return Err(format!("block offset {offset:#x} is outside the volume"));
    }
    let mut block = vec![0u8; BLOCK_SIZE as usize];
    reader
        .seek(SeekFrom::Start(offset))
        .and_then(|_| reader.read_exact(&mut block))
        .map_err(|e| format!("block at {offset:#x} unreadable: {e}"))?;

    if block[..16] != VSS_IDENTIFIER {
        return Err(format!("block at {offset:#x} is not a VSS block"));
    }
    let record_type = le32(&block, 0x14);
    if record_type != expected_type {
        return Err(format!(
            "block at {offset:#x} is record type {record_type}, expected {expected_type}"
        ));
    }
    let claimed = le64(&block, 0x20);
    if claimed != offset {
        return Err(format!("block at {offset:#x} claims to be at {claimed:#x}"));
    }
    Ok(block)
}

pub fn read_catalog<R: Read + Seek>(reader: &mut R, volume_size: u64) -> Catalog {
    let mut catalog = Catalog::default();

    let header = match read_block(reader, VOLUME_HEADER_OFFSET, TYPE_VOLUME_HEADER, volume_size) {
        Ok(b) => b,
        Err(_) => return catalog,
    };

    let catalog_offset = le64(&header, 0x30);
    if catalog_offset == 0 {
        return catalog;
    }

    let mut by_id: Vec<ShadowCopy> = Vec::new();
    let mut visited: Vec<u64> = Vec::new();
    let mut next = catalog_offset;

    while next != 0 && visited.len() < MAX_CATALOG_BLOCKS {
        if visited.contains(&next) {
            catalog.refused.push(format!("catalog chain loops at {next:#x}"));
            break;
        }
        visited.push(next);

        let block = match read_block(reader, next, TYPE_CATALOG, volume_size) {
            Ok(b) => b,
            Err(e) => {
                catalog.refused.push(e);
                break;
            }
        };

        let mut offset = 0x80usize;
        while offset + 0x80 <= block.len() {
            let kind = le64(&block, offset);
            if kind == 0 {
                break;
            }
            match kind {
                ENTRY_STORE_INFO => {
                    let id = guid(&block, offset + 0x10);
                    let entry = find_or_push(&mut by_id, &id);
                    entry.volume_size = le64(&block, offset + 0x08);
                    entry.sequence = le64(&block, offset + 0x20);
                    entry.created = filetime(le64(&block, offset + 0x30));
                }
                ENTRY_STORE_LOCATION => {
                    let id = guid(&block, offset + 0x10);
                    let entry = find_or_push(&mut by_id, &id);
                    entry.block_list_offset = le64(&block, offset + 0x08);
                    entry.store_header_offset = le64(&block, offset + 0x20);
                    entry.block_range_offset = le64(&block, offset + 0x28);
                    entry.bitmap_offset = le64(&block, offset + 0x30);
                    entry.store_file_record = le64(&block, offset + 0x38) & 0x0000_FFFF_FFFF_FFFF;
                }
                _ => {}
            }
            offset += 0x80;
        }

        next = le64(&block, 0x28);
    }

    by_id.retain(|c| {
        if c.block_list_offset == 0 || c.volume_size == 0 {
            catalog.refused.push(format!("store {} is named but not located", c.id));
            false
        } else {
            true
        }
    });

    by_id.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| b.sequence.cmp(&a.sequence)));
    catalog.copies = by_id;
    catalog
}

fn find_or_push<'a>(list: &'a mut Vec<ShadowCopy>, id: &str) -> &'a mut ShadowCopy {
    if let Some(index) = list.iter().position(|c| c.id == id) {
        return &mut list[index];
    }
    list.push(ShadowCopy {
        id: id.to_string(),
        sequence: 0,
        created: None,
        volume_size: 0,
        store_header_offset: 0,
        block_list_offset: 0,
        block_range_offset: 0,
        bitmap_offset: 0,
        store_file_record: 0,
    });
    let last = list.len() - 1;
    &mut list[last]
}

#[derive(Clone, Debug, Default)]
pub struct BlockMap {
    entries: Vec<(u64, u64)>,
    overlays: Vec<u64>,
    pub forwarders: u64,
    pub truncated: bool,
}

impl BlockMap {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn overlay_count(&self) -> usize {
        self.overlays.len()
    }

    fn lookup(&self, original: u64) -> Option<u64> {
        self.entries.binary_search_by_key(&original, |(o, _)| *o).ok().map(|i| self.entries[i].1)
    }

    fn is_overlay(&self, original: u64) -> bool {
        self.overlays.binary_search(&original).is_ok()
    }
}

pub fn read_block_map<R: Read + Seek>(
    reader: &mut R,
    copy: &ShadowCopy,
    volume_size: u64,
) -> (BlockMap, Vec<String>) {
    let mut map = BlockMap::default();
    let mut refused = Vec::new();
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::with_capacity(64);
    let mut next = copy.block_list_offset;

    while next != 0 && visited.len() < MAX_BLOCK_LIST_BLOCKS {
        if !visited.insert(next) {
            refused.push(format!("store {} block list loops at {next:#x}", copy.id));
            break;
        }

        let block = match read_block(reader, next, TYPE_STORE_BLOCK_LIST, volume_size) {
            Ok(b) => b,
            Err(e) => {
                refused.push(e);
                break;
            }
        };

        let mut offset = 0x80usize;
        while offset + 0x20 <= block.len() {
            let original = le64(&block, offset);
            let store_offset = le64(&block, offset + 0x10);
            let flags = le32(&block, offset + 0x18);
            offset += 0x20;

            if original == 0 && store_offset == 0 && flags == 0 {
                continue;
            }
            if flags & DESCRIPTOR_UNUSED != 0 {
                continue;
            }
            if flags & DESCRIPTOR_FORWARDER != 0 {
                map.forwarders += 1;
                continue;
            }
            if flags & DESCRIPTOR_OVERLAY != 0 {
                map.overlays.push(original);
                continue;
            }
            if volume_size - original.min(volume_size) < BLOCK_SIZE
                || volume_size - store_offset.min(volume_size) < BLOCK_SIZE
            {
                continue;
            }
            if map.entries.len() >= MAX_BLOCK_DESCRIPTORS {
                map.truncated = true;
                refused.push(format!(
                    "store {} describes more than {MAX_BLOCK_DESCRIPTORS} blocks",
                    copy.id
                ));
                break;
            }
            map.entries.push((original, store_offset));
        }

        if map.truncated {
            break;
        }
        next = le64(&block, 0x28);
    }

    map.entries.sort_by_key(|(original, _)| *original);
    map.entries.dedup_by_key(|(original, _)| *original);
    map.overlays.sort_unstable();
    map.overlays.dedup();
    (map, refused)
}

pub struct ShadowReader<R> {
    inner: R,
    map: BlockMap,
    size: u64,
    position: u64,
    uncertain: Arc<AtomicU64>,
}

impl<R: Read + Seek> ShadowReader<R> {
    pub fn new(inner: R, map: BlockMap, size: u64) -> Self {
        ShadowReader { inner, map, size, position: 0, uncertain: Arc::new(AtomicU64::new(0)) }
    }

    pub fn uncertainty(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.uncertain)
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

impl<R: Read + Seek> Read for ShadowReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.size - self.position;
        let want = (buf.len() as u64).min(remaining);

        let block_start = self.position - (self.position % BLOCK_SIZE);
        let within = self.position - block_start;
        let take = want.min(BLOCK_SIZE - within) as usize;

        let source = match self.map.lookup(block_start) {
            Some(store_offset) => {
                if self.map.is_overlay(block_start) {
                    self.uncertain.fetch_add(1, Ordering::Relaxed);
                }
                store_offset + within
            }
            None => {
                if self.map.is_overlay(block_start) {
                    self.uncertain.fetch_add(1, Ordering::Relaxed);
                }
                self.position
            }
        };

        self.inner.seek(SeekFrom::Start(source))?;
        let read = self.inner.read(&mut buf[..take])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for ShadowReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(n) => self.size as i128 + n as i128,
            SeekFrom::Current(n) => self.position as i128 + n as i128,
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the shadow copy",
            ));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn block(record_type: u32, offset: u64, next: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK_SIZE as usize];
        b[..16].copy_from_slice(&VSS_IDENTIFIER);
        b[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&record_type.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&offset.to_le_bytes());
        b[0x28..0x30].copy_from_slice(&next.to_le_bytes());
        b
    }

    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_guid(b: &mut [u8], at: usize, tag: u8) {
        for i in 0..16 {
            b[at + i] = tag;
        }
    }

    const VOLUME: u64 = 64 * 1024 * 1024;

    fn volume_with_one_copy() -> Vec<u8> {
        let mut disk = vec![0u8; VOLUME as usize];

        let catalog_at = 0x100000u64;
        let list_at = 0x200000u64;

        let mut header = block(TYPE_VOLUME_HEADER, VOLUME_HEADER_OFFSET, 0);
        put64(&mut header, 0x30, catalog_at);
        disk[VOLUME_HEADER_OFFSET as usize..][..BLOCK_SIZE as usize].copy_from_slice(&header);

        let mut catalog = block(TYPE_CATALOG, catalog_at, 0);
        put64(&mut catalog, 0x80, ENTRY_STORE_INFO);
        put64(&mut catalog, 0x88, VOLUME);
        put_guid(&mut catalog, 0x90, 0xAB);
        put64(&mut catalog, 0xA0, 7);
        put64(&mut catalog, 0xB0, 133_000_000_000_000_000);
        put64(&mut catalog, 0x100, ENTRY_STORE_LOCATION);
        put64(&mut catalog, 0x108, list_at);
        put_guid(&mut catalog, 0x110, 0xAB);
        put64(&mut catalog, 0x120, 0x180000);
        put64(&mut catalog, 0x128, 0x190000);
        put64(&mut catalog, 0x130, 0x1A0000);
        put64(&mut catalog, 0x138, (2u64 << 48) | 4242);
        disk[catalog_at as usize..][..BLOCK_SIZE as usize].copy_from_slice(&catalog);

        let mut list = block(TYPE_STORE_BLOCK_LIST, list_at, 0);
        put64(&mut list, 0x80, 0x400000);
        put64(&mut list, 0x90, 0x800000);
        put64(&mut list, 0xA0, 0x404000);
        put64(&mut list, 0xB0, 0x804000);
        disk[list_at as usize..][..BLOCK_SIZE as usize].copy_from_slice(&list);

        disk[0x400000..0x400000 + 8].copy_from_slice(b"LIVEDATA");
        disk[0x800000..0x800000 + 8].copy_from_slice(b"OLDDATA!");
        disk
    }

    #[test]
    fn a_volume_with_no_vss_header_yields_an_empty_catalog() {
        let disk = vec![0u8; VOLUME as usize];
        let catalog = read_catalog(&mut Cursor::new(disk), VOLUME);
        assert!(catalog.is_empty());
        assert!(catalog.refused.is_empty(), "silence is not a refusal");
    }

    #[test]
    fn the_catalog_yields_the_shadow_copy_it_describes() {
        let disk = volume_with_one_copy();
        let catalog = read_catalog(&mut Cursor::new(disk), VOLUME);
        assert_eq!(catalog.copies.len(), 1);
        let copy = &catalog.copies[0];
        assert_eq!(copy.sequence, 7);
        assert_eq!(copy.volume_size, VOLUME);
        assert_eq!(copy.block_list_offset, 0x200000);
        assert!(copy.created.is_some());
    }

    #[test]
    fn the_store_file_record_is_read_without_its_sequence_number() {
        let disk = volume_with_one_copy();
        let catalog = read_catalog(&mut Cursor::new(disk), VOLUME);
        assert_eq!(catalog.copies[0].store_file_record, 4242);
    }

    #[test]
    fn the_block_map_substitutes_only_the_blocks_it_describes() {
        let disk = volume_with_one_copy();
        let mut cursor = Cursor::new(disk);
        let catalog = read_catalog(&mut cursor, VOLUME);
        let (map, refused) = read_block_map(&mut cursor, &catalog.copies[0], VOLUME);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(map.len(), 2);

        let mut reader = ShadowReader::new(cursor, map, VOLUME);
        let mut buf = [0u8; 8];
        reader.seek(SeekFrom::Start(0x400000)).unwrap();
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"OLDDATA!", "a mapped block must come from the store");

        let mut live = [0u8; 8];
        reader.seek(SeekFrom::Start(0x500000)).unwrap();
        reader.read_exact(&mut live).unwrap();
        assert_eq!(&live, &[0u8; 8]);
    }

    #[test]
    fn a_looping_catalog_chain_is_refused() {
        let mut disk = vec![0u8; VOLUME as usize];
        let at = 0x100000u64;
        let mut header = block(TYPE_VOLUME_HEADER, VOLUME_HEADER_OFFSET, 0);
        put64(&mut header, 0x30, at);
        disk[VOLUME_HEADER_OFFSET as usize..][..BLOCK_SIZE as usize].copy_from_slice(&header);
        let catalog = block(TYPE_CATALOG, at, at);
        disk[at as usize..][..BLOCK_SIZE as usize].copy_from_slice(&catalog);

        let result = read_catalog(&mut Cursor::new(disk), VOLUME);
        assert!(result.copies.is_empty());
        assert!(result.refused.iter().any(|r| r.contains("loops")), "{:?}", result.refused);
    }

    #[test]
    fn a_block_that_misreports_its_own_offset_is_refused() {
        let mut disk = vec![0u8; VOLUME as usize];
        let at = 0x100000u64;
        let mut header = block(TYPE_VOLUME_HEADER, VOLUME_HEADER_OFFSET, 0);
        put64(&mut header, 0x30, at);
        disk[VOLUME_HEADER_OFFSET as usize..][..BLOCK_SIZE as usize].copy_from_slice(&header);
        let catalog = block(TYPE_CATALOG, at + BLOCK_SIZE, 0);
        disk[at as usize..][..BLOCK_SIZE as usize].copy_from_slice(&catalog);

        let result = read_catalog(&mut Cursor::new(disk), VOLUME);
        assert!(result.copies.is_empty());
        assert!(
            result.refused.iter().any(|r| r.contains("claims to be at")),
            "{:?}",
            result.refused
        );
    }

    #[test]
    fn an_offset_outside_the_volume_is_refused() {
        let mut disk = vec![0u8; VOLUME as usize];
        let mut header = block(TYPE_VOLUME_HEADER, VOLUME_HEADER_OFFSET, 0);
        put64(&mut header, 0x30, VOLUME * 4);
        disk[VOLUME_HEADER_OFFSET as usize..][..BLOCK_SIZE as usize].copy_from_slice(&header);

        let result = read_catalog(&mut Cursor::new(disk), VOLUME);
        assert!(result.copies.is_empty());
        assert!(
            result.refused.iter().any(|r| r.contains("outside the volume")),
            "{:?}",
            result.refused
        );
    }

    #[test]
    fn a_store_that_is_named_but_not_located_is_not_counted() {
        let mut disk = vec![0u8; VOLUME as usize];
        let at = 0x100000u64;
        let mut header = block(TYPE_VOLUME_HEADER, VOLUME_HEADER_OFFSET, 0);
        put64(&mut header, 0x30, at);
        disk[VOLUME_HEADER_OFFSET as usize..][..BLOCK_SIZE as usize].copy_from_slice(&header);
        let mut catalog = block(TYPE_CATALOG, at, 0);
        put64(&mut catalog, 0x80, ENTRY_STORE_INFO);
        put64(&mut catalog, 0x88, VOLUME);
        put_guid(&mut catalog, 0x90, 0xCD);
        disk[at as usize..][..BLOCK_SIZE as usize].copy_from_slice(&catalog);

        let result = read_catalog(&mut Cursor::new(disk), VOLUME);
        assert!(result.copies.is_empty());
        assert!(result.refused.iter().any(|r| r.contains("not located")), "{:?}", result.refused);
    }

    #[test]
    fn an_overlay_block_is_counted_rather_than_applied() {
        let mut disk = vec![0u8; VOLUME as usize];
        let catalog_at = 0x100000u64;
        let list_at = 0x200000u64;

        let mut header = block(TYPE_VOLUME_HEADER, VOLUME_HEADER_OFFSET, 0);
        put64(&mut header, 0x30, catalog_at);
        disk[VOLUME_HEADER_OFFSET as usize..][..BLOCK_SIZE as usize].copy_from_slice(&header);

        let mut catalog = block(TYPE_CATALOG, catalog_at, 0);
        put64(&mut catalog, 0x80, ENTRY_STORE_INFO);
        put64(&mut catalog, 0x88, VOLUME);
        put_guid(&mut catalog, 0x90, 0xAB);
        put64(&mut catalog, 0x100, ENTRY_STORE_LOCATION);
        put64(&mut catalog, 0x108, list_at);
        put_guid(&mut catalog, 0x110, 0xAB);
        disk[catalog_at as usize..][..BLOCK_SIZE as usize].copy_from_slice(&catalog);

        let mut list = block(TYPE_STORE_BLOCK_LIST, list_at, 0);
        put64(&mut list, 0x80, 0x400000);
        put64(&mut list, 0x90, 0x800000);
        put32(&mut list, 0x98, DESCRIPTOR_OVERLAY);
        disk[list_at as usize..][..BLOCK_SIZE as usize].copy_from_slice(&list);

        let mut cursor = Cursor::new(disk);
        let catalog = read_catalog(&mut cursor, VOLUME);
        let (map, _) = read_block_map(&mut cursor, &catalog.copies[0], VOLUME);
        assert_eq!(map.len(), 0, "an overlay is not a whole-block substitution");
        assert_eq!(map.overlay_count(), 1);

        let reader = ShadowReader::new(cursor, map, VOLUME);
        let counter = reader.uncertainty();
        let mut reader = reader;
        let mut buf = [0u8; 8];
        reader.seek(SeekFrom::Start(0x400000)).unwrap();
        reader.read_exact(&mut buf).unwrap();
        assert!(
            counter.load(Ordering::Relaxed) > 0,
            "reading an overlay block must be recorded as uncertain"
        );
    }

    #[test]
    fn reading_past_the_end_of_a_shadow_copy_yields_nothing() {
        let mut reader = ShadowReader::new(Cursor::new(vec![0u8; 1024]), BlockMap::default(), 1024);
        reader.seek(SeekFrom::Start(4096)).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn seeking_before_the_start_is_an_error_rather_than_a_wrap() {
        let mut reader = ShadowReader::new(Cursor::new(vec![0u8; 1024]), BlockMap::default(), 1024);
        assert!(reader.seek(SeekFrom::Current(-4096)).is_err());
    }

    #[test]
    fn a_looping_store_block_list_is_refused() {
        let mut disk = volume_with_one_copy();
        let list_at = 0x200000usize;
        put64(&mut disk[list_at..], 0x28, list_at as u64);

        let mut cursor = Cursor::new(disk);
        let catalog = read_catalog(&mut cursor, VOLUME);
        let (map, refused) = read_block_map(&mut cursor, &catalog.copies[0], VOLUME);
        assert_eq!(map.len(), 2);
        assert!(refused.iter().any(|r| r.contains("loops")), "{refused:?}");
    }

    #[test]
    fn a_descriptor_pointing_outside_the_volume_is_dropped() {
        let mut disk = volume_with_one_copy();
        let list_at = 0x200000usize;
        put64(&mut disk[list_at..], 0x80, VOLUME * 8);
        put64(&mut disk[list_at..], 0x90, VOLUME * 8);

        let mut cursor = Cursor::new(disk);
        let catalog = read_catalog(&mut cursor, VOLUME);
        let (map, _) = read_block_map(&mut cursor, &catalog.copies[0], VOLUME);
        assert_eq!(map.len(), 1, "only the in-range descriptor survives");
    }

    #[test]
    fn a_descriptor_whose_block_would_overrun_the_volume_is_dropped() {
        let mut disk = volume_with_one_copy();
        let list_at = 0x200000usize;
        put64(&mut disk[list_at..], 0x80, VOLUME - 8);
        put64(&mut disk[list_at..], 0x90, VOLUME - 8);

        let mut cursor = Cursor::new(disk);
        let catalog = read_catalog(&mut cursor, VOLUME);
        let (map, _) = read_block_map(&mut cursor, &catalog.copies[0], VOLUME);
        assert_eq!(map.len(), 1, "the overrunning descriptor must not survive");
    }

    #[test]
    fn coverage_reports_the_span_the_copies_cover() {
        let catalog = Catalog {
            copies: vec![
                ShadowCopy {
                    id: "a".into(),
                    sequence: 2,
                    created: filetime(133_500_000_000_000_000),
                    volume_size: 1,
                    store_header_offset: 0,
                    block_list_offset: 1,
                    block_range_offset: 0,
                    bitmap_offset: 0,
                    store_file_record: 0,
                },
                ShadowCopy {
                    id: "b".into(),
                    sequence: 1,
                    created: filetime(133_000_000_000_000_000),
                    volume_size: 1,
                    store_header_offset: 0,
                    block_list_offset: 1,
                    block_range_offset: 0,
                    bitmap_offset: 0,
                    store_file_record: 0,
                },
            ],
            refused: vec![],
        };
        let (from, to) = catalog.coverage().unwrap();
        assert!(from < to);
    }
}
