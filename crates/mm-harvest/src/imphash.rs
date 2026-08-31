use std::cell::Cell;
use std::collections::HashSet;

use md5::{Digest, Md5};

#[path = "imphash_ordinals.rs"]
mod ordinals;

const MAX_IMPORT_SYMBOLS: usize = 0x2000;
const MAX_NAME_BYTES: usize = 0x200;
const MAX_SECTIONS: usize = 0x800;
const MAX_DESCRIPTORS: usize = 0x10000;
const MAX_REPEATED_ADDRESSES: usize = 15;
const MAX_ADDRESS_SPREAD: u64 = 128 * 1024 * 1024;
const MAX_EMPTY_DESCRIPTORS: usize = 5;
const MAX_INVALID_NAMES: usize = 1000;
const MAX_SECTION_ERRORS: usize = 3;
const MAX_SECTION_OFFSET: u64 = 0x1000_0000;
const DESCRIPTOR_BYTES: usize = 20;
const SECTION_HEADER_BYTES: usize = 40;
const DIRECTORY_ENTRIES: u32 = 16;
const IMPORT_DIRECTORY: usize = 1;
const STRIPPED_EXTENSIONS: [&str; 3] = ["ocx", "sys", "dll"];
const INVALID: &str = "*invalid*";
const FILENAME_EXTRA: &[u8] = b"!#$%&'()+,-./:;=@[\\]^_`{}~";
const FUNCTION_EXTRA: &[u8] = b"$%&().:<>?@[]_";

const RICH_ANCHOR: usize = 0x80;
const DANS: u32 = 0x536E_6144;
const RICH: u32 = 0x6863_6952;

pub fn imphash(bytes: &[u8]) -> Option<String> {
    let imports = import_strings(bytes)?;
    Some(format!("{:x}", Md5::digest(imports.join(",").as_bytes())))
}

pub fn import_strings(bytes: &[u8]) -> Option<Vec<String>> {
    let image = Image::parse(bytes)?;
    let descriptors = image.import_descriptors()?;
    let mut out = Vec::new();
    for descriptor in &descriptors {
        let dll = descriptor.dll.to_ascii_lowercase();
        let prefix = strip_extension(&dll);
        for symbol in &descriptor.symbols {
            let name = match symbol {
                Symbol::Ordinal(ordinal) => ordinal_name(&dll, *ordinal),
                Symbol::Name(name) => name.clone(),
            };
            out.push(format!("{prefix}.{}", name.to_ascii_lowercase()));
        }
    }
    Some(out)
}

fn strip_extension(dll: &str) -> &str {
    match dll.rsplit_once('.') {
        Some((stem, extension)) if STRIPPED_EXTENSIONS.contains(&extension) => stem,
        _ => dll,
    }
}

fn ordinal_name(dll: &str, ordinal: u16) -> String {
    let mapped = match dll {
        "ws2_32.dll" | "wsock32.dll" => ordinals::ws2_32(ordinal),
        "oleaut32.dll" => ordinals::oleaut32(ordinal),
        _ => None,
    };
    match mapped {
        Some(name) => name.to_string(),
        None => format!("ord{ordinal}"),
    }
}

fn valid_dos_filename(name: &[u8]) -> bool {
    name.iter().all(|b| b.is_ascii_alphanumeric() || FILENAME_EXTRA.contains(b))
}

fn valid_function_name(name: &[u8]) -> bool {
    name.iter().all(|b| b.is_ascii_alphanumeric() || FUNCTION_EXTRA.contains(b))
}

enum Symbol {
    Ordinal(u16),
    Name(String),
}

struct Descriptor {
    dll: String,
    symbols: Vec<Symbol>,
}

struct Section {
    virtual_address: u32,
    adjusted_address: u64,
    pointer: u32,
    adjusted_pointer: u64,
    raw_size: u32,
    virtual_size: u32,
    next_address: Option<u32>,
}

impl Section {
    fn span(&self, file_len: usize) -> (u64, i64) {
        let size = if (file_len as i64) - (self.adjusted_pointer as i64) < i64::from(self.raw_size)
        {
            i64::from(self.virtual_size)
        } else {
            i64::from(self.raw_size.max(self.virtual_size))
        };
        let end = match self.next_address {
            Some(next)
                if next > self.virtual_address
                    && self.adjusted_address as i64 + size > i64::from(next) =>
            {
                i64::from(next) - self.adjusted_address as i64
            }
            _ => size,
        };
        (self.adjusted_address, end)
    }

    fn contains(&self, rva: u64, file_len: usize) -> bool {
        let (start, size) = self.span(file_len);
        (rva as i64) >= start as i64 && (rva as i64) < start as i64 + size
    }

    fn offset(&self, rva: u64) -> u64 {
        rva.wrapping_sub(self.adjusted_address).wrapping_add(self.adjusted_pointer)
    }

    fn data<'a>(&self, bytes: &'a [u8], rva: u64, length: usize) -> &'a [u8] {
        let offset = self.offset(rva);
        let mut end = offset.saturating_add(length as u64);
        let raw_end = u64::from(self.pointer) + u64::from(self.raw_size);
        if end > raw_end {
            end = raw_end;
        }
        slice(bytes, offset, end)
    }
}

fn slice(bytes: &[u8], start: u64, end: u64) -> &[u8] {
    let len = bytes.len() as u64;
    let start = start.min(len) as usize;
    let end = end.min(len) as usize;
    if end <= start {
        &bytes[start..start]
    } else {
        &bytes[start..end]
    }
}

struct Image<'a> {
    bytes: &'a [u8],
    pe64: bool,
    header_len: usize,
    directories_at: usize,
    directory_count: u32,
    sections: Vec<Section>,
    last_section: Cell<Option<usize>>,
    symbols_seen: Cell<usize>,
}

impl<'a> Image<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.get(0..2)? != b"MZ" {
            return None;
        }
        let lfanew = read_u32(bytes, 0x3c)? as usize;
        if bytes.get(lfanew..lfanew.checked_add(4)?)? != b"PE\0\0" {
            return None;
        }
        let coff = lfanew.checked_add(4)?;
        let section_count = read_u16(bytes, coff.checked_add(2)?)? as usize;
        let optional_size = read_u16(bytes, coff.checked_add(16)?)? as usize;
        let optional = coff.checked_add(20)?;
        let magic = read_u16(bytes, optional)?;
        let pe64 = magic == 0x020b;
        bytes.get(optional..optional.checked_add(if pe64 { 112 } else { 96 })?)?;
        let section_alignment = read_u32(bytes, optional + 32)?;
        let file_alignment = read_u32(bytes, optional + 36)?;
        let (count_at, directories_at) =
            if pe64 { (optional + 108, optional + 112) } else { (optional + 92, optional + 96) };
        let directory_count = read_u32(bytes, count_at)?.min(DIRECTORY_ENTRIES);
        let sections_at = optional.checked_add(optional_size)?;

        let mut sections = Vec::new();
        for index in 0..section_count.min(MAX_SECTIONS) {
            let at = sections_at.checked_add(index.checked_mul(SECTION_HEADER_BYTES)?)?;
            let Some(header) =
                at.checked_add(SECTION_HEADER_BYTES).and_then(|end| bytes.get(at..end))
            else {
                if at >= bytes.len() {
                    break;
                }
                return None;
            };
            if header.iter().all(|b| *b == 0) {
                break;
            }
            let virtual_size = read_u32(header, 8)?;
            let virtual_address = read_u32(header, 12)?;
            let raw_size = read_u32(header, 16)?;
            let pointer = read_u32(header, 20)?;
            let adjusted_address =
                adjust_section_alignment(virtual_address, section_alignment, file_alignment);
            let mut errors = 0;
            if u64::from(raw_size) + u64::from(pointer) > bytes.len() as u64 {
                errors += 1;
            }
            if u64::from(pointer & !0x1ff) > bytes.len() as u64 {
                errors += 1;
            }
            if u64::from(virtual_size) > MAX_SECTION_OFFSET {
                errors += 1;
            }
            if adjusted_address > MAX_SECTION_OFFSET {
                errors += 1;
            }
            if file_alignment != 0 && !pointer.is_multiple_of(file_alignment) {
                errors += 1;
            }
            if errors >= MAX_SECTION_ERRORS {
                break;
            }
            let adjusted_pointer = if section_alignment < 0x1000 && pointer == virtual_address {
                u64::from(virtual_address)
            } else {
                u64::from(pointer & !0x1ff)
            };
            sections.push(Section {
                virtual_address,
                adjusted_address,
                pointer,
                adjusted_pointer,
                raw_size,
                virtual_size,
                next_address: None,
            });
        }
        sections.sort_by_key(|s| s.virtual_address);
        let addresses: Vec<u32> = sections.iter().map(|s| s.virtual_address).collect();
        for (index, section) in sections.iter_mut().enumerate() {
            section.next_address = addresses.get(index + 1).copied();
        }

        let table_end = if sections.is_empty() {
            sections_at
        } else {
            sections_at.checked_add(section_count.checked_mul(SECTION_HEADER_BYTES)?)?
        };
        let lowest_pointer =
            sections.iter().filter(|s| s.pointer > 0).map(|s| (s.pointer & !0x1ff) as usize).min();
        let header_len = match lowest_pointer {
            Some(lowest) if lowest >= table_end => lowest,
            _ => table_end,
        }
        .min(bytes.len());

        Some(Image {
            bytes,
            pe64,
            header_len,
            directories_at,
            directory_count,
            sections,
            last_section: Cell::new(None),
            symbols_seen: Cell::new(0),
        })
    }

    fn section_for(&self, rva: u64) -> Option<&Section> {
        if let Some(last) = self.last_section.get() {
            if self.sections[last].contains(rva, self.bytes.len()) {
                return Some(&self.sections[last]);
            }
        }
        let index = self.sections.iter().position(|s| s.contains(rva, self.bytes.len()))?;
        self.last_section.set(Some(index));
        Some(&self.sections[index])
    }

    fn data(&self, rva: u64, length: usize) -> Option<&'a [u8]> {
        if let Some(section) = self.section_for(rva) {
            return Some(section.data(self.bytes, rva, length));
        }
        let end = rva.saturating_add(length as u64);
        if rva < self.header_len as u64 {
            return Some(slice(self.bytes, rva, end.min(self.header_len as u64)));
        }
        if rva < self.bytes.len() as u64 {
            return Some(slice(self.bytes, rva, end));
        }
        None
    }

    fn offset(&self, rva: u64) -> Option<u64> {
        if let Some(section) = self.section_for(rva) {
            return Some(section.offset(rva));
        }
        (rva < self.bytes.len() as u64).then_some(rva)
    }

    fn string_at(&self, rva: u64) -> &'a [u8] {
        let chunk = match self.section_for(rva) {
            Some(section) => section.data(self.bytes, rva, MAX_NAME_BYTES),
            None => slice(self.bytes, rva, rva.saturating_add(MAX_NAME_BYTES as u64)),
        };
        match chunk.iter().position(|b| *b == 0) {
            Some(end) => &chunk[..end],
            None => chunk,
        }
    }

    fn import_descriptors(&self) -> Option<Vec<Descriptor>> {
        if self.directory_count as usize <= IMPORT_DIRECTORY {
            return None;
        }
        let mut rva = u64::from(read_u32(self.bytes, self.directories_at + IMPORT_DIRECTORY * 8)?);
        if rva == 0 {
            return None;
        }
        let mut descriptors = Vec::new();
        let mut empty = 0;
        for _ in 0..MAX_DESCRIPTORS {
            let Some(raw) = self.data(rva, DESCRIPTOR_BYTES) else { break };
            if raw.len() < DESCRIPTOR_BYTES || raw.iter().all(|b| *b == 0) {
                break;
            }
            let original_first_thunk = u64::from(read_u32(raw, 0)?);
            let name_rva = u64::from(read_u32(raw, 12)?);
            let first_thunk = u64::from(read_u32(raw, 16)?);
            let file_offset = self.offset(rva)?;
            rva += DESCRIPTOR_BYTES as u64;

            let mut max_length = self.bytes.len() as i64 - file_offset as i64;
            if rva > original_first_thunk || rva > first_thunk {
                max_length =
                    (rva as i64 - original_first_thunk as i64).max(rva as i64 - first_thunk as i64);
            }
            let symbols =
                self.symbols(original_first_thunk, first_thunk, max_length).unwrap_or_default();
            if empty > MAX_EMPTY_DESCRIPTORS {
                break;
            }
            if symbols.is_empty() {
                empty += 1;
                continue;
            }
            let dll = self.string_at(name_rva);
            let dll = if valid_dos_filename(dll) {
                String::from_utf8_lossy(dll).into_owned()
            } else {
                INVALID.to_string()
            };
            if dll.is_empty() {
                continue;
            }
            descriptors.push(Descriptor { dll, symbols });
        }
        (!descriptors.is_empty()).then_some(descriptors)
    }

    fn symbols(
        &self,
        original_first_thunk: u64,
        first_thunk: u64,
        max_length: i64,
    ) -> Option<Vec<Symbol>> {
        let lookup = self.thunks(original_first_thunk, max_length);
        let address = self.thunks(first_thunk, max_length);
        let table = match (lookup, address) {
            (Some(table), _) if !table.is_empty() => table,
            (_, Some(table)) if !table.is_empty() => table,
            _ => return Some(Vec::new()),
        };
        let flag = if self.pe64 { 1u64 << 63 } else { 1u64 << 31 };
        let mut symbols = Vec::new();
        let mut invalid = 0;
        for (index, entry) in table.into_iter().enumerate() {
            if entry & flag != 0 {
                let ordinal = (entry & 0xffff) as u16;
                if ordinal != 0 {
                    symbols.push(Symbol::Ordinal(ordinal));
                }
                continue;
            }
            self.data(entry, 2)?;
            let name = self.string_at(entry.saturating_add(2));
            if !valid_function_name(name) {
                if invalid > MAX_INVALID_NAMES && invalid == index {
                    return None;
                }
                invalid += 1;
                continue;
            }
            if !name.is_empty() {
                symbols.push(Symbol::Name(String::from_utf8_lossy(name).into_owned()));
            }
        }
        Some(symbols)
    }

    fn thunks(&self, start: u64, max_length: i64) -> Option<Vec<u64>> {
        let mut table = Vec::new();
        if start == 0 {
            return Some(table);
        }
        let size = if self.pe64 { 8 } else { 4 };
        let flag = if self.pe64 { 1u64 << 63 } else { 1u64 << 31 };
        let mut rva = start;
        let mut repeated = 0;
        let mut low = AddressSet::default();
        let mut high = AddressSet::default();
        loop {
            if rva as i64 >= start as i64 + max_length {
                break;
            }
            if self.symbols_seen.get() > MAX_IMPORT_SYMBOLS {
                break;
            }
            self.symbols_seen.set(self.symbols_seen.get() + 1);
            if repeated >= MAX_REPEATED_ADDRESSES {
                return Some(Vec::new());
            }
            if low.spread() > MAX_ADDRESS_SPREAD || high.spread() > MAX_ADDRESS_SPREAD {
                return Some(Vec::new());
            }
            let raw = self.data(rva, size)?;
            if raw.len() != size {
                return None;
            }
            let entry = if self.pe64 { read_u64(raw, 0)? } else { u64::from(read_u32(raw, 0)?) };
            if entry >= start && entry <= rva {
                break;
            }
            if entry != 0 {
                if entry & flag != 0 {
                    if entry & 0x7fff_ffff > 0xffff {
                        return Some(Vec::new());
                    }
                } else {
                    let set = if entry >= 1 << 32 { &mut high } else { &mut low };
                    if !set.insert(entry) {
                        repeated += 1;
                    }
                }
            }
            if entry == 0 {
                break;
            }
            rva += size as u64;
            table.push(entry);
        }
        Some(table)
    }
}

#[derive(Default)]
struct AddressSet {
    seen: HashSet<u64>,
    min: Option<u64>,
    max: Option<u64>,
}

impl AddressSet {
    fn insert(&mut self, value: u64) -> bool {
        self.min = Some(self.min.map_or(value, |m| m.min(value)));
        self.max = Some(self.max.map_or(value, |m| m.max(value)));
        self.seen.insert(value)
    }

    fn spread(&self) -> u64 {
        match (self.min, self.max) {
            (Some(min), Some(max)) => max - min,
            _ => 0,
        }
    }
}

fn adjust_section_alignment(value: u32, section_alignment: u32, file_alignment: u32) -> u64 {
    let alignment = if section_alignment < 0x1000 { file_alignment } else { section_alignment };
    if alignment != 0 && !value.is_multiple_of(alignment) {
        u64::from(value / alignment) * u64::from(alignment)
    } else {
        u64::from(value)
    }
}

pub struct RichHeader {
    pub hash: String,
    pub entries: Vec<RichEntry>,
    pub checksum_valid: bool,
    pub dans_decoded: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RichEntry {
    pub product_id: u16,
    pub build: u16,
    pub count: u32,
}

pub fn rich_header(bytes: &[u8]) -> Option<RichHeader> {
    if bytes.get(0..2)? != b"MZ" {
        return None;
    }
    let lfanew = read_u32(bytes, 0x3c)? as usize;
    if bytes.get(lfanew..lfanew.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let end = lfanew.checked_add(24)?.min(bytes.len());
    let window = bytes.get(RICH_ANCHOR..end)?;
    let marker = window.windows(4).position(|w| w == b"Rich")?.checked_add(RICH_ANCHOR)?;
    if !(marker - RICH_ANCHOR).is_multiple_of(4) {
        return None;
    }
    let key = read_u32(bytes, marker.checked_add(4)?)?;
    let raw = &bytes[RICH_ANCHOR..marker];
    let key_bytes = key.to_le_bytes();
    let clear: Vec<u8> = raw.iter().enumerate().map(|(i, byte)| byte ^ key_bytes[i % 4]).collect();
    let hash = format!("{:x}", Md5::digest(&clear));
    let dans_decoded = read_u32(&clear, 0) == Some(DANS);

    let dwords: Vec<u32> = bytes[RICH_ANCHOR..marker + 8]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    let mut entries = Vec::new();
    for pair in dwords.get(4..).unwrap_or(&[]).as_chunks::<2>().0 {
        if pair[0] == RICH {
            break;
        }
        let compid = pair[0] ^ key;
        entries.push(RichEntry {
            product_id: (compid >> 16) as u16,
            build: (compid & 0xffff) as u16,
            count: pair[1] ^ key,
        });
    }

    let checksum_valid = dans_decoded && checksum(bytes, RICH_ANCHOR, &entries) == key;
    Some(RichHeader { hash, entries, checksum_valid, dans_decoded })
}

fn checksum(bytes: &[u8], dans: usize, entries: &[RichEntry]) -> u32 {
    let mut sum = dans as u32;
    for (i, byte) in bytes.iter().take(dans).enumerate() {
        if (0x3c..0x40).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(*byte).rotate_left(i as u32 & 31));
    }
    for entry in entries {
        let compid = (u32::from(entry.product_id) << 16) | u32::from(entry.build);
        sum = sum.wrapping_add(compid.rotate_left(entry.count & 31));
    }
    sum
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

#[cfg(test)]
pub(crate) mod fixture {
    use super::*;

    pub const LFANEW: usize = 0x80;
    pub const HEADERS: usize = 0x400;
    pub const SECTION_VA: u32 = 0x1000;
    pub const FILE_ALIGN: usize = 0x200;

    pub enum Dll {
        Name(Vec<u8>),
        Rva(u32),
    }

    pub enum Thunk {
        Name(Vec<u8>),
        Ordinal(u16),
        Raw(u64),
    }

    #[derive(Clone, Copy)]
    pub enum Tables {
        Both,
        LookupGarbage,
        LookupZero,
        LookupOnly,
    }

    pub struct Import {
        pub dll: Dll,
        pub thunks: Vec<Thunk>,
        pub tables: Tables,
    }

    pub fn named(dll: &[u8], names: &[&[u8]]) -> Import {
        Import {
            dll: Dll::Name(dll.to_vec()),
            thunks: names.iter().map(|n| Thunk::Name(n.to_vec())).collect(),
            tables: Tables::Both,
        }
    }

    pub struct Layout {
        pub pe64: bool,
        pub in_header: bool,
        pub section_alignment: u32,
    }

    impl Default for Layout {
        fn default() -> Self {
            Layout { pe64: true, in_header: false, section_alignment: 0x1000 }
        }
    }

    pub fn pe(imports: &[Import], layout: &Layout) -> Vec<u8> {
        let pe64 = layout.pe64;
        let base = if layout.in_header { 0x200 } else { SECTION_VA };
        let entry_size = if pe64 { 8 } else { 4 };
        let flag = if pe64 { 1u64 << 63 } else { 1u64 << 31 };
        let mut blob = vec![0u8; DESCRIPTOR_BYTES * (imports.len() + 1)];
        for (index, import) in imports.iter().enumerate() {
            let mut entries = Vec::new();
            for thunk in &import.thunks {
                match thunk {
                    Thunk::Name(name) => {
                        let at = blob.len();
                        blob.extend_from_slice(&[0, 0]);
                        blob.extend_from_slice(name);
                        blob.push(0);
                        if !blob.len().is_multiple_of(2) {
                            blob.push(0);
                        }
                        entries.push(u64::from(base) + at as u64);
                    }
                    Thunk::Ordinal(ordinal) => entries.push(flag | u64::from(*ordinal)),
                    Thunk::Raw(raw) => entries.push(*raw),
                }
            }
            let dll_rva = match &import.dll {
                Dll::Name(name) => {
                    let at = blob.len();
                    blob.extend_from_slice(name);
                    blob.push(0);
                    base + at as u32
                }
                Dll::Rva(rva) => *rva,
            };
            let table_at = blob.len();
            for entry in &entries {
                if pe64 {
                    blob.extend_from_slice(&entry.to_le_bytes());
                } else {
                    blob.extend_from_slice(&(*entry as u32).to_le_bytes());
                }
            }
            blob.extend_from_slice(&vec![0u8; entry_size]);
            let table_rva = base + table_at as u32;
            let (lookup, address) = match import.tables {
                Tables::Both => (table_rva, table_rva),
                Tables::LookupGarbage => (0x7fff_0000, table_rva),
                Tables::LookupZero => (0, table_rva),
                Tables::LookupOnly => (table_rva, 0),
            };
            let descriptor = index * DESCRIPTOR_BYTES;
            blob[descriptor..descriptor + 4].copy_from_slice(&lookup.to_le_bytes());
            blob[descriptor + 12..descriptor + 16].copy_from_slice(&dll_rva.to_le_bytes());
            blob[descriptor + 16..descriptor + 20].copy_from_slice(&address.to_le_bytes());
        }

        let mut image = vec![0u8; HEADERS];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(LFANEW as u32).to_le_bytes());
        image[LFANEW..LFANEW + 4].copy_from_slice(b"PE\0\0");
        let coff = LFANEW + 4;
        let optional_size: u16 = if pe64 { 240 } else { 224 };
        image[coff..coff + 2]
            .copy_from_slice(&(if pe64 { 0x8664u16 } else { 0x014c }).to_le_bytes());
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&optional_size.to_le_bytes());
        let optional = coff + 20;
        image[optional..optional + 2]
            .copy_from_slice(&(if pe64 { 0x020bu16 } else { 0x010b }).to_le_bytes());
        image[optional + 32..optional + 36]
            .copy_from_slice(&layout.section_alignment.to_le_bytes());
        image[optional + 36..optional + 40].copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes());
        image[optional + 60..optional + 64].copy_from_slice(&(HEADERS as u32).to_le_bytes());
        let (count_at, directories) =
            if pe64 { (optional + 108, optional + 112) } else { (optional + 92, optional + 96) };
        image[count_at..count_at + 4].copy_from_slice(&16u32.to_le_bytes());
        let directory = directories + 8;
        image[directory..directory + 4].copy_from_slice(&base.to_le_bytes());
        image[directory + 4..directory + 8]
            .copy_from_slice(&((DESCRIPTOR_BYTES * (imports.len() + 1)) as u32).to_le_bytes());

        let mut section = if layout.in_header {
            image[0x200..0x200 + blob.len()].copy_from_slice(&blob);
            vec![0xccu8; 64]
        } else {
            blob
        };
        let raw_size = section.len().div_ceil(FILE_ALIGN) * FILE_ALIGN;
        section.resize(raw_size, 0);
        let table = optional + optional_size as usize;
        image[table..table + 8].copy_from_slice(b".rdata\0\0");
        image[table + 8..table + 12].copy_from_slice(&(section.len() as u32).to_le_bytes());
        image[table + 12..table + 16].copy_from_slice(&SECTION_VA.to_le_bytes());
        image[table + 16..table + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
        image[table + 20..table + 24].copy_from_slice(&(HEADERS as u32).to_le_bytes());
        image[table + 36..table + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
        image.extend_from_slice(&section);
        image
    }

    pub fn rich(
        entries: &[(u16, u16, u32)],
        stored_key: impl Fn(u32) -> u32,
        xor_key: impl Fn(u32) -> u32,
    ) -> Vec<u8> {
        let mut clear = DANS.to_le_bytes().to_vec();
        clear.extend_from_slice(&[0u8; 12]);
        for (product_id, build, count) in entries {
            let compid = (u32::from(*product_id) << 16) | u32::from(*build);
            clear.extend_from_slice(&compid.to_le_bytes());
            clear.extend_from_slice(&count.to_le_bytes());
        }
        let mut image = vec![0u8; RICH_ANCHOR];
        image[0..2].copy_from_slice(b"MZ");
        for (i, byte) in image.iter_mut().enumerate().take(RICH_ANCHOR).skip(0x40) {
            *byte = (i % 251) as u8;
        }
        let parsed: Vec<RichEntry> = entries
            .iter()
            .map(|(product_id, build, count)| RichEntry {
                product_id: *product_id,
                build: *build,
                count: *count,
            })
            .collect();
        let key = checksum(&image, RICH_ANCHOR, &parsed);
        let stored = stored_key(key);
        let xor = xor_key(key).to_le_bytes();
        let raw: Vec<u8> = clear.iter().enumerate().map(|(i, b)| b ^ xor[i % 4]).collect();
        image.extend_from_slice(&raw);
        image.extend_from_slice(b"Rich");
        image.extend_from_slice(&stored.to_le_bytes());
        while !image.len().is_multiple_of(8) {
            image.push(0);
        }
        let lfanew = image.len();
        image[0x3c..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());
        image.extend_from_slice(b"PE\0\0");
        image.extend_from_slice(&vec![0u8; 20 + 240]);
        image
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    fn plain() -> Vec<u8> {
        pe(&[named(b"KERNEL32.dll", &[b"CreateFileW", b"ExitProcess"])], &Layout::default())
    }

    fn strings(image: &[u8]) -> Option<Vec<String>> {
        import_strings(image)
    }

    #[test]
    fn the_import_strings_are_the_ones_pefile_would_join() {
        let image = pe(
            &[
                named(b"KERNEL32.dll", &[b"CreateFileW", b"ExitProcess"]),
                named(b"USER32.DLL", &[b"MessageBoxA"]),
            ],
            &Layout::default(),
        );
        assert_eq!(
            strings(&image).unwrap(),
            ["kernel32.createfilew", "kernel32.exitprocess", "user32.messageboxa"]
        );
    }

    #[test]
    fn the_extension_rule_is_pefiles_extension_rule() {
        assert_eq!(strip_extension("kernel32.dll"), "kernel32");
        assert_eq!(strip_extension("driver.sys"), "driver");
        assert_eq!(strip_extension("control.ocx"), "control");
        assert_eq!(strip_extension("helper.exe"), "helper.exe");
        assert_eq!(strip_extension("thing.drv"), "thing.drv");
        assert_eq!(strip_extension("api-ms-win-core-x-l1-1-0.dll"), "api-ms-win-core-x-l1-1-0");
        assert_eq!(strip_extension("two.parts.dll"), "two.parts");
        assert_eq!(strip_extension("noextension"), "noextension");
    }

    #[test]
    fn ordinal_imports_resolve_through_the_frozen_tables() {
        assert_eq!(ordinal_name("ws2_32.dll", 3), "closesocket");
        assert_eq!(ordinal_name("ws2_32.dll", 23), "socket");
        assert_eq!(ordinal_name("ws2_32.dll", 24), "GetAddrInfoW");
        assert_eq!(ordinal_name("wsock32.dll", 3), "closesocket");
        assert_eq!(ordinal_name("oleaut32.dll", 144), "DllCanUnloadNow");
        assert_eq!(ordinal_name("oleaut32.dll", 2), "SysAllocString");
        assert_eq!(ordinal_name("ws2_32.dll", 9999), "ord9999");
        assert_eq!(ordinal_name("kernel32.dll", 42), "ord42");
    }

    #[test]
    fn an_ordinal_import_reaches_the_string_lowercased() {
        let image = pe(
            &[Import {
                dll: Dll::Name(b"WS2_32.dll".to_vec()),
                thunks: vec![Thunk::Ordinal(3), Thunk::Ordinal(9999)],
                tables: Tables::Both,
            }],
            &Layout::default(),
        );
        assert_eq!(strings(&image).unwrap(), ["ws2_32.closesocket", "ws2_32.ord9999"]);
    }

    #[test]
    fn the_hash_is_the_md5_of_the_comma_joined_strings() {
        let image = plain();
        assert_eq!(
            imphash(&image).unwrap(),
            format!("{:x}", Md5::digest(b"kernel32.createfilew,kernel32.exitprocess"))
        );
    }

    #[test]
    fn an_import_directory_with_nothing_in_it_has_no_imphash_at_all() {
        assert!(
            strings(&pe(&[], &Layout::default())).is_none(),
            "pefile returns no hash, not md5 of nothing"
        );
        let mut without = plain();
        let directory = LFANEW + 4 + 20 + 112 + 8;
        without[directory..directory + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(imphash(&without).is_none());
    }

    #[test]
    fn a_32_bit_image_is_read_as_a_32_bit_image() {
        let image = pe(
            &[named(b"KERNEL32.dll", &[b"ExitProcess"]), named(b"USER32.dll", &[b"MessageBoxA"])],
            &Layout { pe64: false, ..Layout::default() },
        );
        assert_eq!(strings(&image).unwrap(), ["kernel32.exitprocess", "user32.messageboxa"]);
    }

    #[test]
    fn a_name_outside_pefiles_character_set_is_skipped_not_hashed() {
        let image = pe(
            &[named(b"KERNEL32.dll", &[b"Create-File", b"a%b", b"?foo@@YAXXZ", b"ExitProcess"])],
            &Layout::default(),
        );
        assert_eq!(
            strings(&image).unwrap(),
            ["kernel32.a%b", "kernel32.?foo@@yaxxz", "kernel32.exitprocess"]
        );
    }

    #[test]
    fn a_dll_name_pefile_rejects_becomes_invalid_but_keeps_its_imports() {
        for dll in [&b"my lib.dll"[..], b"a*b.dll", b"lib\xe9.dll"] {
            let image = pe(&[named(dll, &[b"Fn"])], &Layout::default());
            assert_eq!(strings(&image).unwrap(), ["*invalid*.fn"], "{dll:?}");
        }
        let image = pe(&[named(b"sub\\lib.dll", &[b"Fn"])], &Layout::default());
        assert_eq!(strings(&image).unwrap(), ["sub\\lib.fn"]);
    }

    #[test]
    fn a_name_that_cannot_be_fetched_voids_the_whole_descriptor() {
        let image = pe(
            &[Import {
                dll: Dll::Name(b"KERNEL32.dll".to_vec()),
                thunks: vec![
                    Thunk::Name(b"First".to_vec()),
                    Thunk::Raw((u64::from(SECTION_VA) + 0x30) | (1 << 40)),
                    Thunk::Name(b"Third".to_vec()),
                ],
                tables: Tables::Both,
            }],
            &Layout::default(),
        );
        assert!(
            strings(&image).is_none(),
            "the only descriptor is void, so there is no import directory"
        );
    }

    #[test]
    fn a_dll_name_that_cannot_be_read_drops_only_its_own_descriptor() {
        let image = pe(
            &[
                Import {
                    dll: Dll::Rva(0x7fff_0000),
                    thunks: vec![Thunk::Name(b"Fn".to_vec())],
                    tables: Tables::Both,
                },
                named(b"USER32.dll", &[b"MessageBoxA"]),
            ],
            &Layout::default(),
        );
        assert_eq!(strings(&image).unwrap(), ["user32.messageboxa"]);
    }

    #[test]
    fn six_empty_descriptors_stop_the_walk_before_a_seventh_is_read() {
        let mut six: Vec<Import> = (0..6).map(|_| named(b"e.dll", &[])).collect();
        six.push(named(b"USER32.dll", &[b"MessageBoxA"]));
        assert!(strings(&pe(&six, &Layout::default())).is_none());

        let mut five: Vec<Import> = (0..5).map(|_| named(b"e.dll", &[])).collect();
        five.push(named(b"USER32.dll", &[b"MessageBoxA"]));
        assert_eq!(strings(&pe(&five, &Layout::default())).unwrap(), ["user32.messageboxa"]);
    }

    #[test]
    fn a_broken_lookup_table_falls_back_to_the_address_table() {
        for tables in [Tables::LookupGarbage, Tables::LookupZero, Tables::LookupOnly] {
            let image = pe(
                &[Import {
                    dll: Dll::Name(b"KERNEL32.dll".to_vec()),
                    thunks: vec![Thunk::Name(b"ExitProcess".to_vec())],
                    tables,
                }],
                &Layout::default(),
            );
            assert_eq!(strings(&image).unwrap(), ["kernel32.exitprocess"]);
        }
    }

    #[test]
    fn ordinal_zero_is_dropped_and_a_corrupt_ordinal_voids_the_table() {
        let image = pe(
            &[Import {
                dll: Dll::Name(b"KERNEL32.dll".to_vec()),
                thunks: vec![Thunk::Ordinal(0), Thunk::Name(b"ExitProcess".to_vec())],
                tables: Tables::Both,
            }],
            &Layout::default(),
        );
        assert_eq!(strings(&image).unwrap(), ["kernel32.exitprocess"]);

        let image = pe(
            &[Import {
                dll: Dll::Name(b"KERNEL32.dll".to_vec()),
                thunks: vec![
                    Thunk::Raw((1 << 63) | 0x1234_0007),
                    Thunk::Name(b"ExitProcess".to_vec()),
                ],
                tables: Tables::Both,
            }],
            &Layout::default(),
        );
        assert!(strings(&image).is_none());
    }

    #[test]
    fn a_name_address_repeated_sixteen_times_voids_the_table() {
        let mut thunks = vec![Thunk::Name(b"Same".to_vec())];
        thunks.extend((0..16).map(|_| Thunk::Raw(u64::from(SECTION_VA) + 40)));
        let image = pe(
            &[Import { dll: Dll::Name(b"KERNEL32.dll".to_vec()), thunks, tables: Tables::Both }],
            &Layout::default(),
        );
        assert!(strings(&image).is_none());
    }

    #[test]
    fn an_import_table_inside_the_headers_is_read_where_pefile_reads_it() {
        let image = pe(
            &[named(b"KERNEL32.dll", &[b"CreateFileW", b"ExitProcess"])],
            &Layout { in_header: true, ..Layout::default() },
        );
        assert_eq!(strings(&image).unwrap(), ["kernel32.createfilew", "kernel32.exitprocess"]);
    }

    #[test]
    fn the_symbol_budget_is_shared_by_both_tables_and_truncates_like_pefile() {
        let names: Vec<Vec<u8>> = (0..100).map(|j| format!("F{j:05}").into_bytes()).collect();
        let imports: Vec<Import> = (0..60)
            .map(|i| Import {
                dll: Dll::Name(format!("big{i}.dll").into_bytes()),
                thunks: names.iter().map(|n| Thunk::Name(n.clone())).collect(),
                tables: Tables::Both,
            })
            .collect();
        let image = pe(&imports, &Layout::default());
        let got = strings(&image).unwrap();
        assert!(
            got.len() < 6000,
            "pefile stops counting at 8193 thunk reads across both tables: {}",
            got.len()
        );
        assert!(got.len() > 3000, "{}", got.len());
    }

    #[test]
    fn a_rich_header_is_read_back_with_its_toolchain_entries() {
        let image = rich(&[(0x0102, 27412, 9), (0x00ff, 30729, 3)], |k| k, |k| k);
        let header = rich_header(&image).expect("a rich header");
        assert_eq!(header.entries.len(), 2);
        assert_eq!(header.entries[0], RichEntry { product_id: 0x0102, build: 27412, count: 9 });
        assert_eq!(header.entries[1], RichEntry { product_id: 0x00ff, build: 30729, count: 3 });
        assert_eq!(header.hash.len(), 32);
        assert!(header.dans_decoded);
        assert!(header.checksum_valid);
    }

    #[test]
    fn a_key_that_does_not_match_the_stub_is_reported_invalid() {
        let image = rich(&[(0x0102, 27412, 9)], |k| k ^ 0x0f0f_0f0f, |k| k ^ 0x0f0f_0f0f);
        let header = rich_header(&image).expect("the structure still parses");
        assert!(header.dans_decoded);
        assert!(!header.checksum_valid);
        assert_eq!(header.entries.len(), 1);
    }

    #[test]
    fn a_block_that_does_not_decode_is_still_hashed_like_pefile_but_never_valid() {
        let image = rich(&[(0x0102, 27412, 9)], |k| k ^ 0x0f0f_0f0f, |k| k);
        let header = rich_header(&image).expect("pefile hashes it, so do we");
        assert!(!header.dans_decoded);
        assert!(!header.checksum_valid);
        assert_eq!(header.hash.len(), 32);
    }

    #[test]
    fn a_changed_stub_invalidates_the_checksum() {
        let mut image = rich(&[(0x0102, 27412, 9)], |k| k, |k| k);
        assert!(rich_header(&image).unwrap().checksum_valid);
        image[0x50] ^= 0xff;
        assert!(!rich_header(&image).unwrap().checksum_valid);
    }

    #[test]
    fn the_pe_header_offset_is_not_part_of_the_checksum() {
        let image = rich(&[(0x0102, 27412, 9)], |k| k, |k| k);
        let entries = rich_header(&image).unwrap().entries;
        let with = checksum(&image, RICH_ANCHOR, &entries);
        let mut moved = image.clone();
        moved[0x3c..0x40].copy_from_slice(&0xabcd_ef01u32.to_le_bytes());
        assert_eq!(checksum(&moved, RICH_ANCHOR, &entries), with);
    }

    #[test]
    fn a_file_with_no_rich_header_has_none() {
        assert!(rich_header(&plain()).is_none());
    }

    #[test]
    fn hostile_and_damaged_images_yield_nothing_rather_than_failing() {
        let good = plain();
        let signed = rich(&[(1, 2, 3)], |k| k, |k| k);
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x4d]),
            ("MZ only", b"MZ".to_vec()),
            ("no PE signature", vec![0x4d, 0x5a, 0, 0, 0, 0, 0, 0]),
            ("all zeroes", vec![0u8; 4096]),
            ("all 0xff", vec![0xffu8; 4096]),
            ("a text file", b"the quick brown fox\n".repeat(64)),
            ("truncated at the header", good[..0x90].to_vec()),
            ("truncated mid-table", good[..0x80 + 4 + 20 + 240 + 12].to_vec()),
            ("truncated payload", good[..good.len() - 8].to_vec()),
            ("rich truncated", signed[..signed.len() / 2].to_vec()),
            (
                "rich as the last bytes",
                signed[..signed.iter().rposition(|b| *b == b'R').unwrap_or(0) + 4].to_vec(),
            ),
        ];
        let mut lying_rva = good.clone();
        let directory = LFANEW + 4 + 20 + 112 + 8;
        lying_rva[directory..directory + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(("import rva past the end", lying_rva));
        let mut lying_lfanew = good.clone();
        lying_lfanew[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(("lfanew past the end", lying_lfanew));
        let mut lying_sections = good.clone();
        lying_sections[LFANEW + 4 + 2..LFANEW + 4 + 4].copy_from_slice(&u16::MAX.to_le_bytes());
        cases.push(("a section count that lies", lying_sections));
        let mut lying_alignment = good.clone();
        lying_alignment[LFANEW + 24 + 32..LFANEW + 24 + 40].fill(0xff);
        cases.push(("alignments of 0xffffffff", lying_alignment));
        let mut zero_alignment = good.clone();
        zero_alignment[LFANEW + 24 + 32..LFANEW + 24 + 40].fill(0);
        cases.push(("alignments of zero", zero_alignment));
        let mut huge_section = good.clone();
        huge_section[LFANEW + 24 + 240 + 8..LFANEW + 24 + 240 + 24].fill(0xff);
        cases.push(("a section that claims the address space", huge_section));

        for (label, image) in cases {
            let started = std::time::Instant::now();
            let _ = imphash(&image);
            let _ = import_strings(&image);
            let _ = rich_header(&image);
            assert!(started.elapsed().as_secs() < 2, "{label} was not bounded");
        }
    }

    #[test]
    fn a_self_referential_import_table_terminates() {
        let mut image = plain();
        let raw_offset = HEADERS;
        image[raw_offset..raw_offset + 4].copy_from_slice(&SECTION_VA.to_le_bytes());
        let started = std::time::Instant::now();
        let got = import_strings(&image).unwrap_or_default();
        assert!(started.elapsed().as_secs() < 5);
        assert!(got.len() <= MAX_IMPORT_SYMBOLS);
    }
}
