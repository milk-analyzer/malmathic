use chrono::{DateTime, Utc};

use mm_core::{
    from_filetime, ArtifactSource, FileHash, NormalizedPath, Observation, ObservationKind,
};

use crate::Harvested;

const PRODUCT: &str = "Windows Defender";

const RC4_KEY: [u8; 256] = [
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86,
    0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA,
    0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18,
    0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53,
    0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
    0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE,
    0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8,
    0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E,
    0x3E, 0x19, 0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57,
    0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
    0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A,
    0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC,
    0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16,
    0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B,
    0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
    0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
];

const ENTRY_HEADER_LEN: usize = 0x3C;
const ENTRY_MAGIC: [u8; 4] = [0xDB, 0xE8, 0xC5, 0x01];

const OFF_SECTION1_SIZE: usize = 0x28;
const OFF_SECTION2_SIZE: usize = 0x2C;

const OFF_ID: usize = 0x00;
const OFF_SCAN_ID: usize = 0x10;
const OFF_TIMESTAMP: usize = 0x20;
const OFF_THREAT_ID: usize = 0x28;
const OFF_DETECTION_NAME: usize = 0x34;
const SECTION1_MIN_LEN: usize = OFF_DETECTION_NAME;

const FIELD_RESOURCE_ID_FILE: u16 = 0x02;
const FIELD_RESOURCE_ID_REGISTRY: u16 = 0x03;
const FIELD_PHYSICAL_PATH: u16 = 0x0C;
const FIELD_CREATION_TIME: u16 = 0x0F;
const FIELD_LAST_ACCESS_TIME: u16 = 0x10;
const FIELD_LAST_WRITE_TIME: u16 = 0x11;
const FIELD_FILE_SIZE: u16 = 0x12;

const MAX_RESOURCES: usize = 65_536;

const STREAM_HEADER_LEN: usize = 20;
const BACKUP_DATA: u32 = 0x01;
const STREAM_ID_CEILING: u32 = 0x1F;

const REGISTRY_ROOTS: &[&str] = &[
    "HKLM",
    "HKCU",
    "HKCR",
    "HKU",
    "HKCC",
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuarantineEntry {
    pub id: Option<String>,
    pub scan_id: Option<String>,
    pub timestamp: Option<DateTime<Utc>>,
    pub threat_id: Option<u64>,
    pub detection_name: Option<String>,
    pub resources: Vec<QuarantineResource>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuarantineResource {
    pub detection_type: String,
    pub detection_path: Option<String>,
    pub resource_id: Option<String>,
    pub registry_resource_id: Option<String>,
    pub file_size: Option<u64>,
    pub created: Option<DateTime<Utc>>,
    pub last_access: Option<DateTime<Utc>>,
    pub last_write: Option<DateTime<Utc>>,
}

impl QuarantineResource {
    pub fn is_registry(&self) -> bool {
        let detection_type = self.detection_type.as_bytes();
        if detection_type.len() >= 3 && detection_type[..3].eq_ignore_ascii_case(b"reg") {
            return true;
        }
        let Some(raw) = &self.detection_path else { return false };
        let head = raw.trim_start_matches('\\');
        let head = head.split('\\').next().unwrap_or(head);
        REGISTRY_ROOTS.iter().any(|r| head.eq_ignore_ascii_case(r))
    }

    pub fn normalized_path(&self) -> Option<NormalizedPath> {
        if self.is_registry() {
            return None;
        }
        let raw = self.detection_path.as_deref()?;
        if !raw.contains('\\') && !raw.contains('/') && !raw.contains(':') {
            return None;
        }
        NormalizedPath::parse(raw)
    }
}

pub fn decrypt(bytes: &[u8]) -> Vec<u8> {
    rc4(&RC4_KEY, bytes)
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    let mut s = [0u8; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }

    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    let mut out = Vec::with_capacity(data.len());
    let (mut i, mut j) = (0u8, 0u8);
    for byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        out.push(byte ^ k);
    }
    out
}

pub fn parse_entry(entry_bytes: &[u8]) -> Option<QuarantineEntry> {
    let raw_header = entry_bytes.get(..ENTRY_HEADER_LEN)?;
    let plaintext = raw_header.starts_with(&ENTRY_MAGIC);

    let header = if plaintext { raw_header.to_vec() } else { decrypt(raw_header) };

    if !header.starts_with(&ENTRY_MAGIC) {
        return None;
    }

    let section1_size = u32_at(&header, OFF_SECTION1_SIZE)? as usize;
    let section2_size = u32_at(&header, OFF_SECTION2_SIZE)? as usize;

    let s1_start = ENTRY_HEADER_LEN;
    let s1_end = s1_start.saturating_add(section1_size).min(entry_bytes.len());
    let section1 = slice_or_empty(entry_bytes, s1_start, s1_end);

    let s2_start = s1_start.saturating_add(section1_size);
    let s2_end = s2_start.saturating_add(section2_size).min(entry_bytes.len());
    let section2 = slice_or_empty(entry_bytes, s2_start, s2_end);

    let section1 = if plaintext { section1.to_vec() } else { decrypt(section1) };
    let section2 = if plaintext { section2.to_vec() } else { decrypt(section2) };

    let mut entry = QuarantineEntry::default();
    if section1.len() >= SECTION1_MIN_LEN {
        entry.id = section1.get(OFF_ID..OFF_ID + 16).map(hex_upper);
        entry.scan_id = section1.get(OFF_SCAN_ID..OFF_SCAN_ID + 16).map(hex_upper);
        entry.timestamp = u64_at(&section1, OFF_TIMESTAMP).and_then(from_filetime);
        entry.threat_id = u64_at(&section1, OFF_THREAT_ID);
        entry.detection_name =
            utf8_cstr(&section1, OFF_DETECTION_NAME).map(|(s, _)| s).filter(|s| !s.is_empty());
    }
    entry.resources = parse_section2(&section2);
    Some(entry)
}

fn parse_section2(section2: &[u8]) -> Vec<QuarantineResource> {
    let mut out = Vec::new();
    let Some(count) = u32_at(section2, 0) else { return out };

    let fits = section2.len().saturating_sub(4) / 4;
    let count = (count as usize).min(fits);

    let mut budget = section2.len().saturating_add(4096);
    let mut seen = std::collections::HashSet::new();

    for i in 0..count {
        if budget == 0 || out.len() >= MAX_RESOURCES {
            break;
        }
        let Some(offset) = u32_at(section2, 4 + i * 4) else { continue };

        if !seen.insert(offset) {
            continue;
        }

        let (resource, used) = parse_resource(section2, offset as usize, budget);
        budget = budget.saturating_sub(used);
        if let Some(resource) = resource {
            out.push(resource);
        }
    }
    out
}

fn parse_resource(
    section2: &[u8],
    offset: usize,
    budget: usize,
) -> (Option<QuarantineResource>, usize) {
    let limit = offset.saturating_add(budget).min(section2.len());
    let Some(view) = section2.get(..limit) else { return (None, 0) };
    let used = |cursor: usize| cursor.saturating_sub(offset);

    let Some((detection_path, cursor)) = utf16le_cstr(view, offset) else { return (None, 0) };
    let Some(field_count) = u16_at(view, cursor) else { return (None, used(cursor)) };
    let Some(cursor) = cursor.checked_add(2) else { return (None, used(cursor)) };
    let Some((detection_type, mut cursor)) = utf8_cstr(view, cursor) else {
        return (None, used(cursor));
    };

    let mut resource = QuarantineResource {
        detection_type,
        detection_path: Some(detection_path).filter(|s| !s.is_empty()),
        ..Default::default()
    };

    for _ in 0..field_count {
        cursor = align4(cursor);
        let Some(size) = u16_at(view, cursor) else { break };
        let Some(tag) = u16_at(view, cursor.saturating_add(2)) else { break };
        let identifier = tag & 0x0FFF;

        let Some(data_start) = cursor.checked_add(4) else { break };
        let Some(data_end) = data_start.checked_add(size as usize) else { break };
        let Some(data) = view.get(data_start..data_end) else { break };

        apply_field(&mut resource, identifier, data);
        cursor = data_end;
    }

    (Some(resource), used(cursor))
}

fn apply_field(resource: &mut QuarantineResource, identifier: u16, data: &[u8]) {
    match identifier {
        FIELD_RESOURCE_ID_FILE => resource.resource_id = Some(hex_upper(data)),
        FIELD_RESOURCE_ID_REGISTRY => resource.registry_resource_id = Some(hex_upper(data)),
        FIELD_PHYSICAL_PATH => {
            let path = utf16le_lossy(data);
            let path = path.trim_end_matches('\0');
            if !path.is_empty() {
                resource.detection_path = Some(path.to_string());
            }
        }
        FIELD_CREATION_TIME => resource.created = from_filetime(le_uint(data)),
        FIELD_LAST_ACCESS_TIME => resource.last_access = from_filetime(le_uint(data)),
        FIELD_LAST_WRITE_TIME => resource.last_write = from_filetime(le_uint(data)),
        FIELD_FILE_SIZE => resource.file_size = Some(le_uint(data)),
        _ => {}
    }
}

pub fn harvest_entry(entry_bytes: &[u8]) -> Harvested {
    harvest_entry_with_recovery(entry_bytes).0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedFile {
    pub path: NormalizedPath,
    pub resource_id: String,
    pub threat: Option<String>,
    pub claimed_size: Option<u64>,
}

pub fn resource_data_relative_path(resource_id: &str) -> Option<String> {
    if resource_id.len() < 2 || resource_id.len() > 128 || !resource_id.len().is_multiple_of(2) {
        return None;
    }
    if !resource_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{}\\{resource_id}", &resource_id[..2]))
}

pub fn harvest_entry_with_recovery(entry_bytes: &[u8]) -> (Harvested, Vec<QuarantinedFile>) {
    let mut out = Harvested::new();
    let mut recoverable = Vec::new();
    let Some(entry) = parse_entry(entry_bytes) else { return (out, recoverable) };

    for resource in &entry.resources {
        let Some(path) = resource.normalized_path() else { continue };
        out.push(Observation::about_path(
            ArtifactSource::DefenderQuarantine,
            path.clone(),
            ObservationKind::Quarantined {
                product: PRODUCT.to_string(),
                threat: entry.detection_name.clone(),
                when: entry.timestamp,
                severity: None,
            },
        ));

        if let Some(resource_id) = &resource.resource_id {
            if resource_data_relative_path(resource_id).is_some() {
                recoverable.push(QuarantinedFile {
                    path,
                    resource_id: resource_id.clone(),
                    threat: entry.detection_name.clone(),
                    claimed_size: resource.file_size,
                });
            }
        }
    }
    (out, recoverable)
}

pub fn extract_payload(decrypted_resource_data: &[u8]) -> Option<Vec<u8>> {
    let buf = decrypted_resource_data;
    let mut offset: usize = 0;

    while let Some(header) = buf.get(offset..offset.checked_add(STREAM_HEADER_LEN)?) {
        let stream_id = u32_at(header, 0)?;
        let size = u64_at(header, 8)?;
        let name_size = u32_at(header, 16)? as usize;

        if stream_id == 0 || stream_id > STREAM_ID_CEILING {
            return None;
        }

        let size = usize::try_from(size).ok()?;
        let data_start = offset.checked_add(STREAM_HEADER_LEN)?.checked_add(name_size)?;
        let data_end = data_start.checked_add(size)?;
        let data = buf.get(data_start..data_end)?;

        if stream_id == BACKUP_DATA {
            return Some(data.to_vec());
        }
        offset = data_end;
    }
    None
}

pub fn harvest_payload(
    original_path: Option<NormalizedPath>,
    decrypted_resource_data: &[u8],
) -> Harvested {
    let Some(payload) = extract_payload(decrypted_resource_data) else { return Harvested::new() };
    let hash = FileHash::compute(&payload);
    let observation = match original_path {
        Some(path) => Observation::about_path(
            ArtifactSource::DefenderQuarantine,
            path,
            ObservationKind::HashRecovered,
        )
        .with_hash(hash),
        None => Observation::about_hash(
            ArtifactSource::DefenderQuarantine,
            hash,
            ObservationKind::HashRecovered,
        ),
    };
    vec![observation]
}

fn slice_or_empty(bytes: &[u8], start: usize, end: usize) -> &[u8] {
    if start >= end {
        return &[];
    }
    bytes.get(start..end).unwrap_or(&[])
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let raw: [u8; 2] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let raw: [u8; 8] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

fn le_uint(bytes: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for (i, byte) in bytes.iter().take(8).enumerate() {
        value |= (*byte as u64) << (i * 8);
    }
    value
}

fn align4(offset: usize) -> usize {
    offset.saturating_add(3) & !3usize
}

fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(s, "{byte:02X}");
    }
    s
}

fn utf8_cstr(bytes: &[u8], offset: usize) -> Option<(String, usize)> {
    let rest = bytes.get(offset..)?;
    match rest.iter().position(|b| *b == 0) {
        Some(len) => {
            let text = String::from_utf8_lossy(&rest[..len]).into_owned();
            Some((text, offset.saturating_add(len).saturating_add(1)))
        }
        None => {
            let text = String::from_utf8_lossy(rest).into_owned();
            Some((text, bytes.len()))
        }
    }
}

fn utf16le_cstr(bytes: &[u8], offset: usize) -> Option<(String, usize)> {
    let rest = bytes.get(offset..)?;
    let mut units: Vec<u16> = Vec::new();
    let mut consumed = 0usize;

    while let Some(pair) = rest.get(consumed..consumed + 2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        consumed += 2;
        if unit == 0 {
            return Some((decode_utf16(&units), offset.saturating_add(consumed)));
        }
        units.push(unit);
    }

    Some((decode_utf16(&units), bytes.len()))
}

fn utf16le_lossy(bytes: &[u8]) -> String {
    let units: Vec<u16> =
        bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes).collect();
    decode_utf16(&units)
}

fn decode_utf16(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wstr(s: &str) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        v.extend_from_slice(&[0, 0]);
        v
    }

    fn cstr(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        v
    }

    type Field = (u16, u16, Vec<u8>);

    fn field(identifier: u16, field_type: u16, data: Vec<u8>) -> Field {
        (identifier, field_type, data)
    }

    fn build_resource(
        abs_start: usize,
        path: &str,
        detection_type: &str,
        fields: &[Field],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(wstr(path));
        v.extend_from_slice(&(fields.len() as u16).to_le_bytes());
        v.extend(cstr(detection_type));
        for (identifier, field_type, data) in fields {
            while !(abs_start + v.len()).is_multiple_of(4) {
                v.push(0);
            }
            v.extend_from_slice(&(data.len() as u16).to_le_bytes());
            let tag = (field_type << 12) | (identifier & 0x0FFF);
            v.extend_from_slice(&tag.to_le_bytes());
            v.extend_from_slice(data);
        }
        v
    }

    fn build_section2(resources: &[(&str, &str, Vec<Field>)]) -> Vec<u8> {
        let table_len = 4 + 4 * resources.len();
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for (path, detection_type, fields) in resources {
            while !(table_len + body.len()).is_multiple_of(4) {
                body.push(0);
            }
            let start = table_len + body.len();
            offsets.push(start as u32);
            body.extend(build_resource(start, path, detection_type, fields));
        }

        let mut out = Vec::new();
        out.extend_from_slice(&(resources.len() as u32).to_le_bytes());
        for offset in &offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out.extend(body);
        out
    }

    fn build_section1(detection_name: &str, filetime: u64, threat_id: u64) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xAA; 16]);
        v.extend_from_slice(&[0xBB; 16]);
        v.extend_from_slice(&filetime.to_le_bytes());
        v.extend_from_slice(&threat_id.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend(cstr(detection_name));
        v
    }

    fn build_entry_plain(section1: &[u8], section2: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&ENTRY_MAGIC);
        header.extend_from_slice(&[0x01, 0x00, 0x01, 0x00]);
        header.extend_from_slice(&[0u8; 32]);
        header.extend_from_slice(&(section1.len() as u32).to_le_bytes());
        header.extend_from_slice(&(section2.len() as u32).to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&[0u8; 4]);
        assert_eq!(header.len(), ENTRY_HEADER_LEN);

        let mut out = header;
        out.extend_from_slice(section1);
        out.extend_from_slice(section2);
        out
    }

    fn encrypt_entry(plain: &[u8], section1_len: usize, section2_len: usize) -> Vec<u8> {
        let mut out = decrypt(&plain[..ENTRY_HEADER_LEN]);
        let s1 = ENTRY_HEADER_LEN;
        let s2 = s1 + section1_len;
        out.extend(decrypt(&plain[s1..s2]));
        out.extend(decrypt(&plain[s2..s2 + section2_len]));
        out
    }

    const FILETIME_2024: u64 = (1_704_067_200 + 11_644_473_600) * 10_000_000;

    fn eicar_entry() -> (Vec<u8>, usize, usize) {
        let section1 = build_section1("Virus:DOS/EICAR_Test_File", FILETIME_2024, 2147519003);
        let section2 = build_section2(&[(
            "\\\\?\\D:\\Downloads\\eicar.com",
            "file",
            vec![
                field(
                    FIELD_RESOURCE_ID_FILE,
                    0x5,
                    vec![
                        0x38, 0x18, 0xF4, 0x77, 0xCB, 0x70, 0x84, 0x6B, 0xA5, 0xAB, 0x4B, 0x7E,
                        0x35, 0x6E, 0x5C, 0x3B, 0x4D, 0x63, 0x45, 0xDD,
                    ],
                ),
                field(FIELD_FILE_SIZE, 0x6, 68u64.to_le_bytes().to_vec()),
                field(FIELD_CREATION_TIME, 0x6, FILETIME_2024.to_le_bytes().to_vec()),
                field(FIELD_LAST_WRITE_TIME, 0x6, FILETIME_2024.to_le_bytes().to_vec()),
            ],
        )]);
        let (s1_len, s2_len) = (section1.len(), section2.len());
        (build_entry_plain(&section1, &section2), s1_len, s2_len)
    }

    fn build_stream(stream_id: u32, name: &str, data: &[u8]) -> Vec<u8> {
        let name_bytes: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut v = Vec::new();
        v.extend_from_slice(&stream_id.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(data.len() as u64).to_le_bytes());
        v.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        v.extend_from_slice(&name_bytes);
        v.extend_from_slice(data);
        v
    }

    const SAMPLE: &[u8] = b"MZ\x90\x00this is the malware, byte for byte";

    fn resource_data_plain() -> Vec<u8> {
        let mut v = build_stream(0x03, "", b"\x01\x00\x04\x80fake-security-descriptor");
        v.extend(build_stream(BACKUP_DATA, "", SAMPLE));
        v.extend(build_stream(0x04, ":Zone.Identifier:$DATA", b"[ZoneTransfer]\r\nZoneId=3\r\n"));
        v
    }

    const FOREIGN_ENTRY_HEX: &str = concat!(
        "d345c59992fddf68c2f991c781fafc908aa2adb36834039c1661bcc2f0e8cae7",
        "f1ffa302725832b27edbefe0c0bdbb0f5733a021321daf86e5f8165c19bc1189",
        "82eccf79d3e880d690ebed81a8808f914a1621be34439ee0d2cae8c5f13f2a74",
        "3764e8b32b51ef607cbcbb0f5633a0216474ddf396c252137fe5a02ae0bba6c0",
        "ca4d0b54a869e353b6850bad009883fdde687ef991c7c5fbfc90d6a292b33434",
        "479c2c61e0c2b4e8a5e786ffcd021e585db251db8be00fbce70f3233c921511d",
        "ce8697f8385c4fca8a63cefaf49f9b281e499b4a8a3fc785769e80a14fca314b",
        "8d8597da9355d67dd01dad8c8e1973067076347fe3dff225fb293e643ac713f4",
        "5ef5b8daae12ce71fad38636af6c26cee5e18b29028683b0a03fe3cef5f28167",
        "14869fff2d57589d3b6fa03fe622d556d823ebd68f7963bbefaa24e9edc4a50f",
        "0ccd6950a1ea7947edf70f19ebc37fb4f66d0fc18d80d99f86bc908293bb8a6e",
        "c35e04cd9efab198ca4063ed157a6121c9396d14220dc67b788976c2442f62cb",
        "835df776669c73ce533f6234383d687f1b39956ecce51af6925f066ddfe66c34",
        "d6ff0f1e45c1ffe11357f8d4dd7b8bf3491fb114e79da98370b552b3e36adc78",
        "db8e3ca3e36bfbf6384496bc4d56924aac4455c2d71ad79b7f87e17f6d4aeb41",
        "3ee7100ed2cc2d91580adb2817729303768c0e5cd61f23935b52079128b6d744",
        "6a09d7e87b35f79f68e2eb20c73121d1a3caa0178f61d276c31516740dfb094c",
        "1d93391a0546f881b464c4b0485b0f7628c5e9eeab2e8a578efbeec4be3afaa3",
        "72a68ab35fc0",
    );

    const FOREIGN_RESOURCE_DATA_HEX: &str = concat!(
        "0bad009893fdde68def991c781fafc908aa2adb36934071c7000d7a7dd9baf84",
        "848dca760b7556d743b89d890cc8d47d5633a021321daf86c3f8165c2ccae563",
        "a3faf49fd372e8208347e34cf3ec07eeccd1de9d975a65995303bd07c371f552",
        "85cfadab2f261e2f041adddfae25bf29516457c77df432f5d7dae312aa71b3d3",
        "8036a56c21cee3e1c4293986c9b0a63fe2ceecf2e8677286feff47372a5d8819",
        "c10378239c569d43aa165d5549e950ff5e8891d7876a7e90645afb855f22ef93",
        "7e2aabc9",
    );

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[hi, lo]| {
                let hi = (hi as char).to_digit(16).unwrap() as u8;
                let lo = (lo as char).to_digit(16).unwrap() as u8;
                hi * 16 + lo
            })
            .collect()
    }

    #[test]
    fn foreign_entry_decodes_field_for_field() {
        let entry = parse_entry(&unhex(FOREIGN_ENTRY_HEX)).unwrap();

        assert_eq!(entry.detection_name.as_deref(), Some("Virus:DOS/EICAR_Test_File"));
        assert_eq!(entry.threat_id, Some(2147519003));
        assert_eq!(entry.id.as_deref(), Some("11111111111111111111111111111111"));
        assert_eq!(entry.scan_id.as_deref(), Some("22222222222222222222222222222222"));
        assert_eq!(mm_core::filetime::format(entry.timestamp.unwrap()), "2024-01-01 00:00:00Z");
        assert_eq!(entry.resources.len(), 3);

        let eicar = &entry.resources[0];
        assert_eq!(eicar.detection_type, "file");
        assert_eq!(eicar.detection_path.as_deref(), Some("D:\\Downloads\\eicar.com"));
        assert_eq!(eicar.resource_id.as_deref(), Some("3818F477CB70846BA5AB4B7E356E5C3B4D6345DD"));
        assert_eq!(eicar.file_size, Some(68));
        assert_eq!(mm_core::filetime::format(eicar.created.unwrap()), "2024-01-01 00:00:00Z");
        assert_eq!(mm_core::filetime::format(eicar.last_write.unwrap()), "2024-01-01 00:00:00Z");
        assert!(eicar.last_access.is_none());

        let regkey = &entry.resources[1];
        assert_eq!(regkey.detection_type, "regkey");
        assert!(regkey.is_registry());
        assert_eq!(regkey.registry_resource_id.as_deref(), Some(&"0".repeat(40)[..]));

        let dropper = &entry.resources[2];
        assert_eq!(
            dropper.detection_path.as_deref(),
            Some("C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe")
        );
        assert_eq!(dropper.resource_id.as_deref(), Some(&"A".repeat(40)[..]));
    }

    #[test]
    fn foreign_entry_harvests_only_the_files() {
        let observations = harvest_entry(&unhex(FOREIGN_ENTRY_HEX));
        let keys: Vec<&str> = observations.iter().map(|o| o.path.as_ref().unwrap().key()).collect();
        assert_eq!(
            keys,
            vec!["\\downloads\\eicar.com", "\\users\\bob\\appdata\\local\\temp\\dropper.exe"]
        );
        for observation in &observations {
            assert!(matches!(
                &observation.kind,
                ObservationKind::Quarantined { product, threat, .. }
                    if product == "Windows Defender"
                        && threat.as_deref() == Some("Virus:DOS/EICAR_Test_File")
            ));
        }
    }

    #[test]
    fn foreign_resource_data_yields_the_exact_sample() {
        let decrypted = decrypt(&unhex(FOREIGN_RESOURCE_DATA_HEX));
        let payload = extract_payload(&decrypted).unwrap();
        assert_eq!(payload, SAMPLE);
        assert_eq!(
            FileHash::compute(&payload).sha256_hex().unwrap(),
            "b4be2d4442d017fee9640b26c1e7cd9d707000d7ca44ee45f0197d75706ad446"
        );
    }

    #[test]
    fn rc4_keystream_matches_the_published_key() {
        let keystream = decrypt(&[0u8; 16]);
        assert_eq!(
            keystream,
            vec![
                0x08, 0xad, 0x00, 0x98, 0x93, 0xfd, 0xde, 0x68, 0xc2, 0xf9, 0x91, 0xc7, 0x81, 0xfa,
                0xfc, 0x90
            ]
        );
    }

    #[test]
    fn encrypted_entry_header_has_a_stable_signature() {
        let encrypted = decrypt(&ENTRY_MAGIC);
        assert_eq!(encrypted, vec![0xD3, 0x45, 0xC5, 0x99]);
    }

    #[test]
    fn rc4_is_its_own_inverse() {
        for payload in
            [b"".to_vec(), b"a".to_vec(), SAMPLE.to_vec(), (0..=255u8).cycle().take(4096).collect()]
        {
            assert_eq!(decrypt(&decrypt(&payload)), payload);
        }
    }

    #[test]
    fn decrypt_of_nothing_is_nothing() {
        assert!(decrypt(&[]).is_empty());
    }

    #[test]
    fn key_is_exactly_256_bytes() {
        assert_eq!(RC4_KEY.len(), 256);
    }

    #[test]
    fn well_formed_entry_yields_path_and_threat() {
        let (plain, s1, s2) = eicar_entry();
        let on_disk = encrypt_entry(&plain, s1, s2);

        let observations = harvest_entry(&on_disk);
        assert_eq!(observations.len(), 1);

        let observation = &observations[0];
        assert_eq!(observation.source, ArtifactSource::DefenderQuarantine);
        assert_eq!(observation.path.as_ref().unwrap().key(), "\\downloads\\eicar.com");
        match &observation.kind {
            ObservationKind::Quarantined { product, threat, .. } => {
                assert_eq!(product, "Windows Defender");
                assert_eq!(threat.as_deref(), Some("Virus:DOS/EICAR_Test_File"));
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
        assert!(observation.hash.is_empty());
    }

    #[test]
    fn entry_metadata_round_trips() {
        let (plain, s1, s2) = eicar_entry();
        let entry = parse_entry(&encrypt_entry(&plain, s1, s2)).unwrap();

        assert_eq!(entry.detection_name.as_deref(), Some("Virus:DOS/EICAR_Test_File"));
        assert_eq!(entry.threat_id, Some(2147519003));
        assert_eq!(entry.id.as_deref(), Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert_eq!(entry.scan_id.as_deref(), Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"));
        assert_eq!(mm_core::filetime::format(entry.timestamp.unwrap()), "2024-01-01 00:00:00Z");

        assert_eq!(entry.resources.len(), 1);
        let resource = &entry.resources[0];
        assert_eq!(resource.detection_type, "file");
        assert_eq!(
            resource.resource_id.as_deref(),
            Some("3818F477CB70846BA5AB4B7E356E5C3B4D6345DD")
        );
        assert_eq!(resource.file_size, Some(68));
        assert!(resource.created.is_some() && resource.last_write.is_some());
        assert!(resource.last_access.is_none());
    }

    #[test]
    fn plaintext_entries_are_accepted() {
        let (plain, _, _) = eicar_entry();
        assert_eq!(harvest_entry(&plain).len(), 1);
    }

    #[test]
    fn physical_path_field_wins() {
        let section1 = build_section1("Trojan:Win32/Wacatac.B!ml", FILETIME_2024, 1);
        let section2 = build_section2(&[(
            "\\Device\\HarddiskVolume3\\Users\\bob\\evil.exe",
            "file",
            vec![field(
                FIELD_PHYSICAL_PATH,
                0x2,
                wstr("C:\\Users\\bob\\AppData\\Roaming\\evil.exe"),
            )],
        )]);
        let entry = build_entry_plain(&section1, &section2);

        let observations = harvest_entry(&entry);
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].path.as_ref().unwrap().key(),
            "\\users\\bob\\appdata\\roaming\\evil.exe"
        );
    }

    #[test]
    fn multiple_resources_all_reported_registry_excluded() {
        let section1 = build_section1("Trojan:Win32/Occamy.C", FILETIME_2024, 7);
        let section2 = build_section2(&[
            ("C:\\Users\\bob\\a.exe", "file", vec![]),
            ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x", "regvalue", vec![]),
            ("C:\\Windows\\Temp\\b.dll", "file", vec![]),
        ]);
        let entry = build_entry_plain(&section1, &section2);

        let observations = harvest_entry(&entry);
        let keys: Vec<&str> = observations.iter().map(|o| o.path.as_ref().unwrap().key()).collect();
        assert_eq!(keys, vec!["\\users\\bob\\a.exe", "\\windows\\temp\\b.dll"]);

        let entry = parse_entry(&entry).unwrap();
        assert_eq!(entry.resources.len(), 3);
        assert!(entry.resources[1].is_registry());
    }

    #[test]
    fn every_truncation_is_survivable() {
        let (plain, s1, s2) = eicar_entry();
        let on_disk = encrypt_entry(&plain, s1, s2);

        for len in 0..on_disk.len() {
            let observations = harvest_entry(&on_disk[..len]);
            assert!(observations.len() <= 1, "len {len} produced {}", observations.len());
        }

        let foreign = unhex(FOREIGN_ENTRY_HEX);
        for len in 0..foreign.len() {
            assert!(harvest_entry(&foreign[..len]).len() <= 2, "len {len}");
        }
        assert!(parse_entry(&on_disk[..ENTRY_HEADER_LEN - 1]).is_none());
        assert!(harvest_entry(&on_disk[..ENTRY_HEADER_LEN - 1]).is_empty());
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert!(harvest_entry(&[]).is_empty());
        assert!(parse_entry(&[]).is_none());
    }

    #[test]
    fn absurd_section_sizes_are_clamped() {
        let (plain, _, _) = eicar_entry();
        let mut broken = plain;
        broken[OFF_SECTION1_SIZE..OFF_SECTION1_SIZE + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        broken[OFF_SECTION2_SIZE..OFF_SECTION2_SIZE + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        let entry = parse_entry(&broken).unwrap();
        assert!(entry.resources.is_empty());
        assert!(harvest_entry(&broken).is_empty());
    }

    #[test]
    fn absurd_entry_count_is_clamped() {
        let section1 = build_section1("X", FILETIME_2024, 1);
        let mut section2 = build_section2(&[("C:\\a.exe", "file", vec![])]);
        section2[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        let entry = build_entry_plain(&section1, &section2);

        let parsed = parse_entry(&entry).unwrap();
        assert!(parsed.resources.len() <= section2.len() / 4);
    }

    #[test]
    fn out_of_range_resource_offsets_are_skipped() {
        let section1 = build_section1("X", FILETIME_2024, 1);
        let mut section2 = build_section2(&[
            ("C:\\good.exe", "file", vec![]),
            ("C:\\also-good.exe", "file", vec![]),
        ]);
        section2[4..8].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        let entry = build_entry_plain(&section1, &section2);

        let observations = harvest_entry(&entry);
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].path.as_ref().unwrap().key(), "\\also-good.exe");
    }

    #[test]
    fn absurd_field_size_keeps_the_resource() {
        let section1 = build_section1("X", FILETIME_2024, 1);
        let mut section2 = build_section2(&[(
            "C:\\a.exe",
            "file",
            vec![field(FIELD_RESOURCE_ID_FILE, 0x5, vec![0u8; 4])],
        )]);
        let len = section2.len();
        section2[len - 8..len - 6].copy_from_slice(&u16::MAX.to_le_bytes());
        let entry = build_entry_plain(&section1, &section2);

        let parsed = parse_entry(&entry).unwrap();
        assert_eq!(parsed.resources.len(), 1);
        assert_eq!(parsed.resources[0].detection_path.as_deref(), Some("C:\\a.exe"));
        assert!(parsed.resources[0].resource_id.is_none());
        assert_eq!(harvest_entry(&entry).len(), 1);
    }

    #[test]
    fn minimal_section1_without_terminator_still_parses() {
        let mut section1 = Vec::new();
        section1.extend_from_slice(&[0u8; 16]);
        section1.extend_from_slice(&[0u8; 16]);
        section1.extend_from_slice(&FILETIME_2024.to_le_bytes());
        section1.extend_from_slice(&0u64.to_le_bytes());
        section1.extend_from_slice(&1u32.to_le_bytes());
        section1.extend_from_slice(b"Behavior:Win32/Generic");
        let section2 = build_section2(&[("C:\\a.exe", "file", vec![])]);
        let entry = build_entry_plain(&section1, &section2);

        let parsed = parse_entry(&entry).unwrap();
        assert_eq!(parsed.detection_name.as_deref(), Some("Behavior:Win32/Generic"));
        assert_eq!(harvest_entry(&entry).len(), 1);
    }

    #[test]
    fn stub_section1_loses_only_the_metadata() {
        let section1 = vec![0u8; 8];
        let section2 = build_section2(&[("C:\\a.exe", "file", vec![])]);
        let entry = build_entry_plain(&section1, &section2);

        let parsed = parse_entry(&entry).unwrap();
        assert!(parsed.detection_name.is_none());
        let observations = harvest_entry(&entry);
        assert_eq!(observations.len(), 1);
        match &observations[0].kind {
            ObservationKind::Quarantined { threat, .. } => assert!(threat.is_none()),
            other => panic!("expected Quarantined, got {other:?}"),
        }
    }

    #[test]
    fn broken_utf16_paths_do_not_panic() {
        let section1 = build_section1("X", FILETIME_2024, 1);
        let mut path_bytes: Vec<u8> =
            "C:\\a".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        path_bytes.extend_from_slice(&0xD800u16.to_le_bytes());
        path_bytes.extend_from_slice(&[0, 0]);

        let table_len = 8;
        let mut section2 = Vec::new();
        section2.extend_from_slice(&1u32.to_le_bytes());
        section2.extend_from_slice(&(table_len as u32).to_le_bytes());
        section2.extend_from_slice(&path_bytes);
        section2.extend_from_slice(&0u16.to_le_bytes());
        section2.extend(cstr("file"));
        let entry = build_entry_plain(&section1, &section2);

        let parsed = parse_entry(&entry).unwrap();
        assert_eq!(parsed.resources.len(), 1);
        assert!(parsed.resources[0].detection_path.as_deref().unwrap().starts_with("C:\\a"));
    }

    #[test]
    fn mutated_entries_never_panic() {
        let (plain, s1, s2) = eicar_entry();
        let on_disk = encrypt_entry(&plain, s1, s2);

        for index in 0..on_disk.len() {
            for patch in [0x00u8, 0xFF, 0x7F, 0x80] {
                let mut mutated = on_disk.clone();
                mutated[index] = patch;
                let _ = harvest_entry(&mutated);

                let mut mutated_plain = plain.clone();
                mutated_plain[index] = patch;
                let _ = harvest_entry(&mutated_plain);
            }
        }
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let (plain, s1, s2) = eicar_entry();
        let on_disk = encrypt_entry(&plain, s1, s2);
        let resource_data = resource_data_plain();

        for _ in 0..2_000 {
            let len = (next() % 512) as usize;
            let buffer: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            let _ = harvest_entry(&buffer);
            let _ = parse_entry(&buffer);
            let _ = extract_payload(&buffer);
            let _ = harvest_payload(None, &buffer);
            let _ = decrypt(&buffer);

            for seed in [&on_disk, &plain, &resource_data] {
                let mut mutated = seed.clone();
                for _ in 0..8 {
                    let index = (next() as usize) % mutated.len();
                    mutated[index] = (next() & 0xFF) as u8;
                }
                let _ = harvest_entry(&mutated);
                let _ = extract_payload(&mutated);
            }
        }
    }

    #[test]
    fn payload_comes_out_byte_for_byte() {
        let on_disk = decrypt(&resource_data_plain());
        let decrypted = decrypt(&on_disk);
        assert_eq!(extract_payload(&decrypted).as_deref(), Some(SAMPLE));
    }

    #[test]
    fn data_stream_is_found_before_the_security_descriptor_too() {
        let mut blob = build_stream(BACKUP_DATA, "", SAMPLE);
        blob.extend(build_stream(0x03, "", b"sd"));
        assert_eq!(extract_payload(&blob).as_deref(), Some(SAMPLE));
    }

    #[test]
    fn zero_length_payload_is_recovered_not_rejected() {
        let blob = build_stream(BACKUP_DATA, "", b"");
        assert_eq!(extract_payload(&blob), Some(Vec::new()));
    }

    #[test]
    fn resource_data_without_a_data_stream_yields_nothing() {
        let blob = build_stream(0x03, "", b"security-descriptor-only");
        assert!(extract_payload(&blob).is_none());
    }

    #[test]
    fn empty_resource_data_yields_nothing() {
        assert!(extract_payload(&[]).is_none());
        assert!(extract_payload(&[0u8; 8]).is_none());
    }

    #[test]
    fn truncated_resource_data_never_returns_a_partial_sample() {
        let blob = resource_data_plain();
        let full = extract_payload(&blob).unwrap();
        for len in 0..blob.len() {
            match extract_payload(&blob[..len]) {
                None => {}
                Some(payload) => assert_eq!(payload, full, "len {len} returned a short sample"),
            }
        }
    }

    #[test]
    fn absurd_stream_size_is_rejected() {
        let mut blob = build_stream(BACKUP_DATA, "", SAMPLE);
        blob[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(extract_payload(&blob).is_none());

        let mut blob = build_stream(0x03, "", b"sd");
        blob[8..16].copy_from_slice(&0x7FFF_FFFF_FFFF_FFFFu64.to_le_bytes());
        blob.extend(build_stream(BACKUP_DATA, "", SAMPLE));
        assert!(extract_payload(&blob).is_none());
    }

    #[test]
    fn absurd_stream_name_size_is_rejected() {
        let mut blob = build_stream(BACKUP_DATA, "", SAMPLE);
        blob[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(extract_payload(&blob).is_none());
    }

    #[test]
    fn nonsense_stream_id_stops_the_walk() {
        let mut blob = build_stream(0x03, "", b"sd");
        blob[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        blob.extend(build_stream(BACKUP_DATA, "", SAMPLE));
        assert!(extract_payload(&blob).is_none());
    }

    #[test]
    fn unknown_stream_types_are_skipped_not_fatal() {
        let mut blob = build_stream(0x0C, "", b"some future stream");
        blob.extend(build_stream(BACKUP_DATA, "", SAMPLE));
        assert_eq!(extract_payload(&blob).as_deref(), Some(SAMPLE));
    }

    #[test]
    fn mutated_resource_data_never_panics() {
        let blob = resource_data_plain();
        for index in 0..blob.len() {
            for patch in [0x00u8, 0xFF, 0x7F, 0x80] {
                let mut mutated = blob.clone();
                mutated[index] = patch;
                let _ = extract_payload(&mutated);
            }
        }
    }

    #[test]
    fn payload_harvest_produces_a_real_hash() {
        let blob = resource_data_plain();
        let path = NormalizedPath::parse("D:\\Downloads\\eicar.com").unwrap();

        let observations = harvest_payload(Some(path), &blob);
        assert_eq!(observations.len(), 1);
        assert!(matches!(observations[0].kind, ObservationKind::HashRecovered));
        assert!(observations[0].hash.agrees_with(&FileHash::compute(SAMPLE)));
        assert_eq!(observations[0].path.as_ref().unwrap().key(), "\\downloads\\eicar.com");

        let hash_only = harvest_payload(None, &blob);
        assert!(hash_only[0].path.is_none());
        assert!(hash_only[0].identifies_something());
    }

    #[test]
    fn payload_harvest_of_junk_is_empty() {
        assert!(harvest_payload(None, &[]).is_empty());
        assert!(harvest_payload(None, b"not a backup stream at all").is_empty());
    }

    #[test]
    fn le_uint_reads_whatever_width_is_present() {
        assert_eq!(le_uint(&[]), 0);
        assert_eq!(le_uint(&[0x44]), 0x44);
        assert_eq!(le_uint(&[0x44, 0x00, 0x00, 0x00]), 68);
        assert_eq!(le_uint(&[0xFF; 8]), u64::MAX);
        assert_eq!(le_uint(&[0xFF; 32]), u64::MAX);
    }

    #[test]
    fn align4_saturates() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(usize::MAX), usize::MAX & !3);
    }

    #[test]
    fn files_that_are_not_entries_are_refused() {
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("all zeros", vec![0u8; 4096]),
            ("all ones", vec![0xFFu8; 4096]),
            ("ascii", b"A".repeat(4096)),
            ("utf-16 backslashes", b"\\\0".repeat(2048)),
        ];
        for (name, magic) in [
            ("evtx", &b"ElfFile\0"[..]),
            ("hive", &b"regf"[..]),
            ("pe", &b"MZ\x90\x00"[..]),
            ("prefetch", &b"\x1b\x00\x00\x00SCCA"[..]),
        ] {
            let mut v = magic.to_vec();
            v.resize(4096, 0x5C);
            cases.push((name, v));
        }
        let resource_data = resource_data_plain();
        cases.push(("resourcedata", resource_data.clone()));
        cases.push(("resourcedata encrypted", decrypt(&resource_data)));

        for (name, bytes) in cases {
            assert!(parse_entry(&bytes).is_none(), "{name} was parsed as an entry");
            assert!(harvest_entry(&bytes).is_empty(), "{name} produced observations");
        }
    }

    #[test]
    fn only_the_two_spellings_of_the_magic_are_accepted() {
        let (plain, s1, s2) = eicar_entry();
        let on_disk = encrypt_entry(&plain, s1, s2);
        assert!(parse_entry(&plain).is_some(), "plaintext DB E8 C5 01");
        assert!(parse_entry(&on_disk).is_some(), "on-disk D3 45 C5 99");
        assert_eq!(&on_disk[..4], &[0xD3, 0x45, 0xC5, 0x99]);

        for index in 0..4 {
            for patch in [0x00u8, 0xFF, 0x42] {
                let mut broken = on_disk.clone();
                if broken[index] == patch {
                    continue;
                }
                broken[index] = patch;
                assert!(parse_entry(&broken).is_none(), "magic byte {index} = {patch:#04x}");
            }
        }
    }

    fn amplifying_section2(n: usize, terminate: bool) -> Vec<u8> {
        let k = n / 8;
        let table = 4 + 4 * k;
        let mut section2 = vec![0x41u8; n];
        section2[..4].copy_from_slice(&(k as u32).to_le_bytes());
        for i in 0..k {
            section2[4 + i * 4..8 + i * 4].copy_from_slice(&(table as u32).to_le_bytes());
        }
        if terminate {
            let tail = n - 12;
            section2[tail..tail + 2].copy_from_slice(&[0, 0]);
            section2[tail + 2..tail + 4].copy_from_slice(&0u16.to_le_bytes());
            section2[tail + 4..tail + 9].copy_from_slice(b"file\0");
        }
        section2
    }

    #[test]
    fn a_crafted_offset_table_cannot_amplify_work_or_memory() {
        for terminate in [false, true] {
            let section2 = amplifying_section2(256 * 1024, terminate);
            let entry = build_entry_plain(&build_section1("X", FILETIME_2024, 1), &section2);

            let started = std::time::Instant::now();
            let parsed = parse_entry(&entry).expect("the header is well formed");
            let elapsed = started.elapsed();

            let retained: usize = parsed
                .resources
                .iter()
                .map(|r| r.detection_path.as_deref().map_or(0, str::len) + r.detection_type.len())
                .sum();

            assert!(elapsed.as_secs() < 10, "terminate={terminate} took {elapsed:?}");
            assert!(
                retained < 8 * 1024 * 1024,
                "terminate={terminate} retained {retained} bytes from a 256 KiB section"
            );
        }
    }

    #[test]
    fn duplicate_offsets_report_the_resource_once() {
        let section1 = build_section1("Trojan:Win32/X", FILETIME_2024, 1);
        let mut section2 = build_section2(&[("C:\\Users\\bob\\a.exe", "file", vec![])]);
        let offset = u32::from_le_bytes(section2[4..8].try_into().unwrap());

        let mut table = 64u32.to_le_bytes().to_vec();
        for _ in 0..64 {
            table.extend_from_slice(&offset.to_le_bytes());
        }
        let body = section2.split_off(8);
        let mut rebuilt = table;
        rebuilt.resize(offset as usize, 0);
        rebuilt.extend(body);

        let entry = build_entry_plain(&section1, &rebuilt);
        let observations = harvest_entry(&entry);
        assert_eq!(observations.len(), 1, "one record reported {} times", observations.len());
        assert_eq!(observations[0].path.as_ref().unwrap().key(), "\\users\\bob\\a.exe");
    }

    #[test]
    fn the_work_bound_does_not_clip_a_legitimate_entry() {
        let paths: Vec<String> =
            (0..200).map(|i| format!("C:\\Users\\bob\\sample{i:03}.exe")).collect();
        let resources: Vec<(&str, &str, Vec<Field>)> = paths
            .iter()
            .map(|path| {
                (
                    path.as_str(),
                    "file",
                    vec![
                        field(FIELD_RESOURCE_ID_FILE, 0x5, vec![0xCD; 20]),
                        field(FIELD_FILE_SIZE, 0x6, 4096u64.to_le_bytes().to_vec()),
                        field(FIELD_LAST_WRITE_TIME, 0x6, FILETIME_2024.to_le_bytes().to_vec()),
                    ],
                )
            })
            .collect();

        let section2 = build_section2(&resources);
        let entry =
            build_entry_plain(&build_section1("Trojan:Win32/X", FILETIME_2024, 1), &section2);

        let parsed = parse_entry(&entry).unwrap();
        assert_eq!(parsed.resources.len(), 200);
        for (i, resource) in parsed.resources.iter().enumerate() {
            assert_eq!(resource.detection_path.as_deref(), Some(paths[i].as_str()));
            assert_eq!(resource.file_size, Some(4096));
            assert_eq!(resource.resource_id.as_deref(), Some(&"CD".repeat(20)[..]));
            assert!(resource.last_write.is_some());
        }
        assert_eq!(harvest_entry(&entry).len(), 200);
    }

    #[test]
    fn registry_detection_covers_type_and_path() {
        let mut resource = QuarantineResource {
            detection_type: "regkey".into(),
            detection_path: Some("C:\\a.exe".into()),
            ..Default::default()
        };
        assert!(resource.is_registry());

        resource.detection_type = "file".into();
        assert!(!resource.is_registry());

        resource.detection_path = Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\x".into());
        assert!(resource.is_registry());
        assert!(resource.normalized_path().is_none());

        resource.detection_path = Some("_".into());
        assert!(resource.normalized_path().is_none());
    }

    #[test]
    fn a_resource_id_names_its_payload_under_a_two_character_directory() {
        assert_eq!(
            resource_data_relative_path("3818F477CB70846BA5AB4B7E356E5C3B4D6345DD").as_deref(),
            Some("38\\3818F477CB70846BA5AB4B7E356E5C3B4D6345DD")
        );
        assert_eq!(resource_data_relative_path("AB").as_deref(), Some("AB\\AB"));
    }

    #[test]
    fn a_resource_id_that_is_not_hex_never_becomes_a_path() {
        for hostile in [
            "",
            "A",
            "ABC",
            "..\\..\\Windows\\System32\\config\\SAM",
            "38\\3818F477",
            "38/3818",
            "38:3818",
            "ZZZZ",
            "38 18",
            &"A".repeat(129),
        ] {
            assert!(
                resource_data_relative_path(hostile).is_none(),
                "{hostile:?} was accepted as a resource id"
            );
        }
    }

    #[test]
    fn an_entry_yields_both_the_observation_and_the_way_back_to_the_bytes() {
        let (plain, s1, s2) = eicar_entry();
        let (observations, recoverable) =
            harvest_entry_with_recovery(&encrypt_entry(&plain, s1, s2));

        assert_eq!(observations.len(), 1);
        assert_eq!(recoverable.len(), 1);
        let file = &recoverable[0];
        assert_eq!(file.path.key(), "\\downloads\\eicar.com");
        assert_eq!(file.resource_id, "3818F477CB70846BA5AB4B7E356E5C3B4D6345DD");
        assert_eq!(file.threat.as_deref(), Some("Virus:DOS/EICAR_Test_File"));
        assert_eq!(file.claimed_size, Some(68));
        assert_eq!(observations[0].path.as_ref().unwrap().key(), file.path.key());
    }

    #[test]
    fn only_file_resources_defender_stored_are_offered_for_recovery() {
        let section1 = build_section1("Trojan:Win32/Occamy.C", FILETIME_2024, 7);
        let section2 = build_section2(&[
            (
                "C:\\Users\\bob\\a.exe",
                "file",
                vec![field(FIELD_RESOURCE_ID_FILE, 0x5, vec![0xAB; 20])],
            ),
            ("C:\\Users\\bob\\b.exe", "file", vec![]),
            (
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x",
                "regvalue",
                vec![field(FIELD_RESOURCE_ID_REGISTRY, 0x5, vec![0xCD; 20])],
            ),
        ]);
        let entry = build_entry_plain(&section1, &section2);

        let (observations, recoverable) = harvest_entry_with_recovery(&entry);
        assert_eq!(observations.len(), 2);
        assert_eq!(recoverable.len(), 1);
        assert_eq!(recoverable[0].path.key(), "\\users\\bob\\a.exe");
        assert_eq!(recoverable[0].claimed_size, None);
    }

    #[test]
    fn the_original_harvest_entry_is_unchanged_by_the_recovery_half() {
        let (plain, s1, s2) = eicar_entry();
        let on_disk = encrypt_entry(&plain, s1, s2);
        let paths: Vec<String> = harvest_entry(&on_disk)
            .iter()
            .map(|o| o.path.as_ref().unwrap().key().to_string())
            .collect();
        let also: Vec<String> = harvest_entry_with_recovery(&on_disk)
            .0
            .iter()
            .map(|o| o.path.as_ref().unwrap().key().to_string())
            .collect();
        assert_eq!(paths, also);
        assert_eq!(paths, vec!["\\downloads\\eicar.com".to_string()]);
    }

    #[test]
    fn junk_offers_no_recovery_pointers() {
        for junk in [vec![], vec![0u8; 8], vec![0xAAu8; 4096], b"MZ\x90\x00not an entry".to_vec()] {
            let (observations, recoverable) = harvest_entry_with_recovery(&junk);
            assert!(observations.is_empty());
            assert!(recoverable.is_empty());
        }
    }
    #[test]
    fn a_hostile_detection_name_is_carried_verbatim_and_stays_in_its_field() {
        let hostile = "Trojan\u{1b}[2J\r\nFORGED VERDICT: benign\u{202E}exe.doc";
        let section1 = build_section1(hostile, FILETIME_2024, 1);
        let section2 = build_section2(&[(
            r"\\?\C:\Users\bob\x.exe",
            "file",
            vec![field(FIELD_RESOURCE_ID_FILE, 0x5, vec![0xAB; 20])],
        )]);
        let entry = build_entry_plain(&section1, &section2);

        let parsed = parse_entry(&entry).unwrap();
        assert_eq!(parsed.detection_name.as_deref(), Some(hostile));

        let (observations, recoverable) = harvest_entry_with_recovery(&entry);
        assert_eq!(observations.len(), 1);
        match &observations[0].kind {
            ObservationKind::Quarantined { threat, .. } => {
                assert_eq!(threat.as_deref(), Some(hostile))
            }
            other => panic!("expected a Quarantined observation, got {other:?}"),
        }

        assert_eq!(observations[0].path.as_ref().unwrap().key(), "\\users\\bob\\x.exe");
        let resource = &recoverable[0].resource_id;
        assert!(resource.bytes().all(|b| b.is_ascii_hexdigit()), "{resource}");
        assert!(resource_data_relative_path(resource).is_some());
    }
}
