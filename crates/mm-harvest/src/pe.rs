use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind};

use crate::Harvested;

pub const PACKED_ENTROPY: f64 = 7.2;

pub const MIN_SECTION_BYTES: u32 = 16 * 1024;

const MAX_SECTIONS: usize = 96;

const CNT_CODE: u32 = 0x0000_0020;
const MEM_EXECUTE: u32 = 0x2000_0000;

const SECTION_HEADER_BYTES: usize = 40;

const RT_VERSION: u32 = 16;

const MAX_RESOURCE_ENTRIES: usize = 512;

const MAX_RESOURCE_NODES: usize = 4096;

#[derive(Clone, Debug, PartialEq)]
pub struct CodeSection {
    pub name: String,
    pub entropy: f64,
    pub size: u32,
}

impl CodeSection {
    pub fn is_packed(&self) -> bool {
        self.entropy >= PACKED_ENTROPY && self.size >= MIN_SECTION_BYTES
    }
}

const DEBUG_ENTRY_BYTES: usize = 28;
const DEBUG_TYPE_CODEVIEW: u32 = 2;
const MAX_DEBUG_ENTRIES: usize = 32;
const MAX_SELF_NAME_CHARS: usize = 260;

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total;
        entropy -= p * p.log2();
    }
    entropy
}

pub fn is_managed_assembly(bytes: &[u8]) -> bool {
    let Some(optional) = optional_header_offset(bytes) else { return false };
    let magic = read_u16(bytes, optional).unwrap_or(0);
    let (count_at, directories_at) = match magic {
        0x010b => (optional + 92, optional + 96),
        0x020b => (optional + 108, optional + 112),
        _ => return false,
    };
    if read_u32(bytes, count_at).unwrap_or(0) < 15 {
        return false;
    }
    read_u32(bytes, directories_at + 14 * 8).unwrap_or(0) != 0
}

pub fn code_sections(bytes: &[u8]) -> Vec<CodeSection> {
    if is_managed_assembly(bytes) {
        return Vec::new();
    }
    let Some(table) = section_table_offset(bytes) else { return Vec::new() };
    let Some(count) = section_count(bytes) else { return Vec::new() };

    let mut budget = bytes.len();

    let mut sections = Vec::new();
    for index in 0..count.min(MAX_SECTIONS) {
        let header = table + index * SECTION_HEADER_BYTES;
        let Some(characteristics) = read_u32(bytes, header + 36) else { break };
        if characteristics & (CNT_CODE | MEM_EXECUTE) == 0 {
            continue;
        }
        let (Some(raw_size), Some(raw_offset)) =
            (read_u32(bytes, header + 16), read_u32(bytes, header + 20))
        else {
            break;
        };
        let start = raw_offset as usize;
        let end = start.saturating_add(raw_size as usize).min(bytes.len());
        if start >= bytes.len() || end <= start {
            continue;
        }
        let data = &bytes[start..end];
        if data.len() > budget {
            break;
        }
        budget -= data.len();
        sections.push(CodeSection {
            name: section_name(bytes, header),
            entropy: shannon_entropy(data),
            size: data.len() as u32,
        });
    }
    sections
}

pub fn packed_section(bytes: &[u8]) -> Option<CodeSection> {
    code_sections(bytes)
        .into_iter()
        .filter(CodeSection::is_packed)
        .max_by(|a, b| a.entropy.partial_cmp(&b.entropy).unwrap_or(std::cmp::Ordering::Equal))
}

pub fn has_version_resource(bytes: &[u8]) -> Option<bool> {
    let optional = optional_header_offset(bytes)?;
    let magic = read_u16(bytes, optional).unwrap_or(0);
    let (count_at, directories_at) = match magic {
        0x010b => (optional + 92, optional + 96),
        0x020b => (optional + 108, optional + 112),
        _ => return None,
    };
    if read_u32(bytes, count_at).unwrap_or(0) < 3 {
        return Some(false);
    }
    let rva = read_u32(bytes, directories_at + 2 * 8)?;
    if rva == 0 {
        return Some(false);
    }
    let root = rva_to_offset(bytes, rva)?;
    let mut budget = MAX_RESOURCE_NODES;
    resource_type_present(bytes, root, RT_VERSION, &mut budget)
}

fn resource_type_present(
    bytes: &[u8],
    node: usize,
    wanted: u32,
    budget: &mut usize,
) -> Option<bool> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    let named = read_u16(bytes, node + 12)?;
    let ids = read_u16(bytes, node + 14)?;
    let total = (named as usize).saturating_add(ids as usize);
    if total > MAX_RESOURCE_ENTRIES {
        return None;
    }
    for index in 0..total {
        let entry = node + 16 + index * 8;
        let name = read_u32(bytes, entry)?;
        if name & 0x8000_0000 != 0 {
            continue;
        }
        if name == wanted {
            return Some(true);
        }
    }
    Some(false)
}

pub fn entry_point_is_inside_a_section(bytes: &[u8]) -> Option<bool> {
    let optional = optional_header_offset(bytes)?;
    match read_u16(bytes, optional).unwrap_or(0) {
        0x010b | 0x020b => {}
        _ => return None,
    }
    let entry = read_u32(bytes, optional + 16)?;
    if entry == 0 {
        return None;
    }
    let table = section_table_offset(bytes)?;
    let count = section_count(bytes)?;
    let mut any = false;
    for index in 0..count.min(MAX_SECTIONS) {
        let header = table + index * SECTION_HEADER_BYTES;
        let (Some(virtual_size), Some(virtual_address), Some(raw_size)) = (
            read_u32(bytes, header + 8),
            read_u32(bytes, header + 12),
            read_u32(bytes, header + 16),
        ) else {
            return None;
        };
        any = true;
        let span = virtual_size.max(raw_size);
        if entry >= virtual_address && entry < virtual_address.saturating_add(span) {
            return Some(true);
        }
    }
    any.then_some(false)
}

pub fn self_names(bytes: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(pdb) = debug_pdb_path(bytes) {
        names.push(pdb);
    }
    if let Some(exported) = export_name(bytes) {
        names.push(exported);
    }
    names.retain(|name| !name.is_empty() && name.chars().count() <= MAX_SELF_NAME_CHARS);
    names.dedup();
    names
}

pub fn stem_of(name: &str) -> String {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let stem = base.rsplit_once('.').map_or(base, |(before, _)| before);
    stem.to_ascii_lowercase()
}

fn debug_pdb_path(bytes: &[u8]) -> Option<String> {
    let (count_at, directories_at) = directory_table(bytes)?;
    if read_u32(bytes, count_at).unwrap_or(0) < 7 {
        return None;
    }
    let rva = read_u32(bytes, directories_at + 6 * 8)?;
    let size = read_u32(bytes, directories_at + 6 * 8 + 4)? as usize;
    if rva == 0 || size < DEBUG_ENTRY_BYTES {
        return None;
    }
    let table = rva_to_offset(bytes, rva)?;
    for index in 0..(size / DEBUG_ENTRY_BYTES).min(MAX_DEBUG_ENTRIES) {
        let entry = table.checked_add(index.checked_mul(DEBUG_ENTRY_BYTES)?)?;
        if read_u32(bytes, entry + 12)? != DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let at = read_u32(bytes, entry + 24)? as usize;
        if bytes.get(at..at.checked_add(4)?)? != b"RSDS" {
            continue;
        }
        let path = nul_terminated(bytes, at.checked_add(24)?)?;
        return Some(base_name(&path));
    }
    None
}

fn export_name(bytes: &[u8]) -> Option<String> {
    let (count_at, directories_at) = directory_table(bytes)?;
    if read_u32(bytes, count_at).unwrap_or(0) == 0 {
        return None;
    }
    let rva = read_u32(bytes, directories_at)?;
    if rva == 0 {
        return None;
    }
    let table = rva_to_offset(bytes, rva)?;
    let name_rva = read_u32(bytes, table.checked_add(12)?)?;
    if name_rva == 0 {
        return None;
    }
    let at = rva_to_offset(bytes, name_rva)?;
    Some(base_name(&nul_terminated(bytes, at)?))
}

fn directory_table(bytes: &[u8]) -> Option<(usize, usize)> {
    let optional = optional_header_offset(bytes)?;
    match read_u16(bytes, optional)? {
        0x010b => Some((optional + 92, optional + 96)),
        0x020b => Some((optional + 108, optional + 112)),
        _ => None,
    }
}

fn nul_terminated(bytes: &[u8], at: usize) -> Option<String> {
    let rest = bytes.get(at..)?;
    let end = rest.iter().take(MAX_SELF_NAME_CHARS).position(|&b| b == 0)?;
    let text = std::str::from_utf8(rest.get(..end)?).ok()?;
    text.chars()
        .all(|c| c >= ' ' && !matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
        .then(|| text.to_string())
}

fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn rva_to_offset(bytes: &[u8], rva: u32) -> Option<usize> {
    let table = section_table_offset(bytes)?;
    let count = section_count(bytes)?;
    for index in 0..count.min(MAX_SECTIONS) {
        let header = table + index * SECTION_HEADER_BYTES;
        let virtual_address = read_u32(bytes, header + 12)?;
        let virtual_size = read_u32(bytes, header + 8)?;
        let raw_size = read_u32(bytes, header + 16)?;
        let raw_offset = read_u32(bytes, header + 20)?;
        let span = virtual_size.max(raw_size);
        if rva >= virtual_address && rva < virtual_address.saturating_add(span) {
            let offset = (raw_offset as usize).checked_add((rva - virtual_address) as usize)?;
            return (offset.checked_add(16)? <= bytes.len()).then_some(offset);
        }
    }
    None
}

pub fn harvest(bytes: &[u8], path: &NormalizedPath) -> Harvested {
    let note = |kind| Observation::about_path(ArtifactSource::FileContent, path.clone(), kind);

    if is_managed_assembly(bytes) {
        return vec![note(ObservationKind::ManagedAssembly)];
    }

    let mut out = Vec::new();

    if has_version_resource(bytes) == Some(false) {
        out.push(note(ObservationKind::NoVersionResource));
    }
    if entry_point_is_inside_a_section(bytes) == Some(false) {
        out.push(note(ObservationKind::PeAnomaly {
            detail: "the entry point does not lie inside any section the image declares \
                     — no linker produces that, and it is what a hand-edited header \
                     looks like"
                .to_string(),
        }));
    }

    if let Some(rich) = crate::imphash::rich_header(bytes) {
        if !rich.checksum_valid {
            out.push(note(ObservationKind::RichHeaderChecksumInvalid {
                entries: rich.entries.len(),
                decoded: rich.dans_decoded,
            }));
        }
    }

    if let Some(section) = packed_section(bytes) {
        out.push(note(ObservationKind::PeAnomaly {
            detail: format!(
                "the `{}` section holds {} KB at {:.2} bits/byte of entropy — near-random, \
                 which is what packing or encryption looks like (T1027.002)",
                section.name,
                section.size / 1024,
                section.entropy
            ),
        }));
    }

    out
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn coff_header_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.get(0..2)? != b"MZ" {
        return None;
    }
    let lfanew = read_u32(bytes, 0x3c)? as usize;
    if bytes.get(lfanew..lfanew.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    lfanew.checked_add(4)
}

fn optional_header_offset(bytes: &[u8]) -> Option<usize> {
    coff_header_offset(bytes)?.checked_add(20)
}

fn section_count(bytes: &[u8]) -> Option<usize> {
    let count = read_u16(bytes, coff_header_offset(bytes)?.checked_add(2)?)? as usize;
    (count > 0).then_some(count)
}

fn section_table_offset(bytes: &[u8]) -> Option<usize> {
    let coff = coff_header_offset(bytes)?;
    let optional_size = read_u16(bytes, coff.checked_add(16)?)? as usize;
    let table = coff.checked_add(20)?.checked_add(optional_size)?;
    (table < bytes.len()).then_some(table)
}

fn section_name(bytes: &[u8], header: usize) -> String {
    let Some(raw) = bytes.get(header..header + 8) else { return String::new() };
    raw.iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| if byte.is_ascii_graphic() { *byte as char } else { '.' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_with_section(
        name: &[u8; 8],
        characteristics: u32,
        body: &[u8],
        managed: bool,
    ) -> Vec<u8> {
        const LFANEW: usize = 0x80;
        const OPTIONAL_SIZE: usize = 240;
        let coff = LFANEW + 4;
        let optional = coff + 20;
        let table = optional + OPTIONAL_SIZE;
        let raw_offset = table + SECTION_HEADER_BYTES + 8;

        let mut image = vec![0u8; raw_offset];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(LFANEW as u32).to_le_bytes());
        image[LFANEW..LFANEW + 4].copy_from_slice(b"PE\0\0");
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&(OPTIONAL_SIZE as u16).to_le_bytes());
        image[optional..optional + 2].copy_from_slice(&0x020bu16.to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        if managed {
            let cli = optional + 112 + 14 * 8;
            image[cli..cli + 4].copy_from_slice(&0x2008u32.to_le_bytes());
        }
        image[table..table + 8].copy_from_slice(name);
        image[table + 8..table + 12].copy_from_slice(&(body.len() as u32).to_le_bytes());
        image[table + 16..table + 20].copy_from_slice(&(body.len() as u32).to_le_bytes());
        image[table + 20..table + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());
        image[table + 36..table + 40].copy_from_slice(&characteristics.to_le_bytes());

        image.extend_from_slice(body);
        image
    }

    fn near_random(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    fn compiled_looking(len: usize) -> Vec<u8> {
        const OPCODES: &[u8] = &[0x48, 0x89, 0xe5, 0x00, 0x8b, 0x45, 0xc3, 0x00, 0x00, 0x55];
        (0..len).map(|i| OPCODES[i % OPCODES.len()]).collect()
    }

    fn path() -> NormalizedPath {
        NormalizedPath::parse("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe").unwrap()
    }

    fn anomalies(bytes: &[u8]) -> Vec<Observation> {
        harvest(bytes, &path())
            .into_iter()
            .filter(|o| matches!(o.kind, ObservationKind::PeAnomaly { .. }))
            .collect()
    }

    fn pe_naming_itself(pdb: Option<&str>, export: Option<&str>) -> Vec<u8> {
        const LFANEW: usize = 0x80;
        const OPTIONAL_SIZE: usize = 240;
        const VIRTUAL_BASE: u32 = 0x1000;
        let coff = LFANEW + 4;
        let optional = coff + 20;
        let table = optional + OPTIONAL_SIZE;
        let raw_offset = table + SECTION_HEADER_BYTES + 8;

        let mut body = Vec::new();
        let rva = |at: usize| VIRTUAL_BASE + at as u32;

        let debug_directory = pdb.map(|path| {
            let data_at = body.len();
            body.extend_from_slice(b"RSDS");
            body.extend_from_slice(&[0u8; 20]);
            body.extend_from_slice(path.as_bytes());
            body.push(0);
            let table_at = body.len();
            let mut entry = vec![0u8; DEBUG_ENTRY_BYTES];
            entry[12..16].copy_from_slice(&DEBUG_TYPE_CODEVIEW.to_le_bytes());
            entry[24..28].copy_from_slice(&((raw_offset + data_at) as u32).to_le_bytes());
            body.extend_from_slice(&entry);
            (rva(table_at), DEBUG_ENTRY_BYTES as u32)
        });

        let export_directory = export.map(|name| {
            let name_at = body.len();
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            let table_at = body.len();
            let mut directory = vec![0u8; 40];
            directory[12..16].copy_from_slice(&rva(name_at).to_le_bytes());
            body.extend_from_slice(&directory);
            (rva(table_at), 40u32)
        });

        let mut image = vec![0u8; raw_offset];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(LFANEW as u32).to_le_bytes());
        image[LFANEW..LFANEW + 4].copy_from_slice(b"PE\0\0");
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&(OPTIONAL_SIZE as u16).to_le_bytes());
        image[optional..optional + 2].copy_from_slice(&0x020bu16.to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let directories = optional + 112;
        if let Some((rva, size)) = export_directory {
            image[directories..directories + 4].copy_from_slice(&rva.to_le_bytes());
            image[directories + 4..directories + 8].copy_from_slice(&size.to_le_bytes());
        }
        if let Some((rva, size)) = debug_directory {
            let at = directories + 6 * 8;
            image[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            image[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        }
        image[table..table + 8].copy_from_slice(b".rdata\0\0");
        image[table + 8..table + 12].copy_from_slice(&(body.len() as u32).to_le_bytes());
        image[table + 12..table + 16].copy_from_slice(&VIRTUAL_BASE.to_le_bytes());
        image[table + 16..table + 20].copy_from_slice(&(body.len() as u32).to_le_bytes());
        image[table + 20..table + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());

        image.extend_from_slice(&body);
        image
    }

    #[test]
    fn a_debug_build_carries_the_name_it_was_compiled_under() {
        let image = pe_naming_itself(
            Some("C:\\Users\\bob\\AppData\\Local\\Temp\\build\\dropper.pdb"),
            None,
        );
        assert_eq!(self_names(&image), vec!["dropper.pdb".to_string()]);
        assert_eq!(stem_of("dropper.pdb"), "dropper");
    }

    #[test]
    fn a_library_carries_the_name_it_exports_under() {
        let image = pe_naming_itself(None, Some("PayLoad.dll"));
        assert_eq!(self_names(&image), vec!["PayLoad.dll".to_string()]);
        assert_eq!(stem_of("PayLoad.dll"), "payload");
    }

    #[test]
    fn both_names_are_offered_when_both_are_there() {
        let image = pe_naming_itself(Some("D:\\src\\stage2.pdb"), Some("stage2.dll"));
        assert_eq!(self_names(&image), vec!["stage2.pdb".to_string(), "stage2.dll".to_string()]);
    }

    #[test]
    fn a_stripped_image_names_itself_nothing() {
        assert!(self_names(&pe_naming_itself(None, None)).is_empty());
        assert!(self_names(&pe_with_section(b".text\0\0\0", CNT_CODE, b"MZ", false)).is_empty());
        assert!(self_names(b"MZ").is_empty());
        assert!(self_names(&[]).is_empty());
    }

    #[test]
    fn a_stem_survives_any_spelling_of_a_path() {
        assert_eq!(stem_of("x.exe"), "x");
        assert_eq!(stem_of("C:\\a\\b\\Stage2.PDB"), "stage2");
        assert_eq!(stem_of("/tmp/build/loader.pdb"), "loader");
        assert_eq!(stem_of("noextension"), "noextension");
        assert_eq!(stem_of(""), "");
        assert_eq!(stem_of("a.b.c.pdb"), "a.b.c");
    }

    #[test]
    fn a_self_name_is_never_read_past_the_image() {
        let full = pe_naming_itself(Some("D:\\src\\stage2.pdb"), Some("stage2.dll"));
        for cut in 0..full.len() {
            let _ = self_names(&full[..cut]);
        }
        for byte in (0..full.len()).step_by(7) {
            let mut damaged = full.clone();
            damaged[byte] ^= 0xff;
            let _ = self_names(&damaged);
        }
    }

    #[test]
    fn entropy_spans_the_range_it_claims() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0, "one symbol carries no information");

        let uniform: Vec<u8> = (0..=255u8).cycle().take(65536).collect();
        assert!(
            (shannon_entropy(&uniform) - 8.0).abs() < 1e-9,
            "256 equal symbols is exactly 8 bits"
        );

        let random = shannon_entropy(&near_random(65536));
        assert!(random > 7.9, "pseudo-random bytes should be near the ceiling, got {random}");

        let code = shannon_entropy(&compiled_looking(65536));
        assert!(code < 4.0, "a ten-symbol alphabet should be low, got {code}");
    }

    #[test]
    fn entropy_depends_only_on_the_histogram() {
        let mut forward = near_random(8192);
        let backward: Vec<u8> = forward.iter().rev().copied().collect();
        let straight = shannon_entropy(&forward);
        forward.sort_unstable();
        assert!((shannon_entropy(&forward) - straight).abs() < 1e-12);
        assert!((shannon_entropy(&backward) - straight).abs() < 1e-12);
    }

    #[test]
    fn a_rich_header_the_linker_did_not_write_is_reported_and_a_genuine_one_is_not() {
        use crate::imphash::fixture::rich;
        let forged = rich(&[(0x0102, 27412, 9)], |k| k ^ 0x0f0f_0f0f, |k| k ^ 0x0f0f_0f0f);
        let found: Vec<Observation> = harvest(&forged, &path())
            .into_iter()
            .filter(|o| matches!(o.kind, ObservationKind::RichHeaderChecksumInvalid { .. }))
            .collect();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(matches!(
            found[0].kind,
            ObservationKind::RichHeaderChecksumInvalid { entries: 1, decoded: true }
        ));

        let planted = rich(&[(0x0102, 27412, 9)], |k| k ^ 0x0f0f_0f0f, |k| k);
        assert!(harvest(&planted, &path()).iter().any(|o| matches!(
            o.kind,
            ObservationKind::RichHeaderChecksumInvalid { decoded: false, .. }
        )));

        let genuine = rich(&[(0x0102, 27412, 9)], |k| k, |k| k);
        assert!(harvest(&genuine, &path())
            .iter()
            .all(|o| !matches!(o.kind, ObservationKind::RichHeaderChecksumInvalid { .. })));
    }

    #[test]
    fn a_packed_code_section_is_found_and_named() {
        let image = pe_with_section(b"UPX1\0\0\0\0", MEM_EXECUTE, &near_random(64 * 1024), false);
        let section = packed_section(&image).expect("a near-random code section should be packed");
        assert_eq!(section.name, "UPX1");
        assert!(section.entropy > PACKED_ENTROPY);

        let observations = anomalies(&image);
        assert_eq!(observations.len(), 1);
        match &observations[0].kind {
            ObservationKind::PeAnomaly { detail } => {
                assert!(
                    detail.contains("T1027.002"),
                    "scoring routes on the technique id: {detail}"
                );
                assert!(detail.contains("UPX1"));
                assert!(detail.contains("64 KB"));
            }
            other => panic!("expected a PE anomaly, got {other:?}"),
        }
    }

    #[test]
    fn ordinary_compiled_code_stays_silent() {
        let image = pe_with_section(b".text\0\0\0", CNT_CODE, &compiled_looking(64 * 1024), false);
        assert!(packed_section(&image).is_none());
        assert!(anomalies(&image).is_empty());
    }

    #[test]
    fn a_high_entropy_data_section_is_not_a_code_section() {
        let image = pe_with_section(b".rsrc\0\0\0", 0x4000_0040, &near_random(1024 * 1024), false);
        assert!(code_sections(&image).is_empty());
        assert!(anomalies(&image).is_empty());
    }

    #[test]
    fn managed_assemblies_are_excluded() {
        let body = near_random(64 * 1024);
        let managed = pe_with_section(b".text\0\0\0", CNT_CODE, &body, true);
        let native = pe_with_section(b".text\0\0\0", CNT_CODE, &body, false);

        assert!(is_managed_assembly(&managed));
        assert!(!is_managed_assembly(&native));
        assert!(code_sections(&managed).is_empty(), ".NET metadata is not a packing claim");

        let from_managed = harvest(&managed, &path());
        assert_eq!(from_managed.len(), 1);
        assert!(
            matches!(from_managed[0].kind, ObservationKind::ManagedAssembly),
            "a managed assembly must never be reported as packed: {:?}",
            from_managed[0].kind
        );

        let from_native = anomalies(&native);
        assert_eq!(from_native.len(), 1, "the native twin must still fire");
        assert!(matches!(from_native[0].kind, ObservationKind::PeAnomaly { .. }));
    }

    #[test]
    fn an_ordinary_native_image_produces_no_observation() {
        let quiet = pe_with_section(b".text\0\0\0", CNT_CODE, &vec![0x90u8; 64 * 1024], false);
        assert!(!is_managed_assembly(&quiet));
        assert!(anomalies(&quiet).is_empty());
    }

    #[test]
    fn a_section_too_small_to_judge_is_not_judged() {
        let small = pe_with_section(b".no_bbt\0", MEM_EXECUTE, &near_random(6 * 1024), false);
        let sections = code_sections(&small);
        assert_eq!(sections.len(), 1, "it is still reported as a section");
        assert!(sections[0].entropy > PACKED_ENTROPY, "and it is still near-random");
        assert!(!sections[0].is_packed(), "but it is too small to be evidence");
        assert!(anomalies(&small).is_empty());
    }

    #[test]
    fn the_most_random_section_is_the_one_reported() {
        let mut image =
            pe_with_section(b".text\0\0\0", CNT_CODE, &compiled_looking(64 * 1024), false);
        let coff = 0x80 + 4;
        image[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        let table = coff + 20 + 240;
        let second = table + SECTION_HEADER_BYTES;
        let payload = near_random(64 * 1024);
        let raw_offset = image.len();
        image[second..second + 8].copy_from_slice(b".themida");
        image[second + 8..second + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        image[second + 16..second + 20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        image[second + 20..second + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());
        image[second + 36..second + 40].copy_from_slice(&MEM_EXECUTE.to_le_bytes());
        image.extend_from_slice(&payload);

        assert_eq!(code_sections(&image).len(), 2);
        assert_eq!(packed_section(&image).unwrap().name, ".themida");
    }

    #[test]
    fn damaged_and_hostile_headers_yield_nothing_rather_than_failing() {
        let good = pe_with_section(b"UPX1\0\0\0\0", MEM_EXECUTE, &near_random(64 * 1024), false);

        for (label, image) in [
            ("empty", Vec::new()),
            ("one byte", vec![0x4d]),
            ("MZ only", b"MZ".to_vec()),
            ("no PE signature", vec![0x4d, 0x5a, 0, 0, 0, 0, 0, 0]),
            ("truncated at the header", good[..0x90].to_vec()),
            ("truncated mid-section-table", good[..0x80 + 4 + 20 + 240 + 12].to_vec()),
            ("truncated payload", good[..good.len() - 40 * 1024].to_vec()),
            ("all zeroes", vec![0u8; 4096]),
            ("all 0xff", vec![0xffu8; 4096]),
        ] {
            let _ = code_sections(&image);
            let _ = is_managed_assembly(&image);
            assert!(anomalies(&image).len() <= 1, "{label} produced too much");
        }
    }

    #[test]
    fn lying_offsets_and_counts_are_refused() {
        let mut image =
            pe_with_section(b"UPX1\0\0\0\0", MEM_EXECUTE, &near_random(64 * 1024), false);
        let coff = 0x80 + 4;
        let table = coff + 20 + 240;

        let mut lying_count = image.clone();
        lying_count[coff + 2..coff + 4].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(code_sections(&lying_count).len() <= MAX_SECTIONS);

        let mut lying_optional = image.clone();
        lying_optional[coff + 16..coff + 18].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(code_sections(&lying_optional).is_empty());

        image[table + 20..table + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(code_sections(&image).is_empty());

        let mut lying_lfanew = lying_count.clone();
        lying_lfanew[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(code_sections(&lying_lfanew).is_empty());
        assert!(!is_managed_assembly(&lying_lfanew));
    }

    #[test]
    fn hostile_section_names_are_defanged() {
        let image =
            pe_with_section(b"\x1b[2J\x07\n\0\0", MEM_EXECUTE, &near_random(64 * 1024), false);
        let section = packed_section(&image).unwrap();
        assert_eq!(section.name, ".[2J..");
        assert!(section.name.chars().all(|c| c.is_ascii_graphic()));
    }

    #[test]
    fn the_reported_size_is_the_size_that_was_measured() {
        let body = near_random(64 * 1024);
        let full = pe_with_section(b"UPX1\0\0\0\0", MEM_EXECUTE, &body, false);
        let truncated = full[..full.len() - 32 * 1024].to_vec();

        assert_eq!(code_sections(&full)[0].size, 64 * 1024);
        assert_eq!(code_sections(&truncated)[0].size, 32 * 1024);
    }

    #[test]
    fn overlapping_sections_cannot_direct_an_unbounded_amount_of_reading() {
        const MEGABYTE: usize = 1024 * 1024;
        let body = near_random(4 * MEGABYTE);
        let mut image = pe_with_section(b"UPX1\0\0\0\0", MEM_EXECUTE, &body, false);

        let coff = 0x80 + 4;
        let table = coff + 20 + 240;
        image[coff + 2..coff + 4].copy_from_slice(&96u16.to_le_bytes());
        let length = image.len() as u32;
        let mut extra = Vec::new();
        for _ in 0..95 {
            let mut header = vec![0u8; SECTION_HEADER_BYTES];
            header[0..8].copy_from_slice(b"OVERLAP\0");
            header[16..20].copy_from_slice(&length.to_le_bytes());
            header[20..24].copy_from_slice(&0u32.to_le_bytes());
            header[36..40].copy_from_slice(&MEM_EXECUTE.to_le_bytes());
            extra.extend_from_slice(&header);
        }
        image.splice(table + SECTION_HEADER_BYTES..table + SECTION_HEADER_BYTES, extra);

        let started = std::time::Instant::now();
        let sections = code_sections(&image);
        let elapsed = started.elapsed();

        let examined: usize = sections.iter().map(|s| s.size as usize).sum();
        assert!(
            examined <= image.len(),
            "read {examined} bytes of a {}-byte image: the budget is not holding",
            image.len()
        );
        assert!(elapsed.as_secs() < 5, "a 96-section overlapping image took {elapsed:?}");
    }

    fn pe_with_resource_type(resource_type: Option<u32>) -> Vec<u8> {
        const LFANEW: usize = 0x80;
        const OPTIONAL_SIZE: usize = 240;
        let coff = LFANEW + 4;
        let optional = coff + 20;
        let table = optional + OPTIONAL_SIZE;
        let raw_offset = table + SECTION_HEADER_BYTES + 8;
        let body_len = 64usize;
        let virtual_address = 0x1000u32;

        let mut image = vec![0u8; raw_offset];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&(LFANEW as u32).to_le_bytes());
        image[LFANEW..LFANEW + 4].copy_from_slice(b"PE\0\0");
        image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        image[coff + 16..coff + 18].copy_from_slice(&(OPTIONAL_SIZE as u16).to_le_bytes());
        image[optional..optional + 2].copy_from_slice(&0x020bu16.to_le_bytes());
        image[optional + 16..optional + 20].copy_from_slice(&(virtual_address + 8).to_le_bytes());
        image[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let resources = optional + 112 + 2 * 8;
        image[resources..resources + 4].copy_from_slice(&virtual_address.to_le_bytes());
        image[resources + 4..resources + 8].copy_from_slice(&(body_len as u32).to_le_bytes());

        image[table..table + 8].copy_from_slice(b".rsrc\0\0\0");
        image[table + 8..table + 12].copy_from_slice(&(body_len as u32).to_le_bytes());
        image[table + 12..table + 16].copy_from_slice(&virtual_address.to_le_bytes());
        image[table + 16..table + 20].copy_from_slice(&(body_len as u32).to_le_bytes());
        image[table + 20..table + 24].copy_from_slice(&(raw_offset as u32).to_le_bytes());
        image[table + 36..table + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

        let mut body = vec![0u8; body_len];
        if let Some(id) = resource_type {
            body[14..16].copy_from_slice(&1u16.to_le_bytes());
            body[16..20].copy_from_slice(&id.to_le_bytes());
            body[20..24].copy_from_slice(&0x8000_0020u32.to_le_bytes());
        }
        image.extend_from_slice(&body);
        image
    }

    #[test]
    fn a_version_resource_is_found_when_it_is_there() {
        let with = pe_with_resource_type(Some(RT_VERSION));
        assert_eq!(has_version_resource(&with), Some(true));
        assert!(
            harvest(&with, &path())
                .iter()
                .all(|o| !matches!(o.kind, ObservationKind::NoVersionResource)),
            "a file that has one must not be reported as missing one"
        );
    }

    #[test]
    fn a_stripped_resource_directory_is_the_finding() {
        let stripped = pe_with_resource_type(None);
        assert_eq!(has_version_resource(&stripped), Some(false));

        let manifest_only = pe_with_resource_type(Some(24));
        assert_eq!(has_version_resource(&manifest_only), Some(false));

        let found = harvest(&stripped, &path());
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0].kind, ObservationKind::NoVersionResource));
    }

    #[test]
    fn no_resource_directory_at_all_is_still_an_answer() {
        let plain = pe_with_section(b".text\0\0\0", CNT_CODE, &compiled_looking(64 * 1024), false);
        assert_eq!(has_version_resource(&plain), Some(false));
    }

    #[test]
    fn unreadable_bytes_are_unknown_and_never_an_absence() {
        for (label, bytes) in [
            ("empty", Vec::new()),
            ("compressed nonsense", near_random(4096)),
            ("MZ only", b"MZ".to_vec()),
            ("no PE signature", vec![0x4d, 0x5a, 0, 0, 0, 0, 0, 0]),
            ("all zeroes", vec![0u8; 4096]),
            ("a text file", b"the quick brown fox\n".repeat(64)),
        ] {
            assert_eq!(has_version_resource(&bytes), None, "{label} must be UNKNOWN");
            assert!(
                harvest(&bytes, &path())
                    .iter()
                    .all(|o| !matches!(o.kind, ObservationKind::NoVersionResource)),
                "{label} produced an absence claim"
            );
        }
    }

    #[test]
    fn a_resource_directory_we_cannot_reach_is_unknown() {
        let mut image = pe_with_resource_type(Some(RT_VERSION));
        let resources = 0x80 + 4 + 20 + 112 + 2 * 8;
        image[resources..resources + 4].copy_from_slice(&0x7fff_0000u32.to_le_bytes());
        assert_eq!(has_version_resource(&image), None);

        let truncated = image[..image.len() - 64].to_vec();
        assert_eq!(has_version_resource(&truncated), None);
    }

    #[test]
    fn a_lying_resource_entry_count_is_bounded() {
        let mut image = pe_with_resource_type(Some(24));
        let body = image.len() - 64;
        image[body + 12..body + 14].copy_from_slice(&u16::MAX.to_le_bytes());
        image[body + 14..body + 16].copy_from_slice(&u16::MAX.to_le_bytes());
        let started = std::time::Instant::now();
        let answer = has_version_resource(&image);
        assert!(started.elapsed().as_secs() < 2, "the walk is not bounded");
        assert_eq!(answer, None);
    }

    #[test]
    fn an_entry_point_inside_a_section_is_ordinary() {
        let image = pe_with_resource_type(Some(RT_VERSION));
        assert_eq!(entry_point_is_inside_a_section(&image), Some(true));
        assert!(harvest(&image, &path()).is_empty());
    }

    #[test]
    fn an_entry_point_outside_every_section_is_a_structural_finding() {
        let mut image = pe_with_resource_type(Some(RT_VERSION));
        let optional = 0x80 + 4 + 20;
        image[optional + 16..optional + 20].copy_from_slice(&0x00ab_cdefu32.to_le_bytes());
        assert_eq!(entry_point_is_inside_a_section(&image), Some(false));

        let found = harvest(&image, &path());
        assert_eq!(found.len(), 1);
        match &found[0].kind {
            ObservationKind::PeAnomaly { detail } => {
                assert!(detail.contains("entry point"), "{detail}");
                assert!(!detail.contains("T1027.002"), "{detail}");
                assert!(!detail.contains("T1070.006"), "{detail}");
            }
            other => panic!("expected a PE anomaly, got {other:?}"),
        }
    }

    #[test]
    fn a_zero_entry_point_is_not_a_finding() {
        let mut image = pe_with_resource_type(Some(RT_VERSION));
        let optional = 0x80 + 4 + 20;
        image[optional + 16..optional + 20].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(entry_point_is_inside_a_section(&image), None);
        assert!(harvest(&image, &path()).is_empty());
    }

    #[test]
    fn a_managed_assembly_still_produces_only_the_managed_note() {
        let managed = pe_with_section(b".text\0\0\0", CNT_CODE, &compiled_looking(64 * 1024), true);
        let found = harvest(&managed, &path());
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0].kind, ObservationKind::ManagedAssembly));
    }

    #[test]
    fn the_new_readers_survive_the_hostile_corpus() {
        let good = pe_with_section(b"UPX1\0\0\0\0", MEM_EXECUTE, &near_random(64 * 1024), false);
        for image in [
            Vec::new(),
            vec![0x4d],
            b"MZ".to_vec(),
            good[..0x90].to_vec(),
            good[..0x80 + 4 + 20 + 240 + 12].to_vec(),
            vec![0u8; 4096],
            vec![0xffu8; 4096],
            near_random(64 * 1024),
        ] {
            let _ = has_version_resource(&image);
            let _ = entry_point_is_inside_a_section(&image);
            let _ = harvest(&image, &path());
        }
    }
}
