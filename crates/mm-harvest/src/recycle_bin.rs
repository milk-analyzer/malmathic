use chrono::{DateTime, Utc};

use mm_core::{from_filetime, ArtifactSource, NormalizedPath, Observation, ObservationKind};

use crate::Harvested;

pub const MAX_INFO_BYTES: usize = 64 * 1024 + 32;

const V2_HEADER: usize = 28;
const V1_HEADER: usize = 24;
const V1_NAME_UNITS: usize = 260;
const V1_TOTAL: usize = V1_HEADER + V1_NAME_UNITS * 2;
const MAX_NAME_UNITS: usize = 32_767;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfoLayout {
    V1,
    V2,
}

impl InfoLayout {
    pub fn label(&self) -> &'static str {
        match self {
            InfoLayout::V1 => "version 1 (fixed 260-character name)",
            InfoLayout::V2 => "version 2 (variable-length name)",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecycledFile {
    pub original: NormalizedPath,
    pub deleted: Option<DateTime<Utc>>,
    pub original_size: u64,
    pub layout: InfoLayout,
}

pub fn parse_info(bytes: &[u8]) -> Option<RecycledFile> {
    if bytes.len() < V1_HEADER {
        return None;
    }

    let version = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let original_size = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let deleted = from_filetime(u64::from_le_bytes(bytes[16..24].try_into().ok()?));

    let (layout, units) = match version {
        1 => {
            if bytes.len() < V1_TOTAL {
                return None;
            }
            (InfoLayout::V1, utf16_units(&bytes[V1_HEADER..V1_TOTAL]))
        }
        2 => {
            if bytes.len() < V2_HEADER {
                return None;
            }
            let declared = u32::from_le_bytes(bytes[24..28].try_into().ok()?) as usize;
            if declared == 0 || declared > MAX_NAME_UNITS {
                return None;
            }
            let name_bytes = declared.checked_mul(2)?;
            let end = V2_HEADER.checked_add(name_bytes)?;
            if bytes.len() < end {
                return None;
            }
            (InfoLayout::V2, utf16_units(&bytes[V2_HEADER..end]))
        }
        _ => return None,
    };

    let name: Vec<u16> = units.into_iter().take_while(|&u| u != 0).collect();
    if name.is_empty() {
        return None;
    }

    let decoded: String = char::decode_utf16(name)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .filter(|c| !c.is_control())
        .collect();

    if !decoded.contains(['\\', '/']) {
        return None;
    }

    let original = NormalizedPath::parse(&decoded)?;
    Some(RecycledFile { original, deleted, original_size, layout })
}

fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes).collect()
}

pub fn data_file_name(info_name: &str) -> Option<String> {
    let mut chars = info_name.chars();
    if chars.next()? != '$' {
        return None;
    }
    if !chars.next()?.eq_ignore_ascii_case(&'i') {
        return None;
    }
    let suffix: String = chars.collect();
    if suffix.is_empty() || suffix.contains(['\\', '/', ':']) {
        return None;
    }
    Some(format!("$R{suffix}"))
}

pub fn is_info_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() > 2 && b[0] == b'$' && b[1].eq_ignore_ascii_case(&b'I')
}

pub fn harvest(info_name: &str, bytes: &[u8]) -> Harvested {
    let Some(file) = parse_info(bytes) else { return Vec::new() };
    let _ = info_name;
    vec![Observation::about_path(
        ArtifactSource::RecycleBin,
        file.original,
        ObservationKind::FileDeleted { when: file.deleted, record: None, sequence: None },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_DIRECTORY: &[u8] = include_bytes!("../testdata/recycle_bin/v2-directory-IOQ6JGK");
    const REAL_CYRILLIC: &[u8] = include_bytes!("../testdata/recycle_bin/v2-cyrillic-IBWXC72.txt");
    const REAL_SIZED: &[u8] = include_bytes!("../testdata/recycle_bin/v2-sized-IAXUUOL.txt");

    fn v2(size: u64, filetime: u64, path: &str) -> Vec<u8> {
        let mut units: Vec<u16> = path.encode_utf16().collect();
        units.push(0);
        let mut out = Vec::new();
        out.extend_from_slice(&2u64.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&filetime.to_le_bytes());
        out.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    fn v1(size: u64, filetime: u64, path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&filetime.to_le_bytes());
        let mut units: Vec<u16> = path.encode_utf16().collect();
        units.push(0);
        units.resize(V1_NAME_UNITS, 0x4141);
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(out.len(), V1_TOTAL);
        out
    }

    const REAL_FILETIME: u64 = 0x01dc_dfe5_3458_c550;

    #[test]
    fn a_real_stub_yields_its_original_path_size_and_time() {
        let f = parse_info(REAL_DIRECTORY).expect("46-byte real $I must parse");
        assert_eq!(f.layout, InfoLayout::V2);
        assert_eq!(f.original.raw(), "E:\\CASES");
        assert_eq!(f.original_size, 0);
        assert_eq!(
            mm_core::filetime::format(f.deleted.expect("a deletion time")),
            "2026-05-09 18:54:03Z"
        );
    }

    #[test]
    fn a_real_stub_with_a_non_ascii_name_round_trips() {
        let f = parse_info(REAL_CYRILLIC).expect("112-byte real $I must parse");
        assert_eq!(f.original.raw(), "E:\\cases\\collected\\Текстовый документ.txt");
        assert!(f.original.key().ends_with("текстовый документ.txt"), "{}", f.original.key());
    }

    #[test]
    fn a_real_stubs_recorded_size_is_its_r_twins_length() {
        let f = parse_info(REAL_SIZED).expect("116-byte real $I must parse");
        assert_eq!(f.original_size, 417_644);
        assert_eq!(f.original.raw(), "E:\\cases\\collected\\dropper\\overlay_syms.txt");
    }

    #[test]
    fn every_real_stub_is_exactly_twenty_eight_plus_two_per_declared_unit() {
        for bytes in [REAL_DIRECTORY, REAL_CYRILLIC, REAL_SIZED] {
            let declared = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
            assert_eq!(bytes.len(), V2_HEADER + declared * 2);
        }
    }

    #[test]
    fn the_declared_length_counts_the_terminating_nul() {
        let declared = u32::from_le_bytes(REAL_DIRECTORY[24..28].try_into().unwrap());
        assert_eq!(declared, 9, "nine units for the eight characters of `E:\\CASES`");
        assert_eq!(parse_info(REAL_DIRECTORY).unwrap().original.raw().chars().count(), 8);
    }

    #[test]
    fn a_version_one_stub_parses_and_stops_at_the_terminator() {
        let bytes = v1(4096, REAL_FILETIME, "C:\\Users\\bob\\Desktop\\invoice.exe");
        let f = parse_info(&bytes).expect("a 544-byte v1 stub");
        assert_eq!(f.layout, InfoLayout::V1);
        assert_eq!(f.original.raw(), "C:\\Users\\bob\\Desktop\\invoice.exe");
        assert_eq!(f.original_size, 4096);
    }

    #[test]
    fn a_short_version_one_stub_is_refused() {
        let mut bytes = v1(1, REAL_FILETIME, "C:\\x\\y.exe");
        bytes.truncate(V1_TOTAL - 1);
        assert!(parse_info(&bytes).is_none());
    }

    #[test]
    fn an_unknown_version_is_refused_rather_than_read_as_version_two() {
        for version in [0u64, 3, 0xFFFF_FFFF_FFFF_FFFF] {
            let mut bytes = v2(1, REAL_FILETIME, "C:\\x\\y.exe");
            bytes[0..8].copy_from_slice(&version.to_le_bytes());
            assert!(parse_info(&bytes).is_none(), "version {version} must be refused");
        }
    }

    #[test]
    fn a_declared_length_the_buffer_does_not_hold_is_refused() {
        let mut bytes = v2(1, REAL_FILETIME, "C:\\x\\y.exe");
        let too_many = (bytes.len() as u32 - V2_HEADER as u32) / 2 + 1;
        bytes[24..28].copy_from_slice(&too_many.to_le_bytes());
        assert!(parse_info(&bytes).is_none());
    }

    #[test]
    fn an_enormous_declared_length_is_refused_without_allocating() {
        let mut bytes = v2(1, REAL_FILETIME, "C:\\x\\y.exe");
        for declared in [MAX_NAME_UNITS as u32 + 1, 0x4000_0000, 0xFFFF_FFFF] {
            bytes[24..28].copy_from_slice(&declared.to_le_bytes());
            assert!(parse_info(&bytes).is_none(), "{declared} units must be refused");
        }
    }

    #[test]
    fn a_declared_length_that_would_overflow_is_refused() {
        let mut bytes = v2(1, REAL_FILETIME, "C:\\x\\y.exe");
        bytes[24..28].copy_from_slice(&0x8000_0001u32.to_le_bytes());
        assert!(parse_info(&bytes).is_none());
    }

    #[test]
    fn a_zero_declared_length_is_refused() {
        let mut bytes = v2(1, REAL_FILETIME, "C:\\x\\y.exe");
        bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_info(&bytes).is_none());
    }

    #[test]
    fn a_truncated_header_is_refused_at_every_length() {
        let full = v2(1, REAL_FILETIME, "C:\\x\\y.exe");
        for n in 0..full.len() {
            let _ = parse_info(&full[..n]);
        }
        for n in 0..V2_HEADER {
            assert!(parse_info(&full[..n]).is_none(), "a {n}-byte stub must be refused");
        }
    }

    #[test]
    fn a_name_that_states_no_location_is_refused() {
        assert!(parse_info(&v2(1, REAL_FILETIME, "payload.exe")).is_none());
    }

    #[test]
    fn a_name_that_is_only_a_terminator_is_refused() {
        let mut out = Vec::new();
        out.extend_from_slice(&2u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&REAL_FILETIME.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        assert!(parse_info(&out).is_none());
    }

    #[test]
    fn control_characters_in_a_name_are_stripped() {
        let bytes = v2(1, REAL_FILETIME, "C:\\x\\pay\u{7}load\u{1b}[2J.exe");
        let f = parse_info(&bytes).expect("still a usable path");
        assert_eq!(f.original.raw(), "C:\\x\\payload[2J.exe");
    }

    #[test]
    fn an_unpaired_surrogate_does_not_fail_the_parse() {
        let mut out = Vec::new();
        out.extend_from_slice(&2u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&REAL_FILETIME.to_le_bytes());
        let units: Vec<u16> = "C:\\x\\a"
            .encode_utf16()
            .chain(std::iter::once(0xD800))
            .chain(".exe".encode_utf16())
            .chain(std::iter::once(0))
            .collect();
        out.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for u in &units {
            out.extend_from_slice(&u.to_le_bytes());
        }
        let f = parse_info(&out).expect("a lone surrogate must not lose the path");
        assert_eq!(f.original.raw(), "C:\\x\\a\u{FFFD}.exe");
    }

    #[test]
    fn a_zero_or_implausible_deletion_time_is_unknown_not_a_date() {
        assert!(parse_info(&v2(1, 0, "C:\\x\\y.exe")).unwrap().deleted.is_none());
        assert!(parse_info(&v2(1, 1, "C:\\x\\y.exe")).unwrap().deleted.is_none());
    }

    #[test]
    fn slack_after_the_declared_name_is_ignored() {
        let mut bytes = v2(99, REAL_FILETIME, "C:\\x\\y.exe");
        bytes.extend_from_slice(&[0xAB; 512]);
        let f = parse_info(&bytes).expect("slack must not refuse the stub");
        assert_eq!(f.original.raw(), "C:\\x\\y.exe");
        assert_eq!(f.original_size, 99);
    }

    #[test]
    fn the_data_file_name_is_the_stub_name_with_one_character_changed() {
        assert_eq!(data_file_name("$IK9C8D3.exe").as_deref(), Some("$RK9C8D3.exe"));
        assert_eq!(data_file_name("$IOQ6JGK").as_deref(), Some("$ROQ6JGK"));
        assert_eq!(data_file_name("$iK9c8D3.ExE").as_deref(), Some("$RK9c8D3.ExE"));
    }

    #[test]
    fn a_name_that_is_not_a_stubs_yields_no_data_file() {
        for name in ["$RK9C8D3.exe", "desktop.ini", "$", "$I", "I$K9C8D3.exe", ""] {
            assert!(data_file_name(name).is_none(), "{name} must not pair");
        }
    }

    #[test]
    fn a_stub_name_carrying_a_separator_yields_no_data_file() {
        for name in [
            "$I..\\..\\Windows\\System32\\config\\SAM",
            "$I../../etc/passwd",
            "$IC:\\Windows\\notepad.exe",
        ] {
            assert!(data_file_name(name).is_none(), "{name} must not pair");
        }
    }

    #[test]
    fn is_info_name_agrees_with_data_file_name() {
        for name in ["$IK9C8D3.exe", "$RK9C8D3.exe", "desktop.ini", "$I", "$IX"] {
            assert_eq!(is_info_name(name), data_file_name(name).is_some(), "{name}");
        }
    }

    #[test]
    fn the_observation_sits_at_the_original_path_and_carries_no_record() {
        let bytes = v2(4096, REAL_FILETIME, "C:\\Users\\bob\\AppData\\Roaming\\Vendor\\svc.exe");
        let observations = harvest("$IK9C8D3.exe", &bytes);
        assert_eq!(observations.len(), 1);
        let o = &observations[0];
        assert_eq!(o.source, ArtifactSource::RecycleBin);
        assert_eq!(
            o.path.as_ref().unwrap().key(),
            "\\users\\bob\\appdata\\roaming\\vendor\\svc.exe"
        );
        match o.kind {
            ObservationKind::FileDeleted { when, record, .. } => {
                assert!(when.is_some());
                assert_eq!(record, None);
            }
            ref other => panic!("expected FileDeleted, got {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_stub_yields_no_observation_rather_than_a_guess() {
        assert!(harvest("$IK9C8D3.exe", &[]).is_empty());
        assert!(harvest("$IK9C8D3.exe", &[0xFF; 40]).is_empty());
        assert!(harvest("$IK9C8D3.exe", REAL_DIRECTORY[..20].as_ref()).is_empty());
    }

    #[test]
    fn the_drive_letter_survives_on_the_path() {
        let f = parse_info(REAL_DIRECTORY).unwrap();
        assert_eq!(f.original.volume(), &mm_core::VolumeRef::Letter('e'));
        assert_eq!(f.original.key(), "\\cases");
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let len = (next() % 1200) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            let _ = parse_info(&bytes);
            let _ = harvest("$IABCDEF.exe", &bytes);
        }
        for _ in 0..2000 {
            let mut bytes = v2(next(), next(), "C:\\x\\y.exe");
            let len = (next() % 300) as usize;
            bytes.truncate(V2_HEADER.min(bytes.len()));
            bytes.extend((0..len).map(|_| (next() & 0xFF) as u8));
            let _ = parse_info(&bytes);
        }
    }
}
