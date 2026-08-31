use chrono::{DateTime, NaiveDateTime, Utc};
use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind};

use crate::Harvested;

pub const MAX_ROWS: usize = 200_000;

pub const MAX_ROW_CHARS: usize = 64 * 1024;

const MAX_FIELD_CHARS: usize = 256;

const APP_LAUNCH_COLUMNS: usize = 2;

const GENERAL_DB_COLUMNS: usize = 8;

const TIMESTAMP: &str = "%Y-%m-%d %H:%M:%S%.f";

#[derive(Debug, Default, Clone)]
pub struct Pca {
    pub observations: Harvested,
    pub rows: usize,
    pub unattributed: usize,
    pub malformed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub raw_path: String,
    pub when: Option<DateTime<Utc>>,
    pub kind_code: Option<u32>,
    pub product: Option<String>,
    pub company: Option<String>,
    pub version: Option<String>,
    pub program_id: Option<String>,
    pub reason: Option<String>,
}

pub fn harvest_app_launch(bytes: &[u8]) -> Pca {
    observe(parse_app_launch(bytes), None)
}

pub fn harvest_general_db(bytes: &[u8], profile: Option<&str>) -> Pca {
    observe(parse_general_db(bytes), profile)
}

pub fn parse_app_launch(bytes: &[u8]) -> Vec<Row> {
    rows(bytes, APP_LAUNCH_COLUMNS, |f| Row {
        raw_path: f[0].clone(),
        when: timestamp(&f[1]),
        kind_code: None,
        product: None,
        company: None,
        version: None,
        program_id: None,
        reason: None,
    })
}

pub fn parse_general_db(bytes: &[u8]) -> Vec<Row> {
    rows(bytes, GENERAL_DB_COLUMNS, |f| Row {
        raw_path: f[2].clone(),
        when: timestamp(&f[0]),
        kind_code: f[1].trim().parse().ok(),
        product: field(&f[3]),
        company: field(&f[4]),
        version: field(&f[5]),
        program_id: field(&f[6]),
        reason: field(&f[7]),
    })
}

fn observe(rows: Vec<Row>, profile: Option<&str>) -> Pca {
    let mut out = Pca { rows: rows.len(), ..Pca::default() };

    for row in rows {
        match place(&row.raw_path, profile) {
            Placed::At(path) => out.observations.push(Observation::about_path(
                ArtifactSource::Pca,
                path,
                ObservationKind::Executed { when: row.when, run_count: None },
            )),
            Placed::Unattributed => out.unattributed += 1,
            Placed::Unusable => out.malformed += 1,
        }
    }

    out
}

enum Placed {
    At(NormalizedPath),
    Unattributed,
    Unusable,
}

fn place(raw: &str, profile: Option<&str>) -> Placed {
    let raw = raw.trim();
    if raw.is_empty() {
        return Placed::Unusable;
    }

    if raw.starts_with("\\\\") {
        return Placed::Unusable;
    }

    let lowered = raw.to_ascii_lowercase();
    let mut expanded = raw.to_string();
    let mut needed_a_profile = false;

    for (token, suffix) in [
        ("%localappdata%", "\\AppData\\Local"),
        ("%appdata%", "\\AppData\\Roaming"),
        ("%userprofile%", ""),
    ] {
        if !lowered.contains(token) {
            continue;
        }
        needed_a_profile = true;
        let Some(home) = profile else {
            return Placed::Unattributed;
        };
        expanded = replace_ignore_ascii_case(
            &expanded,
            token,
            &format!("{}{suffix}", home.trim_end_matches('\\')),
        );
    }

    let Some(path) = NormalizedPath::parse(&expanded) else {
        return Placed::Unusable;
    };

    if path.key().contains('%') {
        return if needed_a_profile { Placed::Unattributed } else { Placed::Unusable };
    }

    if !path.is_located() {
        return Placed::Unusable;
    }

    Placed::At(path)
}

fn rows<F>(bytes: &[u8], columns: usize, build: F) -> Vec<Row>
where
    F: Fn(&[String]) -> Row,
{
    let text = decode(bytes);
    let mut out = Vec::new();
    let mut fields: Vec<String> = Vec::with_capacity(columns);

    for line in text.lines() {
        if out.len() >= MAX_ROWS {
            break;
        }
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.chars().take(MAX_ROW_CHARS + 1).count() > MAX_ROW_CHARS {
            continue;
        }

        fields.clear();
        for part in line.splitn(columns, '|') {
            fields.push(sanitize(part));
        }
        if fields.len() != columns {
            continue;
        }
        out.push(build(&fields));
    }

    out
}

fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16le(rest);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return String::new();
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if looks_like_utf16le(bytes) {
        return utf16le(bytes);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn looks_like_utf16le(bytes: &[u8]) -> bool {
    const SAMPLE: usize = 512;
    let head = &bytes[..bytes.len().min(SAMPLE)];
    if head.len() < 4 {
        return false;
    }
    let odd = head.iter().skip(1).step_by(2);
    let total = odd.clone().count();
    let zeroes = odd.filter(|b| **b == 0).count();
    total > 0 && zeroes * 10 >= total * 9
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> =
        bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes).collect();
    String::from_utf16_lossy(&units)
}

fn timestamp(raw: &str) -> Option<DateTime<Utc>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    NaiveDateTime::parse_from_str(raw, TIMESTAMP).ok().map(|t| t.and_utc())
}

fn field(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut cut: String = trimmed.chars().take(MAX_FIELD_CHARS + 1).collect();
    if cut.chars().count() > MAX_FIELD_CHARS {
        cut = cut.chars().take(MAX_FIELD_CHARS).collect();
        return Some(format!("{cut}… (truncated)"));
    }
    Some(cut)
}

fn sanitize(value: &str) -> String {
    const BIDI: &[char] = &[
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}', '\u{200E}', '\u{200F}',
    ];
    value
        .chars()
        .filter(|c| !c.is_control() && !BIDI.contains(c))
        .collect::<String>()
        .trim()
        .to_string()
}

fn replace_ignore_ascii_case(haystack: &str, needle_lower: &str, replacement: &str) -> String {
    let lower = haystack.to_ascii_lowercase();
    if !lower.contains(needle_lower) {
        return haystack.to_string();
    }
    let mut out = String::with_capacity(haystack.len());
    let mut at = 0;
    while let Some(found) = lower[at..].find(needle_lower) {
        let start = at + found;
        out.push_str(&haystack[at..start]);
        out.push_str(replacement);
        at = start + needle_lower.len();
    }
    out.push_str(&haystack[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_LAUNCH: &[u8] = include_bytes!("../fixtures/pca/PcaAppLaunchDic.txt");
    const GENERAL_DB: &[u8] = include_bytes!("../fixtures/pca/PcaGeneralDb0.txt");

    const PROFILE: &str = "\\Users\\analyst";

    #[test]
    fn the_general_database_fixture_really_has_no_byte_order_mark() {
        assert_ne!(&GENERAL_DB[..2], &[0xFF, 0xFE], "fixture gained a BOM; it must not have one");
        assert_eq!(&GENERAL_DB[..2], &[b'2', 0x00]);
    }

    #[test]
    fn the_launch_dictionary_parses_every_row() {
        let out = harvest_app_launch(APP_LAUNCH);
        assert_eq!(out.rows, 24);
        assert_eq!(out.malformed, 0);
        assert_eq!(out.unattributed, 0);
        assert_eq!(out.observations.len(), 24);
    }

    #[test]
    fn a_launch_dictionary_row_becomes_an_execution_at_its_path() {
        let out = harvest_app_launch(APP_LAUNCH);
        let found = out
            .observations
            .iter()
            .find(|o| o.path.as_ref().is_some_and(|p| p.key().ends_with("webviewhost.exe")))
            .expect("the first row names WebViewHost.exe");
        assert_eq!(found.source, ArtifactSource::Pca);
        let ObservationKind::Executed { when, run_count } = &found.kind else {
            panic!("PCA states execution and nothing else, got {:?}", found.kind);
        };
        assert_eq!(run_count, &None, "PCA counts nothing; a count would be invented");
        assert_eq!(when.unwrap().to_string(), "2026-01-05 09:14:02.115 UTC");
    }

    #[test]
    fn timestamps_are_read_as_utc() {
        assert_eq!(
            timestamp("2026-01-12 16:31:53.308").unwrap().to_string(),
            "2026-01-12 16:31:53.308 UTC"
        );
    }

    #[test]
    fn a_row_whose_timestamp_is_unreadable_keeps_its_path_and_loses_the_time() {
        let out = harvest_app_launch(b"C:\\Windows\\Temp\\server.exe|not a timestamp\r\n");
        assert_eq!(out.observations.len(), 1);
        assert!(
            matches!(
                out.observations[0].kind,
                ObservationKind::Executed { when: None, run_count: None }
            ),
            "the fact of execution survives a bad clock; a guessed moment must not"
        );
    }

    #[test]
    fn the_general_database_parses_utf16_without_a_bom() {
        let out = harvest_general_db(GENERAL_DB, Some(PROFILE));
        assert_eq!(out.rows, 22);
        assert_eq!(out.malformed, 2);
        assert_eq!(out.unattributed, 0);
        assert_eq!(out.observations.len(), 20);
    }

    #[test]
    fn the_general_databases_identity_columns_are_carried() {
        let rows = parse_general_db(GENERAL_DB);
        let row = rows
            .iter()
            .find(|r| r.raw_path.to_ascii_lowercase().ends_with("vendorbrowser.exe"))
            .expect("the browser row is in the fixture");
        assert_eq!(row.product.as_deref(), Some("vendor browser"));
        assert_eq!(row.company.as_deref(), Some("vendor software ab"));
        assert_eq!(row.version.as_deref(), Some("128.13.0"));
        assert_eq!(row.program_id.as_deref(), Some("0006b13f2ff234dfa038124f4963db00a5ce00000000"));
        assert_eq!(row.kind_code, Some(2));
        assert_eq!(row.reason.as_deref(), Some("Abnormal process exit with code 0x1"));
    }

    #[test]
    fn a_user_profile_row_expands_when_one_profile_can_be_named() {
        let out = harvest_general_db(GENERAL_DB, Some(PROFILE));
        assert!(
            out.observations.iter().any(|o| o
                .path
                .as_ref()
                .is_some_and(|p| p.key().starts_with("\\users\\analyst\\appdata"))),
            "with the profile in hand the token resolves to a real key"
        );
    }

    #[test]
    fn a_user_profile_row_is_dropped_when_no_single_profile_can_be_named() {
        let out = harvest_general_db(GENERAL_DB, None);
        assert!(out.unattributed > 0, "the fixture carries %USERPROFILE% rows");
        assert!(
            !out.observations
                .iter()
                .filter_map(|o| o.path.as_ref())
                .any(|p| p.key().contains("vendorbrowser")),
            "an unattributable row must produce no path at all"
        );
    }

    #[test]
    fn no_observation_ever_carries_an_unexpanded_environment_token() {
        let both =
            [harvest_general_db(GENERAL_DB, Some(PROFILE)), harvest_general_db(GENERAL_DB, None)];
        for out in &both {
            for o in &out.observations {
                let key = o.path.as_ref().unwrap().key();
                assert!(!key.contains('%'), "`{key}` still carries a token");
            }
        }
    }

    #[test]
    fn the_machine_fixed_tokens_resolve_without_any_profile() {
        let out = harvest_general_db(GENERAL_DB, None);
        assert!(
            out.observations
                .iter()
                .filter_map(|o| o.path.as_ref())
                .any(|p| p.key().starts_with("\\program files")),
            "%programfiles% is fixed on every install and needs no profile"
        );
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn a_row_with_the_wrong_column_count_is_refused_rather_than_padded() {
        let out = harvest_general_db(&utf16("2025-01-01 00:00:00.000|2|C:\\a.exe|p|c|v\r\n"), None);
        assert_eq!(out.observations.len(), 0);
        assert_eq!(out.rows, 0);
    }

    #[test]
    fn a_pipe_inside_the_last_column_does_not_discard_the_row() {
        let rows = parse_general_db(&utf16(
            "2025-01-01 00:00:00.000|2|C:\\a.exe|p|c|v|id|exit code 0x1 | retried\r\n",
        ));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason.as_deref(), Some("exit code 0x1 | retried"));
    }

    #[test]
    fn control_characters_cannot_forge_a_line_of_report_output() {
        let out = harvest_app_launch(b"C:\\a\x1b[31m.exe|2025-01-01 00:00:00.000\r\n");
        assert_eq!(out.observations.len(), 1);
        for o in &out.observations {
            let raw = o.path.as_ref().unwrap().raw();
            assert!(!raw.chars().any(char::is_control), "`{raw}` carries a control character");
        }
    }

    #[test]
    fn a_bidirectional_override_is_stripped() {
        let out =
            harvest_app_launch("C:\\Temp\\\u{202E}exe.txt|2025-01-01 00:00:00.000\r\n".as_bytes());
        let raw = out.observations[0].path.as_ref().unwrap().raw();
        assert!(!raw.contains('\u{202E}'));
    }

    #[test]
    fn an_over_long_row_is_skipped_rather_than_truncated_into_a_different_file() {
        let mut line = String::from("C:\\");
        line.push_str(&"a".repeat(MAX_ROW_CHARS + 10));
        line.push_str(".exe|2025-01-01 00:00:00.000\r\n");
        let out = harvest_app_launch(line.as_bytes());
        assert_eq!(out.rows, 0, "a truncated path names a different file");
    }

    #[test]
    fn the_row_count_is_capped() {
        let many = "C:\\a.exe|2025-01-01 00:00:00.000\r\n".repeat(MAX_ROWS + 50);
        let out = harvest_app_launch(many.as_bytes());
        assert_eq!(out.rows, MAX_ROWS);
    }

    #[test]
    fn a_utf16_file_of_odd_length_does_not_panic() {
        let mut bytes = utf16("2025-01-01 00:00:00.000|2|C:\\a.exe|p|c|v|id|r\r\n");
        bytes.push(0x00);
        let _ = harvest_general_db(&bytes, None);
    }

    #[test]
    fn empty_and_garbage_input_yield_nothing_and_never_fail() {
        for bytes in [
            b"".as_slice(),
            b"\x00\x00\x00\x00".as_slice(),
            b"|||||||".as_slice(),
            &[0xFF, 0xFE],
            &[0xFE, 0xFF, 0x00, 0x41],
            &[0xFF; 64],
        ] {
            let _ = harvest_app_launch(bytes);
            let _ = harvest_general_db(bytes, Some(PROFILE));
        }
    }

    #[test]
    fn a_unc_path_is_refused_rather_than_flattened_onto_this_volume() {
        let out = harvest_app_launch(b"\\\\server\\share\\a.exe|2025-01-01 00:00:00.000\r\n");
        assert_eq!(out.observations.len(), 0);
        assert_eq!(out.malformed, 1);
    }

    #[test]
    fn a_non_ascii_path_does_not_panic_the_token_replacement() {
        let out = harvest_general_db(
            &utf16("2025-01-01 00:00:00.000|2|%USERPROFILE%\\Отчёт\\İstanbul.exe|p|c|v|id|r\r\n"),
            Some("\\Users\\Ямал"),
        );
        assert_eq!(out.observations.len(), 1);
    }

    #[test]
    fn pca_corroborates_within_the_execution_family_and_not_beside_it() {
        assert_eq!(ArtifactSource::Pca.family(), "execution");
        assert_eq!(ArtifactSource::Pca.family(), ArtifactSource::ShimCache.family());
        assert_eq!(ArtifactSource::Pca.family(), ArtifactSource::Amcache.family());
    }
}
