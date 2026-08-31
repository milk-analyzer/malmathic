use mm_core::{from_filetime, ArtifactSource, NormalizedPath, Observation, ObservationKind};

use crate::Harvested;

const HEADER_SIZE: usize = 84;
const SCCA_SIGNATURE: &[u8] = b"SCCA";
const NAME_OFFSET: usize = 16;
const NAME_SIZE: usize = 60;

struct Layout {
    run_times: usize,
    run_time_count: usize,
    run_count: usize,
}

pub fn harvest(bytes: &[u8], file_name: &str) -> Harvested {
    let decompressed;
    let scca: &[u8] = if bytes.starts_with(b"MAM") {
        match xpress::decompress_mam(bytes) {
            Some(v) => {
                decompressed = v;
                &decompressed
            }
            None => return Vec::new(),
        }
    } else {
        bytes
    };

    parse_scca(scca, file_name)
}

fn parse_scca(scca: &[u8], file_name: &str) -> Harvested {
    if scca.get(4..8) != Some(SCCA_SIGNATURE) {
        return Vec::new();
    }
    let version = match read_u32(scca, 0) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let (name, name_was_truncated) = executable_name(scca, file_name);
    if name.is_empty() {
        return Vec::new();
    }

    let path = resolve_path(scca, &name, name_was_truncated);

    let layout = match layout_for(version, scca) {
        Some(l) => l,
        None => {
            return match path {
                Some(p) => vec![executed(p, None, None)],
                None => Vec::new(),
            };
        }
    };

    let path = match path {
        Some(p) => p,
        None => return Vec::new(),
    };

    let run_count = read_u32(scca, HEADER_SIZE.saturating_add(layout.run_count));

    let mut out = Vec::new();
    for slot in 0..layout.run_time_count {
        let at =
            HEADER_SIZE.saturating_add(layout.run_times).saturating_add(slot.saturating_mul(8));
        let Some(ticks) = read_u64(scca, at) else { break };
        if let Some(when) = from_filetime(ticks) {
            out.push(executed(path.clone(), Some(when), run_count));
        }
    }

    if out.is_empty() {
        out.push(executed(path, None, run_count));
    }
    out
}

fn executed(
    path: NormalizedPath,
    when: Option<chrono::DateTime<chrono::Utc>>,
    run_count: Option<u32>,
) -> Observation {
    Observation::about_path(
        ArtifactSource::Prefetch,
        path,
        ObservationKind::Executed { when, run_count },
    )
}

fn layout_for(version: u32, scca: &[u8]) -> Option<Layout> {
    match version {
        17 => Some(Layout { run_times: 36, run_time_count: 1, run_count: 60 }),
        23 => Some(Layout { run_times: 44, run_time_count: 1, run_count: 68 }),
        26 => Some(Layout { run_times: 44, run_time_count: 8, run_count: 124 }),
        30 | 31 => {
            let metrics_offset = read_u32(scca, HEADER_SIZE);
            let run_count = match metrics_offset {
                Some(304) => 124,
                Some(296) => 116,
                _ => match read_u32(scca, HEADER_SIZE + 120) {
                    Some(0) => 124,
                    Some(_) => 116,
                    None => 124,
                },
            };
            Some(Layout { run_times: 44, run_time_count: 8, run_count })
        }
        _ => None,
    }
}

fn executable_name(scca: &[u8], file_name: &str) -> (String, bool) {
    if let Some(field) = scca.get(NAME_OFFSET..NAME_OFFSET + NAME_SIZE) {
        let units = utf16_units(field);
        let terminated = units.contains(&0);
        let name = decode_utf16_until_nul(&units);
        let name = name.trim().to_string();
        if !name.is_empty() {
            let maybe_truncated = !terminated || name.chars().count() >= 29;
            return (name, maybe_truncated);
        }
    }
    (name_from_pf_file_name(file_name), true)
}

fn name_from_pf_file_name(file_name: &str) -> String {
    let base = file_name.rsplit(['\\', '/']).next().unwrap_or(file_name).trim();
    let stem = match base.len().checked_sub(3) {
        Some(cut) if base.get(cut..).is_some_and(|e| e.eq_ignore_ascii_case(".pf")) => &base[..cut],
        _ => base,
    };
    if let Some(cut) = stem.rfind('-') {
        let tail = &stem[cut + 1..];
        if tail.len() == 8 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
            return stem[..cut].to_string();
        }
    }
    stem.to_string()
}

fn resolve_path(scca: &[u8], name: &str, name_was_truncated: bool) -> Option<NormalizedPath> {
    if let Some(full) = full_path_from_strings(scca, name, name_was_truncated) {
        if let Some(p) = NormalizedPath::parse(&full) {
            return Some(p);
        }
    }
    NormalizedPath::unlocated(name)
}

fn full_path_from_strings(scca: &[u8], name: &str, allow_prefix: bool) -> Option<String> {
    let offset = read_u32(scca, HEADER_SIZE + 16)? as usize;
    let size = read_u32(scca, HEADER_SIZE + 20)? as usize;
    if size < 2 {
        return None;
    }
    let end = offset.checked_add(size)?;
    let end = end.min(scca.len());
    let section = scca.get(offset..end)?;

    let units = utf16_units(section);
    let lower = name.to_ascii_lowercase();
    let mut prefix_hit: Option<String> = None;

    for run in units.split(|&u| u == 0) {
        if run.is_empty() {
            continue;
        }
        let s = String::from_utf16_lossy(run);
        let base = s.rsplit('\\').next().unwrap_or(&s).to_ascii_lowercase();
        if base == lower {
            return Some(s);
        }
        if allow_prefix && prefix_hit.is_none() && !lower.is_empty() && base.starts_with(&lower) {
            prefix_hit = Some(s);
        }
    }
    prefix_hit
}

fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes.as_chunks::<2>().0.iter().copied().map(u16::from_le_bytes).collect()
}

fn decode_utf16_until_nul(units: &[u16]) -> String {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let s = bytes.get(at..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let s = bytes.get(at..end)?;
    Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

use mm_core::xpress;

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH_DELTA_SECS: i64 = 11_644_473_600;

    fn filetime(unix_secs: i64) -> u64 {
        ((unix_secs + EPOCH_DELTA_SECS) * 10_000_000) as u64
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    fn info_size(version: u32, short_variant: bool) -> usize {
        match version {
            17 => 68,
            23 => 156,
            26 => 220,
            _ if short_variant => 212,
            _ => 220,
        }
    }

    fn build_scca(
        version: u32,
        exe: &str,
        times: &[u64],
        run_count: u32,
        paths: &[&str],
        short_variant: bool,
    ) -> Vec<u8> {
        let info = info_size(version, short_variant);
        let strings_offset = HEADER_SIZE + info;

        let mut strings = Vec::new();
        for p in paths {
            strings.extend_from_slice(&utf16(p));
            strings.extend_from_slice(&[0, 0]);
        }

        let mut buf = vec![0u8; HEADER_SIZE + info];
        buf[0..4].copy_from_slice(&version.to_le_bytes());
        buf[4..8].copy_from_slice(SCCA_SIGNATURE);
        buf[8..12].copy_from_slice(&0x11u32.to_le_bytes());
        let name = utf16(exe);
        let n = name.len().min(NAME_SIZE);
        buf[NAME_OFFSET..NAME_OFFSET + n].copy_from_slice(&name[..n]);

        let (time_at, count_at) = match version {
            17 => (36, 60),
            23 => (44, 68),
            26 => (44, 124),
            _ if short_variant => (44, 116),
            _ => (44, 124),
        };
        buf[HEADER_SIZE..HEADER_SIZE + 4]
            .copy_from_slice(&((HEADER_SIZE + info) as u32).to_le_bytes());
        buf[HEADER_SIZE + 16..HEADER_SIZE + 20]
            .copy_from_slice(&(strings_offset as u32).to_le_bytes());
        buf[HEADER_SIZE + 20..HEADER_SIZE + 24]
            .copy_from_slice(&(strings.len() as u32).to_le_bytes());
        for (i, t) in times.iter().enumerate() {
            let at = HEADER_SIZE + time_at + i * 8;
            buf[at..at + 8].copy_from_slice(&t.to_le_bytes());
        }
        let at = HEADER_SIZE + count_at;
        buf[at..at + 4].copy_from_slice(&run_count.to_le_bytes());

        buf.extend_from_slice(&strings);
        let total = buf.len() as u32;
        buf[12..16].copy_from_slice(&total.to_le_bytes());
        buf
    }

    fn keys(obs: &[Observation]) -> Vec<String> {
        obs.iter().filter_map(|o| o.path.as_ref()).map(|p| p.key().to_string()).collect()
    }

    #[test]
    fn version_23_reports_its_single_run() {
        let pf = build_scca(
            23,
            "NOTEPAD.EXE",
            &[filetime(1_704_067_200)],
            9,
            &["\\VOLUME{01d7a1b2c3d4e5f6}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"],
            false,
        );
        let obs = harvest(&pf, "NOTEPAD.EXE-D8414F97.pf");
        assert_eq!(obs.len(), 1);
        assert_eq!(keys(&obs), vec!["\\windows\\system32\\notepad.exe"]);
        match &obs[0].kind {
            ObservationKind::Executed { when, run_count } => {
                assert_eq!(*run_count, Some(9));
                assert_eq!(when.unwrap().timestamp(), 1_704_067_200);
            }
            other => panic!("expected Executed, got {other:?}"),
        }
        assert!(matches!(obs[0].source, ArtifactSource::Prefetch));
    }

    #[test]
    fn version_17_reads_its_own_offsets() {
        let pf = build_scca(
            17,
            "CMD.EXE",
            &[filetime(1_600_000_000)],
            3,
            &["\\DEVICE\\HARDDISKVOLUME1\\WINDOWS\\SYSTEM32\\CMD.EXE"],
            false,
        );
        let obs = harvest(&pf, "CMD.EXE-4A81B364.pf");
        assert_eq!(obs.len(), 1);
        assert_eq!(keys(&obs), vec!["\\windows\\system32\\cmd.exe"]);
        match &obs[0].kind {
            ObservationKind::Executed { when, run_count } => {
                assert_eq!(*run_count, Some(3));
                assert_eq!(when.unwrap().timestamp(), 1_600_000_000);
            }
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn eight_run_time_versions_emit_one_observation_per_used_slot() {
        for (version, short) in [(26u32, false), (30, false), (30, true), (31, true)] {
            let mut times = [0u64; 8];
            times[0] = filetime(1_704_067_200);
            times[1] = filetime(1_704_000_000);
            times[2] = filetime(1_703_000_000);
            let pf = build_scca(
                version,
                "EVIL.EXE",
                &times,
                42,
                &["\\VOLUME{01d}\\USERS\\BOB\\APPDATA\\ROAMING\\EVIL.EXE"],
                short,
            );
            let obs = harvest(&pf, "EVIL.EXE-AABBCCDD.pf");
            assert_eq!(obs.len(), 3, "version {version} short={short}");
            for o in &obs {
                assert_eq!(
                    o.path.as_ref().unwrap().key(),
                    "\\users\\bob\\appdata\\roaming\\evil.exe"
                );
                match &o.kind {
                    ObservationKind::Executed { run_count, .. } => assert_eq!(*run_count, Some(42)),
                    other => panic!("expected Executed, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn version_30_variants_are_told_apart() {
        let times = [filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0];
        for short in [false, true] {
            let pf = build_scca(30, "A.EXE", &times, 7, &["C:\\TMP\\A.EXE"], short);
            let obs = harvest(&pf, "A.EXE-11223344.pf");
            assert_eq!(obs.len(), 1);
            match &obs[0].kind {
                ObservationKind::Executed { run_count, .. } => {
                    assert_eq!(*run_count, Some(7), "short={short}")
                }
                other => panic!("expected Executed, got {other:?}"),
            }
        }
    }

    #[test]
    fn corrupt_metrics_offset_falls_back_to_the_probe() {
        for (short, expected) in [(false, 7u32), (true, 7)] {
            let times = [filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0];
            let mut pf = build_scca(30, "A.EXE", &times, expected, &["C:\\TMP\\A.EXE"], short);
            if short {
                pf[HEADER_SIZE + 120..HEADER_SIZE + 124].copy_from_slice(&1u32.to_le_bytes());
            }
            pf[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
            let obs = harvest(&pf, "A.EXE-11223344.pf");
            match &obs[0].kind {
                ObservationKind::Executed { run_count, .. } => {
                    assert_eq!(*run_count, Some(expected), "short={short}")
                }
                other => panic!("expected Executed, got {other:?}"),
            }
        }
    }

    #[test]
    fn full_path_is_preferred_over_the_bare_name() {
        let pf = build_scca(
            26,
            "SVCHOST.EXE",
            &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0],
            1,
            &[
                "\\VOLUME{01d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                "\\VOLUME{01d}\\USERS\\BOB\\APPDATA\\SVCHOST.EXE",
                "\\VOLUME{01d}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
            ],
            false,
        );
        let obs = harvest(&pf, "SVCHOST.EXE-DEADBEEF.pf");
        assert_eq!(keys(&obs), vec!["\\users\\bob\\appdata\\svchost.exe"]);
    }

    #[test]
    fn missing_strings_section_falls_back_to_the_header_name() {
        let pf = build_scca(
            26,
            "MALWARE.EXE",
            &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0],
            1,
            &["\\VOLUME{01d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL"],
            false,
        );
        let obs = harvest(&pf, "MALWARE.EXE-00000001.pf");
        assert_eq!(keys(&obs), vec!["\\malware.exe"]);
    }

    #[test]
    fn truncated_header_name_still_matches_the_full_path() {
        let long = "AVERYLONGEXECUTABLENAMEINDEED.EXE";
        let truncated: String = long.chars().take(30).collect();
        let pf = build_scca(
            26,
            &truncated,
            &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0],
            1,
            &[&format!("\\VOLUME{{01d}}\\TEMP\\{long}")],
            false,
        );
        let obs = harvest(&pf, "AVERYLONGEXECUTABLENAMEINDEED.-1234ABCD.pf");
        assert_eq!(keys(&obs), vec![format!("\\temp\\{}", long.to_ascii_lowercase())]);
    }

    #[test]
    fn blank_header_name_recovers_from_the_pf_file_name() {
        let mut pf = build_scca(23, "PLACEHOLDER.EXE", &[filetime(1_704_067_200)], 1, &[], false);
        for b in &mut pf[NAME_OFFSET..NAME_OFFSET + NAME_SIZE] {
            *b = 0;
        }
        let obs = harvest(&pf, "RUNDLL32.EXE-1AC14E77.pf");
        assert_eq!(keys(&obs), vec!["\\rundll32.exe"]);
    }

    #[test]
    fn zeroed_timestamps_still_prove_the_program_ran() {
        let pf = build_scca(26, "X.EXE", &[0; 8], 5, &["C:\\X.EXE"], false);
        let obs = harvest(&pf, "X.EXE-00000000.pf");
        assert_eq!(obs.len(), 1);
        match &obs[0].kind {
            ObservationKind::Executed { when, run_count } => {
                assert!(when.is_none());
                assert_eq!(*run_count, Some(5));
            }
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    #[test]
    fn zero_length_and_tiny_buffers_are_survivable() {
        assert!(harvest(&[], "X.EXE-1.pf").is_empty());
        assert!(harvest(&[0], "X.EXE-1.pf").is_empty());
        assert!(harvest(b"MAM", "X.EXE-1.pf").is_empty());
        assert!(harvest(b"MAM\x04", "X.EXE-1.pf").is_empty());
        assert!(harvest(b"SCCA", "X.EXE-1.pf").is_empty());
        for n in 0..200usize {
            let _ = harvest(&vec![0x41u8; n], "X.EXE-1.pf");
        }
    }

    #[test]
    fn a_truncated_prefetch_file_never_panics() {
        let pf = build_scca(
            26,
            "TRUNC.EXE",
            &[filetime(1_704_067_200); 8],
            2,
            &["C:\\TEMP\\TRUNC.EXE"],
            false,
        );
        for cut in 0..pf.len() {
            let _ = harvest(&pf[..cut], "TRUNC.EXE-ABCDEF12.pf");
        }
        let obs = harvest(&pf[..HEADER_SIZE + 40], "TRUNC.EXE-ABCDEF12.pf");
        assert_eq!(obs.len(), 1);
        assert!(matches!(obs[0].kind, ObservationKind::Executed { when: None, .. }));
    }

    #[test]
    fn absurd_offsets_and_sizes_are_rejected_not_followed() {
        let mut pf = build_scca(
            26,
            "EVIL.EXE",
            &[filetime(1_704_067_200); 8],
            1,
            &["C:\\TEMP\\EVIL.EXE"],
            false,
        );
        pf[HEADER_SIZE + 16..HEADER_SIZE + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        pf[HEADER_SIZE + 20..HEADER_SIZE + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        let obs = harvest(&pf, "EVIL.EXE-11111111.pf");
        assert_eq!(keys(&obs), vec!["\\evil.exe"; 8]);

        let mut pf =
            build_scca(26, "E.EXE", &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0], 0, &[], false);
        pf[HEADER_SIZE + 124..HEADER_SIZE + 128].copy_from_slice(&u32::MAX.to_le_bytes());
        let obs = harvest(&pf, "E.EXE-22222222.pf");
        assert!(matches!(obs[0].kind, ObservationKind::Executed { run_count: Some(u32::MAX), .. }));
    }

    #[test]
    fn an_unknown_format_version_still_yields_the_execution_fact() {
        let mut pf = build_scca(
            26,
            "FUTURE.EXE",
            &[filetime(1_704_067_200); 8],
            1,
            &["C:\\F\\FUTURE.EXE"],
            false,
        );
        pf[0..4].copy_from_slice(&99u32.to_le_bytes());
        let obs = harvest(&pf, "FUTURE.EXE-33333333.pf");
        assert_eq!(obs.len(), 1);
        assert_eq!(keys(&obs), vec!["\\f\\future.exe"]);
        assert!(matches!(obs[0].kind, ObservationKind::Executed { when: None, run_count: None }));
    }

    #[test]
    fn a_missing_scca_signature_is_not_parsed() {
        let mut pf =
            build_scca(26, "X.EXE", &[filetime(1_704_067_200); 8], 1, &["C:\\X.EXE"], false);
        pf[4..8].copy_from_slice(b"XXXX");
        assert!(harvest(&pf, "X.EXE-44444444.pf").is_empty());
    }

    #[test]
    fn timestamps_outside_the_plausible_window_are_dropped() {
        let mut times = [0u64; 8];
        times[0] = 1;
        times[1] = u64::MAX;
        times[2] = filetime(1_704_067_200);
        let pf = build_scca(26, "T.EXE", &times, 1, &["C:\\T.EXE"], false);
        let obs = harvest(&pf, "T.EXE-55555555.pf");
        assert_eq!(obs.len(), 1);
    }

    fn code_lengths(pairs: &[(usize, u8)]) -> Vec<u8> {
        let mut table = vec![0u8; 256];
        for &(symbol, len) in pairs {
            let byte = symbol / 2;
            if symbol % 2 == 0 {
                table[byte] |= len & 0x0f;
            } else {
                table[byte] |= (len & 0x0f) << 4;
            }
        }
        table
    }

    fn bitstream(bits: &str) -> Vec<u8> {
        let mut words: Vec<u16> = Vec::new();
        let mut acc: u16 = 0;
        let mut n = 0;
        for c in bits.chars().filter(|c| *c == '0' || *c == '1') {
            acc = (acc << 1) | u16::from(c == '1');
            n += 1;
            if n == 16 {
                words.push(acc);
                acc = 0;
                n = 0;
            }
        }
        if n > 0 {
            words.push(acc << (16 - n));
        }
        words.push(0);
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn mam(payload: &[u8], uncompressed_size: u32) -> Vec<u8> {
        let mut out = vec![0x4d, 0x41, 0x4d, 0x04];
        out.extend_from_slice(&uncompressed_size.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn xpress_decodes_literals() {
        let table = code_lengths(&[(b'A' as usize, 1), (b'B' as usize, 1)]);
        let mut payload = table;
        payload.extend_from_slice(&bitstream("01010101"));
        assert_eq!(xpress::decompress(&payload, 8), b"ABABABAB");
    }

    #[test]
    fn xpress_decodes_a_back_reference() {
        let table = code_lengths(&[(b'A' as usize, 2), (b'B' as usize, 2), (275, 1)]);
        let mut payload = table;
        payload.extend_from_slice(&bitstream("10 11 0 0"));
        assert_eq!(xpress::decompress(&payload, 8), b"ABABABAB");
    }

    #[test]
    fn xpress_rejects_a_reference_before_the_output_start() {
        let table = code_lengths(&[(b'A' as usize, 2), (b'B' as usize, 2), (275, 1)]);
        let mut payload = table;
        payload.extend_from_slice(&bitstream("0 0"));
        assert!(xpress::decompress(&payload, 8).is_empty());
    }

    #[test]
    fn xpress_survives_truncation_at_every_length() {
        let table = code_lengths(&[(b'A' as usize, 1), (b'B' as usize, 1)]);
        let mut payload = table;
        payload.extend_from_slice(&bitstream("01010101"));
        for cut in 0..payload.len() {
            let _ = xpress::decompress(&payload[..cut], 8);
        }
        for cut in 0..payload.len() {
            let _ = xpress::decompress(&payload[..cut], usize::MAX / 2);
        }
    }

    #[test]
    fn xpress_handles_a_degenerate_code_table() {
        let payload = vec![0u8; 512];
        assert!(xpress::decompress(&payload, 4096).is_empty());
        let payload = vec![0x11u8; 512];
        assert!(xpress::decompress(&payload, 4096).is_empty());
    }

    #[test]
    fn a_compressed_prefetch_file_round_trips() {
        let pf = build_scca(
            30,
            "NOTEPAD.EXE",
            &[filetime(1_704_067_200), filetime(1_703_000_000), 0, 0, 0, 0, 0, 0],
            4,
            &["\\VOLUME{01d7a1}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE"],
            true,
        );
        let compressed = literal_only_stream(&pf);
        let container = mam(&compressed, pf.len() as u32);
        assert_eq!(xpress::decompress_mam(&container).unwrap(), pf);

        let obs = harvest(&container, "NOTEPAD.EXE-D8414F97.pf");
        assert_eq!(obs.len(), 2);
        assert_eq!(
            keys(&obs),
            vec!["\\windows\\system32\\notepad.exe", "\\windows\\system32\\notepad.exe"]
        );
        match &obs[0].kind {
            ObservationKind::Executed { run_count, when } => {
                assert_eq!(*run_count, Some(4));
                assert_eq!(when.unwrap().timestamp(), 1_704_067_200);
            }
            other => panic!("expected Executed, got {other:?}"),
        }
    }

    fn literal_only_stream(data: &[u8]) -> Vec<u8> {
        let pairs: Vec<(usize, u8)> = (0..256).map(|s| (s, 8u8)).collect();
        let mut out = code_lengths(&pairs);
        let bits: String = data.iter().map(|b| format!("{b:08b}")).collect();
        out.extend_from_slice(&bitstream(&bits));
        out
    }

    #[test]
    fn xpress_crosses_block_boundaries() {
        let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut payload = literal_only_stream(&data[..65_536]);
        payload.extend_from_slice(&literal_only_stream(&data[65_536..]));
        assert_eq!(xpress::decompress(&payload, data.len()), data);
    }

    #[test]
    fn xpress_crosses_a_block_boundary_mid_word() {
        let lengths = code_lengths(&[(b'A' as usize, 1), (b'B' as usize, 2), (b'C' as usize, 2)]);

        let mut first_bits = "0".repeat(65_535);
        first_bits.push_str("10");
        let mut payload = lengths.clone();
        payload.extend_from_slice(&bitstream(&first_bits));

        payload.extend_from_slice(&lengths);
        payload.extend_from_slice(&bitstream("0 10 11"));

        let mut expected = vec![b'A'; 65_535];
        expected.push(b'B');
        expected.extend_from_slice(b"ABC");

        assert_eq!(xpress::decompress(&payload, expected.len()), expected);
    }

    #[test]
    fn arbitrary_garbage_neither_panics_nor_hangs() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let valid = build_scca(
            30,
            "SEED.EXE",
            &[filetime(1_704_067_200); 8],
            3,
            &["\\VOLUME{01d}\\TEMP\\SEED.EXE"],
            true,
        );

        for _ in 0..2000 {
            let len = (next() % 600) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = harvest(&buf, "X.EXE-DEADBEEF.pf");
            let _ = xpress::decompress(&buf, 4096);

            let mut wrapped = vec![0x4d, 0x41, 0x4d, 0x04];
            wrapped.extend_from_slice(&((next() % 200_000) as u32).to_le_bytes());
            wrapped.append(&mut buf);
            let _ = harvest(&wrapped, "X.EXE-DEADBEEF.pf");
        }

        for _ in 0..3000 {
            let mut mutated = valid.clone();
            let at = (next() as usize) % mutated.len();
            mutated[at] = next() as u8;
            let _ = harvest(&mutated, "SEED.EXE-01020304.pf");
        }
    }

    #[test]
    fn mam_containers_are_validated_before_use() {
        let table = code_lengths(&[(b'A' as usize, 1), (b'B' as usize, 1)]);
        let mut payload = table;
        payload.extend_from_slice(&bitstream("01010101"));

        let mut bad = mam(&payload, 8);
        bad[3] = 0x03;
        assert!(xpress::decompress_mam(&bad).is_none());

        assert!(xpress::decompress_mam(&mam(&payload, 0)).is_none());

        let huge = mam(&payload, u32::MAX);
        let out = xpress::decompress_mam(&huge).unwrap();
        assert!(out.starts_with(b"ABABABAB"));
        assert!(out.len() < payload.len() * 8);

        assert!(xpress::decompress_mam(&mam(&[], 100)).unwrap().is_empty());
    }

    #[test]
    fn a_mam_file_that_will_not_decompress_yields_nothing() {
        let garbage = mam(&[0xffu8; 300], 4096);
        assert!(harvest(&garbage, "X.EXE-1.pf").is_empty());
    }

    #[test]
    fn pf_file_names_give_up_their_executable() {
        assert_eq!(name_from_pf_file_name("NOTEPAD.EXE-D8414F97.pf"), "NOTEPAD.EXE");
        assert_eq!(name_from_pf_file_name("notepad.exe-d8414f97.PF"), "notepad.exe");
        assert_eq!(name_from_pf_file_name("C:\\Windows\\Prefetch\\CMD.EXE-4A81B364.pf"), "CMD.EXE");
        assert_eq!(name_from_pf_file_name("WEIRD.pf"), "WEIRD");
        assert_eq!(name_from_pf_file_name("A-B.EXE-XYZ.pf"), "A-B.EXE-XYZ");
        assert_eq!(name_from_pf_file_name(""), "");
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            if n == 0 {
                0
            } else {
                (self.next() % n as u64) as usize
            }
        }
    }

    fn every_version() -> Vec<(String, Vec<u8>)> {
        let times = [filetime(1_704_067_200), filetime(1_703_000_000), 0, 0, 0, 0, 0, 0];
        let mut out = Vec::new();
        for (version, short) in
            [(17u32, false), (23, false), (26, false), (30, false), (30, true), (31, true)]
        {
            let t: &[u64] = if version == 17 || version == 23 { &times[..1] } else { &times };
            out.push((
                format!("v{version}{}", if short { "-short" } else { "" }),
                build_scca(
                    version,
                    "SAMPLE.EXE",
                    t,
                    11,
                    &[
                        "\\VOLUME{01d}\\WINDOWS\\SYSTEM32\\SAMPLE.EXE",
                        "\\VOLUME{01d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                    ],
                    short,
                ),
            ));
        }
        out
    }

    #[test]
    fn documented_block_sizes_produce_the_documented_metrics_offsets() {
        assert_eq!(HEADER_SIZE, 84);
        assert_eq!(HEADER_SIZE + info_size(17, false), 152);
        assert_eq!(HEADER_SIZE + info_size(23, false), 240);
        assert_eq!(HEADER_SIZE + info_size(26, false), 304);
        assert_eq!(HEADER_SIZE + info_size(30, false), 304);
        assert_eq!(HEADER_SIZE + info_size(30, true), 296);
        assert_eq!(HEADER_SIZE + info_size(31, true), 296);
    }

    #[test]
    fn truncation_at_every_offset_of_every_version() {
        for (label, pf) in every_version() {
            for cut in 0..=pf.len() {
                let obs = harvest(&pf[..cut], "SAMPLE.EXE-AABBCCDD.pf");
                for o in &obs {
                    let key = o.path.as_ref().unwrap().key().to_string();
                    assert!(
                        key == "\\windows\\system32\\sample.exe" || key == "\\sample.exe",
                        "{label} cut={cut} invented path {key}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_u32_field_driven_to_its_extremes() {
        let poison = [0u32, 1, u32::MAX, 0x8000_0000, 0x7fff_ffff, 0xffff_fffc, 304, 296, 84];
        for (label, pf) in every_version() {
            for at in (0..pf.len().min(320)).step_by(4) {
                if at + 4 > pf.len() {
                    break;
                }
                for value in poison {
                    let mut m = pf.clone();
                    m[at..at + 4].copy_from_slice(&value.to_le_bytes());
                    let obs = harvest(&m, "SAMPLE.EXE-AABBCCDD.pf");
                    for o in &obs {
                        assert!(o.path.is_some(), "{label} at={at} value={value:#x}");
                    }
                }
            }
        }
    }

    #[test]
    fn self_referential_and_backward_offsets_terminate() {
        let base = build_scca(
            26,
            "LOOP.EXE",
            &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0],
            1,
            &["C:\\TEMP\\LOOP.EXE"],
            false,
        );
        let cases: [(u32, u32); 10] = [
            (HEADER_SIZE as u32 + 16, 8),
            (HEADER_SIZE as u32 + 16, u32::MAX),
            (0, base.len() as u32),
            (0, u32::MAX),
            (4, 4),
            (base.len() as u32 - 1, 2),
            (base.len() as u32, 2),
            (base.len() as u32 + 1, 2),
            (u32::MAX, 1),
            (u32::MAX, u32::MAX),
        ];
        for (offset, size) in cases {
            let mut pf = base.clone();
            pf[HEADER_SIZE + 16..HEADER_SIZE + 20].copy_from_slice(&offset.to_le_bytes());
            pf[HEADER_SIZE + 20..HEADER_SIZE + 24].copy_from_slice(&size.to_le_bytes());
            let obs = harvest(&pf, "LOOP.EXE-00000000.pf");
            assert_eq!(obs.len(), 1, "offset={offset:#x} size={size:#x}");
        }
    }

    #[test]
    fn degenerate_strings_sections() {
        let mut pf =
            build_scca(26, "S.EXE", &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0], 1, &[], false);
        let at = pf.len();
        pf.resize(pf.len() + 4096, 0u8);
        pf[HEADER_SIZE + 16..HEADER_SIZE + 20].copy_from_slice(&(at as u32).to_le_bytes());
        pf[HEADER_SIZE + 20..HEADER_SIZE + 24].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(keys(&harvest(&pf, "S.EXE-1.pf")), vec!["\\s.exe"]);

        let mut pf =
            build_scca(26, "S.EXE", &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0], 1, &[], false);
        let at = pf.len();
        pf.resize(pf.len() + 4095, b'A');
        pf[HEADER_SIZE + 16..HEADER_SIZE + 20].copy_from_slice(&(at as u32).to_le_bytes());
        pf[HEADER_SIZE + 20..HEADER_SIZE + 24].copy_from_slice(&4095u32.to_le_bytes());
        assert_eq!(harvest(&pf, "S.EXE-1.pf").len(), 1);

        let mut pf =
            build_scca(26, "S.EXE", &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0], 1, &[], false);
        let at = pf.len();
        for _ in 0..64 {
            pf.extend_from_slice(&0xd800u16.to_le_bytes());
        }
        pf.extend_from_slice(&[0, 0]);
        pf[HEADER_SIZE + 16..HEADER_SIZE + 20].copy_from_slice(&(at as u32).to_le_bytes());
        pf[HEADER_SIZE + 20..HEADER_SIZE + 24].copy_from_slice(&130u32.to_le_bytes());
        assert_eq!(harvest(&pf, "S.EXE-1.pf").len(), 1);
    }

    #[test]
    fn hostile_executable_name_fields() {
        let fillers: [&[u8]; 5] = [&[0xff], &[0x00, 0xd8], &[0x20], &[0x5c], &[0x0a]];
        for filler in fillers {
            let mut pf = build_scca(
                26,
                "N.EXE",
                &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0],
                1,
                &["C:\\N.EXE"],
                false,
            );
            for (i, b) in pf[NAME_OFFSET..NAME_OFFSET + NAME_SIZE].iter_mut().enumerate() {
                *b = filler[i % filler.len()];
            }
            let _ = harvest(&pf, "N.EXE-12345678.pf");
        }
        let mut pf =
            build_scca(26, "N.EXE", &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0], 1, &[], false);
        for c in pf[NAME_OFFSET..NAME_OFFSET + NAME_SIZE].chunks_mut(2) {
            c[0] = b'\\';
            c[1] = 0;
        }
        assert!(harvest(&pf, "\\\\\\.pf").is_empty());
    }

    #[test]
    fn hostile_pf_file_names() {
        let names = [
            "",
            ".pf",
            "-.pf",
            "--------.pf",
            "-DEADBEEF.pf",
            "\\\\server\\share\\X.EXE-1234ABCD.pf",
            "\u{1f600}\u{1f600}-1234ABCD.pf",
            "\u{1f600}.pf",
            "\u{00e9}\u{00e9}\u{00e9}.pf",
            &"A".repeat(4096),
        ];
        let mut pf =
            build_scca(26, "P.EXE", &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0], 1, &[], false);
        for b in &mut pf[NAME_OFFSET..NAME_OFFSET + NAME_SIZE] {
            *b = 0;
        }
        for n in names {
            let _ = name_from_pf_file_name(n);
            let _ = harvest(&pf, n);
        }
    }

    #[test]
    fn mam_containers_truncated_and_mutated() {
        let pf = build_scca(
            30,
            "MAMTEST.EXE",
            &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0],
            2,
            &["\\VOLUME{01d}\\TEMP\\MAMTEST.EXE"],
            true,
        );
        let container = mam(&literal_only_stream(&pf), pf.len() as u32);
        assert_eq!(harvest(&container, "MAMTEST.EXE-AABBCCDD.pf").len(), 1);

        for cut in 0..container.len() {
            let obs = harvest(&container[..cut], "MAMTEST.EXE-AABBCCDD.pf");
            for o in &obs {
                let key = o.path.as_ref().unwrap().key().to_string();
                assert!(
                    key == "\\temp\\mamtest.exe" || key == "\\mamtest.exe",
                    "cut={cut} invented {key}"
                );
            }
        }
        for b in 0u16..=255 {
            let mut m = container.clone();
            m[3] = b as u8;
            let _ = harvest(&m, "MAMTEST.EXE-AABBCCDD.pf");
        }
        for size in [
            0u32,
            1,
            2,
            3,
            7,
            8,
            pf.len() as u32 - 1,
            pf.len() as u32 + 1,
            1 << 20,
            1 << 30,
            u32::MAX,
        ] {
            let m = mam(&literal_only_stream(&pf), size);
            let _ = harvest(&m, "MAMTEST.EXE-AABBCCDD.pf");
        }
        let nested = mam(&literal_only_stream(&container), container.len() as u32);
        assert!(harvest(&nested, "MAMTEST.EXE-AABBCCDD.pf").is_empty());
    }

    #[test]
    fn a_compression_bomb_is_capped_in_size_and_time() {
        let table = code_lengths(&[(b'A' as usize, 2), (271, 2), (300, 2)]);
        let mut payload = table;
        let mut bits = String::from("00");
        for _ in 0..40_000 {
            bits.push_str("10");
            bits.push_str("00");
        }
        payload.extend_from_slice(&bitstream(&bits));
        let mut big = payload.clone();
        for _ in 0..64 {
            big.extend_from_slice(&payload);
        }
        let container = mam(&big, u32::MAX);

        let start = std::time::Instant::now();
        let out = xpress::decompress_mam(&container).unwrap();
        let elapsed = start.elapsed();
        assert!(out.len() <= 64 * 1024 * 1024, "output {} exceeded the cap", out.len());
        assert!(elapsed.as_secs() < 20, "took {elapsed:?}");
        assert!(harvest(&container, "B.EXE-AABBCCDD.pf").is_empty());
    }

    #[test]
    fn an_enormous_strings_section_is_walked_in_linear_time() {
        for (label, unit) in [("tiny runs", &b"A\0\0\0"[..]), ("all nul", &b"\0\0\0\0"[..])] {
            let mut pf = build_scca(
                26,
                "BIG.EXE",
                &[filetime(1_704_067_200), 0, 0, 0, 0, 0, 0, 0],
                1,
                &[],
                false,
            );
            let at = pf.len();
            let bytes = if cfg!(debug_assertions) { 4 } else { 16 } * 1024 * 1024usize;
            pf.reserve(bytes);
            for _ in 0..bytes / 4 {
                pf.extend_from_slice(unit);
            }
            pf[HEADER_SIZE + 16..HEADER_SIZE + 20].copy_from_slice(&(at as u32).to_le_bytes());
            pf[HEADER_SIZE + 20..HEADER_SIZE + 24].copy_from_slice(&(bytes as u32).to_le_bytes());
            let start = std::time::Instant::now();
            let obs = harvest(&pf, "BIG.EXE-AABBCCDD.pf");
            assert_eq!(obs.len(), 1, "{label}");
            assert!(start.elapsed().as_secs() < 60, "{label} took {:?}", start.elapsed());
        }
    }

    #[test]
    fn xpress_structured_fuzz() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..if cfg!(debug_assertions) { 800 } else { 4000 } {
            let mut table = vec![0u8; 256];
            let style = rng.below(4);
            for b in table.iter_mut() {
                *b = match style {
                    0 => rng.next() as u8,
                    1 => 0x88,
                    2 => (rng.below(3) as u8) | ((rng.below(3) as u8) << 4),
                    _ => (rng.below(16) as u8) | ((rng.below(16) as u8) << 4),
                };
            }
            let bit_len = rng.below(400);
            let mut payload = table;
            payload.extend((0..bit_len).map(|_| rng.next() as u8));
            let target = [0usize, 1, 7, 64, 4096, 70_000][rng.below(6)];
            let out = xpress::decompress(&payload, target);
            assert!(out.len() <= target.max(65_536) + 65_536);

            for _ in 0..3 {
                let cut = rng.below(payload.len() + 1);
                let _ = xpress::decompress(&payload[..cut], target);
            }
        }
    }

    #[test]
    fn full_stack_fuzz_never_panics_or_spins() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let samples = every_version();
        let start = std::time::Instant::now();
        let (a, b) = if cfg!(debug_assertions) { (2_000, 4_000) } else { (20_000, 40_000) };

        for _ in 0..a {
            let len = rng.below(1200);
            let buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let _ = harvest(&buf, "X.EXE-DEADBEEF.pf");

            let mut wrapped = vec![0x4d, 0x41, 0x4d, (rng.next() as u8 & 0xf0) | 4];
            wrapped.extend_from_slice(&((rng.below(400_000)) as u32).to_le_bytes());
            wrapped.extend_from_slice(&buf);
            let _ = harvest(&wrapped, "X.EXE-DEADBEEF.pf");
        }

        for _ in 0..b {
            let (_, base) = &samples[rng.below(samples.len())];
            let mut m = base.clone();
            for _ in 0..1 + rng.below(6) {
                let at = rng.below(m.len());
                m[at] = rng.next() as u8;
            }
            let obs = harvest(&m, "SAMPLE.EXE-AABBCCDD.pf");
            for o in &obs {
                assert!(o.path.is_some());
            }
            let c = mam(&literal_only_stream(&m), m.len() as u32);
            let _ = harvest(&c, "SAMPLE.EXE-AABBCCDD.pf");
        }

        assert!(start.elapsed().as_secs() < 300, "fuzz took {:?}", start.elapsed());
    }

    #[test]
    fn partial_run_time_arrays_report_only_what_survived() {
        let pf = build_scca(26, "P.EXE", &[filetime(1_704_067_200); 8], 4, &["C:\\P.EXE"], false);
        for slots in 0..=8usize {
            let cut = HEADER_SIZE + 44 + slots * 8;
            let obs = harvest(&pf[..cut], "P.EXE-1.pf");
            let dated = obs
                .iter()
                .filter(|o| matches!(o.kind, ObservationKind::Executed { when: Some(_), .. }))
                .count();
            assert_eq!(dated, slots, "cut after {slots} slots");
            assert!(!obs.is_empty());
        }
    }

    #[test]
    fn xpress_blocks_with_no_room_for_the_bit_window() {
        let table = code_lengths(&[(b'A' as usize, 1), (b'B' as usize, 1)]);
        for extra in 0..8usize {
            let mut payload = table.clone();
            payload.resize(payload.len() + extra, 0u8);
            let out = xpress::decompress(&payload, 64);
            assert!(out.len() <= 64);
        }
    }

    #[test]
    fn xpress_length_escapes_are_bounded() {
        let table = code_lengths(&[(b'A' as usize, 2), (271, 1)]);

        let mut payload = table.clone();
        payload.extend_from_slice(&escape_stream("10 0", &[5]));
        let out = xpress::decompress(&payload, 24);
        assert_eq!(out.len(), 24, "8-bit escape");
        assert!(out.iter().all(|&b| b == b'A'));

        let mut payload = table.clone();
        payload.extend_from_slice(&escape_stream("10 0", &[255, 0x60, 0xea]));
        assert!(xpress::decompress(&payload, 64).len() <= 64);

        let mut payload = table;
        payload.extend_from_slice(&escape_stream("10 0", &[255, 0, 0, 0xff, 0xff, 0xff, 0xff]));
        assert!(xpress::decompress(&payload, 1024).len() <= 1024);
    }

    fn escape_stream(bits: &str, trailer: &[u8]) -> Vec<u8> {
        let mut v = bitstream(bits);
        v.truncate(4);
        v.extend_from_slice(trailer);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }
}
