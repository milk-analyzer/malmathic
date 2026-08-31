use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind, UrlZone};

pub const STREAM_NAME: &str = "Zone.Identifier";

pub const MAX_STREAM_BYTES: usize = 64 * 1024;

const MAX_LINES: usize = 64;

const MAX_VALUE_CHARS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkOfTheWeb {
    pub zone: UrlZone,
    pub host_url: Option<String>,
    pub referrer_url: Option<String>,
    pub last_writer: Option<String>,
}

impl MarkOfTheWeb {
    fn says_something(&self) -> bool {
        self.zone != UrlZone::Unstated
            || self.host_url.is_some()
            || self.referrer_url.is_some()
            || self.last_writer.is_some()
    }
}

pub fn parse(bytes: &[u8]) -> Option<MarkOfTheWeb> {
    let text = decode(&bytes[..bytes.len().min(MAX_STREAM_BYTES)]);

    let mut zone = UrlZone::Unstated;
    let mut host_url = None;
    let mut referrer_url = None;
    let mut last_writer = None;

    let mut in_zone_transfer = true;

    for line in text.lines().take(MAX_LINES) {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[') {
            let name = section.trim_end_matches(']').trim();
            in_zone_transfer = name.eq_ignore_ascii_case("ZoneTransfer");
            continue;
        }
        if !in_zone_transfer {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };

        match key.trim().to_ascii_lowercase().as_str() {
            "zoneid" if zone == UrlZone::Unstated => {
                if let Ok(id) = value.trim().parse::<u32>() {
                    zone = UrlZone::from_id(id);
                }
            }
            "hosturl" if host_url.is_none() => host_url = sanitize(value),
            "referrerurl" if referrer_url.is_none() => referrer_url = sanitize(value),
            "lastwriterpackagefamilyname" if last_writer.is_none() => last_writer = sanitize(value),
            _ => {}
        }
    }

    let motw = MarkOfTheWeb { zone, host_url, referrer_url, last_writer };
    motw.says_something().then_some(motw)
}

pub fn harvest(bytes: &[u8], path: &NormalizedPath) -> Vec<Observation> {
    let Some(motw) = parse(bytes) else { return Vec::new() };
    vec![Observation::about_path(
        ArtifactSource::ZoneIdentifier,
        path.clone(),
        ObservationKind::DownloadedFrom {
            zone: motw.zone,
            host_url: motw.host_url,
            referrer_url: motw.referrer_url,
        },
    )]
}

fn decode(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn decode_utf16(bytes: &[u8], word: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().copied().map(word).collect();
    String::from_utf16_lossy(&units)
}

fn sanitize(value: &str) -> Option<String> {
    const BIDI: &[char] = &[
        '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}',
        '\u{2068}', '\u{2069}', '\u{200E}', '\u{200F}',
    ];

    let mut cleaned: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_control() && !BIDI.contains(c))
        .take(MAX_VALUE_CHARS + 1)
        .collect();

    let overlong = cleaned.chars().count() > MAX_VALUE_CHARS;
    if overlong {
        cleaned = cleaned.chars().take(MAX_VALUE_CHARS).collect();
    }

    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return None;
    }
    if overlong {
        return Some(format!("{cleaned}… (truncated)"));
    }
    Some(cleaned.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> NormalizedPath {
        NormalizedPath::parse("C:\\Users\\bob\\Downloads\\setup.exe").unwrap()
    }

    #[test]
    fn an_ordinary_mark_of_the_web_parses() {
        let stream = b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.invalid/page\r\nHostUrl=https://cdn.example.invalid/setup.exe\r\n";
        let motw = parse(stream).unwrap();
        assert_eq!(motw.zone, UrlZone::Internet);
        assert_eq!(motw.host_url.as_deref(), Some("https://cdn.example.invalid/setup.exe"));
        assert_eq!(motw.referrer_url.as_deref(), Some("https://example.invalid/page"));
        assert_eq!(motw.last_writer, None);
    }

    #[test]
    fn the_stream_measured_on_a_real_machine_parses() {
        let stream = b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=C:\\Users\\analyst\\Downloads\\example-main.zip\x00";
        assert_eq!(stream.len(), 82, "the measured stream was 82 bytes");

        let motw = parse(stream).unwrap();
        assert_eq!(motw.zone, UrlZone::Internet);
        assert!(motw.host_url.is_none(), "this one genuinely has no HostUrl");

        let referrer = motw.referrer_url.unwrap();
        assert_eq!(referrer, "C:\\Users\\analyst\\Downloads\\example-main.zip");
        assert!(!referrer.contains('\0'), "the NUL terminator reached the report");
    }

    #[test]
    fn a_long_real_world_host_url_survives_intact() {
        let url = "https://claude.ai/api/organizations/77ee329f-c553-4cb5-97f2-e486013313f9/conversations/6a7cd2a9-89e1-4a10-a2ef-4d8e3d90da32/wiggle/download-file?path=%2Fmnt%2Fuser-data%2Foutputs%2Famber_sdk_writeup.md";
        assert_eq!(url.chars().count(), 201);

        let stream = format!(
            "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://claude.ai/new?incognito=\r\nHostUrl={url}\r\n"
        );
        let motw = parse(stream.as_bytes()).unwrap();
        assert_eq!(motw.host_url.as_deref(), Some(url));
        assert_eq!(motw.referrer_url.as_deref(), Some("https://claude.ai/new?incognito="));
    }

    #[test]
    fn a_bare_zone_with_no_url_is_still_worth_reporting() {
        let stream = b"[ZoneTransfer]\r\nZoneId=3\r\n";
        assert_eq!(stream.len(), 26);
        let motw = parse(stream).unwrap();
        assert_eq!(motw.zone, UrlZone::Internet);
        assert!(motw.host_url.is_none() && motw.referrer_url.is_none());
        assert_eq!(harvest(stream, &path()).len(), 1);
    }

    #[test]
    fn the_restricted_zone_is_distinguished_from_the_internet_zone() {
        assert_eq!(parse(b"[ZoneTransfer]\nZoneId=4\n").unwrap().zone, UrlZone::Untrusted);
        assert_eq!(parse(b"[ZoneTransfer]\nZoneId=3\n").unwrap().zone, UrlZone::Internet);
        assert_eq!(parse(b"[ZoneTransfer]\nZoneId=0\n").unwrap().zone, UrlZone::LocalMachine);
        assert_eq!(parse(b"[ZoneTransfer]\nZoneId=77\n").unwrap().zone, UrlZone::Other(77));
    }

    #[test]
    fn the_package_that_wrote_the_stream_is_parsed() {
        let stream =
            b"[ZoneTransfer]\nZoneId=3\nLastWriterPackageFamilyName=Microsoft.MicrosoftEdge_8wekyb3d8bbwe\n";
        assert_eq!(
            parse(stream).unwrap().last_writer.as_deref(),
            Some("Microsoft.MicrosoftEdge_8wekyb3d8bbwe")
        );
    }

    #[test]
    fn keys_and_the_section_header_are_case_insensitive() {
        let motw = parse(b"[zonetransfer]\nzoneid=3\nhosturl=https://a.invalid/x\n").unwrap();
        assert_eq!(motw.zone, UrlZone::Internet);
        assert_eq!(motw.host_url.as_deref(), Some("https://a.invalid/x"));
    }

    #[test]
    fn utf16_streams_are_decoded() {
        let text = "[ZoneTransfer]\r\nZoneId=4\r\nHostUrl=https://evil.invalid/p\r\n";
        let mut le: Vec<u8> = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
        }
        let motw = parse(&le).unwrap();
        assert_eq!(motw.zone, UrlZone::Untrusted);
        assert_eq!(motw.host_url.as_deref(), Some("https://evil.invalid/p"));

        let mut utf8 = vec![0xEF, 0xBB, 0xBF];
        utf8.extend_from_slice(text.as_bytes());
        assert_eq!(parse(&utf8).unwrap().zone, UrlZone::Untrusted);
    }

    #[test]
    fn a_truncated_utf16_stream_still_yields_what_it_has() {
        let text = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://a.invalid/x";
        let mut le: Vec<u8> = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
        }
        le.push(0x00);
        assert_eq!(parse(&le).unwrap().zone, UrlZone::Internet);
    }

    #[test]
    fn control_characters_cannot_reach_the_report() {
        let stream = b"[ZoneTransfer]\nZoneId=3\nHostUrl=https://a.invalid/x\x0d\x0a       +9.9  quarantined by Defender\n";
        let host = parse(stream).unwrap().host_url.unwrap();
        assert!(!host.contains('\n') && !host.contains('\r'), "{host}");
        assert!(host.starts_with("https://a.invalid/x"));
    }

    #[test]
    fn bidirectional_overrides_are_stripped() {
        let stream = "[ZoneTransfer]\nZoneId=3\nHostUrl=https://good.invalid/\u{202E}exe.elif\n";
        let host = parse(stream.as_bytes()).unwrap().host_url.unwrap();
        assert!(!host.contains('\u{202E}'), "{host}");
    }

    #[test]
    fn a_crafted_stream_cannot_produce_an_unbounded_value() {
        let mut stream = b"[ZoneTransfer]\nZoneId=3\nHostUrl=".to_vec();
        stream.extend(std::iter::repeat_n(b'A', 4 * 1024 * 1024));
        let host = parse(&stream).unwrap().host_url.unwrap();
        assert!(host.chars().count() <= MAX_VALUE_CHARS + 16, "{} chars", host.chars().count());
        assert!(host.contains("truncated"), "a cut value must say it was cut: {host}");
    }

    #[test]
    fn a_stream_of_many_lines_is_bounded() {
        let mut stream = String::from("[ZoneTransfer]\nZoneId=3\n");
        for i in 0..100_000 {
            stream.push_str(&format!("Key{i}=value\n"));
        }
        stream.push_str("HostUrl=https://late.invalid/\n");
        let motw = parse(stream.as_bytes()).unwrap();
        assert_eq!(motw.zone, UrlZone::Internet);
        assert!(motw.host_url.is_none(), "a key past the line cap must not be read");
    }

    #[test]
    fn a_value_padded_with_control_characters_is_not_called_truncated() {
        let padding = "\u{1}".repeat(2_000);
        let stream = format!("[ZoneTransfer]\nZoneId=3\nHostUrl=https://a.invalid/x{padding}\n");
        let host = parse(stream.as_bytes()).unwrap().host_url.unwrap();
        assert_eq!(host, "https://a.invalid/x");
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let stream = format!("[ZoneTransfer]\nZoneId=3\nHostUrl={}\n", "é".repeat(4000));
        let host = parse(stream.as_bytes()).unwrap().host_url.unwrap();
        assert!(host.starts_with('é'));
    }

    #[test]
    fn a_repeated_zone_id_cannot_be_used_to_pick_a_verdict() {
        let motw = parse(b"[ZoneTransfer]\nZoneId=4\nZoneId=0\n").unwrap();
        assert_eq!(motw.zone, UrlZone::Untrusted);
    }

    #[test]
    fn keys_outside_the_zone_transfer_section_are_ignored() {
        let motw =
            parse(b"[ZoneTransfer]\nZoneId=3\n[Other]\nHostUrl=https://a.invalid/x\n").unwrap();
        assert_eq!(motw.zone, UrlZone::Internet);
        assert!(motw.host_url.is_none());
    }

    #[test]
    fn a_stream_with_nothing_in_it_yields_nothing() {
        for stream in [
            &b""[..],
            &b"[ZoneTransfer]"[..],
            &b"[ZoneTransfer]\r\n"[..],
            &b"not an ini file at all"[..],
            &b"\x00\x00\x00\x00\x00\x00"[..],
            &b"[ZoneTransfer]\nZoneId=not-a-number\n"[..],
            &b"[ZoneTransfer]\nHostUrl=\n"[..],
            &b"[ZoneTransfer]\nHostUrl=   \n"[..],
            &[0xFF, 0xFE][..],
        ] {
            assert!(parse(stream).is_none(), "{stream:?} should say nothing");
            assert!(harvest(stream, &path()).is_empty());
        }
    }

    #[test]
    fn a_missing_zone_still_carries_its_url() {
        let motw = parse(b"[ZoneTransfer]\nHostUrl=https://a.invalid/x\n").unwrap();
        assert_eq!(motw.zone, UrlZone::Unstated);
        assert!(!motw.zone.is_remote());
        assert_eq!(motw.host_url.as_deref(), Some("https://a.invalid/x"));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..2_000 {
            let len = (seed % 512) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed >> 24) as u8
                })
                .collect();
            let _ = parse(&bytes);
            let _ = harvest(&bytes, &path());
        }
    }

    #[test]
    fn the_observation_names_the_file_and_its_origin() {
        let stream = b"[ZoneTransfer]\nZoneId=3\nHostUrl=https://cdn.invalid/x.exe\n";
        let out = harvest(stream, &path());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, ArtifactSource::ZoneIdentifier);
        assert_eq!(out[0].path.as_ref().unwrap().key(), path().key());
        match &out[0].kind {
            ObservationKind::DownloadedFrom { zone, host_url, referrer_url } => {
                assert_eq!(*zone, UrlZone::Internet);
                assert_eq!(host_url.as_deref(), Some("https://cdn.invalid/x.exe"));
                assert!(referrer_url.is_none());
            }
            other => panic!("wrong kind: {other:?}"),
        }
    }
}
