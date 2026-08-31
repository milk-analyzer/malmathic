use std::io::Cursor;

use chrono::{DateTime, Utc};

use mm_core::{ArtifactSource, NormalizedPath, Observation, ObservationKind};

use crate::Harvested;

pub const CHANNEL: &str = "Microsoft-Windows-Windows Defender/Operational";

const PRODUCT: &str = "Windows Defender";

pub const EVENT_DETECTED: u32 = 1116;
pub const EVENT_ACTION_TAKEN: u32 = 1117;
pub const EVENT_ACTION_FAILED: u32 = 1118;
pub const EVENT_ACTION_CRITICAL_FAILURE: u32 = 1119;

pub const EVENT_IDS: &[u32] =
    &[EVENT_DETECTED, EVENT_ACTION_TAKEN, EVENT_ACTION_FAILED, EVENT_ACTION_CRITICAL_FAILURE];

const ACTION_CLEAN: u32 = 1;
const ACTION_QUARANTINE: u32 = 2;
const ACTION_REMOVE: u32 = 3;

const MAX_RECORDS: usize = 5_000_000;

const MAX_DETECTIONS: usize = 100_000;

const MAX_PATH_FIELD: usize = 256 * 1024;

const MAX_LOCATORS: usize = 512;

const MAX_LOCATOR_BYTES: usize = 16 * 1024 * 1024;

const MAX_PATH_VALUE: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocatorKind {
    File,
    ContainerFile,
    CmdLine,
    WebFile,
    Process,
    Registry,
    Other(String),
}

impl LocatorKind {
    fn from_prefix(prefix: &str) -> Self {
        match prefix.to_ascii_lowercase().as_str() {
            "file" => LocatorKind::File,
            "containerfile" => LocatorKind::ContainerFile,
            "cmdline" => LocatorKind::CmdLine,
            "webfile" => LocatorKind::WebFile,
            "process" => LocatorKind::Process,
            "regkey" | "regvalue" | "runkey" => LocatorKind::Registry,
            other => LocatorKind::Other(other.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Locator {
    pub kind: LocatorKind,
    pub value: String,
}

impl Locator {
    pub fn is_nested(&self) -> bool {
        self.value.contains("->")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Containment {
    Contained,
    NotContained,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub event_id: u32,
    pub threat: Option<String>,
    pub threat_id: Option<u64>,
    pub detected: Option<DateTime<Utc>>,
    pub action_id: Option<u32>,
    pub severity_id: Option<u32>,
    pub locators: Vec<Locator>,
}

impl Detection {
    pub fn containment(&self) -> Containment {
        match (self.event_id, self.action_id) {
            (EVENT_ACTION_TAKEN, Some(ACTION_CLEAN | ACTION_QUARANTINE | ACTION_REMOVE)) => {
                Containment::Contained
            }
            _ => Containment::NotContained,
        }
    }

    pub fn is_container_scoped(&self) -> bool {
        self.locators.iter().any(|l| l.kind == LocatorKind::ContainerFile || l.is_nested())
    }

    pub fn file_paths(&self) -> Vec<NormalizedPath> {
        if self.is_container_scoped() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for locator in &self.locators {
            if locator.kind != LocatorKind::File {
                continue;
            }
            let raw = locator.value.trim();
            if raw.is_empty() || raw.len() > MAX_PATH_VALUE {
                continue;
            }
            if !raw.contains('\\') && !raw.contains('/') && !raw.contains(':') {
                continue;
            }
            if let Some(path) = NormalizedPath::parse(raw) {
                if !out.contains(&path) {
                    out.push(path);
                }
            }
        }
        out
    }
}

pub fn parse_locators(path_field: &str) -> Vec<Locator> {
    let field = if path_field.len() > MAX_PATH_FIELD {
        let mut end = MAX_PATH_FIELD;
        while end > 0 && !path_field.is_char_boundary(end) {
            end -= 1;
        }
        &path_field[..end]
    } else {
        path_field
    };

    let mut out: Vec<Locator> = Vec::new();
    for segment in field.split(';') {
        match split_prefix(segment.trim_start()) {
            Some((prefix, value)) if out.len() < MAX_LOCATORS => {
                out.push(Locator {
                    kind: LocatorKind::from_prefix(prefix),
                    value: value.to_string(),
                });
            }
            Some(_) => {
                if let Some(last) = out.last_mut() {
                    last.value.push(';');
                    last.value.push_str(segment);
                }
            }
            None => {
                if let Some(last) = out.last_mut() {
                    last.value.push(';');
                    last.value.push_str(segment);
                }
            }
        }
    }
    out
}

fn split_prefix(segment: &str) -> Option<(&str, &str)> {
    let colon = segment.find(":_")?;
    let prefix = &segment[..colon];
    if prefix.len() < 2 || prefix.len() > 32 {
        return None;
    }
    if !prefix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    if !prefix.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    Some((prefix, &segment[colon + 2..]))
}

pub fn parse(bytes: &[u8]) -> Vec<Detection> {
    let mut out = Vec::new();

    let Ok(mut parser) = evtx::EvtxParser::from_read_seek(Cursor::new(bytes)) else {
        return out;
    };

    let mut seen = 0usize;
    let mut locator_bytes = 0usize;
    for record in parser.records() {
        seen += 1;
        if seen > MAX_RECORDS || out.len() >= MAX_DETECTIONS || locator_bytes >= MAX_LOCATOR_BYTES {
            break;
        }
        let Ok(record) = record else { continue };
        if let Some(detection) = parse_record_xml(&record.data) {
            locator_bytes += detection.locators.iter().map(|l| l.value.len()).sum::<usize>();
            out.push(detection);
        }
    }
    out
}

fn parse_record_xml(xml: &str) -> Option<Detection> {
    use quick_xml::events::Event as XmlEvent;

    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().trim_text(false);

    let mut event_id: Option<u32> = None;
    let mut in_event_id = false;
    let mut data_name: Option<String> = None;
    let mut text = String::new();

    let mut threat = None;
    let mut threat_id = None;
    let mut detected = None;
    let mut action_id = None;
    let mut severity_id = None;
    let mut path_field: Option<String> = None;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                text.clear();
                match e.local_name().as_ref() {
                    b"EventID" => in_event_id = true,
                    b"Data" => {
                        data_name = e
                            .try_get_attribute("Name")
                            .ok()
                            .flatten()
                            .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()));
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::End(e)) => {
                match e.local_name().as_ref() {
                    b"EventID" => {
                        in_event_id = false;
                        event_id = text.trim().parse().ok();
                        if !event_id.is_some_and(|id| EVENT_IDS.contains(&id)) {
                            return None;
                        }
                    }
                    b"Data" => {
                        if let Some(name) = data_name.take() {
                            let value = text.trim();
                            match name.as_str() {
                                "Threat Name" if !value.is_empty() => {
                                    threat = Some(value.to_string());
                                }
                                "Threat ID" => threat_id = value.parse().ok(),
                                "Detection Time" => detected = parse_iso8601(value),
                                "Action ID" => action_id = value.parse().ok(),
                                "Severity ID" => severity_id = value.parse().ok(),
                                "Path" if !value.is_empty() => {
                                    path_field = Some(value.to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                    b"EventData" => break,
                    _ => {}
                }
                text.clear();
            }
            Ok(XmlEvent::Text(t)) => {
                if (in_event_id || data_name.is_some()) && text.len() < MAX_PATH_FIELD {
                    if let Ok(t) = t.xml10_content() {
                        text.push_str(&t);
                    }
                }
            }
            Ok(XmlEvent::GeneralRef(r)) => {
                if (in_event_id || data_name.is_some()) && text.len() < MAX_PATH_FIELD {
                    text.push_str(&resolve_entity(&r));
                }
            }
            Ok(XmlEvent::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    let event_id = event_id.filter(|id| EVENT_IDS.contains(id))?;
    Some(Detection {
        event_id,
        threat,
        threat_id,
        detected,
        action_id,
        severity_id,
        locators: path_field.as_deref().map(parse_locators).unwrap_or_default(),
    })
}

fn resolve_entity(r: &quick_xml::events::BytesRef) -> String {
    if let Ok(Some(c)) = r.resolve_char_ref() {
        return c.to_string();
    }
    let Ok(name) = r.decode() else { return String::new() };
    match name.as_ref() {
        "amp" => "&".to_string(),
        "lt" => "<".to_string(),
        "gt" => ">".to_string(),
        "quot" => "\"".to_string(),
        "apos" => "'".to_string(),
        other => format!("&{other};"),
    }
}

fn parse_iso8601(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text).ok().map(|t| t.with_timezone(&Utc))
}

pub fn harvest(bytes: &[u8]) -> Harvested {
    let mut out = Harvested::new();
    let mut seen: std::collections::HashMap<(String, Option<String>, bool), usize> =
        std::collections::HashMap::new();

    for detection in parse(bytes) {
        let contained = detection.containment() == Containment::Contained;
        for path in detection.file_paths() {
            let key = (path.key().to_string(), detection.threat.clone(), contained);
            if let Some(&index) = seen.get(&key) {
                keep_earliest(&mut out[index], detection.detected);
                keep_severity(&mut out[index], detection.severity_id);
                continue;
            }
            let kind = if contained {
                ObservationKind::Quarantined {
                    product: PRODUCT.to_string(),
                    threat: detection.threat.clone(),
                    when: detection.detected,
                    severity: detection.severity_id,
                }
            } else {
                ObservationKind::AvDetected {
                    product: PRODUCT.to_string(),
                    threat: detection.threat.clone(),
                    when: detection.detected,
                    severity: detection.severity_id,
                }
            };
            seen.insert(key, out.len());
            out.push(Observation::about_path(
                ArtifactSource::DefenderLog { event_id: detection.event_id },
                path,
                kind,
            ));
        }
    }
    out
}

fn keep_severity(observation: &mut Observation, candidate: Option<u32>) {
    let Some(candidate) = candidate else { return };
    let slot = match &mut observation.kind {
        ObservationKind::Quarantined { severity, .. }
        | ObservationKind::AvDetected { severity, .. } => severity,
        _ => return,
    };
    if slot.is_none() {
        *slot = Some(candidate);
    }
}

fn keep_earliest(observation: &mut Observation, candidate: Option<DateTime<Utc>>) {
    let Some(candidate) = candidate else { return };
    let slot = match &mut observation.kind {
        ObservationKind::Quarantined { when, .. } | ObservationKind::AvDetected { when, .. } => {
            when
        }
        _ => return,
    };
    if slot.is_none_or(|existing| candidate < existing) {
        *slot = Some(candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detection(event_id: u32, action_id: Option<u32>, path_field: &str) -> Detection {
        Detection {
            event_id,
            threat: Some("Trojan:Win32/Test".into()),
            threat_id: Some(1),
            detected: None,
            action_id,
            severity_id: Some(5),
            locators: parse_locators(path_field),
        }
    }

    fn keys(d: &Detection) -> Vec<String> {
        d.file_paths().iter().map(|p| p.key().to_string()).collect()
    }

    #[test]
    fn a_command_line_is_never_a_path() {
        let field = "CmdLine:_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe \
                     -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command try { \
                     $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8' } catch {}; \
                     if ($null -ne $PSStyle) { try { $PSStyle.OutputRendering = 'PlainText' } \
                     catch {} }";
        let d = detection(EVENT_ACTION_TAKEN, Some(ACTION_REMOVE), field);

        assert_eq!(d.containment(), Containment::Contained);
        assert!(keys(&d).is_empty(), "powershell.exe must not become a candidate");

        assert_eq!(d.locators.len(), 1);
        assert_eq!(d.locators[0].kind, LocatorKind::CmdLine);
        assert!(d.locators[0].value.contains("PlainText"), "continuations rejoin");
    }

    #[test]
    fn a_detection_inside_an_archive_names_no_file() {
        let field = "containerfile:_C:\\ISOs\\kali-linux-2026.2.iso; \
                     file:_C:\\ISOs\\kali-linux-2026.2.iso->pool\\main\\m\\metasploit-framework\\\
                     metasploit-framework_6.4.135-0kali1_amd64.deb->data.tar.xz->(xz)->\
                     ./usr/share/metasploit-framework/modules/exploits/windows/browser/\
                     ms14_012_cmarkup_uaf.rb->(SCRIPT0000)";
        let d = detection(EVENT_DETECTED, Some(9), field);

        assert_eq!(d.locators.len(), 2);
        assert_eq!(d.locators[0].kind, LocatorKind::ContainerFile);
        assert_eq!(d.locators[1].kind, LocatorKind::File);
        assert!(d.locators[1].is_nested());
        assert!(d.is_container_scoped());
        assert!(keys(&d).is_empty(), "neither the ISO nor its members is the sample");
    }

    #[test]
    fn a_truncated_nested_path_is_still_container_scoped() {
        let d = detection(
            EVENT_DETECTED,
            Some(9),
            "containerfile:_C:\\ISOs\\kali.iso; file:_C:\\ISOs\\kali.iso-",
        );
        assert!(d.is_container_scoped());
        assert!(keys(&d).is_empty());
    }

    #[test]
    fn a_bare_file_locator_becomes_a_path() {
        let d = detection(
            EVENT_ACTION_TAKEN,
            Some(ACTION_QUARANTINE),
            "file:_C:\\Users\\analyst\\Downloads\\capa-v9.4.0-windows.zip",
        );
        assert_eq!(d.containment(), Containment::Contained);
        assert_eq!(keys(&d), vec!["\\users\\analyst\\downloads\\capa-v9.4.0-windows.zip"]);
    }

    #[test]
    fn non_file_locators_are_read_but_never_pathed() {
        let d = detection(
            EVENT_DETECTED,
            Some(9),
            "regkey:_HKLM\\Software\\Evil; process:_pid:4242; amsi:_powershell; \
             webfile:_C:\\Users\\b\\Downloads\\x.exe|https://evil.example/x.exe|",
        );
        assert_eq!(
            d.locators.iter().map(|l| l.kind.clone()).collect::<Vec<_>>(),
            vec![
                LocatorKind::Registry,
                LocatorKind::Process,
                LocatorKind::Other("amsi".into()),
                LocatorKind::WebFile,
            ]
        );
        assert!(keys(&d).is_empty());
    }

    #[test]
    fn a_drive_letter_is_not_a_prefix() {
        assert_eq!(split_prefix("C:_odd"), None);
        assert_eq!(split_prefix("C:\\Windows\\notepad.exe"), None);
        assert_eq!(split_prefix("file:_C:\\x.exe"), Some(("file", "C:\\x.exe")));
    }

    #[test]
    fn a_leading_segment_with_no_prefix_is_dropped_not_guessed() {
        assert!(parse_locators("C:\\Windows\\notepad.exe").is_empty());
        assert!(parse_locators("").is_empty());
        assert!(parse_locators(";;;").is_empty());
    }

    #[test]
    fn a_detection_event_never_claims_the_file_was_dealt_with() {
        for action in [None, Some(1), Some(2), Some(3), Some(9)] {
            let d = detection(EVENT_DETECTED, action, "file:_C:\\x.exe");
            assert_eq!(
                d.containment(),
                Containment::NotContained,
                "1116 with action {action:?} must not claim containment"
            );
        }
    }

    #[test]
    fn a_failed_remediation_is_not_containment() {
        for id in [EVENT_ACTION_FAILED, EVENT_ACTION_CRITICAL_FAILURE] {
            for action in [Some(ACTION_REMOVE), Some(ACTION_QUARANTINE), Some(ACTION_CLEAN)] {
                let d = detection(id, action, "file:_C:\\x.exe");
                assert_eq!(d.containment(), Containment::NotContained);
            }
        }
    }

    #[test]
    fn only_a_remediating_action_on_an_action_event_is_containment() {
        for action in [ACTION_CLEAN, ACTION_QUARANTINE, ACTION_REMOVE] {
            assert_eq!(
                detection(EVENT_ACTION_TAKEN, Some(action), "file:_C:\\x.exe").containment(),
                Containment::Contained
            );
        }
        for action in [Some(4), Some(5), Some(6), Some(7), Some(9), Some(99), None] {
            assert_eq!(
                detection(EVENT_ACTION_TAKEN, action, "file:_C:\\x.exe").containment(),
                Containment::NotContained,
                "action {action:?} leaves the file in place"
            );
        }
    }

    fn record_xml(event_id: u32, action_id: u32, threat: &str, path: &str) -> String {
        format!(
            "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\
             <System><Provider Name=\"Microsoft-Windows-Windows Defender\"/>\
             <EventID>{event_id}</EventID><Level>3</Level>\
             <TimeCreated SystemTime=\"2026-07-28T21:07:54.9348589Z\"/>\
             <Channel>{CHANNEL}</Channel></System>\
             <EventData>\
             <Data Name=\"Product Name\">Антивирусная программа Microsoft Defender</Data>\
             <Data Name=\"Unused\"></Data>\
             <Data Name=\"Detection Time\">2026-07-28T21:07:54.844Z</Data>\
             <Data Name=\"Threat ID\">2147686191</Data>\
             <Data Name=\"Threat Name\">{threat}</Data>\
             <Data Name=\"Severity ID\">5</Data>\
             <Data Name=\"Unused2\"></Data>\
             <Data Name=\"Path\">{path}</Data>\
             <Data Name=\"Action ID\">{action_id}</Data>\
             <Data Name=\"Action Name\">Удалить</Data>\
             </EventData></Event>"
        )
    }

    #[test]
    fn a_record_is_read_by_field_name_not_by_position() {
        let d = parse_record_xml(&record_xml(
            EVENT_ACTION_TAKEN,
            ACTION_QUARANTINE,
            "Trojan:Win32/Ravartar!rfn",
            "file:_C:\\Users\\analyst\\Videos\\sample.apk",
        ))
        .unwrap();

        assert_eq!(d.event_id, EVENT_ACTION_TAKEN);
        assert_eq!(d.threat.as_deref(), Some("Trojan:Win32/Ravartar!rfn"));
        assert_eq!(d.threat_id, Some(2147686191));
        assert_eq!(d.action_id, Some(ACTION_QUARANTINE));
        assert_eq!(d.severity_id, Some(5));
        assert_eq!(mm_core::filetime::format(d.detected.unwrap()), "2026-07-28 21:07:54Z");
        assert_eq!(keys(&d), vec!["\\users\\analyst\\videos\\sample.apk"]);
    }

    #[test]
    fn records_that_are_not_detections_are_skipped() {
        for id in [1000u32, 1013, 2000, 2010, 5007, 1115, 1120] {
            assert!(
                parse_record_xml(&record_xml(id, 0, "x", "file:_C:\\x.exe")).is_none(),
                "event {id} is not a detection"
            );
        }
    }

    #[test]
    fn escaped_arrows_are_unescaped_before_the_nesting_test() {
        let d = parse_record_xml(&record_xml(
            EVENT_DETECTED,
            9,
            "Exploit:JS/CVE-2014-0322.A",
            "containerfile:_C:\\ISOs\\kali.iso; file:_C:\\ISOs\\kali.iso-&gt;pool\\x.rb",
        ))
        .unwrap();
        assert!(d.locators[1].is_nested());
        assert!(d.is_container_scoped());
        assert!(keys(&d).is_empty());
    }

    #[test]
    fn malformed_xml_costs_the_record_and_nothing_else() {
        assert!(parse_record_xml("").is_none());
        assert!(parse_record_xml("<Event><System><EventID>oops").is_none());
        assert!(parse_record_xml("<Event/>").is_none());
        assert!(parse_record_xml(&"<".repeat(10_000)).is_none());
    }

    #[test]
    fn a_file_that_is_not_an_evtx_yields_nothing_rather_than_failing() {
        assert!(parse(&[]).is_empty());
        assert!(parse(b"MZ\x90\x00not an event log").is_empty());
        assert!(parse(&vec![0u8; 128 * 1024]).is_empty());
        assert!(parse(&(0..=255u8).cycle().take(200_000).collect::<Vec<_>>()).is_empty());
    }

    #[test]
    fn locator_parsing_is_bounded() {
        let huge = format!("CmdLine:_{}", "x;".repeat(400_000));
        let locators = parse_locators(&huge);
        assert_eq!(locators.len(), 1);
        assert!(locators[0].value.len() <= MAX_PATH_FIELD);

        let many = "file:_C:\\x.exe;".repeat(10_000);
        assert!(parse_locators(&many).len() <= MAX_LOCATORS);
    }

    #[test]
    fn truncation_respects_character_boundaries() {
        let field = format!("CmdLine:_{}", "Ы".repeat(MAX_PATH_FIELD));
        let locators = parse_locators(&field);
        assert_eq!(locators.len(), 1);
    }

    #[test]
    fn an_absurd_path_value_is_not_offered_as_a_path() {
        let d = detection(
            EVENT_DETECTED,
            Some(9),
            &format!("file:_C:\\{}", "a".repeat(MAX_PATH_VALUE + 10)),
        );
        assert!(keys(&d).is_empty());
    }

    #[test]
    fn a_repeated_detection_keeps_the_earliest_moment() {
        let mut log = String::new();
        for stamp in
            ["2026-07-28T21:07:54.844Z", "2026-04-24T15:18:24.345Z", "2026-06-01T00:00:00Z"]
        {
            log.push_str(&record_with_time(EVENT_DETECTED, 9, stamp));
        }
        let detections: Vec<Detection> = log
            .split("<Event ")
            .skip(1)
            .filter_map(|r| parse_record_xml(&format!("<Event {r}")))
            .collect();
        assert_eq!(detections.len(), 3);

        let mut observation = Observation::about_path(
            ArtifactSource::DefenderLog { event_id: EVENT_DETECTED },
            detections[0].file_paths().remove(0),
            ObservationKind::AvDetected {
                product: PRODUCT.to_string(),
                threat: detections[0].threat.clone(),
                when: detections[0].detected,
                severity: None,
            },
        );
        keep_earliest(&mut observation, detections[1].detected);
        keep_earliest(&mut observation, detections[2].detected);
        assert_eq!(
            mm_core::filetime::format(observation.timestamp().unwrap()),
            "2026-04-24 15:18:24Z"
        );

        let mut blank = Observation::about_path(
            ArtifactSource::DefenderLog { event_id: EVENT_DETECTED },
            NormalizedPath::parse("C:\\x.exe").unwrap(),
            ObservationKind::AvDetected {
                product: PRODUCT.to_string(),
                threat: None,
                when: None,
                severity: None,
            },
        );
        keep_earliest(&mut blank, detections[0].detected);
        assert_eq!(blank.timestamp(), detections[0].detected);
        keep_earliest(&mut blank, None);
        assert_eq!(blank.timestamp(), detections[0].detected);
    }

    fn record_with_time(event_id: u32, action_id: u32, detected: &str) -> String {
        record_xml(event_id, action_id, "Trojan:Win32/Test", "file:_C:\\Users\\b\\x.exe")
            .replace("2026-07-28T21:07:54.844Z", detected)
    }

    const ONE_CHUNK: &[u8] = include_bytes!("../fixtures/defender-operational-one-chunk.evtx");

    const FILE_HEADER: usize = 4096;

    #[test]
    fn the_fixture_is_a_real_log_and_yields_real_detections() {
        assert_eq!(ONE_CHUNK.len(), FILE_HEADER + 65_536);
        assert_eq!(&ONE_CHUNK[..8], b"ElfFile\0");

        let detections = parse(ONE_CHUNK);
        assert_eq!(detections.len(), 2, "the chunk holds a 1116 and its 1117");
        assert_eq!(
            detections.iter().map(|d| d.event_id).collect::<Vec<_>>(),
            vec![EVENT_DETECTED, EVENT_ACTION_TAKEN]
        );
        assert!(
            detections.iter().all(|d| d.detected.is_some()),
            "both carry a Detection Time; the incident window anchors on it"
        );

        let observations = harvest(ONE_CHUNK);
        assert_eq!(observations.len(), 2);
        assert!(
            observations.iter().all(|o| o.timestamp().is_some()),
            "the detection time must survive the trip onto the observation"
        );
        assert!(observations.iter().any(|o| matches!(o.kind, ObservationKind::AvDetected { .. })));
        assert!(observations.iter().any(|o| matches!(o.kind, ObservationKind::Quarantined { .. })));
        assert!(observations
            .iter()
            .all(|o| matches!(o.source, ArtifactSource::DefenderLog { .. })));
    }

    #[test]
    fn a_truncated_log_degrades_rather_than_dying() {
        let mut prefixes = 0usize;
        for end in (0..ONE_CHUNK.len()).step_by(331) {
            prefixes += 1;
            let detections = parse(&ONE_CHUNK[..end]);
            assert!(
                detections.is_empty(),
                "a prefix of {end} bytes yielded {} detections from a partial chunk",
                detections.len()
            );
            assert!(harvest(&ONE_CHUNK[..end]).is_empty());
        }
        assert!(prefixes > 200, "the stride must actually cover the file");

        let two = two_chunk_log();
        let whole = parse(&two).len();
        assert_eq!(whole, 4, "the doubled chunk must read as two chunks of two");
        let mut survived = 0usize;
        let mut cuts = 0usize;
        for end in (ONE_CHUNK.len()..two.len()).step_by(331) {
            cuts += 1;
            let detections = parse(&two[..end]);
            assert_eq!(
                detections.len(),
                2,
                "cutting at {end} cost the intact first chunk as well as the second"
            );
            assert!(detections.iter().all(|d| d.detected.is_some()));
            survived += 1;
        }
        assert!(cuts > 190 && survived == cuts, "{survived}/{cuts}");
    }

    fn two_chunk_log() -> Vec<u8> {
        let mut out = ONE_CHUNK.to_vec();
        out.extend_from_slice(&ONE_CHUNK[FILE_HEADER..]);
        out
    }

    #[test]
    fn a_byte_corrupted_log_degrades_rather_than_dying() {
        let mut rng = 0x5eed_1116_1117_1118u64;
        let mut next = move || {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        let started = std::time::Instant::now();
        let mut yielded = 0usize;
        const ROUNDS: usize = 250;
        for _ in 0..ROUNDS {
            let mut damaged = ONE_CHUNK.to_vec();
            let flips = 1 + (next() % 16) as usize;
            for _ in 0..flips {
                let at = (next() as usize) % damaged.len();
                damaged[at] ^= (next() % 256) as u8;
            }
            let detections = parse(&damaged);
            assert!(detections.len() <= 64, "{} detections from one chunk", detections.len());
            if !detections.is_empty() {
                yielded += 1;
            }
            for d in &detections {
                let _ = d.containment();
                let _ = d.is_container_scoped();
                assert!(d.file_paths().iter().all(|p| p.key().len() <= MAX_PATH_VALUE));
            }
            assert!(harvest(&damaged).len() <= 64);
        }
        assert!(
            yielded > ROUNDS / 2,
            "only {yielded}/{ROUNDS} mutations reached a record; this test is vacuous"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "corrupted logs took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_record_caps_are_tested_before_the_record_is_decoded() {
        let source = include_str!("defender_log.rs");
        let body = source
            .split_once("pub fn parse(bytes: &[u8]) -> Vec<Detection> {")
            .expect("parse must still be here")
            .1;
        let guard = body.find("break;").expect("parse must still have a cap");
        let decode = body.find("parse_record_xml").expect("parse must still decode");
        assert!(
            guard < decode,
            "a cap that fires after the record is built has already paid for it"
        );
        for cap in ["MAX_RECORDS", "MAX_DETECTIONS", "MAX_LOCATOR_BYTES"] {
            assert!(body[..decode].contains(cap), "{cap} is no longer checked before decoding");
        }
    }
}
